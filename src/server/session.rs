//! Server-side session state machine for SMTP submission and LMTP.
//!
//! [`SmtpServerSession`] is fed the bytes the caller reads and yields
//! the bytes to write, plus the decisions only the caller can take:
//! whether credentials are valid, whether a sender, a recipient or a
//! message is accepted, and when to upgrade the stream to TLS. It
//! never touches a socket.
//!
//! Commands may arrive pipelined (RFC 2920): every complete line in
//! the buffer is processed and the replies are written in order, in as
//! few writes as the decisions allow. Message data is dot-unstuffed
//! and its `CRLF.CRLF` terminator found across read boundaries; a
//! message over the size cap is read to its end, then refused with
//! `552 5.3.4`.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{fmt, mem};

use base64_codec::codec::Base64Codec;
use bounded_static::IntoBoundedStatic;
use io_sasl::server::{
    SaslServer, SaslServerArg, SaslServerCredentials, SaslServerError, SaslServerMechanism,
    SaslServerState,
};
use log::debug;
use thiserror::Error;

use crate::{
    coroutine::SmtpCoroutineState,
    rfc5321::{SmtpForwardPath, SmtpMailbox, SmtpReversePath},
    scan::position,
    server::{
        command::{
            SmtpServerBody, SmtpServerCommand, SmtpServerCommandError, SmtpServerMailParams,
            SmtpServerRcptParams,
        },
        reply::SmtpServerReply,
    },
};

/// Line length cap of `AUTH` commands and responses (RFC 4954 section
/// 4).
pub const SMTP_SERVER_MAX_AUTH_LINE_LEN: usize = 12288;

/// The protocol a session speaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmtpServerMode {
    /// SMTP, submission included (RFC 5321, RFC 6409).
    Smtp,
    /// LMTP (RFC 2033): `LHLO`, one reply per recipient after DATA.
    Lmtp,
}

/// Extensions a session advertises.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpServerExtensions {
    /// PIPELINING (RFC 2920).
    pub pipelining: bool,
    /// 8BITMIME (RFC 6152).
    pub eight_bit_mime: bool,
    /// SMTPUTF8 (RFC 6531).
    pub smtputf8: bool,
    /// ENHANCEDSTATUSCODES (RFC 2034).
    pub enhanced_status_codes: bool,
    /// DSN (RFC 3461).
    pub dsn: bool,
    /// STARTTLS (RFC 3207), advertised while TLS is not active.
    pub starttls: bool,
}

impl Default for SmtpServerExtensions {
    fn default() -> Self {
        Self {
            pipelining: true,
            eight_bit_mime: true,
            smtputf8: true,
            enhanced_status_codes: true,
            dsn: true,
            starttls: false,
        }
    }
}

/// Session configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpServerConfig {
    /// The host name of the greeting and of the EHLO reply.
    pub hostname: String,
    /// The SIZE cap in bytes (RFC 1870), 0 for none.
    pub max_message_size: u64,
    /// The recipient cap of one transaction.
    pub max_recipients: usize,
    /// The command line cap, CRLF included (RFC 5321 section
    /// 4.5.3.1.4). AUTH lines get [`SMTP_SERVER_MAX_AUTH_LINE_LEN`] at
    /// least.
    pub max_line_len: usize,
    /// The count of failed commands after which the session replies
    /// 421 and closes, 0 for none.
    pub max_errors: usize,
    /// The extensions advertised.
    pub extensions: SmtpServerExtensions,
    /// The SASL mechanisms advertised, none disabling AUTH.
    pub auth_mechanisms: Vec<SaslServerMechanism>,
    /// Whether MAIL needs a prior successful AUTH.
    pub auth_required: bool,
    /// Whether AUTH needs TLS.
    pub auth_requires_tls: bool,
    /// Whether the stream is already TLS (implicit TLS).
    pub tls_active: bool,
}

impl Default for SmtpServerConfig {
    fn default() -> Self {
        Self {
            hostname: String::from("localhost"),
            max_message_size: 25 * 1024 * 1024,
            max_recipients: 100,
            max_line_len: 512,
            max_errors: 10,
            extensions: SmtpServerExtensions::default(),
            auth_mechanisms: vec![SaslServerMechanism::Plain, SaslServerMechanism::Login],
            auth_required: false,
            auth_requires_tls: true,
            tls_active: false,
        }
    }
}

/// An authenticated identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpServerIdentity {
    /// The authorization identity, if the client asked for one.
    pub authzid: Option<String>,
    /// The authentication identity.
    pub authcid: String,
}

/// An accepted recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpServerRecipient {
    /// The recipient.
    pub forward_path: SmtpForwardPath<'static>,
    /// Its parameters.
    pub params: SmtpServerRcptParams,
}

/// The envelope of a received message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpServerEnvelope {
    /// The domain the client greeted with.
    pub helo: String,
    /// The authenticated identity, if any.
    pub identity: Option<SmtpServerIdentity>,
    /// Whether the message came over TLS.
    pub tls: bool,
    /// The sender.
    pub reverse_path: SmtpReversePath<'static>,
    /// The MAIL parameters.
    pub params: SmtpServerMailParams,
    /// The accepted recipients, in order.
    pub recipients: Vec<SmtpServerRecipient>,
}

/// Argument a session is resumed with.
#[derive(Clone, Debug, Default)]
pub enum SmtpServerArg<'a> {
    /// Nothing: the first resume, after a write or after the TLS
    /// upgrade.
    #[default]
    None,
    /// Bytes read from the stream, an empty slice meaning EOF.
    Read(&'a [u8]),
    /// Accepts what was asked, with the default reply.
    Accept,
    /// Answers what was asked with this reply, a 2xx one accepting.
    Reply(SmtpServerReply),
    /// LMTP only: one reply per accepted recipient of a message, in
    /// order. A missing one is written as `451 4.3.0`.
    Replies(Vec<SmtpServerReply>),
}

/// What a session asks the caller.
#[derive(Debug)]
pub enum SmtpServerYield {
    /// Read from the stream and resume with [`SmtpServerArg::Read`].
    WantsRead,
    /// Write these bytes and resume with [`SmtpServerArg::None`].
    WantsWrite(Vec<u8>),
    /// Upgrade the stream to TLS and resume with
    /// [`SmtpServerArg::None`]; the session restarts from the EHLO.
    WantsTlsUpgrade,
    /// Verify these credentials and resume with a verdict.
    WantsAuth(SaslServerCredentials),
    /// Accept or reject this sender.
    WantsMailFrom {
        /// The sender.
        reverse_path: SmtpReversePath<'static>,
        /// The MAIL parameters.
        params: SmtpServerMailParams,
    },
    /// Accept or reject this recipient.
    WantsRcptTo {
        /// The recipient.
        forward_path: SmtpForwardPath<'static>,
        /// The RCPT parameters.
        params: SmtpServerRcptParams,
    },
    /// Accept or reject this message: one reply in SMTP, one per
    /// recipient in LMTP.
    WantsMessage {
        /// The envelope.
        envelope: SmtpServerEnvelope,
        /// The message, dot-unstuffed, without its terminator.
        data: Vec<u8>,
    },
}

/// Why a session ended other than by QUIT.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SmtpServerError {
    /// The client closed the stream without QUIT.
    #[error("SMTP client closed the connection")]
    Eof,
    /// The client failed too many commands; 421 was written.
    #[error("SMTP client failed too many commands")]
    TooManyErrors,
    /// The session was resumed with an argument it does not expect.
    #[error("SMTP server session resumed with an unexpected argument")]
    UnexpectedArg,
}

/// The state a session resume returns: a yield, or the end of the
/// session, `Ok` after QUIT.
pub type SmtpServerState = SmtpCoroutineState<SmtpServerYield, Result<(), SmtpServerError>>;

/// I/O-free SMTP and LMTP server session.
pub struct SmtpServerSession {
    mode: SmtpServerMode,
    config: SmtpServerConfig,
    input: Vec<u8>,
    pos: usize,
    output: Vec<u8>,
    phase: Phase,
    wait: Wait,
    helo: Option<String>,
    extended: bool,
    identity: Option<SmtpServerIdentity>,
    tls: bool,
    txn: Option<Transaction>,
    errors: usize,
    discarding: bool,
    close: Option<Result<(), SmtpServerError>>,
}

impl fmt::Debug for SmtpServerSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpServerSession")
            .field("mode", &self.mode)
            .field("helo", &self.helo)
            .field("identity", &self.identity)
            .field("tls", &self.tls)
            .field("errors", &self.errors)
            .finish_non_exhaustive()
    }
}

enum Phase {
    Greet,
    ReadCommand,
    ReadAuthResponse(SaslServer),
    ReadData(Data),
    Closed,
}

enum Wait {
    Nothing,
    Auth(SaslServer),
    Mail(SmtpReversePath<'static>, SmtpServerMailParams),
    Rcpt(SmtpForwardPath<'static>, SmtpServerRcptParams),
    Message(usize),
    FlushThenUpgrade,
    TlsUpgrade,
}

struct Transaction {
    reverse_path: SmtpReversePath<'static>,
    params: SmtpServerMailParams,
    recipients: Vec<SmtpServerRecipient>,
}

struct Data {
    bytes: Vec<u8>,
    size: u64,
    too_big: bool,
    line_start: bool,
    cr: bool,
}

enum Line {
    Complete(usize, usize),
    TooLong,
    Incomplete,
}

impl SmtpServerSession {
    /// Builds a session; the first resume writes the greeting.
    pub fn new(mode: SmtpServerMode, config: SmtpServerConfig) -> Self {
        Self {
            mode,
            tls: config.tls_active,
            config,
            input: Vec::new(),
            pos: 0,
            output: Vec::new(),
            phase: Phase::Greet,
            wait: Wait::Nothing,
            helo: None,
            extended: false,
            identity: None,
            txn: None,
            errors: 0,
            discarding: false,
            close: None,
        }
    }

    /// The protocol spoken.
    pub fn mode(&self) -> SmtpServerMode {
        self.mode
    }

    /// The domain of the last hello command.
    pub fn helo(&self) -> Option<&str> {
        self.helo.as_deref()
    }

    /// The authenticated identity.
    pub fn identity(&self) -> Option<&SmtpServerIdentity> {
        self.identity.as_ref()
    }

    /// Whether the stream is TLS.
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    /// Advances the session.
    pub fn resume(&mut self, arg: SmtpServerArg<'_>) -> SmtpServerState {
        if let Phase::Closed = self.phase {
            return SmtpCoroutineState::Complete(Err(SmtpServerError::UnexpectedArg));
        }

        match mem::replace(&mut self.wait, Wait::Nothing) {
            Wait::Nothing => match arg {
                SmtpServerArg::None => (),
                SmtpServerArg::Read([]) => {
                    debug!("smtp client closed the connection");
                    self.phase = Phase::Closed;
                    return SmtpCoroutineState::Complete(Err(SmtpServerError::Eof));
                }
                SmtpServerArg::Read(bytes) => self.input.extend_from_slice(bytes),
                _ => return self.unexpected(),
            },
            Wait::FlushThenUpgrade => match arg {
                SmtpServerArg::None => self.wait = Wait::FlushThenUpgrade,
                _ => return self.unexpected(),
            },
            Wait::TlsUpgrade => match arg {
                SmtpServerArg::None => {
                    debug!("smtp stream upgraded to tls");
                    self.tls = true;
                    self.reset_hello();
                    self.input.clear();
                    self.pos = 0;
                }
                _ => return self.unexpected(),
            },
            Wait::Auth(sasl) => {
                let Some(reply) = verdict(arg) else {
                    return self.unexpected();
                };
                self.auth_verdict(sasl, reply);
            }
            Wait::Mail(reverse_path, params) => {
                let Some(reply) = verdict(arg) else {
                    return self.unexpected();
                };

                if reply.as_ref().is_none_or(SmtpServerReply::is_positive) {
                    self.txn = Some(Transaction {
                        reverse_path,
                        params,
                        recipients: Vec::new(),
                    });
                }

                self.reply_or(reply, 250, (2, 1, 0), "Sender OK");
            }
            Wait::Rcpt(forward_path, params) => {
                let Some(reply) = verdict(arg) else {
                    return self.unexpected();
                };

                if reply.as_ref().is_none_or(SmtpServerReply::is_positive)
                    && let Some(txn) = &mut self.txn
                {
                    txn.recipients.push(SmtpServerRecipient {
                        forward_path,
                        params,
                    });
                }

                self.reply_or(reply, 250, (2, 1, 5), "Recipient OK");
            }
            Wait::Message(count) => match (self.mode, arg) {
                (SmtpServerMode::Smtp, SmtpServerArg::Accept) => {
                    self.reply(250, Some((2, 0, 0)), "Message accepted");
                }
                (SmtpServerMode::Smtp, SmtpServerArg::Reply(reply)) => self.write(&reply),
                (SmtpServerMode::Smtp, SmtpServerArg::Replies(replies)) if replies.len() == 1 => {
                    self.write(&replies[0]);
                }
                (SmtpServerMode::Lmtp, SmtpServerArg::Accept) => {
                    for _ in 0..count {
                        self.reply(250, Some((2, 1, 5)), "Delivered");
                    }
                }
                (SmtpServerMode::Lmtp, SmtpServerArg::Reply(reply)) => {
                    for _ in 0..count {
                        self.write(&reply);
                    }
                }
                (SmtpServerMode::Lmtp, SmtpServerArg::Replies(replies)) => {
                    for i in 0..count {
                        match replies.get(i) {
                            Some(reply) => self.write(reply),
                            None => self.reply(451, Some((4, 3, 0)), "No delivery status"),
                        }
                    }
                }
                _ => return self.unexpected(),
            },
        }

        self.run()
    }

    fn unexpected(&mut self) -> SmtpServerState {
        self.phase = Phase::Closed;
        SmtpCoroutineState::Complete(Err(SmtpServerError::UnexpectedArg))
    }

    fn run(&mut self) -> SmtpServerState {
        loop {
            if let Some(result) = self.close.take() {
                if !self.output.is_empty() {
                    self.close = Some(result);
                    return self.flush();
                }

                self.phase = Phase::Closed;
                return SmtpCoroutineState::Complete(result);
            }

            if let Wait::FlushThenUpgrade = self.wait {
                if !self.output.is_empty() {
                    return self.flush();
                }

                self.wait = Wait::TlsUpgrade;
                return SmtpCoroutineState::Yielded(SmtpServerYield::WantsTlsUpgrade);
            }

            match &self.phase {
                Phase::Greet => {
                    let protocol = match self.mode {
                        SmtpServerMode::Smtp => "ESMTP",
                        SmtpServerMode::Lmtp => "LMTP",
                    };
                    let text = format!("{} {protocol} ready", self.config.hostname);
                    self.reply(220, None, &text);
                    self.phase = Phase::ReadCommand;
                }
                Phase::ReadCommand => {
                    let rest = &self.input[self.pos..];
                    let is_auth = rest.len() >= 5 && rest[..5].eq_ignore_ascii_case(b"AUTH ");
                    let limit = if is_auth {
                        self.config.max_line_len.max(SMTP_SERVER_MAX_AUTH_LINE_LEN)
                    } else {
                        self.config.max_line_len
                    };

                    match self.take_line(limit) {
                        Line::Incomplete => break,
                        Line::TooLong => self.error(500, (5, 5, 2), "Line too long"),
                        Line::Complete(start, end) => {
                            let line = self.input[start..end].to_vec();

                            if let Some(state) = self.command(&line) {
                                return state;
                            }
                        }
                    }
                }
                Phase::ReadAuthResponse(_) => match self.take_line(SMTP_SERVER_MAX_AUTH_LINE_LEN) {
                    Line::Incomplete => break,
                    Line::TooLong => {
                        self.phase = Phase::ReadCommand;
                        self.error(500, (5, 5, 2), "Line too long");
                    }
                    Line::Complete(start, end) => {
                        let Phase::ReadAuthResponse(sasl) =
                            mem::replace(&mut self.phase, Phase::ReadCommand)
                        else {
                            unreachable!();
                        };

                        let line = &self.input[start..end];

                        let arg = if line == b"*" {
                            SaslServerArg::Cancel
                        } else {
                            let mut decoded = Vec::new();

                            if !Base64Codec::default().decode_vec(line, &mut decoded) {
                                self.error(501, (5, 5, 2), "Invalid base64 data");
                                continue;
                            }

                            SaslServerArg::Response(decoded)
                        };

                        if let Some(state) = self.auth_step(sasl, arg) {
                            return state;
                        }
                    }
                },
                Phase::ReadData(_) => {
                    if !self.read_data() {
                        break;
                    }

                    if let Some(state) = self.end_data() {
                        return state;
                    }
                }
                Phase::Closed => {
                    return SmtpCoroutineState::Complete(Err(SmtpServerError::UnexpectedArg));
                }
            }
        }

        if self.pos > 0 {
            self.input.drain(..self.pos);
            self.pos = 0;
        }

        if !self.output.is_empty() {
            return self.flush();
        }

        SmtpCoroutineState::Yielded(SmtpServerYield::WantsRead)
    }

    fn flush(&mut self) -> SmtpServerState {
        let bytes = mem::take(&mut self.output);
        SmtpCoroutineState::Yielded(SmtpServerYield::WantsWrite(bytes))
    }

    fn take_line(&mut self, limit: usize) -> Line {
        let rest = &self.input[self.pos..];

        match position(rest, |b| b == b'\n') {
            Some(i) => {
                let start = self.pos;
                self.pos += i + 1;

                if mem::take(&mut self.discarding) || i + 1 > limit {
                    return Line::TooLong;
                }

                let mut end = start + i;

                if end > start && self.input[end - 1] == b'\r' {
                    end -= 1;
                }

                Line::Complete(start, end)
            }
            None => {
                if rest.len() >= limit {
                    self.discarding = true;
                    self.pos = self.input.len();
                }

                Line::Incomplete
            }
        }
    }

    /// Reads message data, returning whether the terminator was found.
    fn read_data(&mut self) -> bool {
        let max = self.config.max_message_size;
        let Phase::ReadData(data) = &mut self.phase else {
            return false;
        };

        loop {
            let rest = &self.input[self.pos..];

            if data.line_start {
                match rest {
                    [] | [b'.'] | [b'.', b'\r'] => return false,
                    [b'.', b'\r', b'\n', ..] => {
                        self.pos += 3;
                        return true;
                    }
                    [b'.', ..] => self.pos += 1,
                    _ => (),
                }

                data.line_start = false;
                continue;
            }

            let (chunk, line_end) = match position(rest, |b| b == b'\n') {
                Some(0) => (&rest[..1], data.cr),
                Some(i) => (&rest[..=i], rest[i - 1] == b'\r'),
                None => (rest, false),
            };

            if chunk.is_empty() {
                return false;
            }

            data.size += chunk.len() as u64;

            if max > 0 && data.size > max {
                data.too_big = true;
                data.bytes = Vec::new();
            }

            if !data.too_big {
                data.bytes.extend_from_slice(chunk);
            }

            self.pos += chunk.len();
            data.line_start = line_end;
            data.cr = chunk.last() == Some(&b'\r');
        }
    }

    fn end_data(&mut self) -> Option<SmtpServerState> {
        let Phase::ReadData(data) = mem::replace(&mut self.phase, Phase::ReadCommand) else {
            return None;
        };

        let txn = self.txn.take()?;

        if data.too_big {
            debug!("smtp message over the size cap refused");
            let text = "Message size exceeds fixed maximum message size";
            self.reply(552, Some((5, 3, 4)), text);
            return None;
        }

        debug!("smtp message received");
        self.wait = Wait::Message(txn.recipients.len());

        let envelope = SmtpServerEnvelope {
            helo: self.helo.clone().unwrap_or_default(),
            identity: self.identity.clone(),
            tls: self.tls,
            reverse_path: txn.reverse_path,
            params: txn.params,
            recipients: txn.recipients,
        };

        Some(SmtpCoroutineState::Yielded(SmtpServerYield::WantsMessage {
            envelope,
            data: data.bytes,
        }))
    }

    fn command(&mut self, line: &[u8]) -> Option<SmtpServerState> {
        let command = match SmtpServerCommand::parse(line) {
            Ok(command) => command,
            Err(err) => {
                match err {
                    SmtpServerCommandError::Unknown => {
                        self.error(500, (5, 5, 1), "Command unrecognized");
                    }
                    SmtpServerCommandError::NotImplemented => {
                        self.error(502, (5, 5, 1), "Command not implemented");
                    }
                    SmtpServerCommandError::Syntax => {
                        self.error(501, (5, 5, 2), "Syntax error in parameters or arguments");
                    }
                    SmtpServerCommandError::Address => {
                        self.error(501, (5, 1, 3), "Invalid address syntax");
                    }
                    SmtpServerCommandError::UnknownParam(_) => {
                        self.error(555, (5, 5, 4), "Parameter not recognized");
                    }
                    SmtpServerCommandError::InvalidParam(_) => {
                        self.error(501, (5, 5, 4), "Invalid parameter");
                    }
                }

                return None;
            }
        };

        let lmtp = self.mode == SmtpServerMode::Lmtp;

        match command {
            SmtpServerCommand::Ehlo(_) | SmtpServerCommand::Helo(_) if lmtp => {
                self.error(500, (5, 5, 1), "Use LHLO");
            }
            SmtpServerCommand::Lhlo(_) if !lmtp => {
                self.error(500, (5, 5, 1), "Command unrecognized");
            }
            SmtpServerCommand::Ehlo(domain) | SmtpServerCommand::Lhlo(domain) => {
                self.reset_hello();
                self.helo = Some(domain);
                self.extended = true;
                let reply = self.ehlo_reply();
                self.write(&reply);
            }
            SmtpServerCommand::Helo(domain) => {
                self.reset_hello();
                self.helo = Some(domain);
                let text = self.config.hostname.clone();
                self.reply(250, None, &text);
            }
            SmtpServerCommand::Mail {
                reverse_path,
                params,
            } => return self.mail(reverse_path, params),
            SmtpServerCommand::Rcpt {
                forward_path,
                params,
            } => return self.rcpt(forward_path, params),
            SmtpServerCommand::Data => match &self.txn {
                None => self.error(503, (5, 5, 1), "Need MAIL command"),
                Some(txn) if txn.recipients.is_empty() => {
                    self.error(554, (5, 5, 1), "No valid recipients");
                }
                Some(_) => {
                    self.reply(354, None, "Start mail input; end with <CRLF>.<CRLF>");
                    self.phase = Phase::ReadData(Data {
                        bytes: Vec::new(),
                        size: 0,
                        too_big: false,
                        line_start: true,
                        cr: false,
                    });
                }
            },
            SmtpServerCommand::Rset => {
                self.txn = None;
                self.reply(250, Some((2, 0, 0)), "OK");
            }
            SmtpServerCommand::Noop => self.reply(250, Some((2, 0, 0)), "OK"),
            SmtpServerCommand::Quit => {
                let text = format!("{} closing connection", self.config.hostname);
                self.reply(221, Some((2, 0, 0)), &text);
                self.close = Some(Ok(()));
            }
            SmtpServerCommand::Vrfy(_) => {
                let text = "Cannot VRFY user, but will accept message and attempt delivery";
                self.reply(252, Some((2, 5, 0)), text);
            }
            SmtpServerCommand::Help(_) => {
                self.reply(214, Some((2, 0, 0)), "See RFC 5321");
            }
            SmtpServerCommand::StartTls => {
                if self.tls {
                    self.error(503, (5, 5, 1), "TLS already active");
                } else if !self.config.extensions.starttls {
                    self.error(502, (5, 5, 1), "Command not implemented");
                } else {
                    self.reply(220, Some((2, 0, 0)), "Ready to start TLS");
                    self.input.clear();
                    self.pos = 0;
                    self.wait = Wait::FlushThenUpgrade;
                }
            }
            SmtpServerCommand::Auth {
                mechanism,
                initial_response,
            } => return self.auth(&mechanism, initial_response),
        }

        None
    }

    fn mail(
        &mut self,
        reverse_path: SmtpReversePath<'static>,
        params: SmtpServerMailParams,
    ) -> Option<SmtpServerState> {
        let ext = &self.config.extensions;
        let unadvertised = (params.smtputf8 && !ext.smtputf8)
            || (params.body == Some(SmtpServerBody::EightBitMime) && !ext.eight_bit_mime)
            || ((params.ret.is_some() || params.envid.is_some()) && !ext.dsn)
            || (params.auth.is_some() && self.config.auth_mechanisms.is_empty());

        if self.helo.is_none() {
            self.error(503, (5, 5, 1), "Send hello first");
        } else if self.txn.is_some() {
            self.error(503, (5, 5, 1), "Nested MAIL command");
        } else if self.config.auth_required && self.identity.is_none() {
            self.error(530, (5, 7, 0), "Authentication required");
        } else if unadvertised {
            self.error(555, (5, 5, 4), "Parameter not supported");
        } else if params.body == Some(SmtpServerBody::BinaryMime) {
            self.error(504, (5, 5, 4), "BINARYMIME requires CHUNKING");
        } else if self.config.max_message_size > 0
            && params
                .size
                .is_some_and(|s| s > self.config.max_message_size)
        {
            let text = "Message size exceeds fixed maximum message size";
            self.reply(552, Some((5, 3, 4)), text);
        } else if !params.smtputf8 && !reverse_path.to_string().is_ascii() {
            self.reply(553, Some((5, 6, 7)), "Address requires SMTPUTF8");
        } else {
            self.wait = Wait::Mail(reverse_path.clone(), params.clone());
            let state = SmtpServerYield::WantsMailFrom {
                reverse_path,
                params,
            };
            return Some(SmtpCoroutineState::Yielded(state));
        }

        None
    }

    fn rcpt(
        &mut self,
        forward_path: Option<SmtpForwardPath<'static>>,
        params: SmtpServerRcptParams,
    ) -> Option<SmtpServerState> {
        let Some(txn) = &self.txn else {
            self.error(503, (5, 5, 1), "Need MAIL command");
            return None;
        };

        let smtputf8 = txn.params.smtputf8;

        if txn.recipients.len() >= self.config.max_recipients {
            self.reply(452, Some((4, 5, 3)), "Too many recipients");
            return None;
        }

        if (params.notify.is_some() || params.orcpt.is_some()) && !self.config.extensions.dsn {
            self.error(555, (5, 5, 4), "Parameter not supported");
            return None;
        }

        let forward_path = match forward_path {
            Some(forward_path) => forward_path,
            None => {
                let postmaster = format!("postmaster@{}", self.config.hostname);

                match SmtpMailbox::try_from(postmaster.as_str()) {
                    Ok(mailbox) => SmtpForwardPath(mailbox.into_static()),
                    Err(_) => {
                        self.reply(550, Some((5, 1, 1)), "Mailbox unavailable");
                        return None;
                    }
                }
            }
        };

        if !smtputf8 && !forward_path.to_string().is_ascii() {
            self.reply(553, Some((5, 6, 7)), "Address requires SMTPUTF8");
            return None;
        }

        self.wait = Wait::Rcpt(forward_path.clone(), params.clone());
        let state = SmtpServerYield::WantsRcptTo {
            forward_path,
            params,
        };
        Some(SmtpCoroutineState::Yielded(state))
    }

    fn auth(&mut self, mechanism: &str, initial: Option<String>) -> Option<SmtpServerState> {
        let mechanism = SaslServerMechanism::from_name(mechanism)
            .filter(|m| self.config.auth_mechanisms.contains(m));

        if self.config.auth_mechanisms.is_empty() {
            self.error(502, (5, 5, 1), "Command not implemented");
        } else if self.helo.is_none() || !self.extended {
            self.error(503, (5, 5, 1), "Send EHLO first");
        } else if self.identity.is_some() {
            self.error(503, (5, 5, 1), "Already authenticated");
        } else if self.txn.is_some() {
            self.error(
                503,
                (5, 5, 1),
                "AUTH not permitted during a mail transaction",
            );
        } else if self.config.auth_requires_tls && !self.tls {
            self.error(530, (5, 7, 0), "Must issue a STARTTLS command first");
        } else if let Some(mechanism) = mechanism {
            let initial = match initial.as_deref() {
                None => None,
                Some("=") => Some(Vec::new()),
                Some(encoded) => {
                    let mut decoded = Vec::new();

                    if !Base64Codec::default().decode_vec(encoded.as_bytes(), &mut decoded) {
                        self.error(501, (5, 5, 2), "Invalid base64 data");
                        return None;
                    }

                    Some(decoded)
                }
            };

            debug!("smtp auth {} started", mechanism.name());
            let sasl = SaslServer::new(mechanism, initial);
            return self.auth_step(sasl, SaslServerArg::None);
        } else {
            self.error(504, (5, 5, 4), "Unrecognized authentication type");
        }

        None
    }

    fn auth_step(&mut self, mut sasl: SaslServer, arg: SaslServerArg) -> Option<SmtpServerState> {
        match sasl.resume(arg) {
            SaslServerState::Challenge(bytes) => {
                let mut line = b"334 ".to_vec();
                Base64Codec::default().encode_vec(&bytes, &mut line);
                line.extend_from_slice(b"\r\n");
                self.output.extend_from_slice(&line);
                self.phase = Phase::ReadAuthResponse(sasl);
                None
            }
            SaslServerState::Verify(creds) => {
                self.wait = Wait::Auth(sasl);
                Some(SmtpCoroutineState::Yielded(SmtpServerYield::WantsAuth(
                    creds,
                )))
            }
            SaslServerState::Success { authzid, authcid } => {
                self.identity = Some(SmtpServerIdentity { authzid, authcid });
                self.reply(235, Some((2, 7, 0)), "Authentication successful");
                None
            }
            SaslServerState::Failure(SaslServerError::Cancelled) => {
                self.error(501, (5, 0, 0), "Authentication cancelled");
                None
            }
            SaslServerState::Failure(SaslServerError::Malformed) => {
                self.error(501, (5, 5, 2), "Malformed authentication response");
                None
            }
            SaslServerState::Failure(_) => {
                self.reply(535, Some((5, 7, 8)), "Authentication credentials invalid");
                None
            }
        }
    }

    fn auth_verdict(&mut self, mut sasl: SaslServer, reply: Option<SmtpServerReply>) {
        let accepted = reply.as_ref().is_none_or(SmtpServerReply::is_positive);

        match sasl.resume(SaslServerArg::Verdict(accepted)) {
            SaslServerState::Success { authzid, authcid } => {
                debug!("smtp auth succeeded");
                self.identity = Some(SmtpServerIdentity { authzid, authcid });
                self.reply_or(reply, 235, (2, 7, 0), "Authentication successful");
            }
            _ => {
                debug!("smtp auth failed");
                self.reply_or(reply, 535, (5, 7, 8), "Authentication credentials invalid");
            }
        }
    }

    fn ehlo_reply(&self) -> SmtpServerReply {
        let ext = &self.config.extensions;
        let mut reply = SmtpServerReply::from_codes(250, None, &self.config.hostname)
            .expect("250 is a valid reply code");

        if ext.pipelining {
            reply = reply.with_line("PIPELINING");
        }

        reply = match self.config.max_message_size {
            0 => reply.with_line("SIZE"),
            max => reply.with_line(format!("SIZE {max}")),
        };

        if ext.eight_bit_mime {
            reply = reply.with_line("8BITMIME");
        }

        if ext.smtputf8 {
            reply = reply.with_line("SMTPUTF8");
        }

        if ext.enhanced_status_codes {
            reply = reply.with_line("ENHANCEDSTATUSCODES");
        }

        if ext.dsn {
            reply = reply.with_line("DSN");
        }

        if ext.starttls && !self.tls {
            reply = reply.with_line("STARTTLS");
        }

        let auth_offered =
            !self.config.auth_mechanisms.is_empty() && (self.tls || !self.config.auth_requires_tls);

        if auth_offered {
            let names: Vec<&str> = self
                .config
                .auth_mechanisms
                .iter()
                .map(SaslServerMechanism::name)
                .collect();
            reply = reply.with_line(format!("AUTH {}", names.join(" ")));
        }

        reply
    }

    fn reset_hello(&mut self) {
        self.helo = None;
        self.extended = false;
        self.txn = None;

        if !matches!(self.phase, Phase::ReadCommand | Phase::Greet) {
            self.phase = Phase::ReadCommand;
        }
    }

    fn write(&mut self, reply: &SmtpServerReply) {
        let enhanced = self.config.extensions.enhanced_status_codes;
        reply.encode(enhanced, &mut self.output);
    }

    fn reply(&mut self, code: u16, enhanced: Option<(u8, u16, u16)>, text: &str) {
        let reply = SmtpServerReply::from_codes(code, enhanced, text).expect("valid reply code");
        self.write(&reply);
    }

    fn reply_or(
        &mut self,
        reply: Option<SmtpServerReply>,
        code: u16,
        enhanced: (u8, u16, u16),
        text: &str,
    ) {
        match reply {
            Some(reply) => self.write(&reply),
            None => self.reply(code, Some(enhanced), text),
        }
    }

    fn error(&mut self, code: u16, enhanced: (u8, u16, u16), text: &str) {
        self.reply(code, Some(enhanced), text);
        self.errors += 1;

        if self.config.max_errors > 0 && self.errors >= self.config.max_errors {
            debug!("smtp client failed too many commands");
            self.reply(421, Some((4, 7, 0)), "Too many errors, closing connection");
            self.close = Some(Err(SmtpServerError::TooManyErrors));
        }
    }
}

/// Reads a verdict argument: `None` inside for the default reply.
fn verdict(arg: SmtpServerArg<'_>) -> Option<Option<SmtpServerReply>> {
    match arg {
        SmtpServerArg::Accept => Some(None),
        SmtpServerArg::Reply(reply) => Some(Some(reply)),
        _ => None,
    }
}
