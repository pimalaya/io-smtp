//! SMTP composite coroutine; chains MAIL FROM, one RCPT TO per
//! recipient, then DATA.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
//!     message::{SmtpMessageSend, SmtpMessageSendOptions},
//!     rfc5321::{SmtpForwardPath, SmtpMailbox, SmtpReversePath},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, AUTH consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let alice = SmtpMailbox::try_from("alice@example.org").unwrap();
//! let bob = SmtpMailbox::try_from("bob@example.org").unwrap();
//! let message =
//!     b"From: alice@example.org\r\nTo: bob@example.org\r\nSubject: hi\r\n\r\nhello\r\n".to_vec();
//!
//! let mut coroutine = SmtpMessageSend::new(
//!     SmtpReversePath::SmtpMailbox(alice),
//!     [SmtpForwardPath(bob)],
//!     message,
//!     SmtpMessageSendOptions::default(),
//! );
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(arg.take()) {
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         SmtpCoroutineState::Complete(Ok(_refused)) => break,
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::{fmt, mem};

use alloc::{collections::VecDeque, string::String, vec::Vec};

use bounded_static::IntoBoundedStatic;
use log::debug;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::{
        SmtpForwardPath, SmtpParameter, SmtpReversePath,
        data::{SmtpData, SmtpDataError},
        mail::{SmtpMail, SmtpMailError},
        rcpt::{SmtpRcpt, SmtpRcptError},
        rset::SmtpRset,
    },
    scan::position,
    smtp_try,
};

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const CRLF: &[u8] = b"\r\n";

/// The reply code of a server closing the connection.
const CLOSING: u16 = 421;

/// Failure causes during the SMTP send composite coroutine.
///
/// The message reached nobody. When the server refused a recipient or
/// the DATA command, RSET was sent first, so the connection is ready
/// for another transaction; after any other failure, drop it.
#[derive(Debug, Error)]
pub enum SmtpMessageSendError {
    /// The MAIL FROM step failed.
    #[error(transparent)]
    MailFrom(#[from] SmtpMailError),
    /// A RCPT TO step failed.
    #[error("Recipient {forward_path}: {error}")]
    RcptTo {
        /// The forward path of the recipient.
        forward_path: SmtpForwardPath<'static>,
        /// What the step failed with.
        error: SmtpRcptError,
    },
    /// The server refused every recipient, leaving none to send to.
    #[error("SMTP server refused every recipient")]
    NoRecipient(Vec<SmtpMessageSendRefusal>),
    /// The DATA step failed.
    #[error(transparent)]
    Data(#[from] SmtpDataError),
}

/// A recipient the server refused, with its reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpMessageSendRefusal {
    /// The forward path of the recipient.
    pub forward_path: SmtpForwardPath<'static>,
    /// The reply code.
    pub code: u16,
    /// The reply text.
    pub message: String,
}

/// Options for [`SmtpMessageSend`].
#[derive(Clone, Debug, Default)]
pub struct SmtpMessageSendOptions {
    /// Transmit the `Bcc` and `Resent-Bcc` fields instead of removing
    /// them (RFC 5322 3.6.3, 3.6.6).
    pub keep_bcc: bool,
    /// ESMTP parameters of the MAIL FROM command (RFC 5321 4.1.1.2), such
    /// as the DSN `RET` and `ENVID` (RFC 3461 4.3, 4.4).
    pub mail_parameters: Vec<SmtpParameter<'static>>,
    /// ESMTP parameters of every RCPT TO command (RFC 5321 4.1.1.3), such
    /// as the DSN `NOTIFY` (RFC 3461 4.1).
    pub rcpt_parameters: Vec<SmtpParameter<'static>>,
    /// Send to the recipients the server accepts when it refuses others,
    /// instead of sending to none.
    pub skip_refused_recipients: bool,
}

/// I/O-free SMTP composite send coroutine.
///
/// It submits a message rather than relaying one: unless told to keep
/// them, the `Bcc` and `Resent-Bcc` fields are removed from the
/// transmitted header section, so the blind recipients reached through
/// the forward paths stay hidden.
///
/// One refused recipient fails the whole send, naming it, unless
/// [`SmtpMessageSendOptions::skip_refused_recipients`] is set: the
/// refused recipients are then returned once the others got the
/// message.
pub struct SmtpMessageSend {
    state: State,
    forward_paths: VecDeque<SmtpForwardPath<'static>>,
    rcpt_parameters: Vec<SmtpParameter<'static>>,
    skip_refused_recipients: bool,
    accepted: bool,
    refused: Vec<SmtpMessageSendRefusal>,
    message: Option<Vec<u8>>,
}

impl SmtpMessageSend {
    /// Creates the coroutine from the sender path, the recipient
    /// paths and the complete message (headers plus body).
    pub fn new<'a>(
        reverse_path: SmtpReversePath<'_>,
        forward_paths: impl IntoIterator<Item = SmtpForwardPath<'a>>,
        message: Vec<u8>,
        options: SmtpMessageSendOptions,
    ) -> Self {
        let forward_paths = forward_paths
            .into_iter()
            .map(IntoBoundedStatic::into_static)
            .collect();

        Self {
            state: State::MailFrom(SmtpMail::new(
                reverse_path.into_static(),
                options.mail_parameters,
            )),
            forward_paths,
            rcpt_parameters: options.rcpt_parameters,
            skip_refused_recipients: options.skip_refused_recipients,
            accepted: false,
            refused: Vec::new(),
            message: Some(match options.keep_bcc {
                true => message,
                false => strip_bcc(message),
            }),
        }
    }
}

impl SmtpCoroutine for SmtpMessageSend {
    type Yield = SmtpYield;
    type Return = Result<Vec<SmtpMessageSendRefusal>, SmtpMessageSendError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::MailFrom(mail) => {
                    let () = smtp_try!(mail, arg.take());
                    self.state = self.next_rcpt_or_data();
                    debug!("mail from accepted, next: {}", self.state);
                }
                State::RcptTo { rcpt, forward_path } => {
                    let error = match rcpt.resume(arg.take()) {
                        SmtpCoroutineState::Yielded(y) => {
                            return SmtpCoroutineState::Yielded(y);
                        }
                        SmtpCoroutineState::Complete(Ok(())) => {
                            self.accepted = true;
                            self.state = self.next_rcpt_or_data();
                            debug!("rcpt to accepted, next: {}", self.state);
                            continue;
                        }
                        SmtpCoroutineState::Complete(Err(error)) => error,
                    };

                    let forward_path = forward_path.clone();

                    let reset = match error {
                        SmtpRcptError::Rejected { code, .. } => code != CLOSING,
                        SmtpRcptError::Send(_) => false,
                    };

                    self.state = match error {
                        SmtpRcptError::Rejected { code, message }
                            if reset && self.skip_refused_recipients =>
                        {
                            self.refused.push(SmtpMessageSendRefusal {
                                forward_path,
                                code,
                                message,
                            });

                            self.next_rcpt_or_data()
                        }
                        error => {
                            let error = SmtpMessageSendError::RcptTo {
                                forward_path,
                                error,
                            };

                            if !reset {
                                return SmtpCoroutineState::Complete(Err(error));
                            }

                            State::rset(error)
                        }
                    };

                    debug!("rcpt to refused, next: {}", self.state);
                }
                State::Data(data) => {
                    let error = match data.resume(arg.take()) {
                        SmtpCoroutineState::Yielded(y) => {
                            return SmtpCoroutineState::Yielded(y);
                        }
                        SmtpCoroutineState::Complete(Ok(())) => {
                            debug!("message sent");
                            let refused = mem::take(&mut self.refused);
                            return SmtpCoroutineState::Complete(Ok(refused));
                        }
                        SmtpCoroutineState::Complete(Err(error)) => error,
                    };

                    let reset = match error {
                        SmtpDataError::CommandRejected { code, .. } => code != CLOSING,
                        _ => false,
                    };

                    if !reset {
                        return SmtpCoroutineState::Complete(Err(error.into()));
                    }

                    self.state = State::rset(error.into());
                    debug!("data refused, next: {}", self.state);
                }
                State::Rset { rset, error } => {
                    // NOTE: whatever RSET ends with, the send fails with error
                    if let SmtpCoroutineState::Yielded(y) = rset.resume(arg.take()) {
                        return SmtpCoroutineState::Yielded(y);
                    }

                    let error = error.take().expect("error taken twice");
                    return SmtpCoroutineState::Complete(Err(error));
                }
            }
        }
    }
}

impl SmtpMessageSend {
    fn next_rcpt_or_data(&mut self) -> State {
        if let Some(forward_path) = self.forward_paths.pop_front() {
            let parameters = self.rcpt_parameters.clone();
            let rcpt = SmtpRcpt::new(forward_path.clone(), parameters);
            return State::RcptTo { rcpt, forward_path };
        }

        if !self.accepted && !self.refused.is_empty() {
            let refused = mem::take(&mut self.refused);
            return State::rset(SmtpMessageSendError::NoRecipient(refused));
        }

        let body = self.message.take().expect("message taken twice");
        State::Data(SmtpData::new(body))
    }
}

enum State {
    MailFrom(SmtpMail),
    RcptTo {
        rcpt: SmtpRcpt,
        forward_path: SmtpForwardPath<'static>,
    },
    Data(SmtpData),
    Rset {
        rset: SmtpRset,
        error: Option<SmtpMessageSendError>,
    },
}

impl State {
    /// The state closing the transaction before the send fails with
    /// `error`.
    fn rset(error: SmtpMessageSendError) -> Self {
        Self::Rset {
            rset: SmtpRset::new(),
            error: Some(error),
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MailFrom(_) => f.write_str("mail from"),
            Self::RcptTo { .. } => f.write_str("rcpt to"),
            Self::Data(_) => f.write_str("data"),
            Self::Rset { .. } => f.write_str("rset"),
        }
    }
}

/// Removes every `Bcc` and `Resent-Bcc` field, folded lines included,
/// from the header section of `message`, leaving the body untouched.
///
/// A line ends where `DATA` ends it: at CRLF, a bare CR or a bare LF.
/// `message` is returned as is when it carries no such field.
fn strip_bcc(message: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    // NOTE: message[..copied] is in out already, once a field was stripped.
    let mut copied = 0;
    let mut stripped = false;
    let mut in_bcc = false;
    let mut start = 0;

    while start < message.len() {
        let rest = &message[start..];

        let (len, end) = match position(rest, |b| (b == CR) | (b == LF)) {
            Some(i) if rest.get(i..i + 2) == Some(CRLF) => (i, start + i + 2),
            Some(i) => (i, start + i + 1),
            None => (rest.len(), message.len()),
        };

        if len == 0 {
            break;
        }

        let line = &rest[..len];

        if !matches!(line.first(), Some(b' ' | b'\t')) {
            in_bcc = is_bcc(line);
        }

        if in_bcc {
            if !stripped {
                out.reserve(message.len());
                stripped = true;
            }

            out.extend_from_slice(&message[copied..start]);

            // NOTE: a kept bare CR must not pair with an LF after the field
            if out.last() == Some(&CR) {
                out.push(LF);
            }

            copied = end;
        }

        start = end;
    }

    if !stripped {
        return message;
    }

    out.extend_from_slice(&message[copied..]);
    out
}

/// Whether a header line opens a `Bcc` or `Resent-Bcc` field, allowing
/// the obsolete whitespace before the colon (RFC 5322 4.5.3).
fn is_bcc(line: &[u8]) -> bool {
    line.iter()
        .position(|&byte| byte == b':')
        .is_some_and(|colon| {
            let name = line[..colon].trim_ascii_end();
            name.eq_ignore_ascii_case(b"bcc") || name.eq_ignore_ascii_case(b"resent-bcc")
        })
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use crate::{
        message::*,
        rfc3461::parameter::{SmtpDsnNotify, SmtpDsnRet},
        rfc5321::SmtpMailbox,
    };

    #[test]
    fn removes_the_bcc_field_and_keeps_everything_else() {
        let raw =
            b"From: a@x\r\nTo: b@x\r\nBcc: c@x\r\nSubject: s\r\n\r\nBcc: in the body stays\r\n";
        assert_eq!(
            strip_bcc(raw.to_vec()),
            b"From: a@x\r\nTo: b@x\r\nSubject: s\r\n\r\nBcc: in the body stays\r\n"
        );
    }

    #[test]
    fn removes_folded_continuation_lines_and_any_case() {
        let raw = b"From: a@x\r\nBCC: c@x,\r\n d@x,\r\n\te@x\r\nTo: b@x\r\n\r\nbody\r\n";
        assert_eq!(
            strip_bcc(raw.to_vec()),
            b"From: a@x\r\nTo: b@x\r\n\r\nbody\r\n"
        );
    }

    #[test]
    fn removes_the_obsolete_spelling_with_space_before_the_colon() {
        let raw = b"From: a@x\r\nBcc : c@x\r\nTo: b@x\r\n\r\nbody\r\n";
        assert_eq!(
            strip_bcc(raw.to_vec()),
            b"From: a@x\r\nTo: b@x\r\n\r\nbody\r\n"
        );
    }

    #[test]
    fn leaves_a_message_without_bcc_byte_identical() {
        let raw = b"From: a@x\nTo: b@x\nX-Bccish: keep\n\nbody\n";
        assert_eq!(strip_bcc(raw.to_vec()), raw.to_vec());
    }

    #[test]
    fn removes_the_bcc_field_after_a_bare_cr() {
        let raw = b"To: b@x\rBcc: c@x\r\n\r\nbody\r\n";
        let written = transmitted(raw, SmtpMessageSendOptions::default());
        assert_eq!(written[3], b"To: b@x\r\n\r\nbody\r\n.\r\n");
    }

    #[test]
    fn keeps_the_empty_line_between_a_bare_cr_and_a_bare_lf() {
        let raw = b"To: b@x\rBcc: c@x\n\nbody\n";
        let written = transmitted(raw, SmtpMessageSendOptions::default());
        assert_eq!(written[3], b"To: b@x\r\n\r\nbody\r\n.\r\n");
    }

    #[test]
    fn removes_the_resent_bcc_field() {
        let raw = b"Resent-To: b@x\r\nResent-Bcc: c@x,\r\n d@x\r\nTo: e@x\r\n\r\nbody\r\n";
        assert_eq!(
            strip_bcc(raw.to_vec()),
            b"Resent-To: b@x\r\nTo: e@x\r\n\r\nbody\r\n"
        );
    }

    /// Every short message made of field names, blanks and line endings:
    /// what `DATA` transmits is what it would transmit with the blind
    /// fields kept, less every line of theirs and nothing else.
    #[test]
    fn matches_a_line_by_line_removal() {
        let alphabet: [&[u8]; 7] = [b"Bcc:", b"Resent-Bcc:", b"To:", b"x", b" ", b"\r", b"\n"];
        let mut message = Vec::new();

        for len in 0..=6u32 {
            for mut n in 0..alphabet.len().pow(len) {
                message.clear();

                for _ in 0..len {
                    message.extend_from_slice(alphabet[n % alphabet.len()]);
                    n /= alphabet.len();
                }

                let kept = SmtpData::prepare_body(message.clone());
                let sent = SmtpData::prepare_body(strip_bcc(message.clone()));
                let expected = line_by_line(&kept);

                assert_eq!(sent, expected, "{}", message.escape_ascii());
            }
        }
    }

    /// A `DATA` payload without the lines of its blind fields.
    fn line_by_line(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut in_header = true;
        let mut in_blind = false;

        let message = payload.strip_suffix(b".\r\n").unwrap();

        for line in message.split_inclusive(|b| *b == b'\n') {
            let content = line.strip_suffix(b"\r\n").unwrap();

            if content.is_empty() {
                in_header = false;
            }

            if in_header && !matches!(content.first(), Some(b' ' | b'\t')) {
                let colon = content.iter().position(|b| *b == b':');
                let name = colon.map(|i| content[..i].trim_ascii_end().to_ascii_lowercase());
                in_blind = name.is_some_and(|name| name == b"bcc" || name == b"resent-bcc");
            }

            if in_header && in_blind {
                continue;
            }

            out.extend_from_slice(line);
        }

        // NOTE: an empty message is transmitted as one empty line
        if out.is_empty() {
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(b".\r\n");
        out
    }

    #[test]
    fn transmits_the_bcc_field_only_when_kept() {
        let raw = b"From: a@x\r\nBcc: c@x\r\n\r\nbody\r\n";

        let removed = transmitted(raw, SmtpMessageSendOptions::default());
        assert!(!removed[3].windows(4).any(|w| w == b"Bcc:"));

        let options = SmtpMessageSendOptions {
            keep_bcc: true,
            ..Default::default()
        };
        let kept = transmitted(raw, options);
        assert!(kept[3].windows(4).any(|w| w == b"Bcc:"));
    }

    #[test]
    fn sends_the_parameters_on_mail_from_and_rcpt_to() {
        let notify = SmtpDsnNotify::SUCCESS | SmtpDsnNotify::FAILURE;
        let options = SmtpMessageSendOptions {
            mail_parameters: vec![
                SmtpDsnRet::Hdrs.into_parameter(),
                SmtpParameter::envid("abc123").unwrap(),
            ],
            rcpt_parameters: vec![notify.into_parameter()],
            ..Default::default()
        };

        let written = transmitted(b"\r\nbody\r\n", options);
        assert_eq!(written[0], b"MAIL FROM:<a@x> RET=HDRS ENVID=abc123\r\n");
        assert_eq!(written[1], b"RCPT TO:<c@x> NOTIFY=SUCCESS,FAILURE\r\n");
    }

    #[test]
    fn names_the_refused_recipient_and_resets() {
        let replies = [OK, OK, b"550-5.1.1 User\r\n550 unknown\r\n", OK];
        let (written, result) = sent(&["c@x", "d@x", "e@x"], Default::default(), &replies);

        let Err(SmtpMessageSendError::RcptTo {
            forward_path,
            error,
        }) = result
        else {
            panic!("expected SmtpMessageSendError::RcptTo, got {result:?}");
        };

        let SmtpRcptError::Rejected { code, message } = error else {
            panic!("expected SmtpRcptError::Rejected, got {error:?}");
        };

        assert_eq!(forward_path, path("d@x"));
        assert_eq!(code, 550);
        assert_eq!(message, "5.1.1 User unknown");

        let commands: [&[u8]; 4] = [
            b"MAIL FROM:<a@x>\r\n",
            b"RCPT TO:<c@x>\r\n",
            b"RCPT TO:<d@x>\r\n",
            b"RSET\r\n",
        ];
        assert_eq!(written, commands);
    }

    #[test]
    fn keeps_the_first_error_when_rset_fails() {
        for rset_reply in [b"500 what\r\n".as_slice(), b""] {
            let replies = [OK, b"550 no such user\r\n", rset_reply];
            let (_, result) = sent(&["c@x"], Default::default(), &replies);
            assert!(matches!(result, Err(SmtpMessageSendError::RcptTo { .. })));
        }
    }

    #[test]
    fn sends_no_rset_when_the_session_state_is_unknown() {
        for rcpt_reply in [b"".as_slice(), b"421 closing\r\n", b"999 x\r\n"] {
            let replies = [OK, rcpt_reply];
            let (written, result) = sent(&["c@x"], Default::default(), &replies);
            assert!(matches!(result, Err(SmtpMessageSendError::RcptTo { .. })));
            assert_eq!(written.last().unwrap(), b"RCPT TO:<c@x>\r\n");
        }
    }

    #[test]
    fn sends_no_rset_after_a_refused_mail_from() {
        let replies = [b"550 sender refused\r\n".as_slice()];
        let (written, result) = sent(&["c@x"], Default::default(), &replies);

        assert!(matches!(result, Err(SmtpMessageSendError::MailFrom(_))));
        assert_eq!(written.len(), 1);
    }

    #[test]
    fn resets_after_a_refused_data_command() {
        let replies = [OK, OK, b"554 no valid recipients\r\n", OK];
        let (written, result) = sent(&["c@x"], Default::default(), &replies);

        let Err(SmtpMessageSendError::Data(error)) = result else {
            panic!("expected SmtpMessageSendError::Data, got {result:?}");
        };

        assert!(matches!(
            error,
            SmtpDataError::CommandRejected { code: 554, .. }
        ));
        assert_eq!(written.last().unwrap(), b"RSET\r\n");
    }

    #[test]
    fn sends_no_rset_once_the_body_was_answered() {
        let replies = [OK, OK, b"354 go\r\n", b"552 too large\r\n"];
        let (written, result) = sent(&["c@x"], Default::default(), &replies);

        assert!(matches!(result, Err(SmtpMessageSendError::Data(_))));
        assert_eq!(written.len(), 4);
    }

    #[test]
    fn skips_the_refused_recipients_when_told_to() {
        let options = SmtpMessageSendOptions {
            skip_refused_recipients: true,
            ..Default::default()
        };

        let replies = [OK, b"550 no such user\r\n", OK, b"354 go\r\n", OK];
        let (written, result) = sent(&["c@x", "d@x"], options, &replies);

        let refused = SmtpMessageSendRefusal {
            forward_path: path("c@x"),
            code: 550,
            message: "no such user".into(),
        };
        assert_eq!(result.unwrap(), [refused]);
        assert_eq!(written[3], b"DATA\r\n");
        assert_eq!(written.len(), 5);
    }

    #[test]
    fn fails_when_every_recipient_is_refused() {
        let options = SmtpMessageSendOptions {
            skip_refused_recipients: true,
            ..Default::default()
        };

        let replies = [OK, b"550 no such user\r\n", b"551 not local\r\n", OK];
        let (written, result) = sent(&["c@x", "d@x"], options, &replies);

        let Err(SmtpMessageSendError::NoRecipient(refused)) = result else {
            panic!("expected SmtpMessageSendError::NoRecipient, got {result:?}");
        };

        let codes: Vec<u16> = refused.iter().map(|refusal| refusal.code).collect();
        assert_eq!(codes, [550, 551]);
        assert_eq!(written.last().unwrap(), b"RSET\r\n");
        assert_eq!(written.len(), 4);
    }

    const OK: &[u8] = b"250 ok\r\n";

    fn path(address: &'static str) -> SmtpForwardPath<'static> {
        SmtpForwardPath(SmtpMailbox::try_from(address).unwrap())
    }

    /// Runs the send of one message against canned replies, returning
    /// every write.
    fn transmitted(raw: &[u8], options: SmtpMessageSendOptions) -> Vec<Vec<u8>> {
        let replies = [OK, OK, b"354 go\r\n", OK];
        let (written, result) = run(&["c@x"], raw, options, &replies);
        result.unwrap();
        written
    }

    /// Runs a send to the given recipients against canned replies,
    /// returning every write and how it completed.
    fn sent(
        recipients: &[&'static str],
        options: SmtpMessageSendOptions,
        replies: &[&[u8]],
    ) -> (Vec<Vec<u8>>, <SmtpMessageSend as SmtpCoroutine>::Return) {
        run(recipients, b"body\r\n", options, replies)
    }

    fn run(
        recipients: &[&'static str],
        raw: &[u8],
        options: SmtpMessageSendOptions,
        replies: &[&[u8]],
    ) -> (Vec<Vec<u8>>, <SmtpMessageSend as SmtpCoroutine>::Return) {
        let SmtpForwardPath(sender) = path("a@x");

        let mut send = SmtpMessageSend::new(
            SmtpReversePath::SmtpMailbox(sender),
            recipients.iter().copied().map(path),
            raw.to_vec(),
            options,
        );

        let mut replies = replies.iter().copied();
        let mut arg = None;
        let mut written = Vec::new();

        loop {
            match send.resume(arg.take()) {
                SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => written.push(bytes),
                SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => arg = replies.next(),
                SmtpCoroutineState::Complete(result) => break (written, result),
            }
        }
    }
}
