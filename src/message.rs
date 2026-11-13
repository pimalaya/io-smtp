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
//!         SmtpCoroutineState::Complete(Ok(())) => break,
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::fmt;

use alloc::{collections::VecDeque, vec::Vec};

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
    },
    scan::position,
    smtp_try,
};

/// Failure causes during the SMTP send composite coroutine.
#[derive(Debug, Error)]
pub enum SmtpMessageSendError {
    /// The MAIL FROM step failed.
    #[error(transparent)]
    MailFrom(#[from] SmtpMailError),
    /// A RCPT TO step failed.
    #[error(transparent)]
    RcptTo(#[from] SmtpRcptError),
    /// The DATA step failed.
    #[error(transparent)]
    Data(#[from] SmtpDataError),
}

/// Options for [`SmtpMessageSend`].
#[derive(Clone, Debug, Default)]
pub struct SmtpMessageSendOptions {
    /// Transmit the `Bcc` field instead of removing it (RFC 5322 3.6.3).
    pub keep_bcc: bool,
    /// ESMTP parameters of the MAIL FROM command (RFC 5321 4.1.1.2), such
    /// as the DSN `RET` and `ENVID` (RFC 3461 4.3, 4.4).
    pub mail_parameters: Vec<SmtpParameter<'static>>,
    /// ESMTP parameters of every RCPT TO command (RFC 5321 4.1.1.3), such
    /// as the DSN `NOTIFY` (RFC 3461 4.1).
    pub rcpt_parameters: Vec<SmtpParameter<'static>>,
}

/// I/O-free SMTP composite send coroutine.
///
/// It submits a message rather than relaying one: unless told to keep it,
/// the `Bcc` field is removed from the transmitted header section, so the
/// blind recipients reached through the forward paths stay hidden.
pub struct SmtpMessageSend {
    state: State,
    forward_paths: VecDeque<SmtpForwardPath<'static>>,
    rcpt_parameters: Vec<SmtpParameter<'static>>,
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
            message: Some(match options.keep_bcc {
                true => message,
                false => strip_bcc(message),
            }),
        }
    }
}

impl SmtpCoroutine for SmtpMessageSend {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpMessageSendError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::MailFrom(mail) => {
                    let () = smtp_try!(mail, arg);
                    self.state = self.next_rcpt_or_data();
                    debug!("mail from accepted, next: {}", self.state);
                }
                State::RcptTo(rcpt) => {
                    let () = smtp_try!(rcpt, arg);
                    self.state = self.next_rcpt_or_data();
                    debug!("rcpt to accepted, next: {}", self.state);
                }
                State::Data(data) => {
                    let () = smtp_try!(data, arg);
                    debug!("message sent");
                    return SmtpCoroutineState::Complete(Ok(()));
                }
            }
        }
    }
}

impl SmtpMessageSend {
    fn next_rcpt_or_data(&mut self) -> State {
        match self.forward_paths.pop_front() {
            Some(path) => State::RcptTo(SmtpRcpt::new(path, self.rcpt_parameters.clone())),
            None => {
                let body = self.message.take().expect("message taken twice");
                State::Data(SmtpData::new(body))
            }
        }
    }
}

enum State {
    MailFrom(SmtpMail),
    RcptTo(SmtpRcpt),
    Data(SmtpData),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MailFrom(_) => f.write_str("mail from"),
            Self::RcptTo(_) => f.write_str("rcpt to"),
            Self::Data(_) => f.write_str("data"),
        }
    }
}

/// Removes every `Bcc` field, folded lines included, from the header
/// section of `message`, leaving the body untouched.
///
/// `message` is returned as is when it carries no `Bcc` field.
fn strip_bcc(message: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    // NOTE: message[..copied] is in out already, once a field was stripped.
    let mut copied = 0;
    let mut stripped = false;
    let mut in_bcc = false;
    let mut start = 0;

    while start < message.len() {
        let end = match position(&message[start..], |byte| byte == b'\n') {
            Some(lf) => start + lf + 1,
            None => message.len(),
        };

        let line = &message[start..end];

        if line == b"\r\n" || line == b"\n" {
            break;
        }

        if !matches!(line.first(), Some(b' ' | b'\t')) {
            in_bcc = is_bcc(line);
        }

        if in_bcc {
            if !stripped {
                out.reserve(message.len());
                stripped = true;
            }

            out.extend_from_slice(&message[copied..start]);
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

/// Whether a header line opens a `Bcc` field, allowing the obsolete
/// whitespace before the colon (RFC 5322 4.5.3).
fn is_bcc(line: &[u8]) -> bool {
    line.iter()
        .position(|&byte| byte == b':')
        .is_some_and(|colon| line[..colon].trim_ascii_end().eq_ignore_ascii_case(b"bcc"))
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

    /// Runs the send against canned replies, returning every write.
    fn transmitted(raw: &[u8], options: SmtpMessageSendOptions) -> Vec<Vec<u8>> {
        let mailbox = |address: &'static str| SmtpMailbox::try_from(address).unwrap();

        let mut send = SmtpMessageSend::new(
            SmtpReversePath::SmtpMailbox(mailbox("a@x")),
            [SmtpForwardPath(mailbox("c@x"))],
            raw.to_vec(),
            options,
        );

        let replies: [&[u8]; 4] = [b"250 ok\r\n", b"250 ok\r\n", b"354 go\r\n", b"250 ok\r\n"];
        let mut replies = replies.into_iter();
        let mut arg = None;
        let mut written = Vec::new();

        loop {
            match send.resume(arg.take()) {
                SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => written.push(bytes),
                SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => arg = replies.next(),
                SmtpCoroutineState::Complete(result) => break result.unwrap(),
            }
        }

        written
    }
}
