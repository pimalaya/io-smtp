//! SMTP composite coroutine; chains MAIL FROM, one RCPT TO per
//! recipient, then DATA.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     borrow::Cow,
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
//!     message::{SmtpMessageSend, SmtpMessageSendOptions},
//!     rfc5321::{
//!         SmtpDomain, SmtpEhloDomain, SmtpForwardPath,
//!         SmtpLocalPart, SmtpMailbox, SmtpReversePath,
//!     },
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, AUTH consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let alice = SmtpMailbox {
//!     local_part: SmtpLocalPart(Cow::Borrowed("alice")),
//!     domain: SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.org"))),
//! };
//! let bob = SmtpMailbox {
//!     local_part: SmtpLocalPart(Cow::Borrowed("bob")),
//!     domain: SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.org"))),
//! };
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
        SmtpForwardPath, SmtpReversePath,
        data::{SmtpData, SmtpDataError},
        mail::{SmtpMail, SmtpMailError},
        rcpt::{SmtpRcpt, SmtpRcptError},
    },
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
}

/// I/O-free SMTP composite send coroutine.
///
/// It submits a message rather than relaying one: unless told to keep it,
/// the `Bcc` field is removed from the transmitted header section, so the
/// blind recipients reached through the forward paths stay hidden.
pub struct SmtpMessageSend {
    state: State,
    forward_paths: VecDeque<SmtpForwardPath<'static>>,
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
            state: State::MailFrom(SmtpMail::new(reverse_path.into_static(), Vec::new())),
            forward_paths,
            message: Some(match options.keep_bcc {
                true => message,
                false => strip_bcc(&message),
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
            Some(path) => State::RcptTo(SmtpRcpt::new(path, Vec::new())),
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
/// section of `message`, copying the body verbatim.
fn strip_bcc(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len());
    let mut lines = message.split_inclusive(|&byte| byte == b'\n');
    let mut in_bcc = false;

    for line in lines.by_ref() {
        if line == b"\r\n" || line == b"\n" {
            out.extend_from_slice(line);
            break;
        }

        if !matches!(line.first(), Some(b' ' | b'\t')) {
            in_bcc = is_bcc(line);
        }

        if !in_bcc {
            out.extend_from_slice(line);
        }
    }

    lines.for_each(|line| out.extend_from_slice(line));
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
    use alloc::vec::Vec;

    use crate::{
        coroutine::*,
        message::*,
        rfc5321::{SmtpDomain, SmtpEhloDomain, SmtpLocalPart, SmtpMailbox},
    };

    #[test]
    fn removes_the_bcc_field_and_keeps_everything_else() {
        let raw =
            b"From: a@x\r\nTo: b@x\r\nBcc: c@x\r\nSubject: s\r\n\r\nBcc: in the body stays\r\n";
        assert_eq!(
            strip_bcc(raw),
            b"From: a@x\r\nTo: b@x\r\nSubject: s\r\n\r\nBcc: in the body stays\r\n"
        );
    }

    #[test]
    fn removes_folded_continuation_lines_and_any_case() {
        let raw = b"From: a@x\r\nBCC: c@x,\r\n d@x,\r\n\te@x\r\nTo: b@x\r\n\r\nbody\r\n";
        assert_eq!(strip_bcc(raw), b"From: a@x\r\nTo: b@x\r\n\r\nbody\r\n");
    }

    #[test]
    fn removes_the_obsolete_spelling_with_space_before_the_colon() {
        let raw = b"From: a@x\r\nBcc : c@x\r\nTo: b@x\r\n\r\nbody\r\n";
        assert_eq!(strip_bcc(raw), b"From: a@x\r\nTo: b@x\r\n\r\nbody\r\n");
    }

    #[test]
    fn leaves_a_message_without_bcc_byte_identical() {
        let raw = b"From: a@x\nTo: b@x\nX-Bccish: keep\n\nbody\n";
        assert_eq!(strip_bcc(raw), raw.to_vec());
    }

    #[test]
    fn transmits_the_bcc_field_only_when_kept() {
        let raw = b"From: a@x\r\nBcc: c@x\r\n\r\nbody\r\n";

        let removed = transmitted(raw, SmtpMessageSendOptions::default());
        assert!(!removed.windows(4).any(|w| w == b"Bcc:"));

        let kept = transmitted(raw, SmtpMessageSendOptions { keep_bcc: true });
        assert!(kept.windows(4).any(|w| w == b"Bcc:"));
    }

    fn transmitted(raw: &[u8], options: SmtpMessageSendOptions) -> Vec<u8> {
        let mailbox = |local: &'static str| SmtpMailbox {
            local_part: SmtpLocalPart(local.into()),
            domain: SmtpEhloDomain::SmtpDomain(SmtpDomain("x".into())),
        };

        let mut send = SmtpMessageSend::new(
            SmtpReversePath::SmtpMailbox(mailbox("a")),
            [SmtpForwardPath(mailbox("c"))],
            raw.to_vec(),
            options,
        );

        let replies: [&[u8]; 4] = [b"250 ok\r\n", b"250 ok\r\n", b"354 go\r\n", b"250 ok\r\n"];
        let mut replies = replies.into_iter();
        let mut arg = None;
        let mut written = Vec::new();

        loop {
            match send.resume(arg.take()) {
                SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => written = bytes,
                SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => arg = replies.next(),
                SmtpCoroutineState::Complete(result) => break result.unwrap(),
            }
        }

        written
    }
}
