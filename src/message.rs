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
//!     message::SmtpMessageSend,
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

/// I/O-free SMTP composite send coroutine.
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
    ) -> Self {
        let forward_paths = forward_paths
            .into_iter()
            .map(IntoBoundedStatic::into_static)
            .collect();

        Self {
            state: State::MailFrom(SmtpMail::new(reverse_path.into_static(), Vec::new())),
            forward_paths,
            message: Some(message),
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
