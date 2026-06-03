//! SMTP MAIL FROM coroutine; opens a mail transaction.
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
//!     rfc5321::{mail::SmtpMail, types::reverse_path::ReversePath},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = SmtpMail::new(ReversePath::Null, Vec::new());
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

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::types::{parameter::Parameter, reply_code::ReplyCode, reverse_path::ReversePath},
    send::*,
    smtp_try,
};

/// The MAIL FROM command (RFC 5321 §4.1.1.2).
pub struct SmtpMailCommand<'a> {
    /// The sender's reverse path (may be the null path `<>`).
    pub reverse_path: ReversePath<'a>,
    /// Optional ESMTP parameters (e.g. `SIZE=`, `BODY=`).
    pub parameters: Vec<Parameter<'a>>,
}

impl<'a> From<SmtpMailCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpMailCommand<'a>) -> Vec<u8> {
        let mut buf = String::from("MAIL FROM:");
        buf.push_str(&cmd.reverse_path.to_string());
        for p in cmd.parameters {
            buf.push(' ');
            buf.push_str(&p.to_string());
        }
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Failure causes during the SMTP MAIL FROM exchange.
#[derive(Clone, Debug, Error)]
pub enum SmtpMailError {
    #[error("SMTP MAIL FROM failed: rejected {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("SMTP MAIL FROM failed: {0}")]
    Send(#[from] SendSmtpCommandError),
}

/// I/O-free SMTP MAIL FROM coroutine.
pub struct SmtpMail {
    state: State,
}

impl SmtpMail {
    /// Pass an empty `parameters` vector for the bare `MAIL FROM`
    /// form; non-empty entries are appended after the reverse path
    /// (e.g. `SIZE=`, `BODY=`, DSN).
    pub fn new(reverse_path: ReversePath<'_>, parameters: Vec<Parameter<'_>>) -> Self {
        let cmd = SmtpMailCommand {
            reverse_path: reverse_path.into_static(),
            parameters: parameters.into_iter().map(|p| p.into_static()).collect(),
        };

        Self {
            state: State::Send(SendSmtpCommand::new(cmd)),
        }
    }
}

impl SmtpCoroutine for SmtpMail {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpMailError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("mail: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code == ReplyCode::OK {
                        return SmtpCoroutineState::Complete(Ok(()));
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpMailError::Rejected {
                        code,
                        message,
                    }));
                }
            }
        }
    }
}

enum State {
    Send(SendSmtpCommand<SmtpMailCommand<'static>>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send mail from"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn null_path() -> ReversePath<'static> {
        ReversePath::Null
    }

    #[test]
    fn success_returns_ok() {
        let mut mail = SmtpMail::new(null_path(), Vec::new());

        let bytes = expect_wants_write(&mut mail, None);
        assert!(bytes.starts_with(b"MAIL FROM:"));

        expect_wants_read(&mut mail);
        expect_complete_ok(&mut mail, b"250 sender ok\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut mail = SmtpMail::new(null_path(), Vec::new());
        let _ = expect_wants_write(&mut mail, None);
        expect_wants_read(&mut mail);

        let err = expect_complete_err(&mut mail, b"550 mailbox unavailable\r\n");
        let SmtpMailError::Rejected { code, message } = err else {
            panic!("expected SmtpMailError::Rejected, got {err:?}");
        };
        assert_eq!(code, 550);
        assert_eq!(message, "mailbox unavailable");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut mail = SmtpMail::new(null_path(), Vec::new());
        let _ = expect_wants_write(&mut mail, None);
        expect_wants_read(&mut mail);

        let err = expect_complete_err(&mut mail, b"");
        assert!(matches!(
            err,
            SmtpMailError::Send(SendSmtpCommandError::Eof)
        ));
    }

    // --- utils

    fn expect_wants_write(cor: &mut SmtpMail, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpMail) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpMail, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpMail, reply: &[u8]) -> SmtpMailError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
