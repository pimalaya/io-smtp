//! SMTP HELO coroutine; legacy handshake. Prefer
//! [`crate::rfc5321::ehlo`] and fall back to HELO only when the
//! server rejects EHLO with `500`/`502`.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use std::borrow::Cow;
//!
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
//!     rfc5321::{helo::SmtpHelo, types::domain::Domain},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, greeting consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let domain = Domain(Cow::Borrowed("example.com"));
//! let mut coroutine = SmtpHelo::new(domain);
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
    rfc5321::types::{domain::Domain, reply_code::ReplyCode},
    send::*,
    smtp_try,
};

/// The HELO command (RFC 5321 §4.1.1.1).
pub struct SmtpHeloCommand<'a> {
    /// The client's domain.
    pub domain: Domain<'a>,
}

impl<'a> From<SmtpHeloCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpHeloCommand<'a>) -> Vec<u8> {
        let mut buf = String::from("HELO ");
        buf.push_str(&cmd.domain.to_string());
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Failure causes during the SMTP HELO exchange.
#[derive(Clone, Debug, Error)]
pub enum SmtpHeloError {
    #[error("SMTP HELO failed: rejected {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("SMTP HELO failed: {0}")]
    Send(#[from] SendSmtpCommandError),
}

/// I/O-free SMTP HELO coroutine.
pub struct SmtpHelo {
    state: State,
}

impl SmtpHelo {
    pub fn new(domain: Domain<'_>) -> Self {
        let cmd = SmtpHeloCommand {
            domain: domain.into_static(),
        };

        Self {
            state: State::Send(SendSmtpCommand::new(cmd)),
        }
    }
}

impl SmtpCoroutine for SmtpHelo {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpHeloError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("helo: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code == ReplyCode::OK {
                        return SmtpCoroutineState::Complete(Ok(()));
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpHeloError::Rejected {
                        code,
                        message,
                    }));
                }
            }
        }
    }
}

enum State {
    Send(SendSmtpCommand<SmtpHeloCommand<'static>>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send helo"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;

    use super::*;

    fn domain() -> Domain<'static> {
        Domain(Cow::Borrowed("example.com"))
    }

    #[test]
    fn success_returns_ok() {
        let mut helo = SmtpHelo::new(domain());

        let bytes = expect_wants_write(&mut helo, None);
        assert_eq!(bytes, b"HELO example.com\r\n");

        expect_wants_read(&mut helo);
        expect_complete_ok(&mut helo, b"250 server.example.com\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut helo = SmtpHelo::new(domain());
        let _ = expect_wants_write(&mut helo, None);
        expect_wants_read(&mut helo);

        let err = expect_complete_err(&mut helo, b"550 bad domain\r\n");
        let SmtpHeloError::Rejected { code, message } = err else {
            panic!("expected SmtpHeloError::Rejected, got {err:?}");
        };
        assert_eq!(code, 550);
        assert_eq!(message, "bad domain");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut helo = SmtpHelo::new(domain());
        let _ = expect_wants_write(&mut helo, None);
        expect_wants_read(&mut helo);

        let err = expect_complete_err(&mut helo, b"");
        assert!(matches!(
            err,
            SmtpHeloError::Send(SendSmtpCommandError::Eof)
        ));
    }

    // --- utils

    fn expect_wants_write(cor: &mut SmtpHelo, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpHelo) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpHelo, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpHelo, reply: &[u8]) -> SmtpHeloError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
