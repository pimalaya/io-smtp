//! SMTP NOOP coroutine, useful as keep-alive or round-trip probe.
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
//!     rfc5321::noop::SmtpNoop,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, SMTP-handshaked)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = SmtpNoop::new();
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
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, rfc5321::SmtpReplyCode, send::*, smtp_try};

/// The NOOP command (RFC 5321 §4.1.1.9).
pub struct SmtpNoopCommand<'a> {
    /// Optional string argument; servers must ignore it.
    pub string: Option<Cow<'a, str>>,
}

impl<'a> From<SmtpNoopCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpNoopCommand<'a>) -> Vec<u8> {
        let mut buf = String::from("NOOP");

        if let Some(s) = cmd.string {
            buf.push(' ');
            buf.push_str(&s);
        }

        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Failure causes during the SMTP NOOP exchange.
#[derive(Clone, Debug, Error)]
pub enum SmtpNoopError {
    /// The server rejected the NOOP command.
    #[error("SMTP NOOP failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The underlying command exchange failed.
    #[error("SMTP NOOP failed: {0}")]
    Send(#[from] SmtpCommandSendError),
}

/// I/O-free SMTP NOOP coroutine.
pub struct SmtpNoop {
    state: State,
}

impl SmtpNoop {
    /// Creates the coroutine.
    pub fn new() -> Self {
        Self {
            state: State::Send(SmtpCommandSend::new(SmtpNoopCommand { string: None })),
        }
    }
}

impl Default for SmtpNoop {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpCoroutine for SmtpNoop {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpNoopError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = smtp_try!(send, arg);

                if out.response.code == SmtpReplyCode::OK {
                    debug!("noop accepted");
                    return SmtpCoroutineState::Complete(Ok(()));
                }

                let code = out.response.code.code();
                let message = out.response.text().to_string();
                SmtpCoroutineState::Complete(Err(SmtpNoopError::Rejected { code, message }))
            }
        }
    }
}

enum State {
    Send(SmtpCommandSend<SmtpNoopCommand<'static>>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send noop"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{coroutine::*, rfc5321::noop::*, send::SmtpCommandSendError};

    #[test]
    fn success_returns_ok() {
        let mut noop = SmtpNoop::new();

        let bytes = expect_wants_write(&mut noop, None);
        assert_eq!(bytes, b"NOOP\r\n");

        expect_wants_read(&mut noop);
        expect_complete_ok(&mut noop, b"250 OK\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut noop = SmtpNoop::new();
        let _ = expect_wants_write(&mut noop, None);
        expect_wants_read(&mut noop);

        let err = expect_complete_err(&mut noop, b"500 syntax error\r\n");
        let SmtpNoopError::Rejected { code, message } = err else {
            panic!("expected SmtpNoopError::Rejected, got {err:?}");
        };
        assert_eq!(code, 500);
        assert_eq!(message, "syntax error");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut noop = SmtpNoop::new();
        let _ = expect_wants_write(&mut noop, None);
        expect_wants_read(&mut noop);

        let err = expect_complete_err(&mut noop, b"");
        assert!(matches!(
            err,
            SmtpNoopError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpNoop, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpNoop) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpNoop, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpNoop, reply: &[u8]) -> SmtpNoopError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
