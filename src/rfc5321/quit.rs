//! SMTP QUIT coroutine; asks the server to close the session.
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
//!     rfc5321::quit::SmtpQuit,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, SMTP-handshaked)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = SmtpQuit::new();
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

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, rfc5321::types::reply_code::SmtpReplyCode, send::*, smtp_try};

/// The QUIT command (RFC 5321 §4.1.1.10).
pub struct SmtpQuitCommand;

impl From<SmtpQuitCommand> for Vec<u8> {
    fn from(_: SmtpQuitCommand) -> Vec<u8> {
        b"QUIT\r\n".to_vec()
    }
}

/// Failure causes during the SMTP QUIT exchange.
#[derive(Clone, Debug, Error)]
pub enum SmtpQuitError {
    /// The server rejected the QUIT command.
    #[error("SMTP QUIT failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The underlying command exchange failed.
    #[error("SMTP QUIT failed: {0}")]
    Send(#[from] SmtpCommandSendError),
}

/// I/O-free SMTP QUIT coroutine.
pub struct SmtpQuit {
    state: State,
}

impl SmtpQuit {
    /// Creates the coroutine.
    pub fn new() -> Self {
        Self {
            state: State::Send(SmtpCommandSend::new(SmtpQuitCommand)),
        }
    }
}

impl Default for SmtpQuit {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpCoroutine for SmtpQuit {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpQuitError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = smtp_try!(send, arg);

                if out.response.code == SmtpReplyCode::SERVICE_CLOSING {
                    debug!("quit accepted");
                    return SmtpCoroutineState::Complete(Ok(()));
                }

                let code = out.response.code.code();
                let message = out.response.text().to_string();
                SmtpCoroutineState::Complete(Err(SmtpQuitError::Rejected { code, message }))
            }
        }
    }
}

enum State {
    Send(SmtpCommandSend<SmtpQuitCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send quit"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{coroutine::*, rfc5321::quit::*, send::SmtpCommandSendError};

    #[test]
    fn success_returns_ok() {
        let mut quit = SmtpQuit::new();

        let bytes = expect_wants_write(&mut quit, None);
        assert_eq!(bytes, b"QUIT\r\n");

        expect_wants_read(&mut quit);
        expect_complete_ok(&mut quit, b"221 service closing\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut quit = SmtpQuit::new();
        let _ = expect_wants_write(&mut quit, None);
        expect_wants_read(&mut quit);

        let err = expect_complete_err(&mut quit, b"500 syntax error\r\n");
        let SmtpQuitError::Rejected { code, message } = err else {
            panic!("expected SmtpQuitError::Rejected, got {err:?}");
        };
        assert_eq!(code, 500);
        assert_eq!(message, "syntax error");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut quit = SmtpQuit::new();
        let _ = expect_wants_write(&mut quit, None);
        expect_wants_read(&mut quit);

        let err = expect_complete_err(&mut quit, b"");
        assert!(matches!(
            err,
            SmtpQuitError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpQuit, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpQuit) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpQuit, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpQuit, reply: &[u8]) -> SmtpQuitError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
