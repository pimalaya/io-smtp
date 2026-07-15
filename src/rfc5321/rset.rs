//! SMTP RSET coroutine; aborts the current mail transaction.
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
//!     rfc5321::rset::SmtpRset,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, SMTP-handshaked)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = SmtpRset::new();
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

/// The RSET command (RFC 5321 §4.1.1.5).
pub struct SmtpRsetCommand;

impl From<SmtpRsetCommand> for Vec<u8> {
    fn from(_: SmtpRsetCommand) -> Vec<u8> {
        b"RSET\r\n".to_vec()
    }
}

/// Failure causes during the SMTP RSET exchange.
#[derive(Clone, Debug, Error)]
pub enum SmtpRsetError {
    /// The server rejected the RSET command.
    #[error("SMTP RSET failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The underlying command exchange failed.
    #[error("SMTP RSET failed: {0}")]
    Send(#[from] SmtpCommandSendError),
}

/// I/O-free SMTP RSET coroutine.
pub struct SmtpRset {
    state: State,
}

impl SmtpRset {
    /// Creates the coroutine.
    pub fn new() -> Self {
        Self {
            state: State::Send(SmtpCommandSend::new(SmtpRsetCommand)),
        }
    }
}

impl Default for SmtpRset {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpCoroutine for SmtpRset {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpRsetError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = smtp_try!(send, arg);

                if out.response.code == SmtpReplyCode::OK {
                    debug!("rset accepted");
                    return SmtpCoroutineState::Complete(Ok(()));
                }

                let code = out.response.code.code();
                let message = out.response.text().to_string();
                SmtpCoroutineState::Complete(Err(SmtpRsetError::Rejected { code, message }))
            }
        }
    }
}

enum State {
    Send(SmtpCommandSend<SmtpRsetCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send rset"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{coroutine::*, rfc5321::rset::*, send::SmtpCommandSendError};

    #[test]
    fn success_returns_ok() {
        let mut rset = SmtpRset::new();

        let bytes = expect_wants_write(&mut rset, None);
        assert_eq!(bytes, b"RSET\r\n");

        expect_wants_read(&mut rset);
        expect_complete_ok(&mut rset, b"250 OK\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut rset = SmtpRset::new();
        let _ = expect_wants_write(&mut rset, None);
        expect_wants_read(&mut rset);

        let err = expect_complete_err(&mut rset, b"500 syntax error\r\n");
        let SmtpRsetError::Rejected { code, message } = err else {
            panic!("expected SmtpRsetError::Rejected, got {err:?}");
        };
        assert_eq!(code, 500);
        assert_eq!(message, "syntax error");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut rset = SmtpRset::new();
        let _ = expect_wants_write(&mut rset, None);
        expect_wants_read(&mut rset);

        let err = expect_complete_err(&mut rset, b"");
        assert!(matches!(
            err,
            SmtpRsetError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpRset, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpRset) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpRset, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpRset, reply: &[u8]) -> SmtpRsetError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
