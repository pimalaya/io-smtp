//! SMTP STARTTLS coroutine; returns any bytes received past the
//! `220` reply. RFC 3207 §6 forbids trailing bytes, so a non-empty
//! return value is a STARTTLS-injection signal: refuse the upgrade.
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
//!     rfc3207::starttls::SmtpStartTls,
//! };
//!
//! // Ready stream needed (TCP-connected, plain SMTP, greeting + EHLO done)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = SmtpStartTls::new();
//! let mut arg = None;
//!
//! let remaining = loop {
//!     match coroutine.resume(arg.take()) {
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         SmtpCoroutineState::Complete(Ok(remaining)) => break remaining,
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! assert!(remaining.is_empty(), "STARTTLS-injection: refuse the upgrade");
//! // Now upgrade `stream` to TLS before sending further SMTP commands.
//! ```

use core::fmt;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::debug;
use thiserror::Error;

use crate::{coroutine::*, rfc5321::types::reply_code::SmtpReplyCode, send::*, smtp_try};

/// The STARTTLS command (RFC 3207).
pub struct SmtpStartTlsCommand;

impl From<SmtpStartTlsCommand> for Vec<u8> {
    fn from(_: SmtpStartTlsCommand) -> Vec<u8> {
        b"STARTTLS\r\n".to_vec()
    }
}

/// Failure causes during the SMTP STARTTLS handshake.
#[derive(Clone, Debug, Error)]
pub enum SmtpStartTlsError {
    /// The server rejected the STARTTLS command.
    #[error("SMTP STARTTLS failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The underlying command exchange failed.
    #[error("SMTP STARTTLS failed: {0}")]
    Send(#[from] SmtpCommandSendError),
}

/// I/O-free SMTP STARTTLS coroutine.
pub struct SmtpStartTls {
    state: State,
}

impl SmtpStartTls {
    /// Creates the coroutine.
    pub fn new() -> Self {
        Self {
            state: State::Send(SmtpCommandSend::new(SmtpStartTlsCommand)),
        }
    }
}

impl Default for SmtpStartTls {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpCoroutine for SmtpStartTls {
    type Yield = SmtpYield;
    type Return = Result<Vec<u8>, SmtpStartTlsError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = smtp_try!(send, arg);

                if out.response.code == SmtpReplyCode::SERVICE_READY {
                    debug!("starttls accepted, ready to upgrade");
                    return SmtpCoroutineState::Complete(Ok(Vec::new()));
                }

                let code = out.response.code.code();
                let message = out.response.text().to_string();
                SmtpCoroutineState::Complete(Err(SmtpStartTlsError::Rejected { code, message }))
            }
        }
    }
}

enum State {
    Send(SmtpCommandSend<SmtpStartTlsCommand>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send starttls"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{coroutine::*, rfc3207::starttls::*, send::SmtpCommandSendError};

    #[test]
    fn success_returns_empty_remaining() {
        let mut starttls = SmtpStartTls::new();

        let bytes = expect_wants_write(&mut starttls, None);
        assert_eq!(bytes, b"STARTTLS\r\n");

        expect_wants_read(&mut starttls);
        let remaining = expect_complete_ok(&mut starttls, b"220 ready\r\n");
        assert!(remaining.is_empty());
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut starttls = SmtpStartTls::new();
        let _ = expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        let err = expect_complete_err(&mut starttls, b"454 TLS not available\r\n");
        let SmtpStartTlsError::Rejected { code, message } = err else {
            panic!("expected SmtpStartTlsError::Rejected, got {err:?}");
        };
        assert_eq!(code, 454);
        assert_eq!(message, "TLS not available");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut starttls = SmtpStartTls::new();
        let _ = expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        let err = expect_complete_err(&mut starttls, b"");
        assert!(matches!(
            err,
            SmtpStartTlsError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpStartTls, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpStartTls) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpStartTls, reply: &[u8]) -> Vec<u8> {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(remaining)) => remaining,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpStartTls, reply: &[u8]) -> SmtpStartTlsError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
