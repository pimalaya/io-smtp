//! I/O-free coroutine to perform SMTP STARTTLS negotiation.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::trace;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::types::{reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
};

/// The STARTTLS command (RFC 3207).
pub struct SmtpStartTlsCommand;

impl From<SmtpStartTlsCommand> for Vec<u8> {
    fn from(_: SmtpStartTlsCommand) -> Vec<u8> {
        b"STARTTLS\r\n".to_vec()
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpStartTlsError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("STARTTLS rejected by server: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Per-coroutine Yield for [`SmtpStartTls`].
///
/// Extends the standard [`SmtpYield`] with a [`WantsStartTls`] variant
/// that signals the driver to upgrade the underlying socket to TLS.
/// The driver does not resume the coroutine after a [`WantsStartTls`]:
/// the upgrade is the terminal step on the happy path.
///
/// [`WantsStartTls`]: SmtpStartTlsYield::WantsStartTls
#[derive(Debug)]
pub enum SmtpStartTlsYield {
    /// Driver should read more bytes from the socket and feed them
    /// back on the next resume.
    WantsRead,
    /// Driver should write these bytes to the socket; the next resume
    /// typically takes `None`.
    WantsWrite(Vec<u8>),
    /// The server accepted STARTTLS. The driver should now upgrade
    /// the underlying socket to TLS and stop driving this coroutine.
    ///
    /// The payload carries any bytes the coroutine pre-read from the
    /// socket past the `220` reply, so the caller can re-feed them
    /// after the TLS handshake. A well-behaved server never speaks
    /// before the handshake (any pre-handshake bytes are a classic
    /// STARTTLS-injection signal, RFC 3207 §6), so the payload is
    /// normally empty.
    WantsStartTls(Vec<u8>),
}

/// I/O-free coroutine to perform SMTP STARTTLS negotiation.
///
/// Yields [`SmtpStartTlsYield::WantsStartTls`] once the server replies
/// with a `220` ready code; the driver performs the TLS upgrade. The
/// terminal [`SmtpCoroutineState::Complete`] arm is reserved for the
/// error path (rejection, parse failure, EOF).
pub struct SmtpStartTls {
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl Default for SmtpStartTls {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpStartTls {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        trace!("sending STARTTLS command");

        Self {
            wants_read: false,
            wants_write: Some(SmtpStartTlsCommand.into()),
            buf: Vec::new(),
        }
    }
}

impl SmtpCoroutine for SmtpStartTls {
    type Yield = SmtpStartTlsYield;
    type Return = Result<(), SmtpStartTlsError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpCoroutineState::Yielded(SmtpStartTlsYield::WantsWrite(bytes));
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::Yielded(SmtpStartTlsYield::WantsRead);
            }

            match arg.take() {
                Some(&[]) => {
                    return SmtpCoroutineState::Complete(Err(SmtpStartTlsError::Eof));
                }
                Some(data) => {
                    trace!("read SMTP bytes: {}", escape_byte_string(data));
                    self.buf.extend_from_slice(data);
                }
                None => {}
            }

            if !Response::is_complete(&self.buf) {
                self.wants_read = true;
                continue;
            }

            return match Response::parse(&self.buf) {
                Ok(response) => {
                    if response.code == ReplyCode::SERVICE_READY {
                        let _ = mem::take(&mut self.buf);
                        SmtpCoroutineState::Yielded(SmtpStartTlsYield::WantsStartTls(Vec::new()))
                    } else {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        SmtpCoroutineState::Complete(Err(SmtpStartTlsError::Rejected {
                            code,
                            message,
                        }))
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpCoroutineState::Complete(Err(SmtpStartTlsError::ParseResponse(reason)))
                }
            };
        }
    }
}
