//! I/O-free coroutine to perform SMTP STARTTLS negotiation.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::trace;
use thiserror::Error;

use crate::{
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

/// Result returned by [`SmtpStartTls::resume`].
#[derive(Debug)]
pub enum SmtpStartTlsResult {
    /// The server accepted STARTTLS. The caller must now upgrade the
    /// socket to TLS.
    ///
    /// The single payload carries any bytes the coroutine pre-read
    /// from the socket past the `220` reply, so the caller can re-feed
    /// them after the TLS handshake. A well-behaved server never
    /// speaks before the handshake (any pre-handshake bytes are a
    /// classic STARTTLS-injection signal — RFC 3207 §6), so the
    /// payload is normally empty.
    WantsStartTls(Vec<u8>),
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SmtpStartTlsError),
}

/// I/O-free coroutine to perform SMTP STARTTLS negotiation.
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

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpStartTlsResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpStartTlsResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpStartTlsResult::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return SmtpStartTlsResult::Err(SmtpStartTlsError::Eof),
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
                        SmtpStartTlsResult::WantsStartTls(Vec::new())
                    } else {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        SmtpStartTlsResult::Err(SmtpStartTlsError::Rejected { code, message })
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpStartTlsResult::Err(SmtpStartTlsError::ParseResponse(reason))
                }
            };
        }
    }
}
