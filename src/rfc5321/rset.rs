//! I/O-free coroutine to send SMTP RSET command.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::{reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
};

/// The RSET command (RFC 5321 §4.1.1.5).
pub struct SmtpRsetCommand;

impl From<SmtpRsetCommand> for Vec<u8> {
    fn from(_: SmtpRsetCommand) -> Vec<u8> {
        b"RSET\r\n".to_vec()
    }
}

/// Errors that can occur during RSET.
#[derive(Debug, Error)]
pub enum SmtpRsetError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("RSET rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Result returned by [`SmtpRset::resume`].
#[derive(Debug)]
pub enum SmtpRsetResult {
    Ok,
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SmtpRsetError),
}

/// I/O-free coroutine to send SMTP RSET command.
///
/// RSET aborts the current mail transaction and returns to Ready state.
pub struct SmtpRset {
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl Default for SmtpRset {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpRset {
    /// Creates a new RSET coroutine.
    pub fn new() -> Self {
        trace!("sending RSET command");

        Self {
            wants_read: false,
            wants_write: Some(SmtpRsetCommand.into()),
            buf: Vec::new(),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpRsetResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpRsetResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpRsetResult::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return SmtpRsetResult::Err(SmtpRsetError::Eof),
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
                    let response = response.into_static();
                    if response.code == ReplyCode::OK {
                        SmtpRsetResult::Ok
                    } else {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        SmtpRsetResult::Err(SmtpRsetError::Rejected { code, message })
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpRsetResult::Err(SmtpRsetError::ParseResponse(reason))
                }
            };
        }
    }
}
