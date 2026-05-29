//! I/O-free coroutine to send SMTP QUIT command.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::trace;
use thiserror::Error;

use crate::{
    coroutine::{SmtpCoroutine, SmtpCoroutineState},
    rfc5321::types::{reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
};

/// The QUIT command (RFC 5321 §4.1.1.10).
pub struct SmtpQuitCommand;

impl From<SmtpQuitCommand> for Vec<u8> {
    fn from(_: SmtpQuitCommand) -> Vec<u8> {
        b"QUIT\r\n".to_vec()
    }
}

/// Errors that can occur during QUIT.
#[derive(Debug, Error)]
pub enum SmtpQuitError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("QUIT rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// I/O-free coroutine to send SMTP QUIT command.
pub struct SmtpQuit {
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl Default for SmtpQuit {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpQuit {
    /// Creates a new QUIT coroutine.
    pub fn new() -> Self {
        trace!("sending QUIT command");

        Self {
            wants_read: false,
            wants_write: Some(SmtpQuitCommand.into()),
            buf: Vec::new(),
        }
    }
}

impl SmtpCoroutine for SmtpQuit {
    type Output = ();
    type Error = SmtpQuitError;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Output, Self::Error> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpCoroutineState::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return SmtpCoroutineState::Err(SmtpQuitError::Eof),
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
                    if response.code == ReplyCode::SERVICE_CLOSING {
                        SmtpCoroutineState::Done(())
                    } else {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        SmtpCoroutineState::Err(SmtpQuitError::Rejected { code, message })
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpCoroutineState::Err(SmtpQuitError::ParseResponse(reason))
                }
            };
        }
    }
}
