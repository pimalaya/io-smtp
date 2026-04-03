//! I/O-free coroutine to send SMTP RSET command.

use bounded_static::IntoBoundedStatic;
use io_socket::{
    coroutines::{read::ReadSocketError, write::WriteSocketError},
    io::{SocketInput, SocketOutput},
};
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::{command::Command, reply_code::ReplyCode, response::Response},
    send_bytes::{SmtpBytesSend, SmtpBytesSendResult},
    utils::escape_byte_string,
};

/// Errors that can occur during RSET.
#[derive(Debug, Error)]
pub enum SmtpRsetError {
    #[error("RSET rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Write RSET command error")]
    Write(#[from] WriteSocketError),
    #[error("Write RSET command error (unexpected EOF)")]
    WriteEof,
    #[error("Read RSET response error")]
    Read(#[from] ReadSocketError),
    #[error("Read RSET response error (unexpected EOF)")]
    ReadEof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpRsetResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpRsetError },
}

/// I/O-free coroutine to send SMTP RSET command.
///
/// RSET aborts the current mail transaction and returns to Ready state.
pub struct SmtpRset {
    io: SmtpBytesSend,
    buffer: Vec<u8>,
}

impl SmtpRset {
    /// Creates a new RSET coroutine.
    pub fn new() -> Self {
        let bytes = Command::Rset.to_bytes();
        trace!("command to send: {}", escape_byte_string(&bytes));
        Self {
            io: SmtpBytesSend::new(bytes),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpRsetResult {
        loop {
            match self.io.resume(arg.take()) {
                SmtpBytesSendResult::Io { input } => return SmtpRsetResult::Io { input },
                SmtpBytesSendResult::WriteErr { err } => {
                    return SmtpRsetResult::Err {
                        err: SmtpRsetError::Write(err),
                    };
                }
                SmtpBytesSendResult::WriteEof => {
                    return SmtpRsetResult::Err {
                        err: SmtpRsetError::WriteEof,
                    };
                }
                SmtpBytesSendResult::ReadErr { err } => {
                    return SmtpRsetResult::Err {
                        err: SmtpRsetError::Read(err),
                    };
                }
                SmtpBytesSendResult::ReadEof => {
                    return SmtpRsetResult::Err {
                        err: SmtpRsetError::ReadEof,
                    };
                }
                SmtpBytesSendResult::Ok { bytes } => {
                    trace!("read SMTP bytes: {}", escape_byte_string(&bytes));
                    self.buffer.extend_from_slice(&bytes);

                    if !Response::is_complete(&self.buffer) {
                        self.io = SmtpBytesSend::new(vec![]);
                        continue;
                    }

                    match Response::parse(&self.buffer) {
                        Ok(response) => {
                            let response = response.into_static();
                            if response.code == ReplyCode::OK {
                                return SmtpRsetResult::Ok;
                            } else {
                                let message = response.text().to_string();
                                return SmtpRsetResult::Err {
                                    err: SmtpRsetError::Rejected {
                                        code: response.code.code(),
                                        message,
                                    },
                                };
                            }
                        }
                        Err(errors) => {
                            let reason = errors
                                .iter()
                                .map(|e| e.to_string())
                                .collect::<Vec<_>>()
                                .join("; ");
                            return SmtpRsetResult::Err {
                                err: SmtpRsetError::ParseResponse(reason),
                            };
                        }
                    }
                }
            }
        }
    }
}
