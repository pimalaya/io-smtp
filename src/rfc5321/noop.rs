//! I/O-free coroutine to send SMTP NOOP command.

use bounded_static::IntoBoundedStatic;
use io_stream::{
    coroutines::{read::ReadStreamError, write::WriteStreamError},
    io::StreamIo,
};
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::{command::Command, reply_code::ReplyCode, response::Response},
    send_bytes::{SmtpBytesSend, SmtpBytesSendResult},
    utils::escape_byte_string,
};

/// Errors that can occur during NOOP.
#[derive(Debug, Error)]
pub enum SmtpNoopError {
    #[error("NOOP rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Write NOOP command error")]
    Write(#[from] WriteStreamError),
    #[error("Write NOOP command error (unexpected EOF)")]
    WriteEof,
    #[error("Read NOOP response error")]
    Read(#[from] ReadStreamError),
    #[error("Read NOOP response error (unexpected EOF)")]
    ReadEof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpNoopResult {
    Ok,
    Io { io: StreamIo },
    Err { err: SmtpNoopError },
}

/// I/O-free coroutine to send SMTP NOOP command.
pub struct SmtpNoop {
    io: SmtpBytesSend,
    buffer: Vec<u8>,
}

impl SmtpNoop {
    /// Creates a new NOOP coroutine.
    pub fn new() -> Self {
        let bytes = Command::Noop { string: None }.to_bytes();
        trace!("command to send: {}", escape_byte_string(&bytes));
        Self {
            io: SmtpBytesSend::new(bytes),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpNoopResult {
        loop {
            match self.io.resume(arg.take()) {
                SmtpBytesSendResult::Io { io } => return SmtpNoopResult::Io { io },
                SmtpBytesSendResult::WriteErr { err } => {
                    return SmtpNoopResult::Err {
                        err: SmtpNoopError::Write(err),
                    }
                }
                SmtpBytesSendResult::WriteEof => {
                    return SmtpNoopResult::Err {
                        err: SmtpNoopError::WriteEof,
                    }
                }
                SmtpBytesSendResult::ReadErr { err } => {
                    return SmtpNoopResult::Err {
                        err: SmtpNoopError::Read(err),
                    }
                }
                SmtpBytesSendResult::ReadEof => {
                    return SmtpNoopResult::Err {
                        err: SmtpNoopError::ReadEof,
                    }
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
                                return SmtpNoopResult::Ok;
                            } else {
                                let message = response.text().to_string();
                                return SmtpNoopResult::Err {
                                    err: SmtpNoopError::Rejected {
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
                            return SmtpNoopResult::Err {
                                err: SmtpNoopError::ParseResponse(reason),
                            };
                        }
                    }
                }
            }
        }
    }
}
