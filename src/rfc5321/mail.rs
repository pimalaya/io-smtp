//! I/O-free coroutine to send SMTP MAIL FROM command.

use bounded_static::IntoBoundedStatic;
use io_stream::{
    coroutines::{read::ReadStreamError, write::WriteStreamError},
    io::StreamIo,
};
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::{
        command::Command, parameter::Parameter, reply_code::ReplyCode, response::Response,
        reverse_path::ReversePath,
    },
    send_bytes::{SmtpBytesSend, SmtpBytesSendResult},
    utils::escape_byte_string,
};

/// Errors that can occur during MAIL FROM.
#[derive(Debug, Error)]
pub enum SmtpMailError {
    #[error("MAIL FROM rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Write MAIL FROM command error")]
    Write(#[from] WriteStreamError),
    #[error("Write MAIL FROM command error (unexpected EOF)")]
    WriteEof,
    #[error("Read MAIL FROM response error")]
    Read(#[from] ReadStreamError),
    #[error("Read MAIL FROM response error (unexpected EOF)")]
    ReadEof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpMailResult {
    Io { io: StreamIo },
    Ok,
    Err { err: SmtpMailError },
}

/// I/O-free coroutine to send SMTP MAIL FROM command.
pub struct SmtpMail {
    io: SmtpBytesSend,
    buffer: Vec<u8>,
}

impl SmtpMail {
    /// Creates a new MAIL FROM coroutine.
    pub fn new(reverse_path: ReversePath<'_>) -> Self {
        let bytes = Command::Mail {
            reverse_path,
            parameters: Vec::new(),
        }
        .to_bytes();
        trace!("command to send: {}", escape_byte_string(&bytes));
        Self {
            io: SmtpBytesSend::new(bytes),
            buffer: Vec::new(),
        }
    }

    /// Creates a new MAIL FROM coroutine with parameters.
    pub fn with_params(reverse_path: ReversePath<'_>, parameters: Vec<Parameter<'_>>) -> Self {
        let bytes = Command::Mail {
            reverse_path,
            parameters,
        }
        .to_bytes();
        trace!("command to send: {}", escape_byte_string(&bytes));
        Self {
            io: SmtpBytesSend::new(bytes),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpMailResult {
        loop {
            match self.io.resume(arg.take()) {
                SmtpBytesSendResult::Io { io } => return SmtpMailResult::Io { io },
                SmtpBytesSendResult::WriteErr { err } => {
                    return SmtpMailResult::Err {
                        err: SmtpMailError::Write(err),
                    }
                }
                SmtpBytesSendResult::WriteEof => {
                    return SmtpMailResult::Err {
                        err: SmtpMailError::WriteEof,
                    }
                }
                SmtpBytesSendResult::ReadErr { err } => {
                    return SmtpMailResult::Err {
                        err: SmtpMailError::Read(err),
                    }
                }
                SmtpBytesSendResult::ReadEof => {
                    return SmtpMailResult::Err {
                        err: SmtpMailError::ReadEof,
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
                                return SmtpMailResult::Ok;
                            } else {
                                let message = response.text().to_string();
                                return SmtpMailResult::Err {
                                    err: SmtpMailError::Rejected {
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
                            return SmtpMailResult::Err {
                                err: SmtpMailError::ParseResponse(reason),
                            };
                        }
                    }
                }
            }
        }
    }
}
