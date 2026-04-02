//! I/O-free coroutine to send SMTP RCPT TO command.

use bounded_static::IntoBoundedStatic;
use io_stream::{
    coroutines::{read::ReadStreamError, write::WriteStreamError},
    io::StreamIo,
};
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::{
        command::Command, forward_path::ForwardPath, parameter::Parameter, reply_code::ReplyCode,
        response::Response,
    },
    send_bytes::{SmtpBytesSend, SmtpBytesSendResult},
    utils::escape_byte_string,
};

/// Errors that can occur during RCPT TO.
#[derive(Debug, Error)]
pub enum SmtpRcptError {
    #[error("RCPT TO rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Write RCPT TO command error")]
    Write(#[from] WriteStreamError),
    #[error("Write RCPT TO command error (unexpected EOF)")]
    WriteEof,
    #[error("Read RCPT TO response error")]
    Read(#[from] ReadStreamError),
    #[error("Read RCPT TO response error (unexpected EOF)")]
    ReadEof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpRcptResult {
    Io { io: StreamIo },
    Ok,
    Err { err: SmtpRcptError },
}

/// I/O-free coroutine to send SMTP RCPT TO command.
pub struct SmtpRcpt {
    io: SmtpBytesSend,
    buffer: Vec<u8>,
}

impl SmtpRcpt {
    /// Creates a new RCPT TO coroutine.
    pub fn new(forward_path: ForwardPath<'_>) -> Self {
        let bytes = Command::Rcpt {
            forward_path,
            parameters: Vec::new(),
        }
        .to_bytes();
        trace!("command to send: {}", escape_byte_string(&bytes));
        Self {
            io: SmtpBytesSend::new(bytes),
            buffer: Vec::new(),
        }
    }

    /// Creates a new RCPT TO coroutine with parameters.
    pub fn with_params(forward_path: ForwardPath<'_>, parameters: Vec<Parameter<'_>>) -> Self {
        let bytes = Command::Rcpt {
            forward_path,
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
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpRcptResult {
        loop {
            match self.io.resume(arg.take()) {
                SmtpBytesSendResult::Io { io } => return SmtpRcptResult::Io { io },
                SmtpBytesSendResult::WriteErr { err } => {
                    return SmtpRcptResult::Err {
                        err: SmtpRcptError::Write(err),
                    }
                }
                SmtpBytesSendResult::WriteEof => {
                    return SmtpRcptResult::Err {
                        err: SmtpRcptError::WriteEof,
                    }
                }
                SmtpBytesSendResult::ReadErr { err } => {
                    return SmtpRcptResult::Err {
                        err: SmtpRcptError::Read(err),
                    }
                }
                SmtpBytesSendResult::ReadEof => {
                    return SmtpRcptResult::Err {
                        err: SmtpRcptError::ReadEof,
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
                                return SmtpRcptResult::Ok;
                            } else {
                                let message = response.text().to_string();
                                return SmtpRcptResult::Err {
                                    err: SmtpRcptError::Rejected {
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
                            return SmtpRcptResult::Err {
                                err: SmtpRcptError::ParseResponse(reason),
                            };
                        }
                    }
                }
            }
        }
    }
}
