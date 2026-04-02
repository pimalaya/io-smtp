//! I/O-free coroutine to send SMTP QUIT command.

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

/// Errors that can occur during QUIT.
#[derive(Debug, Error)]
pub enum SmtpQuitError {
    #[error("QUIT rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Write QUIT command error")]
    Write(#[from] WriteStreamError),
    #[error("Write QUIT command error (unexpected EOF)")]
    WriteEof,
    #[error("Read QUIT response error")]
    Read(#[from] ReadStreamError),
    #[error("Read QUIT response error (unexpected EOF)")]
    ReadEof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpQuitResult {
    Io { io: StreamIo },
    Ok,
    Err { err: SmtpQuitError },
}

/// I/O-free coroutine to send SMTP QUIT command.
pub struct SmtpQuit {
    io: SmtpBytesSend,
    buffer: Vec<u8>,
}

impl SmtpQuit {
    /// Creates a new QUIT coroutine.
    pub fn new() -> Self {
        let bytes = Command::Quit.to_bytes();
        trace!("command to send: {}", escape_byte_string(&bytes));
        Self {
            io: SmtpBytesSend::new(bytes),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpQuitResult {
        loop {
            match self.io.resume(arg.take()) {
                SmtpBytesSendResult::Io { io } => return SmtpQuitResult::Io { io },
                SmtpBytesSendResult::WriteErr { err } => {
                    return SmtpQuitResult::Err {
                        err: SmtpQuitError::Write(err),
                    }
                }
                SmtpBytesSendResult::WriteEof => {
                    return SmtpQuitResult::Err {
                        err: SmtpQuitError::WriteEof,
                    }
                }
                SmtpBytesSendResult::ReadErr { err } => {
                    return SmtpQuitResult::Err {
                        err: SmtpQuitError::Read(err),
                    }
                }
                SmtpBytesSendResult::ReadEof => {
                    return SmtpQuitResult::Err {
                        err: SmtpQuitError::ReadEof,
                    }
                }
                SmtpBytesSendResult::Ok { bytes } => {
                    trace!("read SMTP bytes: {}", escape_byte_string(&bytes));
                    self.buffer.extend_from_slice(&bytes);

                    if !Response::is_complete(&self.buffer) {
                        self.io = SmtpBytesSend::new(vec![]);
                        continue;
                    }

                    return match Response::parse(&self.buffer) {
                        Ok(response) => {
                            if response.code == ReplyCode::SERVICE_CLOSING {
                                SmtpQuitResult::Ok
                            } else {
                                let message = response.text().to_string();

                                SmtpQuitResult::Err {
                                    err: SmtpQuitError::Rejected {
                                        code: response.code.code(),
                                        message,
                                    },
                                }
                            }
                        }
                        Err(errors) => {
                            let reason = errors
                                .iter()
                                .map(|e| e.to_string())
                                .collect::<Vec<_>>()
                                .join("; ");

                            SmtpQuitResult::Err {
                                err: SmtpQuitError::ParseResponse(reason),
                            }
                        }
                    };
                }
            }
        }
    }
}
