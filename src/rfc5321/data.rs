//! I/O-free coroutine to send SMTP DATA command and message body.

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

/// Errors that can occur during DATA.
#[derive(Debug, Error)]
pub enum SmtpDataError {
    #[error("Write DATA command error")]
    WriteCommand(#[source] WriteSocketError),
    #[error("Write DATA command error (unexpected EOF)")]
    WriteCommandEof,
    #[error("Write message body error")]
    WriteBody(#[source] WriteSocketError),
    #[error("Write message body error (unexpected EOF)")]
    WriteBodyEof,
    #[error("Read response error")]
    Read(#[from] ReadSocketError),
    #[error("Read response error (unexpected EOF)")]
    ReadEof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("DATA rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Output emitted when the coroutine terminates.
pub enum SmtpDataResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpDataError },
}

enum DataState {
    /// Send DATA command, then read 354 response
    Command(SmtpBytesSend),
    /// Send message body, then read final 250 response
    Body(SmtpBytesSend),
}

/// I/O-free coroutine to send SMTP DATA command and message body.
///
/// The message body should be the raw email content. This coroutine handles
/// dot-stuffing (prepending dots to lines starting with dots) automatically.
pub struct SmtpData {
    state: DataState,
    message_body: Option<Vec<u8>>,
    buffer: Vec<u8>,
}

impl SmtpData {
    /// Creates a new DATA coroutine.
    ///
    /// The `message` should be the complete email message (headers + body).
    /// Dot-stuffing will be applied automatically.
    pub fn new(message: Vec<u8>) -> Self {
        let encoded = Command::Data.to_bytes();
        trace!("DATA command to send: {}", escape_byte_string(&encoded));

        Self {
            state: DataState::Command(SmtpBytesSend::new(encoded)),
            message_body: Some(message),
            buffer: Vec::new(),
        }
    }

    /// Apply dot-stuffing to the message body and append terminator.
    fn prepare_body(message: Vec<u8>) -> Vec<u8> {
        let mut result = Vec::with_capacity(message.len() + 5);

        // Apply dot-stuffing: lines starting with a dot get an extra dot
        let mut at_line_start = true;
        for &byte in &message {
            if at_line_start && byte == b'.' {
                result.push(b'.');
            }
            result.push(byte);
            at_line_start = byte == b'\n';
        }

        // Ensure message ends with CRLF
        if !result.ends_with(b"\r\n") {
            if result.ends_with(b"\n") {
                // Replace \n with \r\n
                result.pop();
                result.extend_from_slice(b"\r\n");
            } else if result.ends_with(b"\r") {
                result.push(b'\n');
            } else {
                result.extend_from_slice(b"\r\n");
            }
        }

        // Add terminator: CRLF.CRLF (but we already have CRLF, so just .CRLF)
        result.extend_from_slice(b".\r\n");

        result
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpDataResult {
        loop {
            match &mut self.state {
                DataState::Command(io) => match io.resume(arg.take()) {
                    SmtpBytesSendResult::Io { input } => return SmtpDataResult::Io { input },
                    SmtpBytesSendResult::WriteErr { err } => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::WriteCommand(err),
                        };
                    }
                    SmtpBytesSendResult::WriteEof => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::WriteCommandEof,
                        };
                    }
                    SmtpBytesSendResult::ReadErr { err } => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::Read(err),
                        };
                    }
                    SmtpBytesSendResult::ReadEof => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::ReadEof,
                        };
                    }
                    SmtpBytesSendResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = DataState::Command(SmtpBytesSend::new(vec![]));
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Ok(response) => {
                                let response = response.into_static();

                                // Expect 354 START_MAIL_INPUT
                                if response.code != ReplyCode::START_MAIL_INPUT {
                                    let message = response.text().to_string();
                                    return SmtpDataResult::Err {
                                        err: SmtpDataError::Rejected {
                                            code: response.code.code(),
                                            message,
                                        },
                                    };
                                }

                                // Prepare and send message body
                                let body = self.message_body.take().unwrap();
                                let prepared = Self::prepare_body(body);
                                trace!("message body prepared: {} bytes", prepared.len());

                                self.buffer.clear();
                                self.state = DataState::Body(SmtpBytesSend::new(prepared));
                                continue;
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");
                                return SmtpDataResult::Err {
                                    err: SmtpDataError::ParseResponse(reason),
                                };
                            }
                        }
                    }
                },
                DataState::Body(io) => match io.resume(arg.take()) {
                    SmtpBytesSendResult::Io { input } => return SmtpDataResult::Io { input },
                    SmtpBytesSendResult::WriteErr { err } => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::WriteBody(err),
                        };
                    }
                    SmtpBytesSendResult::WriteEof => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::WriteBodyEof,
                        };
                    }
                    SmtpBytesSendResult::ReadErr { err } => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::Read(err),
                        };
                    }
                    SmtpBytesSendResult::ReadEof => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::ReadEof,
                        };
                    }
                    SmtpBytesSendResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = DataState::Body(SmtpBytesSend::new(vec![]));
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Ok(response) => {
                                let response = response.into_static();

                                if response.code == ReplyCode::OK {
                                    return SmtpDataResult::Ok;
                                } else {
                                    let message = response.text().to_string();
                                    return SmtpDataResult::Err {
                                        err: SmtpDataError::Rejected {
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
                                return SmtpDataResult::Err {
                                    err: SmtpDataError::ParseResponse(reason),
                                };
                            }
                        }
                    }
                },
            }
        }
    }
}
