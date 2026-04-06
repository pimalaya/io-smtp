//! I/O-free coroutine to send SMTP DATA command and message body.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use bounded_static::IntoBoundedStatic;
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use thiserror::Error;

use crate::{
    read::{SmtpRead, SmtpReadError, SmtpReadResult},
    rfc5321::types::{command::Command, reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// Errors that can occur during DATA.
#[derive(Debug, Error)]
pub enum SmtpDataError {
    #[error("DATA command write error")]
    CommandWrite(#[source] SmtpWriteError),
    #[error("DATA command read error")]
    CommandRead(#[source] SmtpReadError),
    #[error("DATA body write error")]
    BodyWrite(#[source] SmtpWriteError),
    #[error("DATA body read error")]
    BodyRead(#[source] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("DATA command rejected: {code} {message}")]
    CommandRejected { code: u16, message: String },
    #[error("DATA body rejected: {code} {message}")]
    BodyRejected { code: u16, message: String },
}

/// Output emitted when the coroutine terminates.
pub enum SmtpDataResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpDataError },
}

enum State {
    CommandWrite(SmtpWrite),
    CommandRead(SmtpRead),
    BodyWrite(SmtpWrite),
    BodyRead(SmtpRead),
}

/// I/O-free coroutine to send SMTP DATA command and message body.
///
/// The message body should be the raw email content. This coroutine handles
/// dot-stuffing (prepending dots to lines starting with dots) automatically.
pub struct SmtpData {
    state: State,
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
            state: State::CommandWrite(SmtpWrite::new(encoded)),
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
                State::CommandWrite(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::CommandRead(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpDataResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::CommandWrite(err),
                        };
                    }
                },
                State::CommandRead(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpDataResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::CommandRead(err),
                        };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::CommandRead(SmtpRead::new());
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Ok(response) => {
                                let response = response.into_static();

                                if response.code != ReplyCode::START_MAIL_INPUT {
                                    let message = response.text().to_string();
                                    return SmtpDataResult::Err {
                                        err: SmtpDataError::CommandRejected {
                                            code: response.code.code(),
                                            message,
                                        },
                                    };
                                }

                                let body = self.message_body.take().unwrap();
                                let prepared = Self::prepare_body(body);
                                trace!("message body prepared: {} bytes", prepared.len());

                                self.buffer.clear();
                                self.state = State::BodyWrite(SmtpWrite::new(prepared));
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
                State::BodyWrite(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::BodyRead(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpDataResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::BodyWrite(err),
                        };
                    }
                },
                State::BodyRead(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpDataResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpDataResult::Err {
                            err: SmtpDataError::BodyRead(err),
                        };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::BodyRead(SmtpRead::new());
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
                                        err: SmtpDataError::BodyRejected {
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
