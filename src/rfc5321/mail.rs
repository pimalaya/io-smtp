//! I/O-free coroutine to send SMTP MAIL FROM command.

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
    rfc5321::types::{
        command::Command, parameter::Parameter, reply_code::ReplyCode, response::Response,
        reverse_path::ReversePath,
    },
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// Errors that can occur during MAIL FROM.
#[derive(Debug, Error)]
pub enum SmtpMailError {
    #[error("MAIL FROM rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpMailResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpMailError },
}

enum State {
    Write(SmtpWrite),
    Read(SmtpRead),
}

/// I/O-free coroutine to send SMTP MAIL FROM command.
pub struct SmtpMail {
    state: State,
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
            state: State::Write(SmtpWrite::new(bytes)),
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
            state: State::Write(SmtpWrite::new(bytes)),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpMailResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpMailResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        return SmtpMailResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpMailResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpMailResult::Err { err: err.into() };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read SMTP bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::Read(SmtpRead::new());
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
                },
            }
        }
    }
}
