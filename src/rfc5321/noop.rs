//! I/O-free coroutine to send SMTP NOOP command.

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

/// Errors that can occur during NOOP.
#[derive(Debug, Error)]
pub enum SmtpNoopError {
    #[error("NOOP rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpNoopResult {
    Ok,
    Io { input: SocketInput },
    Err { err: SmtpNoopError },
}

enum State {
    Write(SmtpWrite),
    Read(SmtpRead),
}

/// I/O-free coroutine to send SMTP NOOP command.
pub struct SmtpNoop {
    state: State,
    buffer: Vec<u8>,
}

impl SmtpNoop {
    /// Creates a new NOOP coroutine.
    pub fn new() -> Self {
        let bytes = Command::Noop { string: None }.to_bytes();
        trace!("command to send: {}", escape_byte_string(&bytes));
        Self {
            state: State::Write(SmtpWrite::new(bytes)),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpNoopResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpNoopResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        return SmtpNoopResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpNoopResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpNoopResult::Err { err: err.into() };
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
                },
            }
        }
    }
}

impl Default for SmtpNoop {
    fn default() -> Self {
        Self::new()
    }
}
