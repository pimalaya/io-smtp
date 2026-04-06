//! I/O-free coroutine to send SMTP QUIT command.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use thiserror::Error;

use crate::{
    read::{SmtpRead, SmtpReadError, SmtpReadResult},
    rfc5321::types::{command::Command, reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// Errors that can occur during QUIT.
#[derive(Debug, Error)]
pub enum SmtpQuitError {
    #[error("QUIT rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpQuitResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpQuitError },
}

enum State {
    Write(SmtpWrite),
    Read(SmtpRead),
}

/// I/O-free coroutine to send SMTP QUIT command.
pub struct SmtpQuit {
    state: State,
    buffer: Vec<u8>,
}

impl SmtpQuit {
    /// Creates a new QUIT coroutine.
    pub fn new() -> Self {
        let bytes = Command::Quit.to_bytes();
        trace!("command to send: {}", escape_byte_string(&bytes));
        Self {
            state: State::Write(SmtpWrite::new(bytes)),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpQuitResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpQuitResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        return SmtpQuitResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpQuitResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpQuitResult::Err { err: err.into() };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read SMTP bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::Read(SmtpRead::new());
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
                },
            }
        }
    }
}

impl Default for SmtpQuit {
    fn default() -> Self {
        Self::new()
    }
}
