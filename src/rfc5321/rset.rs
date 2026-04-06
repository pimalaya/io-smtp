//! I/O-free coroutine to send SMTP RSET command.

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

/// Errors that can occur during RSET.
#[derive(Debug, Error)]
pub enum SmtpRsetError {
    #[error("RSET rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpRsetResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpRsetError },
}

enum State {
    Write(SmtpWrite),
    Read(SmtpRead),
}

/// I/O-free coroutine to send SMTP RSET command.
///
/// RSET aborts the current mail transaction and returns to Ready state.
pub struct SmtpRset {
    state: State,
    buffer: Vec<u8>,
}

impl SmtpRset {
    /// Creates a new RSET coroutine.
    pub fn new() -> Self {
        let bytes = Command::Rset.to_bytes();
        trace!("command to send: {}", escape_byte_string(&bytes));
        Self {
            state: State::Write(SmtpWrite::new(bytes)),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpRsetResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpRsetResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        return SmtpRsetResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpRsetResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpRsetResult::Err { err: err.into() };
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
                },
            }
        }
    }
}

impl Default for SmtpRset {
    fn default() -> Self {
        Self::new()
    }
}
