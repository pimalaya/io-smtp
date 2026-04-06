//! I/O-free coroutine to send SMTP NOOP command.

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};
use bounded_static::IntoBoundedStatic;
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use thiserror::Error;

use crate::{
    read::{SmtpRead, SmtpReadError, SmtpReadResult},
    rfc5321::types::{reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// The NOOP command (RFC 5321 §4.1.1.9).
pub struct SmtpNoopCommand<'a> {
    /// Optional string argument (ignored by server).
    pub string: Option<Cow<'a, str>>,
}

impl<'a> From<SmtpNoopCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpNoopCommand<'a>) -> Vec<u8> {
        let mut buf = String::new();
        buf.push_str("NOOP");
        if let Some(s) = cmd.string {
            buf.push(' ');
            buf.push_str(&s);
        }
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

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
        trace!("sending NOOP command");
        Self {
            state: State::Write(SmtpWrite::new(SmtpNoopCommand { string: None })),
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
