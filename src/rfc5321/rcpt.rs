//! I/O-free coroutine to send SMTP RCPT TO command.

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
        command::Command, forward_path::ForwardPath, parameter::Parameter, reply_code::ReplyCode,
        response::Response,
    },
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// Errors that can occur during RCPT TO.
#[derive(Debug, Error)]
pub enum SmtpRcptError {
    #[error("RCPT TO rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpRcptResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpRcptError },
}

enum State {
    Write(SmtpWrite),
    Read(SmtpRead),
}

/// I/O-free coroutine to send SMTP RCPT TO command.
pub struct SmtpRcpt {
    state: State,
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
            state: State::Write(SmtpWrite::new(bytes)),
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
            state: State::Write(SmtpWrite::new(bytes)),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpRcptResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpRcptResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        return SmtpRcptResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpRcptResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpRcptResult::Err { err: err.into() };
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
                },
            }
        }
    }
}
