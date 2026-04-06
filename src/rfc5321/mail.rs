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
    read::*,
    rfc5321::types::{
        parameter::Parameter, reply_code::ReplyCode, response::Response, reverse_path::ReversePath,
    },
    utils::escape_byte_string,
    write::*,
};

/// The MAIL FROM command (RFC 5321 §4.1.1.2).
pub struct SmtpMailCommand<'a> {
    /// The sender's reverse path (can be null `<>`).
    pub reverse_path: ReversePath<'a>,
    /// Optional ESMTP parameters (e.g., SIZE, BODY).
    pub parameters: Vec<Parameter<'a>>,
}

impl<'a> From<SmtpMailCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpMailCommand<'a>) -> Vec<u8> {
        let mut buf = String::new();
        buf.push_str("MAIL FROM:");
        buf.push_str(&cmd.reverse_path.to_string());
        for p in cmd.parameters {
            buf.push(' ');
            buf.push_str(&p.to_string());
        }
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

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
    Ok,
    Io { input: SocketInput },
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
        trace!("sending MAIL FROM command");
        Self {
            state: State::Write(SmtpWrite::new(SmtpMailCommand {
                reverse_path,
                parameters: Vec::new(),
            })),
            buffer: Vec::new(),
        }
    }

    /// Creates a new MAIL FROM coroutine with parameters.
    pub fn with_params(reverse_path: ReversePath<'_>, parameters: Vec<Parameter<'_>>) -> Self {
        trace!("sending MAIL FROM command with parameters");
        Self {
            state: State::Write(SmtpWrite::new(SmtpMailCommand {
                reverse_path,
                parameters,
            })),
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
                        let err = err.into();
                        return SmtpMailResult::Err { err };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpMailResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpMailResult::Err { err };
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
                                }

                                let message = response.text().to_string();
                                let code = response.code.code();
                                let err = SmtpMailError::Rejected { code, message };
                                return SmtpMailResult::Err { err };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpMailError::ParseResponse(reason);
                                return SmtpMailResult::Err { err };
                            }
                        }
                    }
                },
            }
        }
    }
}
