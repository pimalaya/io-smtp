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
    read::*,
    rfc5321::types::{
        forward_path::ForwardPath, parameter::Parameter, reply_code::ReplyCode, response::Response,
    },
    utils::escape_byte_string,
    write::*,
};

/// The RCPT TO command (RFC 5321 §4.1.1.3).
pub struct SmtpRcptCommand<'a> {
    /// The recipient's forward path.
    pub forward_path: ForwardPath<'a>,
    /// Optional ESMTP parameters.
    pub parameters: Vec<Parameter<'a>>,
}

impl<'a> From<SmtpRcptCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpRcptCommand<'a>) -> Vec<u8> {
        let mut buf = String::new();
        buf.push_str("RCPT TO:");
        buf.push_str(&cmd.forward_path.to_string());
        for p in cmd.parameters {
            buf.push(' ');
            buf.push_str(&p.to_string());
        }
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

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
    Ok,
    Io { input: SocketInput },
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
        trace!("sending RCPT TO command");
        Self {
            state: State::Write(SmtpWrite::new(SmtpRcptCommand {
                forward_path,
                parameters: Vec::new(),
            })),
            buffer: Vec::new(),
        }
    }

    /// Creates a new RCPT TO coroutine with parameters.
    pub fn with_params(forward_path: ForwardPath<'_>, parameters: Vec<Parameter<'_>>) -> Self {
        trace!("sending RCPT TO command with parameters");
        Self {
            state: State::Write(SmtpWrite::new(SmtpRcptCommand {
                forward_path,
                parameters,
            })),
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
                        let err = err.into();
                        return SmtpRcptResult::Err { err };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpRcptResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpRcptResult::Err { err };
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
                                }

                                let message = response.text().to_string();
                                let code = response.code.code();
                                let err = SmtpRcptError::Rejected { code, message };
                                return SmtpRcptResult::Err { err };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpRcptError::ParseResponse(reason);
                                return SmtpRcptResult::Err { err };
                            }
                        }
                    }
                },
            }
        }
    }
}
