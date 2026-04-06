//! I/O-free coroutine to perform SMTP STARTTLS negotiation.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use thiserror::Error;

use crate::{
    read::{SmtpRead, SmtpReadError, SmtpReadResult},
    rfc5321::types::{reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// The STARTTLS command (RFC 3207).
pub struct SmtpStartTlsCommand;

impl From<SmtpStartTlsCommand> for Vec<u8> {
    fn from(_: SmtpStartTlsCommand) -> Vec<u8> {
        b"STARTTLS\r\n".to_vec()
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpStartTlsError {
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("STARTTLS rejected by server: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Output emitted when the coroutine terminates its progression.
#[derive(Debug)]
pub enum SmtpStartTlsResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpStartTlsError },
}

enum State {
    Write(SmtpWrite),
    Read(SmtpRead),
}

/// I/O-free coroutine to perform SMTP STARTTLS negotiation.
pub struct SmtpStartTls {
    state: State,
    buffer: Vec<u8>,
}

impl SmtpStartTls {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        trace!("sending STARTTLS command");

        Self {
            state: State::Write(SmtpWrite::new(SmtpStartTlsCommand)),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpStartTlsResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpStartTlsResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        return SmtpStartTlsResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpStartTlsResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpStartTlsResult::Err { err: err.into() };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::Read(SmtpRead::new());
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Ok(response) => {
                                if response.code == ReplyCode::SERVICE_READY {
                                    return SmtpStartTlsResult::Ok;
                                } else {
                                    let message = response.text().to_string();
                                    return SmtpStartTlsResult::Err {
                                        err: SmtpStartTlsError::Rejected {
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
                                return SmtpStartTlsResult::Err {
                                    err: SmtpStartTlsError::ParseResponse(reason),
                                };
                            }
                        }
                    }
                },
            }
        }
    }
}

impl Default for SmtpStartTls {
    fn default() -> Self {
        Self::new()
    }
}
