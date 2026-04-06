//! I/O-free coroutine to send SMTP QUIT command.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use thiserror::Error;

use crate::{
    read::*,
    rfc5321::types::{reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
    write::*,
};

/// The QUIT command (RFC 5321 §4.1.1.10).
pub struct SmtpQuitCommand;

impl From<SmtpQuitCommand> for Vec<u8> {
    fn from(_: SmtpQuitCommand) -> Vec<u8> {
        b"QUIT\r\n".to_vec()
    }
}

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
    Ok,
    Io { input: SocketInput },
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
        trace!("sending QUIT command");
        Self {
            state: State::Write(SmtpWrite::new(SmtpQuitCommand)),
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
                        let err = err.into();
                        return SmtpQuitResult::Err { err };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpQuitResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpQuitResult::Err { err };
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
                                if response.code == ReplyCode::SERVICE_CLOSING {
                                    return SmtpQuitResult::Ok;
                                }

                                let message = response.text().to_string();
                                let code = response.code.code();
                                let err = SmtpQuitError::Rejected { code, message };
                                return SmtpQuitResult::Err { err };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpQuitError::ParseResponse(reason);
                                return SmtpQuitResult::Err { err };
                            }
                        }
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
