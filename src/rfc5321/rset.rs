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
    read::*,
    rfc5321::types::{reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
    write::*,
};

/// The RSET command (RFC 5321 §4.1.1.5).
pub struct SmtpRsetCommand;

impl From<SmtpRsetCommand> for Vec<u8> {
    fn from(_: SmtpRsetCommand) -> Vec<u8> {
        b"RSET\r\n".to_vec()
    }
}

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
    Ok,
    Io { input: SocketInput },
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
        trace!("sending RSET command");
        Self {
            state: State::Write(SmtpWrite::new(SmtpRsetCommand)),
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
                        let err = err.into();
                        return SmtpRsetResult::Err { err };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpRsetResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpRsetResult::Err { err };
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
                                }

                                let message = response.text().to_string();
                                let code = response.code.code();
                                let err = SmtpRsetError::Rejected { code, message };
                                return SmtpRsetResult::Err { err };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpRsetError::ParseResponse(reason);
                                return SmtpRsetResult::Err { err };
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
