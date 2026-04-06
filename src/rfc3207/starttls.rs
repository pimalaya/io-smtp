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
    rfc5321::types::{command::Command, reply_code::ReplyCode},
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpStartTlsError {
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("STARTTLS rejected by server: {0}")]
    Rejected(String),
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
        let encoded = Command::StartTls.to_bytes();
        trace!("STARTTLS command to send: {}", escape_byte_string(&encoded));

        Self {
            state: State::Write(SmtpWrite::new(encoded)),
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
                        self.buffer.extend_from_slice(&bytes);

                        let Some(newline_pos) = self.buffer.iter().position(|&b| b == b'\n') else {
                            self.state = State::Read(SmtpRead::new());
                            continue;
                        };

                        let response_line = &self.buffer[..=newline_pos];
                        trace!("STARTTLS response: {}", escape_byte_string(response_line));

                        if response_line.len() >= 3 {
                            if let Ok(reply_code) = ReplyCode::parse(&response_line[..3]) {
                                if reply_code == ReplyCode::SERVICE_READY {
                                    return SmtpStartTlsResult::Ok;
                                } else {
                                    let msg =
                                        String::from_utf8_lossy(response_line).trim().to_string();
                                    return SmtpStartTlsResult::Err {
                                        err: SmtpStartTlsError::Rejected(msg),
                                    };
                                }
                            }
                        }

                        let msg = String::from_utf8_lossy(response_line).trim().to_string();
                        return SmtpStartTlsResult::Err {
                            err: SmtpStartTlsError::Rejected(msg),
                        };
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
