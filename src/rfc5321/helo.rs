//! I/O-free coroutine to send SMTP HELO command.
//!
//! HELO is the legacy SMTP greeting command. Prefer [`crate::rfc5321::ehlo`]
//! (`EHLO`) for any modern server. Fall back to HELO only when the server
//! rejects EHLO with 500 or 502.

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
    rfc5321::types::{command::Command, domain::Domain, reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpHeloError {
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("HELO rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Output emitted when the coroutine terminates its progression.
pub enum SmtpHeloResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpHeloError },
}

enum State {
    Write(SmtpWrite),
    Read(SmtpRead),
}

/// I/O-free coroutine to send SMTP HELO command.
///
/// HELO is the legacy handshake. It does not negotiate extensions. If the
/// server supports ESMTP, use [`crate::rfc5321::ehlo::SmtpEhlo`] instead.
pub struct SmtpHelo {
    state: State,
    buffer: Vec<u8>,
}

impl SmtpHelo {
    /// Creates a new coroutine.
    pub fn new(domain: Domain<'_>) -> Self {
        let encoded = Command::Helo {
            domain: domain.into_static(),
        }
        .to_bytes();
        trace!("HELO command to send: {}", escape_byte_string(&encoded));

        Self {
            state: State::Write(SmtpWrite::new(encoded)),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpHeloResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpHeloResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        return SmtpHeloResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpHeloResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpHeloResult::Err { err: err.into() };
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
                                if response.code == ReplyCode::OK {
                                    return SmtpHeloResult::Ok;
                                } else {
                                    let message = response.text().to_string();
                                    return SmtpHeloResult::Err {
                                        err: SmtpHeloError::Rejected {
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
                                return SmtpHeloResult::Err {
                                    err: SmtpHeloError::ParseResponse(reason),
                                };
                            }
                        }
                    }
                },
            }
        }
    }
}
