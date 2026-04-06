//! I/O-free coroutine to send SMTP HELO command.
//!
//! HELO is the legacy SMTP greeting command. Prefer
//! [`crate::rfc5321::ehlo`] (`EHLO`) for any modern server. Fall back
//! to HELO only when the server rejects EHLO with 500 or 502.

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
    rfc5321::types::{domain::Domain, reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
    write::*,
};

/// The HELO command (RFC 5321 §4.1.1.1).
pub struct SmtpHeloCommand<'a> {
    /// The client's domain.
    pub domain: Domain<'a>,
}

impl<'a> From<SmtpHeloCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpHeloCommand<'a>) -> Vec<u8> {
        let mut buf = String::new();
        buf.push_str("HELO ");
        buf.push_str(&cmd.domain.to_string());
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

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
    Ok,
    Io { input: SocketInput },
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
        trace!("sending HELO command");

        Self {
            state: State::Write(SmtpWrite::new(SmtpHeloCommand {
                domain: domain.into_static(),
            })),
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
                        let err = err.into();
                        return SmtpHeloResult::Err { err };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpHeloResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpHeloResult::Err { err };
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
                                }

                                let message = response.text().to_string();
                                let code = response.code.code();
                                let err = SmtpHeloError::Rejected { code, message };
                                return SmtpHeloResult::Err { err };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpHeloError::ParseResponse(reason);
                                return SmtpHeloResult::Err { err };
                            }
                        }
                    }
                },
            }
        }
    }
}
