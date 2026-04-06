//! I/O-free coroutine to send SMTP EHLO command.

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
    read::*,
    rfc5321::types::{ehlo_domain::EhloDomain, ehlo_response::EhloResponse},
    utils::escape_byte_string,
    write::*,
};

/// The EHLO command (RFC 5321 §4.1.1.1).
pub struct SmtpEhloCommand<'a> {
    /// The client's domain or address literal.
    pub domain: EhloDomain<'a>,
}

impl<'a> From<SmtpEhloCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpEhloCommand<'a>) -> Vec<u8> {
        let mut buf = String::from("EHLO ");
        buf.push_str(&cmd.domain.to_string());
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpEhloError {
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates its progression.
pub enum SmtpEhloResult {
    Ok {
        /// Raw capability strings from the EHLO response (e.g. `"AUTH
        /// PLAIN LOGIN"`, `"SIZE 10240000"`).  Each entry is the full
        /// capability line after the initial domain/greeting line.
        /// Parse mechanism-specific parameters using the relevant RFC
        /// module.
        capabilities: Vec<Cow<'static, str>>,
    },
    Io {
        input: SocketInput,
    },
    Err {
        err: SmtpEhloError,
    },
}

enum State {
    Write(SmtpWrite),
    Read(SmtpRead),
}

/// I/O-free coroutine to send SMTP EHLO command.
pub struct SmtpEhlo {
    state: State,
    buffer: Vec<u8>,
}

impl SmtpEhlo {
    /// Creates a new coroutine.
    pub fn new(domain: EhloDomain<'_>) -> Self {
        trace!("sending EHLO command");

        Self {
            state: State::Write(SmtpWrite::new(SmtpEhloCommand { domain })),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpEhloResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => return SmtpEhloResult::Io { input },
                    SmtpWriteResult::Err { err } => {
                        let err = err.into();
                        return SmtpEhloResult::Err { err };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpEhloResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpEhloResult::Err { err };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !EhloResponse::is_complete(&self.buffer) {
                            self.state = State::Read(SmtpRead::new());
                            continue;
                        }

                        match EhloResponse::parse(&self.buffer) {
                            Ok(response) => {
                                let capabilities = response.into_static().capabilities;
                                return SmtpEhloResult::Ok { capabilities };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpEhloError::ParseResponse(reason);
                                return SmtpEhloResult::Err { err };
                            }
                        }
                    }
                },
            }
        }
    }
}
