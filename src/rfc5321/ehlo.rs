//! I/O-free coroutine to send SMTP EHLO command.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use bounded_static::IntoBoundedStatic;
use hashbrown::HashSet;
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use thiserror::Error;

use crate::{
    read::{SmtpRead, SmtpReadError, SmtpReadResult},
    rfc5321::types::{
        command::Command,
        ehlo_domain::EhloDomain,
        ehlo_response::{Capability, EhloResponse},
    },
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

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
    Io {
        input: SocketInput,
    },
    Ok {
        capabilities: HashSet<Capability<'static>>,
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
        let encoded = Command::Ehlo { domain }.to_bytes();
        trace!("EHLO command to send: {}", escape_byte_string(&encoded));

        Self {
            state: State::Write(SmtpWrite::new(encoded)),
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
                        return SmtpEhloResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => return SmtpEhloResult::Io { input },
                    SmtpReadResult::Err { err } => {
                        return SmtpEhloResult::Err { err: err.into() };
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
                                let response = response.into_static();
                                let capabilities = response.capabilities.into_iter().collect();
                                return SmtpEhloResult::Ok { capabilities };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");
                                return SmtpEhloResult::Err {
                                    err: SmtpEhloError::ParseResponse(reason),
                                };
                            }
                        }
                    }
                },
            }
        }
    }
}
