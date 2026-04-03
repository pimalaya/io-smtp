//! I/O-free coroutine to send SMTP EHLO command.

use std::collections::HashSet;

use bounded_static::IntoBoundedStatic;
use io_socket::{
    coroutines::{read::ReadSocketError, write::WriteSocketError},
    io::{SocketInput, SocketOutput},
};
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::{
        command::Command,
        ehlo_domain::EhloDomain,
        ehlo_response::{Capability, EhloResponse},
    },
    send_bytes::{SmtpBytesSend, SmtpBytesSendResult},
    utils::escape_byte_string,
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpEhloError {
    #[error("Write EHLO command to SMTP socket error")]
    Write(#[from] WriteSocketError),
    #[error("Write EHLO command to SMTP socket error (unexpected EOF)")]
    WriteEof,
    #[error("Read EHLO response from SMTP socket error")]
    Read(#[from] ReadSocketError),
    #[error("Read EHLO response from SMTP socket error (unexpected EOF)")]
    ReadEof,
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

/// I/O-free coroutine to send SMTP EHLO command.
pub struct SmtpEhlo {
    io: SmtpBytesSend,
    buffer: Vec<u8>,
}

impl SmtpEhlo {
    /// Creates a new coroutine.
    pub fn new(domain: EhloDomain<'_>) -> Self {
        let encoded = Command::Ehlo { domain }.to_bytes();
        trace!("EHLO command to send: {}", escape_byte_string(&encoded));

        Self {
            io: SmtpBytesSend::new(encoded),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpEhloResult {
        loop {
            match self.io.resume(arg.take()) {
                SmtpBytesSendResult::Io { input } => return SmtpEhloResult::Io { input },
                SmtpBytesSendResult::WriteErr { err } => {
                    return SmtpEhloResult::Err {
                        err: SmtpEhloError::Write(err),
                    };
                }
                SmtpBytesSendResult::WriteEof => {
                    return SmtpEhloResult::Err {
                        err: SmtpEhloError::WriteEof,
                    };
                }
                SmtpBytesSendResult::ReadErr { err } => {
                    return SmtpEhloResult::Err {
                        err: SmtpEhloError::Read(err),
                    };
                }
                SmtpBytesSendResult::ReadEof => {
                    return SmtpEhloResult::Err {
                        err: SmtpEhloError::ReadEof,
                    };
                }
                SmtpBytesSendResult::Ok { bytes } => {
                    trace!("read bytes: {}", escape_byte_string(&bytes));
                    self.buffer.extend_from_slice(&bytes);

                    if !EhloResponse::is_complete(&self.buffer) {
                        self.io = SmtpBytesSend::new(vec![]);
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
            }
        }
    }
}
