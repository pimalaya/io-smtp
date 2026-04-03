//! I/O-free coroutine to read the greeting from an SMTP server.

use bounded_static::IntoBoundedStatic;
use io_socket::{
    coroutines::read::ReadSocketError,
    io::{SocketInput, SocketOutput},
};
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::greeting::Greeting,
    send_bytes::{SmtpBytesSend, SmtpBytesSendResult},
    utils::escape_byte_string,
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum GetSmtpGreetingError {
    #[error("Read greeting from SMTP socket error")]
    Read(#[from] ReadSocketError),
    #[error("Read greeting from SMTP socket error (unexpected EOF)")]
    ReadEof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates its progression.
pub enum GetSmtpGreetingResult {
    Io { input: SocketInput },
    Ok { greeting: Greeting<'static> },
    Err { err: GetSmtpGreetingError },
}

/// I/O-free coroutine to read the greeting from an SMTP server.
pub struct GetSmtpGreeting {
    io: SmtpBytesSend,
    buffer: Vec<u8>,
}

impl GetSmtpGreeting {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        Self {
            io: SmtpBytesSend::new(vec![]),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> GetSmtpGreetingResult {
        loop {
            match self.io.resume(arg.take()) {
                SmtpBytesSendResult::Io { input } => {
                    return GetSmtpGreetingResult::Io { input };
                }
                SmtpBytesSendResult::WriteErr { .. } => unreachable!(),
                SmtpBytesSendResult::WriteEof => unreachable!(),
                SmtpBytesSendResult::ReadErr { err } => {
                    return GetSmtpGreetingResult::Err {
                        err: GetSmtpGreetingError::Read(err),
                    };
                }
                SmtpBytesSendResult::ReadEof => {
                    return GetSmtpGreetingResult::Err {
                        err: GetSmtpGreetingError::ReadEof,
                    };
                }
                SmtpBytesSendResult::Ok { bytes } => {
                    trace!("read SMTP bytes: {}", escape_byte_string(&bytes));
                    self.buffer.extend_from_slice(&bytes);

                    if !Greeting::is_complete(&self.buffer) {
                        self.io = SmtpBytesSend::new(vec![]);
                        continue;
                    }

                    return match Greeting::parse(&self.buffer) {
                        Ok(greeting) => GetSmtpGreetingResult::Ok {
                            greeting: greeting.into_static(),
                        },
                        Err(errors) => {
                            let reason = errors
                                .iter()
                                .map(|e| e.to_string())
                                .collect::<Vec<_>>()
                                .join("; ");

                            GetSmtpGreetingResult::Err {
                                err: GetSmtpGreetingError::ParseResponse(reason),
                            }
                        }
                    };
                }
            }
        }
    }
}
