//! I/O-free coroutine to read the greeting from an SMTP server.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use thiserror::Error;

use crate::{read::*, rfc5321::types::greeting::Greeting, utils::escape_byte_string};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum GetSmtpGreetingError {
    #[error(transparent)]
    Io(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Output emitted when the coroutine terminates its progression.
pub enum GetSmtpGreetingResult {
    Ok { greeting: Greeting<'static> },
    Io { input: SocketInput },
    Err { err: GetSmtpGreetingError },
}

/// I/O-free coroutine to read the greeting from an SMTP server.
pub struct GetSmtpGreeting {
    io: SmtpRead,
    buffer: Vec<u8>,
}

impl GetSmtpGreeting {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        Self {
            io: SmtpRead::new(),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> GetSmtpGreetingResult {
        loop {
            match self.io.resume(arg.take()) {
                SmtpReadResult::Io { input } => return GetSmtpGreetingResult::Io { input },
                SmtpReadResult::Err { err } => {
                    let err = err.into();
                    return GetSmtpGreetingResult::Err { err };
                }
                SmtpReadResult::Ok { bytes } => {
                    trace!("read SMTP bytes: {}", escape_byte_string(&bytes));
                    self.buffer.extend_from_slice(&bytes);

                    if !Greeting::is_complete(&self.buffer) {
                        self.io = SmtpRead::new();
                        continue;
                    }

                    match Greeting::parse(&self.buffer) {
                        Ok(greeting) => {
                            return GetSmtpGreetingResult::Ok {
                                greeting: greeting.into_static(),
                            };
                        }
                        Err(errors) => {
                            let reason = errors
                                .iter()
                                .map(|e| e.to_string())
                                .collect::<Vec<_>>()
                                .join("; ");

                            let err = GetSmtpGreetingError::ParseResponse(reason);
                            return GetSmtpGreetingResult::Err { err };
                        }
                    }
                }
            }
        }
    }
}

impl Default for GetSmtpGreeting {
    fn default() -> Self {
        Self::new()
    }
}
