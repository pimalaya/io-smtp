//! I/O-free coroutine to read the greeting from an SMTP server.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use thiserror::Error;

use crate::{rfc5321::types::greeting::Greeting, utils::escape_byte_string};

/// Output of [`SmtpClientStd::greeting`]: the parsed greeting line plus
/// any bytes read past it that the caller may need to re-feed.
///
/// [`SmtpClientStd::greeting`]: crate::client::SmtpClientStd::greeting
pub type SmtpGreetingOutput = (Greeting<'static>, Vec<u8>);

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum GetSmtpGreetingError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Result returned by [`GetSmtpGreeting::resume`].
#[derive(Debug)]
pub enum GetSmtpGreetingResult {
    Ok {
        greeting: Greeting<'static>,
        remaining: Vec<u8>,
    },
    WantsRead,
    Err(GetSmtpGreetingError),
}

/// I/O-free coroutine to read the greeting from an SMTP server.
#[derive(Debug, Default)]
pub struct GetSmtpGreeting {
    wants_read: bool,
    buf: Vec<u8>,
}

impl GetSmtpGreeting {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advances the coroutine.
    ///
    /// Pass [`None`] when there is no data to provide (initial call).
    /// Pass `Some(data)` with bytes read from the socket after a
    /// [`GetSmtpGreetingResult::WantsRead`]. Pass `Some(&[])` to
    /// signal EOF.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> GetSmtpGreetingResult {
        loop {
            if mem::take(&mut self.wants_read) {
                return GetSmtpGreetingResult::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return GetSmtpGreetingResult::Err(GetSmtpGreetingError::Eof),
                Some(data) => {
                    trace!("read SMTP bytes: {}", escape_byte_string(data));
                    self.buf.extend_from_slice(data);
                }
                None => {}
            }

            if !Greeting::is_complete(&self.buf) {
                self.wants_read = true;
                continue;
            }

            return match Greeting::parse(&self.buf) {
                Ok(greeting) => {
                    let greeting = greeting.into_static();
                    let _ = mem::take(&mut self.buf);
                    GetSmtpGreetingResult::Ok {
                        greeting,
                        remaining: Vec::new(),
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    GetSmtpGreetingResult::Err(GetSmtpGreetingError::ParseResponse(reason))
                }
            };
        }
    }
}
