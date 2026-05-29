//! I/O-free coroutine to send SMTP NOOP command.

use core::mem;

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use thiserror::Error;

use crate::{
    coroutine::{SmtpCoroutine, SmtpCoroutineState},
    rfc5321::types::{reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
};

/// The NOOP command (RFC 5321 §4.1.1.9).
pub struct SmtpNoopCommand<'a> {
    /// Optional string argument (ignored by server).
    pub string: Option<Cow<'a, str>>,
}

impl<'a> From<SmtpNoopCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpNoopCommand<'a>) -> Vec<u8> {
        let mut buf = String::from("NOOP");

        if let Some(s) = cmd.string {
            buf.push(' ');
            buf.push_str(&s);
        }

        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Errors that can occur during NOOP.
#[derive(Debug, Error)]
pub enum SmtpNoopError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("NOOP rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// I/O-free coroutine to send SMTP NOOP command.
pub struct SmtpNoop {
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl Default for SmtpNoop {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpNoop {
    /// Creates a new NOOP coroutine.
    pub fn new() -> Self {
        trace!("sending NOOP command");

        let bytes = SmtpNoopCommand { string: None }.into();

        Self {
            wants_read: false,
            wants_write: Some(bytes),
            buf: Vec::new(),
        }
    }
}

impl SmtpCoroutine for SmtpNoop {
    type Output = ();
    type Error = SmtpNoopError;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Output, Self::Error> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpCoroutineState::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return SmtpCoroutineState::Err(SmtpNoopError::Eof),
                Some(data) => {
                    trace!("read SMTP bytes: {}", escape_byte_string(data));
                    self.buf.extend_from_slice(data);
                }
                None => {}
            }

            if !Response::is_complete(&self.buf) {
                self.wants_read = true;
                continue;
            }

            return match Response::parse(&self.buf) {
                Ok(response) => {
                    let response = response.into_static();
                    if response.code == ReplyCode::OK {
                        SmtpCoroutineState::Done(())
                    } else {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        SmtpCoroutineState::Err(SmtpNoopError::Rejected { code, message })
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpCoroutineState::Err(SmtpNoopError::ParseResponse(reason))
                }
            };
        }
    }
}
