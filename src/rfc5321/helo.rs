//! I/O-free coroutine to send SMTP HELO command.
//!
//! HELO is the legacy SMTP greeting command. Prefer
//! [`crate::rfc5321::ehlo`] (`EHLO`) for any modern server. Fall back
//! to HELO only when the server rejects EHLO with 500 or 502.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use thiserror::Error;

use crate::{
    coroutine::{SmtpCoroutine, SmtpCoroutineState},
    rfc5321::types::{domain::Domain, reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
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
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("HELO rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// I/O-free coroutine to send SMTP HELO command.
///
/// HELO is the legacy handshake. It does not negotiate extensions. If the
/// server supports ESMTP, use [`crate::rfc5321::ehlo::SmtpEhlo`] instead.
pub struct SmtpHelo {
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl SmtpHelo {
    /// Creates a new coroutine.
    pub fn new(domain: Domain<'_>) -> Self {
        trace!("sending HELO command");

        let bytes = SmtpHeloCommand {
            domain: domain.into_static(),
        }
        .into();

        Self {
            wants_read: false,
            wants_write: Some(bytes),
            buf: Vec::new(),
        }
    }
}

impl SmtpCoroutine for SmtpHelo {
    type Output = ();
    type Error = SmtpHeloError;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Output, Self::Error> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpCoroutineState::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return SmtpCoroutineState::Err(SmtpHeloError::Eof),
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
                    if response.code == ReplyCode::OK {
                        SmtpCoroutineState::Done(())
                    } else {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        SmtpCoroutineState::Err(SmtpHeloError::Rejected { code, message })
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpCoroutineState::Err(SmtpHeloError::ParseResponse(reason))
                }
            };
        }
    }
}
