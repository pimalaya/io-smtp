//! I/O-free coroutine to send SMTP MAIL FROM command.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::{
        parameter::Parameter, reply_code::ReplyCode, response::Response, reverse_path::ReversePath,
    },
    utils::escape_byte_string,
};

/// The MAIL FROM command (RFC 5321 §4.1.1.2).
pub struct SmtpMailCommand<'a> {
    /// The sender's reverse path (can be null `<>`).
    pub reverse_path: ReversePath<'a>,
    /// Optional ESMTP parameters (e.g., SIZE, BODY).
    pub parameters: Vec<Parameter<'a>>,
}

impl<'a> From<SmtpMailCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpMailCommand<'a>) -> Vec<u8> {
        let mut buf = String::new();
        buf.push_str("MAIL FROM:");
        buf.push_str(&cmd.reverse_path.to_string());
        for p in cmd.parameters {
            buf.push(' ');
            buf.push_str(&p.to_string());
        }
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Errors that can occur during MAIL FROM.
#[derive(Debug, Error)]
pub enum SmtpMailError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("MAIL FROM rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Result returned by [`SmtpMail::resume`].
#[derive(Debug)]
pub enum SmtpMailResult {
    Ok,
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SmtpMailError),
}

/// I/O-free coroutine to send SMTP MAIL FROM command.
pub struct SmtpMail {
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl SmtpMail {
    /// Creates a new MAIL FROM coroutine.
    pub fn new(reverse_path: ReversePath<'_>) -> Self {
        trace!("sending MAIL FROM command");

        let bytes = SmtpMailCommand {
            reverse_path,
            parameters: Vec::new(),
        }
        .into();

        Self {
            wants_read: false,
            wants_write: Some(bytes),
            buf: Vec::new(),
        }
    }

    /// Creates a new MAIL FROM coroutine with parameters.
    pub fn with_params(reverse_path: ReversePath<'_>, parameters: Vec<Parameter<'_>>) -> Self {
        trace!("sending MAIL FROM command with parameters");

        let bytes = SmtpMailCommand {
            reverse_path,
            parameters,
        }
        .into();

        Self {
            wants_read: false,
            wants_write: Some(bytes),
            buf: Vec::new(),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpMailResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpMailResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpMailResult::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return SmtpMailResult::Err(SmtpMailError::Eof),
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
                        SmtpMailResult::Ok
                    } else {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        SmtpMailResult::Err(SmtpMailError::Rejected { code, message })
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpMailResult::Err(SmtpMailError::ParseResponse(reason))
                }
            };
        }
    }
}
