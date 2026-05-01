//! I/O-free coroutine to send SMTP RCPT TO command.

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
        forward_path::ForwardPath, parameter::Parameter, reply_code::ReplyCode, response::Response,
    },
    utils::escape_byte_string,
};

/// The RCPT TO command (RFC 5321 §4.1.1.3).
pub struct SmtpRcptCommand<'a> {
    /// The recipient's forward path.
    pub forward_path: ForwardPath<'a>,
    /// Optional ESMTP parameters.
    pub parameters: Vec<Parameter<'a>>,
}

impl<'a> From<SmtpRcptCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpRcptCommand<'a>) -> Vec<u8> {
        let mut buf = String::new();
        buf.push_str("RCPT TO:");
        buf.push_str(&cmd.forward_path.to_string());
        for p in cmd.parameters {
            buf.push(' ');
            buf.push_str(&p.to_string());
        }
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Errors that can occur during RCPT TO.
#[derive(Debug, Error)]
pub enum SmtpRcptError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("RCPT TO rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Result returned by [`SmtpRcpt::resume`].
#[derive(Debug)]
pub enum SmtpRcptResult {
    Ok,
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SmtpRcptError),
}

/// I/O-free coroutine to send SMTP RCPT TO command.
pub struct SmtpRcpt {
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl SmtpRcpt {
    /// Creates a new RCPT TO coroutine.
    pub fn new(forward_path: ForwardPath<'_>) -> Self {
        trace!("sending RCPT TO command");

        let bytes = SmtpRcptCommand {
            forward_path,
            parameters: Vec::new(),
        }
        .into();

        Self {
            wants_read: false,
            wants_write: Some(bytes),
            buf: Vec::new(),
        }
    }

    /// Creates a new RCPT TO coroutine with parameters.
    pub fn with_params(forward_path: ForwardPath<'_>, parameters: Vec<Parameter<'_>>) -> Self {
        trace!("sending RCPT TO command with parameters");

        let bytes = SmtpRcptCommand {
            forward_path,
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
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpRcptResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpRcptResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpRcptResult::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return SmtpRcptResult::Err(SmtpRcptError::Eof),
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
                        SmtpRcptResult::Ok
                    } else {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        SmtpRcptResult::Err(SmtpRcptError::Rejected { code, message })
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpRcptResult::Err(SmtpRcptError::ParseResponse(reason))
                }
            };
        }
    }
}
