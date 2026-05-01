//! I/O-free coroutine to send SMTP DATA command and message body.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::{reply_code::ReplyCode, response::Response},
    utils::escape_byte_string,
};

/// The DATA command (RFC 5321 §4.1.1.4).
pub struct SmtpDataCommand;

impl From<SmtpDataCommand> for Vec<u8> {
    fn from(_: SmtpDataCommand) -> Vec<u8> {
        b"DATA\r\n".to_vec()
    }
}

/// Errors that can occur during DATA.
#[derive(Debug, Error)]
pub enum SmtpDataError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("DATA command rejected: {code} {message}")]
    CommandRejected { code: u16, message: String },
    #[error("DATA body rejected: {code} {message}")]
    BodyRejected { code: u16, message: String },
}

/// Result returned by [`SmtpData::resume`].
#[derive(Debug)]
pub enum SmtpDataResult {
    Ok,
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SmtpDataError),
}

#[derive(Debug)]
enum State {
    /// Awaiting the 354 intermediate reply after `DATA\r\n`.
    AwaitIntermediate,
    /// Awaiting the final 250 reply after the body terminator.
    AwaitFinal,
}

/// I/O-free coroutine to send SMTP DATA command and message body.
///
/// The message body should be the raw email content. This coroutine handles
/// dot-stuffing (prepending dots to lines starting with dots) automatically.
pub struct SmtpData {
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    body: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl SmtpData {
    /// Creates a new DATA coroutine.
    ///
    /// The `message` should be the complete email message (headers + body).
    /// Dot-stuffing will be applied automatically.
    pub fn new(message: Vec<u8>) -> Self {
        trace!("sending DATA command");

        Self {
            state: State::AwaitIntermediate,
            wants_read: false,
            wants_write: Some(SmtpDataCommand.into()),
            body: Some(message),
            buf: Vec::new(),
        }
    }

    /// Apply dot-stuffing to the message body and append terminator.
    fn prepare_body(message: Vec<u8>) -> Vec<u8> {
        let mut result = Vec::with_capacity(message.len() + 5);

        let mut at_line_start = true;
        for &byte in &message {
            if at_line_start && byte == b'.' {
                result.push(b'.');
            }
            result.push(byte);
            at_line_start = byte == b'\n';
        }

        if !result.ends_with(b"\r\n") {
            if result.ends_with(b"\n") {
                result.pop();
                result.extend_from_slice(b"\r\n");
            } else if result.ends_with(b"\r") {
                result.push(b'\n');
            } else {
                result.extend_from_slice(b"\r\n");
            }
        }

        result.extend_from_slice(b".\r\n");

        result
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpDataResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpDataResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpDataResult::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return SmtpDataResult::Err(SmtpDataError::Eof),
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

            let response = match Response::parse(&self.buf) {
                Ok(response) => response.into_static(),
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    return SmtpDataResult::Err(SmtpDataError::ParseResponse(reason));
                }
            };

            match self.state {
                State::AwaitIntermediate => {
                    if response.code != ReplyCode::START_MAIL_INPUT {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        return SmtpDataResult::Err(SmtpDataError::CommandRejected {
                            code,
                            message,
                        });
                    }

                    let body = self.body.take().expect("body taken twice");
                    let prepared = Self::prepare_body(body);
                    trace!("message body prepared: {} bytes", prepared.len());

                    self.buf.clear();
                    self.state = State::AwaitFinal;
                    self.wants_write = Some(prepared);
                }
                State::AwaitFinal => {
                    return if response.code == ReplyCode::OK {
                        SmtpDataResult::Ok
                    } else {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        SmtpDataResult::Err(SmtpDataError::BodyRejected { code, message })
                    };
                }
            }
        }
    }
}
