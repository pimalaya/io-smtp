//! I/O-free coroutine to send SMTP EHLO command.

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
    coroutine::*,
    rfc5321::types::{ehlo_domain::EhloDomain, ehlo_response::EhloResponse},
    utils::escape_byte_string,
};

/// Output of [`SmtpClientStd::ehlo`]: the raw capability strings (one
/// entry per EHLO continuation line) plus any bytes read past the
/// final reply line.
///
/// [`SmtpClientStd::ehlo`]: crate::client::SmtpClientStd::ehlo
pub type SmtpEhloOutput = (Vec<Cow<'static, str>>, Vec<u8>);

/// The EHLO command (RFC 5321 §4.1.1.1).
pub struct SmtpEhloCommand<'a> {
    /// The client's domain or address literal.
    pub domain: EhloDomain<'a>,
}

impl<'a> From<SmtpEhloCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpEhloCommand<'a>) -> Vec<u8> {
        let mut buf = String::from("EHLO ");
        buf.push_str(&cmd.domain.to_string());
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpEhloError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// I/O-free coroutine to send SMTP EHLO command.
pub struct SmtpEhlo {
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl SmtpEhlo {
    /// Creates a new coroutine.
    pub fn new(domain: EhloDomain<'_>) -> Self {
        trace!("sending EHLO command");

        let bytes = SmtpEhloCommand { domain }.into();

        Self {
            wants_read: false,
            wants_write: Some(bytes),
            buf: Vec::new(),
        }
    }
}

impl SmtpCoroutine for SmtpEhlo {
    type Yield = SmtpYield;
    type Return = Result<SmtpEhloOutput, SmtpEhloError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes));
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::Yielded(SmtpYield::WantsRead);
            }

            match arg.take() {
                Some(&[]) => return SmtpCoroutineState::Complete(Err(SmtpEhloError::Eof)),
                Some(data) => {
                    trace!("read SMTP bytes: {}", escape_byte_string(data));
                    self.buf.extend_from_slice(data);
                }
                None => {}
            }

            if !EhloResponse::is_complete(&self.buf) {
                self.wants_read = true;
                continue;
            }

            return match EhloResponse::parse(&self.buf) {
                Ok(response) => {
                    let capabilities = response.into_static().capabilities;
                    let _ = mem::take(&mut self.buf);
                    SmtpCoroutineState::Complete(Ok((capabilities, Vec::new())))
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpCoroutineState::Complete(Err(SmtpEhloError::ParseResponse(reason)))
                }
            };
        }
    }
}
