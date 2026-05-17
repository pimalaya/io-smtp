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

/// Result returned by [`SmtpEhlo::resume`].
#[derive(Debug)]
pub enum SmtpEhloResult {
    /// The coroutine has successfully terminated.
    ///
    /// `capabilities` are the raw capability strings from the EHLO
    /// response (e.g. `"AUTH PLAIN LOGIN"`, `"SIZE 10240000"`). Each
    /// entry is the full capability line after the initial domain
    /// greeting line. Parse mechanism-specific parameters using the
    /// relevant RFC module.
    Ok {
        capabilities: Vec<Cow<'static, str>>,
        remaining: Vec<u8>,
    },
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SmtpEhloError),
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

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpEhloResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpEhloResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpEhloResult::WantsRead;
            }

            match arg.take() {
                Some(&[]) => return SmtpEhloResult::Err(SmtpEhloError::Eof),
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
                    SmtpEhloResult::Ok {
                        capabilities,
                        remaining: Vec::new(),
                    }
                }
                Err(errors) => {
                    let reason = errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");

                    SmtpEhloResult::Err(SmtpEhloError::ParseResponse(reason))
                }
            };
        }
    }
}
