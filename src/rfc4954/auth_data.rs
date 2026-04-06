//! SMTP AUTH continuation data (RFC 4954 §4).

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;

/// Errors that can occur while parsing auth data.
#[derive(Debug, Error)]
pub enum SmtpAuthDataError {
    #[error("Parse SMTP auth data error: incomplete input")]
    Incomplete,
    #[error("Parse SMTP auth data error: {0}")]
    Base64(String),
}

/// Data line used during SMTP AUTH exchange.
///
/// Holds the raw binary data, i.e., a `Vec<u8>`, *not* the BASE64
/// string.
#[derive(Debug)]
pub enum SmtpAuthData {
    /// Continue SASL authentication with response data.
    Continue(SecretBox<[u8]>),
    /// Cancel SASL authentication.
    ///
    /// The client sends a single `*` to cancel the authentication
    /// exchange.
    Cancel,
}

impl SmtpAuthData {
    /// Create a continuation response with the given data.
    pub fn r#continue(data: impl Into<Box<[u8]>>) -> Self {
        Self::Continue(SecretBox::new(data.into()))
    }

    /// Returns true if `buf` contains a complete auth data line.
    pub fn is_complete(buf: &[u8]) -> bool {
        buf.ends_with(b"\r\n")
    }

    /// Parse auth data from bytes.
    pub fn parse(input: &[u8]) -> Result<SmtpAuthData, SmtpAuthDataError> {
        if !input.ends_with(b"\r\n") {
            return Err(SmtpAuthDataError::Incomplete);
        }

        let line = &input[..input.len() - 2];
        if line == b"*" {
            return Ok(SmtpAuthData::Cancel);
        }

        let decoded = base64
            .decode(line)
            .map_err(|e| SmtpAuthDataError::Base64(e.to_string()))?;

        Ok(SmtpAuthData::r#continue(decoded.into_boxed_slice()))
    }
}

impl From<SmtpAuthData> for Vec<u8> {
    fn from(data: SmtpAuthData) -> Vec<u8> {
        let mut buf = Vec::new();

        match data {
            SmtpAuthData::Continue(secret) => {
                buf.extend_from_slice(base64.encode(secret.expose_secret()).as_bytes());
            }
            SmtpAuthData::Cancel => buf.push(b'*'),
        }

        buf.extend_from_slice(b"\r\n");
        buf
    }
}
