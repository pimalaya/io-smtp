//! Module dedicated to the SMTP authenticate data.

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;

/// Errors that can occur while parsing authenticate data.
#[derive(Debug, Error)]
pub enum ParseAuthenticateDataError {
    #[error("Parse SMTP authenticate data error: incomplete input")]
    Incomplete,
    #[error("Parse SMTP authenticate data error: {0}")]
    Base64(String),
}

/// Data line used during SMTP AUTH exchange.
///
/// Holds the raw binary data, i.e., a `Vec<u8>`, *not* the BASE64 string.
#[derive(Debug)]
pub enum AuthenticateData {
    /// Continue SASL authentication with response data.
    Continue(SecretBox<Box<[u8]>>),
    /// Cancel SASL authentication.
    ///
    /// The client sends a single "*" to cancel the authentication exchange.
    Cancel,
}

impl AuthenticateData {
    /// Create a continuation response with the given data.
    pub fn r#continue(data: impl Into<Box<[u8]>>) -> Self {
        Self::Continue(SecretBox::new(Box::new(data.into())))
    }

    /// Serialize this authenticate data to wire bytes (includes CRLF).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            AuthenticateData::Continue(data) => {
                buf.extend_from_slice(base64.encode(data.expose_secret().as_ref()).as_bytes());
            }
            AuthenticateData::Cancel => buf.push(b'*'),
        }

        buf.extend_from_slice(b"\r\n");
        buf
    }

    /// Returns true if `buf` contains a complete authenticate data line.
    pub fn is_complete(buf: &[u8]) -> bool {
        buf.ends_with(b"\r\n")
    }

    /// Parse authenticate data from bytes.
    pub fn parse(input: &[u8]) -> Result<AuthenticateData, ParseAuthenticateDataError> {
        if !input.ends_with(b"\r\n") {
            return Err(ParseAuthenticateDataError::Incomplete);
        }

        let line = &input[..input.len() - 2];
        if line == b"*" {
            return Ok(AuthenticateData::Cancel);
        }

        let decoded = base64
            .decode(line)
            .map_err(|e| ParseAuthenticateDataError::Base64(e.to_string()))?;

        Ok(AuthenticateData::r#continue(decoded.into_boxed_slice()))
    }
}
