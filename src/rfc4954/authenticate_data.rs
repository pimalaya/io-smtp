//! Module dedicated to the SMTP authenticate data and AUTH command.

use alloc::{
    borrow::Cow,
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
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

/// The AUTH command (RFC 4954).
///
/// Serializes to `AUTH <mechanism> [<base64-ir>]\r\n`.
pub struct SmtpAuthCommand<'a> {
    /// The SASL mechanism name as it appears on the wire (e.g. `"PLAIN"`).
    pub mechanism: Cow<'a, str>,
    /// Optional initial response (base64-encoded on serialization).
    pub initial_response: Option<SecretBox<[u8]>>,
}

impl<'a> From<SmtpAuthCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpAuthCommand<'a>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"AUTH ");
        buf.extend_from_slice(cmd.mechanism.as_bytes());
        if let Some(ir) = cmd.initial_response {
            let data = ir.expose_secret();
            if data.is_empty() {
                buf.extend_from_slice(b" =");
            } else {
                buf.push(b' ');
                buf.extend_from_slice(base64.encode(data).as_bytes());
            }
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

/// Data line used during SMTP AUTH exchange.
///
/// Holds the raw binary data, i.e., a `Vec<u8>`, *not* the BASE64 string.
#[derive(Debug)]
pub enum AuthenticateData {
    /// Continue SASL authentication with response data.
    Continue(SecretBox<[u8]>),
    /// Cancel SASL authentication.
    ///
    /// The client sends a single "*" to cancel the authentication exchange.
    Cancel,
}

impl AuthenticateData {
    /// Create a continuation response with the given data.
    pub fn r#continue(data: impl Into<Box<[u8]>>) -> Self {
        Self::Continue(SecretBox::new(data.into()))
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

impl From<AuthenticateData> for Vec<u8> {
    fn from(data: AuthenticateData) -> Vec<u8> {
        let mut buf = Vec::new();
        match data {
            AuthenticateData::Continue(secret) => {
                buf.extend_from_slice(base64.encode(secret.expose_secret()).as_bytes());
            }
            AuthenticateData::Cancel => buf.push(b'*'),
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}
