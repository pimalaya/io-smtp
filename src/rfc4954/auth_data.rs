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
    /// The input carries no terminating CRLF yet.
    #[error("Parse SMTP auth data error: incomplete input")]
    Incomplete,
    /// The base64 payload could not be decoded.
    #[error("Parse SMTP auth data error: {0}")]
    Base64(String),
}

/// Errors that can occur while decoding a server challenge.
#[derive(Clone, Debug, Error)]
pub enum SmtpAuthChallengeError {
    /// The challenge payload could not be decoded.
    #[error("Parse SMTP auth challenge error: {0}")]
    Base64(String),
}

/// Decodes the payload a server challenge carries.
///
/// The text of a 334 reply is the base64 of the SASL message the
/// mechanism has to answer, empty when the mechanism expects no
/// message. The same encoding carries the final server message when a
/// server puts it in the 235 reply instead, as RFC 4954 section 4
/// allows.
pub fn parse_challenge(text: &str) -> Result<Vec<u8>, SmtpAuthChallengeError> {
    let payload = text.trim();

    if payload.is_empty() {
        return Ok(Vec::new());
    }

    base64
        .decode(payload)
        .map_err(|err| SmtpAuthChallengeError::Base64(err.to_string()))
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
