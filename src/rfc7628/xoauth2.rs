//! I/O-free coroutine to authenticate using SMTP AUTH XOAUTH2 then
//! refresh capabilities via EHLO.
//!
//! # Protocol flow
//!
//! ```text
//! C: AUTH XOAUTH2 <base64(user=USERNAME^Aauth=Bearer TOKEN^A^A)>
//! S: 235 OK  (success)
//!   — or —
//! S: 334 <base64(JSON-error)>  (failure detail)
//! C: ^A  (= AQ==, acknowledges error)
//! S: 535 Authentication credentials invalid
//! ```
//!
//! XOAUTH2 is Google's pre-standard OAuth 2.0 SASL mechanism. The
//! IETF-standardised replacement is OAUTHBEARER (RFC 7628); prefer
//! that on servers that support both.
//!
//! # Reference
//!
//! Google: <https://developers.google.com/gmail/imap/xoauth2-protocol>.

use core::mem;

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use bounded_static::IntoBoundedStatic;
use log::trace;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use thiserror::Error;

use crate::{
    rfc4954::{auth::SmtpAuthCommand, auth_data::SmtpAuthData},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError, SmtpEhloResult},
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response},
    },
    utils::escape_byte_string,
};

/// The SASL mechanism name as it appears on the wire.
pub const XOAUTH2: &str = "XOAUTH2";

/// Errors that can occur during AUTH XOAUTH2.
#[derive(Debug, Error)]
pub enum SmtpXoauth2Error {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH XOAUTH2 rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// Result returned by [`SmtpXOAuth2::resume`].
#[derive(Debug)]
pub enum SmtpXoauth2Result {
    Ok,
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SmtpXoauth2Error),
}

enum State {
    /// Awaiting the reply to the initial `AUTH XOAUTH2` command.
    AwaitInitial,
    /// Awaiting the final 535 reply after sending the `\x01`
    /// acknowledgement following a 334 error response.
    AwaitError,
    /// Auth succeeded; refreshing capabilities via EHLO.
    Ehlo(SmtpEhlo),
}

/// I/O-free coroutine to authenticate using SMTP AUTH XOAUTH2.
///
/// The `token` is an OAuth 2.0 bearer access token. It is sent over
/// the wire so the connection **must** be TLS-protected before
/// calling this coroutine.
pub struct SmtpXoauth2 {
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    domain: Option<EhloDomain<'static>>,
    /// Error detail from the 334 response (base64-decoded JSON), if any.
    error_detail: Option<String>,
    buf: Vec<u8>,
}

impl SmtpXoauth2 {
    /// Creates a new XOAUTH2 coroutine.
    pub fn new(username: &str, token: &SecretString, domain: EhloDomain<'_>) -> Self {
        let initial = build_initial_response(username, token);
        trace!("sending AUTH XOAUTH2 command");

        let bytes = SmtpAuthCommand {
            mechanism: Cow::Borrowed(XOAUTH2),
            initial_response: Some(SecretBox::new(initial.into_boxed_slice())),
        }
        .into();

        Self {
            state: State::AwaitInitial,
            wants_read: false,
            wants_write: Some(bytes),
            domain: Some(domain.into_static()),
            error_detail: None,
            buf: Vec::new(),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpXoauth2Result {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpXoauth2Result::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpXoauth2Result::WantsRead;
            }

            match &mut self.state {
                State::AwaitInitial => {
                    match arg.take() {
                        Some(&[]) => return SmtpXoauth2Result::Err(SmtpXoauth2Error::Eof),
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

                            return SmtpXoauth2Result::Err(SmtpXoauth2Error::ParseResponse(reason));
                        }
                    };

                    if response.code == ReplyCode::AUTH_SUCCESSFUL {
                        self.buf.clear();
                        let domain = self.domain.take().expect("domain taken twice");
                        self.state = State::Ehlo(SmtpEhlo::new(domain));
                        continue;
                    }

                    if response.code == ReplyCode::AUTH_CONTINUE {
                        let text = response.text().0.trim_start();
                        if let Ok(detail_bytes) = base64.decode(text.as_bytes()) {
                            self.error_detail = String::from_utf8(detail_bytes).ok();
                        }

                        self.buf.clear();
                        self.state = State::AwaitError;
                        let ack: Vec<u8> = SmtpAuthData::r#continue(vec![0x01u8]).into();
                        return SmtpXoauth2Result::WantsWrite(ack);
                    }

                    let code = response.code.code();
                    let message = response.text().to_string();
                    return SmtpXoauth2Result::Err(SmtpXoauth2Error::Rejected { code, message });
                }

                State::AwaitError => {
                    match arg.take() {
                        Some(&[]) => return SmtpXoauth2Result::Err(SmtpXoauth2Error::Eof),
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

                    let message = self
                        .error_detail
                        .take()
                        .unwrap_or_else(|| "authentication failed".into());

                    return SmtpXoauth2Result::Err(SmtpXoauth2Error::Rejected {
                        code: 535,
                        message,
                    });
                }

                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Ok { .. } => return SmtpXoauth2Result::Ok,
                    SmtpEhloResult::WantsRead => return SmtpXoauth2Result::WantsRead,
                    SmtpEhloResult::WantsWrite(bytes) => {
                        return SmtpXoauth2Result::WantsWrite(bytes);
                    }
                    SmtpEhloResult::Err(err) => {
                        return SmtpXoauth2Result::Err(SmtpXoauth2Error::Ehlo(err));
                    }
                },
            }
        }
    }
}

/// Build the XOAUTH2 initial-response bytes.
///
/// Format: `user=<username>\x01auth=Bearer <token>\x01\x01`
fn build_initial_response(username: &str, token: &SecretString) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"user=");
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x01);
    payload.extend_from_slice(b"auth=Bearer ");
    payload.extend_from_slice(token.expose_secret().as_bytes());
    payload.push(0x01);
    payload.push(0x01);
    payload
}
