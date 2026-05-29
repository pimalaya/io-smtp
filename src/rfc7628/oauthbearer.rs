//! I/O-free coroutine to authenticate using SMTP AUTH OAUTHBEARER then
//! refresh capabilities via EHLO.
//!
//! # Protocol flow
//!
//! ```text
//! C: AUTH OAUTHBEARER <base64(n,,^Aauth=Bearer <token>^A^A)>
//! S: 235 OK  (success)
//!   or
//! S: 334 <base64(JSON-error)>  (failure detail)
//! C: ^A  (= AQ==, acknowledges error)
//! S: 535 Authentication credentials invalid
//! ```
//!
//! # Reference
//!
//! RFC 7628: A Set of Simple Authentication and Security Layer (SASL)
//! Mechanisms for OAuth.

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
    coroutine::*,
    rfc4954::{auth::SmtpAuthCommand, auth_data::SmtpAuthData},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError},
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response},
    },
    utils::escape_byte_string,
};

/// The SASL mechanism name as it appears on the wire.
pub const OAUTHBEARER: &str = "OAUTHBEARER";

/// Errors that can occur during AUTH OAUTHBEARER.
#[derive(Debug, Error)]
pub enum SmtpOauthbearerError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH OAUTHBEARER rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

enum State {
    /// Awaiting the reply to the initial `AUTH OAUTHBEARER` command.
    AwaitInitial,
    /// Awaiting the final 535 reply after sending the `\x01`
    /// acknowledgement following a 334 error response.
    AwaitError,
    /// Auth succeeded; refreshing capabilities via EHLO.
    Ehlo(SmtpEhlo),
}

/// I/O-free coroutine to authenticate using SMTP AUTH OAUTHBEARER.
///
/// The `token` is an OAuth 2.0 bearer access token. It is sent over the wire
/// so the connection **must** be TLS-protected before calling this coroutine.
///
/// The optional `username` (authorization identity) is embedded in the GS2
/// header when provided. Most servers ignore it; leave as `None` unless your
/// provider requires it.
pub struct SmtpOauthbearer {
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    domain: Option<EhloDomain<'static>>,
    /// Error detail from the 334 response (base64-decoded JSON), if any.
    error_detail: Option<String>,
    buf: Vec<u8>,
}

impl SmtpOauthbearer {
    /// Creates a new OAUTHBEARER coroutine.
    pub fn new(token: &SecretString, username: Option<&str>, domain: EhloDomain<'_>) -> Self {
        let initial = build_initial_response(token, username);
        trace!("sending AUTH OAUTHBEARER command");

        let bytes = SmtpAuthCommand {
            mechanism: Cow::Borrowed(OAUTHBEARER),
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
}

impl SmtpCoroutine for SmtpOauthbearer {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpOauthbearerError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes));
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::Yielded(SmtpYield::WantsRead);
            }

            match &mut self.state {
                State::AwaitInitial => {
                    match arg.take() {
                        Some(&[]) => {
                            return SmtpCoroutineState::Complete(Err(SmtpOauthbearerError::Eof));
                        }
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

                            return SmtpCoroutineState::Complete(Err(
                                SmtpOauthbearerError::ParseResponse(reason),
                            ));
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
                        return SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(ack));
                    }

                    let code = response.code.code();
                    let message = response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpOauthbearerError::Rejected {
                        code,
                        message,
                    }));
                }

                State::AwaitError => {
                    match arg.take() {
                        Some(&[]) => {
                            return SmtpCoroutineState::Complete(Err(SmtpOauthbearerError::Eof));
                        }
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

                    return SmtpCoroutineState::Complete(Err(SmtpOauthbearerError::Rejected {
                        code: 535,
                        message,
                    }));
                }

                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpCoroutineState::Complete(Ok(_)) => {
                        return SmtpCoroutineState::Complete(Ok(()));
                    }
                    SmtpCoroutineState::Complete(Err(err)) => {
                        return SmtpCoroutineState::Complete(Err(SmtpOauthbearerError::Ehlo(err)));
                    }
                    SmtpCoroutineState::Yielded(y) => return SmtpCoroutineState::Yielded(y),
                },
            }
        }
    }
}

/// Build the OAUTHBEARER initial-response bytes.
///
/// Format: `n,` [a=<username>] `,\x01auth=Bearer <token>\x01\x01`
fn build_initial_response(token: &SecretString, username: Option<&str>) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"n,");
    if let Some(user) = username {
        payload.extend_from_slice(b"a=");
        payload.extend_from_slice(user.as_bytes());
    }
    payload.push(b',');
    payload.push(0x01);
    payload.extend_from_slice(b"auth=Bearer ");
    payload.extend_from_slice(token.expose_secret().as_bytes());
    payload.push(0x01);
    payload.push(0x01);
    payload
}
