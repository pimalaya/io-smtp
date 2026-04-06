//! I/O-free coroutine to authenticate using SMTP AUTH OAUTHBEARER then
//! refresh capabilities via EHLO.
//!
//! # Protocol flow
//!
//! ```text
//! C: AUTH OAUTHBEARER <base64(n,,^Aauth=Bearer <token>^A^A)>
//! S: 235 OK  (success)
//!   — or —
//! S: 334 <base64(JSON-error)>  (failure detail)
//! C: ^A  (= AQ==, acknowledges error)
//! S: 535 Authentication credentials invalid
//! ```
//!
//! # Reference
//!
//! RFC 7628: A Set of Simple Authentication and Security Layer (SASL)
//! Mechanisms for OAuth.

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use bounded_static::IntoBoundedStatic;
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use thiserror::Error;

use crate::{
    read::*,
    rfc4954::{auth::SmtpAuthCommand, auth_data::SmtpAuthData},
    rfc5321::{
        ehlo::*,
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response},
    },
    utils::escape_byte_string,
    write::*,
};

/// The SASL mechanism name as it appears on the wire.
pub const OAUTHBEARER: &str = "OAUTHBEARER";

/// Errors that can occur during AUTH OAUTHBEARER.
#[derive(Debug, Error)]
pub enum SmtpOAuthBearerError {
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH OAUTHBEARER rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpOAuthBearerResult {
    Ok,
    Io { input: SocketInput },
    Err { err: SmtpOAuthBearerError },
}

enum State {
    WriteInitial(SmtpWrite),
    ReadResult(SmtpRead),
    /// Server returned 334 with error JSON; send the mandatory `\x01`
    /// acknowledgement, then read the final 535.
    WriteAck(SmtpWrite),
    ReadError(SmtpRead),
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
pub struct SmtpOAuthBearer {
    state: State,
    domain: Option<EhloDomain<'static>>,
    /// Error detail from the 334 response (base64-decoded JSON), if any.
    error_detail: Option<String>,
    buffer: Vec<u8>,
}

impl SmtpOAuthBearer {
    /// Creates a new OAUTHBEARER coroutine.
    pub fn new(token: &SecretString, username: Option<&str>, domain: EhloDomain<'_>) -> Self {
        let initial = build_initial_response(token, username);
        trace!("sending AUTH OAUTHBEARER command");

        Self {
            state: State::WriteInitial(SmtpWrite::new(SmtpAuthCommand {
                mechanism: Cow::Borrowed(OAUTHBEARER),
                initial_response: Some(SecretBox::new(initial.into_boxed_slice())),
            })),
            domain: Some(domain.into_static()),
            error_detail: None,
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpOAuthBearerResult {
        loop {
            match &mut self.state {
                State::WriteInitial(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::ReadResult(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpOAuthBearerResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        let err = err.into();
                        return SmtpOAuthBearerResult::Err { err };
                    }
                },

                State::ReadResult(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpOAuthBearerResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpOAuthBearerResult::Err { err };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::ReadResult(SmtpRead::new());
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpOAuthBearerError::ParseResponse(reason);
                                return SmtpOAuthBearerResult::Err { err };
                            }
                            Ok(response) => {
                                let response = response.into_static();

                                if response.code == ReplyCode::AUTH_SUCCESSFUL {
                                    // Immediately refresh capabilities.
                                    let domain = self.domain.take().unwrap();
                                    self.state = State::Ehlo(SmtpEhlo::new(domain));
                                    continue;
                                }

                                if response.code == ReplyCode::AUTH_CONTINUE {
                                    // Server sent a 334 with JSON error detail.
                                    // Decode and store it, then send the \x01 ack.
                                    let text = response.text().0.trim_start();
                                    if let Ok(detail_bytes) = base64.decode(text.as_bytes()) {
                                        self.error_detail = String::from_utf8(detail_bytes).ok();
                                    }

                                    self.buffer.clear();
                                    self.state = State::WriteAck(SmtpWrite::new(
                                        SmtpAuthData::r#continue(vec![0x01u8]),
                                    ));
                                    continue;
                                }

                                // Any other response (5xx / 4xx) is a direct rejection.
                                let message = response.text().to_string();
                                let code = response.code.code();
                                let err = SmtpOAuthBearerError::Rejected { code, message };
                                return SmtpOAuthBearerResult::Err { err };
                            }
                        }
                    }
                },

                State::WriteAck(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::ReadError(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpOAuthBearerResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        let err = err.into();
                        return SmtpOAuthBearerResult::Err { err };
                    }
                },

                State::ReadError(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpOAuthBearerResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpOAuthBearerResult::Err { err };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::ReadError(SmtpRead::new());
                            continue;
                        }

                        let message = self
                            .error_detail
                            .take()
                            .unwrap_or_else(|| "authentication failed".into());

                        let err = SmtpOAuthBearerError::Rejected { code: 535, message };
                        return SmtpOAuthBearerResult::Err { err };
                    }
                },

                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Io { input } => {
                        return SmtpOAuthBearerResult::Io { input };
                    }
                    SmtpEhloResult::Ok { .. } => {
                        return SmtpOAuthBearerResult::Ok;
                    }
                    SmtpEhloResult::Err { err } => {
                        let err = err.into();
                        return SmtpOAuthBearerResult::Err { err };
                    }
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
    payload.push(0x01); // \x01
    payload.extend_from_slice(b"auth=Bearer ");
    payload.extend_from_slice(token.expose_secret().as_bytes());
    payload.push(0x01); // \x01
    payload.push(0x01); // \x01
    payload
}
