//! I/O-free coroutine to authenticate using SMTP AUTH ANONYMOUS then
//! refresh capabilities via EHLO.
//!
//! # Protocol flow
//!
//! ```text
//! C: AUTH ANONYMOUS [<base64(trace)>]
//! S: 235 Authentication successful
//!   — or —
//! S: 535 Authentication credentials invalid
//! ```
//!
//! # Reference
//!
//! RFC 4505: Anonymous Simple Authentication and Security Layer
//! (SASL) Mechanism.

use core::mem;

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use secrecy::SecretBox;
use thiserror::Error;

use crate::{
    coroutine::{SmtpCoroutine, SmtpCoroutineState},
    rfc4954::auth::SmtpAuthCommand,
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError},
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response},
    },
    utils::escape_byte_string,
};

/// The SASL mechanism name as it appears on the wire.
pub const ANONYMOUS: &str = "ANONYMOUS";

/// Errors that can occur during AUTH ANONYMOUS.
#[derive(Debug, Error)]
pub enum SmtpAnonymousError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH ANONYMOUS rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

enum State {
    /// Awaiting the AUTH ANONYMOUS reply.
    AwaitAuth,
    /// Auth succeeded; refreshing capabilities via EHLO.
    Ehlo(SmtpEhlo),
}

/// I/O-free coroutine to authenticate using SMTP AUTH ANONYMOUS then
/// refresh capabilities via EHLO.
///
/// ANONYMOUS carries an optional trace token (RFC 4505 §3): typically
/// an email-like string the server can log. The token is sent in
/// cleartext; do not put credentials in it.
pub struct SmtpAnonymous {
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    domain: Option<EhloDomain<'static>>,
    buf: Vec<u8>,
}

impl SmtpAnonymous {
    /// Creates a new AUTH ANONYMOUS coroutine.
    ///
    /// Pass [`None`] (or an empty string) to send `AUTH ANONYMOUS =`,
    /// the empty-IR form. Pass `Some(token)` to send the trace token
    /// base64-encoded.
    pub fn new(trace: Option<&str>, domain: EhloDomain<'_>) -> Self {
        trace!("sending AUTH ANONYMOUS command");

        let payload = trace.unwrap_or("").as_bytes().to_vec();

        let bytes = SmtpAuthCommand {
            mechanism: Cow::Borrowed(ANONYMOUS),
            initial_response: Some(SecretBox::new(payload.into_boxed_slice())),
        }
        .into();

        Self {
            state: State::AwaitAuth,
            wants_read: false,
            wants_write: Some(bytes),
            domain: Some(domain.into_static()),
            buf: Vec::new(),
        }
    }
}

impl SmtpCoroutine for SmtpAnonymous {
    type Output = ();
    type Error = SmtpAnonymousError;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Output, Self::Error> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpCoroutineState::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::WantsRead;
            }

            match &mut self.state {
                State::AwaitAuth => {
                    match arg.take() {
                        Some(&[]) => return SmtpCoroutineState::Err(SmtpAnonymousError::Eof),
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

                            return SmtpCoroutineState::Err(SmtpAnonymousError::ParseResponse(
                                reason,
                            ));
                        }
                    };

                    if response.code != ReplyCode::AUTH_SUCCESSFUL {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        return SmtpCoroutineState::Err(SmtpAnonymousError::Rejected {
                            code,
                            message,
                        });
                    }

                    self.buf.clear();
                    let domain = self.domain.take().expect("domain taken twice");
                    self.state = State::Ehlo(SmtpEhlo::new(domain));
                }
                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpCoroutineState::Done(_) => return SmtpCoroutineState::Done(()),
                    SmtpCoroutineState::WantsRead => return SmtpCoroutineState::WantsRead,
                    SmtpCoroutineState::WantsWrite(bytes) => {
                        return SmtpCoroutineState::WantsWrite(bytes);
                    }
                    SmtpCoroutineState::Err(err) => {
                        return SmtpCoroutineState::Err(SmtpAnonymousError::Ehlo(err));
                    }
                },
            }
        }
    }
}
