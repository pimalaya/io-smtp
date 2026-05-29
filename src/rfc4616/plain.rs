//! I/O-free coroutine to authenticate using SMTP AUTH PLAIN then refresh
//! capabilities via EHLO.

use core::mem;

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use secrecy::{ExposeSecret, SecretBox, SecretString};
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
pub const PLAIN: &str = "PLAIN";

/// Errors that can occur during AUTH PLAIN.
#[derive(Debug, Error)]
pub enum SmtpPlainError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH PLAIN rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

enum State {
    /// Awaiting the AUTH PLAIN reply.
    AwaitAuth,
    /// Auth succeeded; refreshing capabilities via EHLO.
    Ehlo(SmtpEhlo),
}

/// I/O-free coroutine to authenticate using SMTP AUTH PLAIN then refresh
/// capabilities via EHLO.
///
/// AUTH PLAIN sends credentials as: base64(authzid\0authcid\0password)
/// where authzid is optional (usually empty), authcid is the username.
pub struct SmtpPlain {
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    domain: Option<EhloDomain<'static>>,
    buf: Vec<u8>,
}

impl SmtpPlain {
    /// Creates a new AUTH PLAIN coroutine.
    ///
    /// Uses initial response (IR) to send credentials in a single round-trip.
    pub fn new(login: &str, password: &SecretString, domain: EhloDomain<'_>) -> Self {
        let mut payload = Vec::new();
        payload.push(0);
        payload.extend_from_slice(login.as_bytes());
        payload.push(0);
        payload.extend_from_slice(password.expose_secret().as_bytes());

        trace!("sending AUTH PLAIN command");

        let bytes = SmtpAuthCommand {
            mechanism: Cow::Borrowed(PLAIN),
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

impl SmtpCoroutine for SmtpPlain {
    type Output = ();
    type Error = SmtpPlainError;

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
                        Some(&[]) => return SmtpCoroutineState::Err(SmtpPlainError::Eof),
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

                            return SmtpCoroutineState::Err(SmtpPlainError::ParseResponse(reason));
                        }
                    };

                    if response.code != ReplyCode::AUTH_SUCCESSFUL {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        return SmtpCoroutineState::Err(SmtpPlainError::Rejected { code, message });
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
                        return SmtpCoroutineState::Err(SmtpPlainError::Ehlo(err));
                    }
                },
            }
        }
    }
}
