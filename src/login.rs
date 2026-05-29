//! AUTH LOGIN command and coroutine (no formal RFC).
//!
//! LOGIN is a legacy de-facto SASL mechanism. It performs a two-step
//! challenge/response exchange: the server asks for the username,
//! then the password, each base64-encoded. Prefer PLAIN or
//! SCRAM-SHA-256 when the server supports them.

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::trace;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{
    coroutine::{SmtpCoroutine, SmtpCoroutineState},
    rfc4954::auth_data::SmtpAuthData,
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError},
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response},
    },
    utils::escape_byte_string,
};

/// The AUTH LOGIN command.
///
/// Sends `AUTH LOGIN\r\n` to initiate the two-step challenge/response
/// exchange.
pub struct SmtpLoginCommand;

impl From<SmtpLoginCommand> for Vec<u8> {
    fn from(_: SmtpLoginCommand) -> Vec<u8> {
        b"AUTH LOGIN\r\n".to_vec()
    }
}

/// The SASL mechanism name as it appears on the wire.
pub const LOGIN: &str = "LOGIN";

/// Errors that can occur during AUTH LOGIN.
#[derive(Debug, Error)]
pub enum SmtpLoginError {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH LOGIN rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

enum State {
    /// Awaiting the 334 reply that asks for the username.
    AwaitUsernameChallenge,
    /// Awaiting the 334 reply that asks for the password.
    AwaitPasswordChallenge,
    /// Awaiting the 235 reply that confirms authentication.
    AwaitFinal,
    /// Auth succeeded; refreshing capabilities via EHLO.
    Ehlo(SmtpEhlo),
}

/// I/O-free coroutine to authenticate using SMTP AUTH LOGIN then refresh
/// capabilities via EHLO.
pub struct SmtpLogin {
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    domain: Option<EhloDomain<'static>>,
    username_bytes: Option<Vec<u8>>,
    password_bytes: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl SmtpLogin {
    /// Creates a new AUTH LOGIN coroutine.
    pub fn new(login: &str, password: &SecretString, domain: EhloDomain<'_>) -> Self {
        trace!("sending AUTH LOGIN command");

        let username_bytes: Vec<u8> = SmtpAuthData::r#continue(login.as_bytes()).into();
        let password_bytes: Vec<u8> =
            SmtpAuthData::r#continue(password.expose_secret().as_bytes()).into();

        Self {
            state: State::AwaitUsernameChallenge,
            wants_read: false,
            wants_write: Some(SmtpLoginCommand.into()),
            domain: Some(domain.into_static()),
            username_bytes: Some(username_bytes),
            password_bytes: Some(password_bytes),
            buf: Vec::new(),
        }
    }

    /// Feed the read argument into the buffer and return the terminal
    /// state the caller should propagate (EOF or "want more bytes").
    /// Returns [`None`] when the buffer is ready to parse.
    fn feed_response(
        &mut self,
        arg: Option<&[u8]>,
    ) -> Option<SmtpCoroutineState<(), SmtpLoginError>> {
        match arg {
            Some(&[]) => return Some(SmtpCoroutineState::Err(SmtpLoginError::Eof)),
            Some(data) => {
                trace!("read SMTP bytes: {}", escape_byte_string(data));
                self.buf.extend_from_slice(data);
            }
            None => {}
        }

        if !Response::is_complete(&self.buf) {
            return Some(SmtpCoroutineState::WantsRead);
        }

        None
    }
}

impl SmtpCoroutine for SmtpLogin {
    type Output = ();
    type Error = SmtpLoginError;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Output, Self::Error> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpCoroutineState::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::WantsRead;
            }

            match &mut self.state {
                State::AwaitUsernameChallenge => {
                    if let Some(state) = self.feed_response(arg.take()) {
                        return state;
                    }

                    let response = match Response::parse(&self.buf) {
                        Ok(response) => response.into_static(),
                        Err(errors) => {
                            return SmtpCoroutineState::Err(SmtpLoginError::ParseResponse(
                                join_errors(errors),
                            ));
                        }
                    };

                    if response.code != ReplyCode::AUTH_CONTINUE {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        return SmtpCoroutineState::Err(SmtpLoginError::Rejected { code, message });
                    }

                    self.buf.clear();
                    self.state = State::AwaitPasswordChallenge;
                    let bytes = self.username_bytes.take().expect("username taken twice");
                    return SmtpCoroutineState::WantsWrite(bytes);
                }
                State::AwaitPasswordChallenge => {
                    if let Some(state) = self.feed_response(arg.take()) {
                        return state;
                    }

                    let response = match Response::parse(&self.buf) {
                        Ok(response) => response.into_static(),
                        Err(errors) => {
                            return SmtpCoroutineState::Err(SmtpLoginError::ParseResponse(
                                join_errors(errors),
                            ));
                        }
                    };

                    if response.code != ReplyCode::AUTH_CONTINUE {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        return SmtpCoroutineState::Err(SmtpLoginError::Rejected { code, message });
                    }

                    self.buf.clear();
                    self.state = State::AwaitFinal;
                    let bytes = self.password_bytes.take().expect("password taken twice");
                    return SmtpCoroutineState::WantsWrite(bytes);
                }
                State::AwaitFinal => {
                    if let Some(state) = self.feed_response(arg.take()) {
                        return state;
                    }

                    let response = match Response::parse(&self.buf) {
                        Ok(response) => response.into_static(),
                        Err(errors) => {
                            return SmtpCoroutineState::Err(SmtpLoginError::ParseResponse(
                                join_errors(errors),
                            ));
                        }
                    };

                    if response.code != ReplyCode::AUTH_SUCCESSFUL {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        return SmtpCoroutineState::Err(SmtpLoginError::Rejected { code, message });
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
                        return SmtpCoroutineState::Err(SmtpLoginError::Ehlo(err));
                    }
                },
            }
        }
    }
}

fn join_errors<E: ToString>(errors: impl IntoIterator<Item = E>) -> String {
    errors
        .into_iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}
