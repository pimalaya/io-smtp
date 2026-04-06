//! I/O-free coroutine to authenticate using SMTP AUTH PLAIN then refresh
//! capabilities via EHLO.

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use bounded_static::IntoBoundedStatic;
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use thiserror::Error;

use crate::{
    read::{SmtpRead, SmtpReadError, SmtpReadResult},
    rfc4954::types::auth_mechanism::AuthMechanism,
    rfc5321::{
        ehlo::*,
        types::{
            command::Command, ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response,
        },
    },
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// Errors that can occur during AUTH PLAIN.
#[derive(Debug, Error)]
pub enum SmtpAuthenticatePlainError {
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH PLAIN rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpAuthenticatePlainResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpAuthenticatePlainError },
}

enum State {
    Write(SmtpWrite),
    Read(SmtpRead),
    Ehlo(SmtpEhlo),
}

/// I/O-free coroutine to authenticate using SMTP AUTH PLAIN then refresh
/// capabilities via EHLO.
///
/// AUTH PLAIN sends credentials as: base64(authzid\0authcid\0password)
/// where authzid is optional (usually empty), authcid is the username.
pub struct SmtpAuthenticatePlain {
    state: State,
    domain: Option<EhloDomain<'static>>,
    buffer: Vec<u8>,
}

impl SmtpAuthenticatePlain {
    /// Creates a new AUTH PLAIN coroutine.
    ///
    /// Uses initial response (IR) to send credentials in a single round-trip.
    pub fn new(login: &str, password: &SecretString, domain: EhloDomain<'_>) -> Self {
        let mut payload = Vec::new();
        payload.push(0); // empty authzid
        payload.extend_from_slice(login.as_bytes());
        payload.push(0);
        payload.extend_from_slice(password.expose_secret().as_bytes());

        let encoded = Command::Auth {
            mechanism: AuthMechanism::Plain,
            initial_response: Some(SecretBox::new(Box::new(payload.into_boxed_slice()))),
        }
        .to_bytes();
        trace!("AUTH PLAIN command to send: {} bytes", encoded.len());

        Self {
            state: State::Write(SmtpWrite::new(encoded)),
            domain: Some(domain.into_static()),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpAuthenticatePlainResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpAuthenticatePlainResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        return SmtpAuthenticatePlainResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpAuthenticatePlainResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        return SmtpAuthenticatePlainResult::Err { err: err.into() };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::Read(SmtpRead::new());
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Ok(response) => {
                                let response: Response<'static> = response.into_static();

                                if response.code == ReplyCode::AUTH_SUCCESSFUL {
                                    let domain = self.domain.take().unwrap();
                                    self.state = State::Ehlo(SmtpEhlo::new(domain));
                                    continue;
                                } else {
                                    let message = response.text().to_string();
                                    return SmtpAuthenticatePlainResult::Err {
                                        err: SmtpAuthenticatePlainError::Rejected {
                                            code: response.code.code(),
                                            message,
                                        },
                                    };
                                }
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");
                                return SmtpAuthenticatePlainResult::Err {
                                    err: SmtpAuthenticatePlainError::ParseResponse(reason),
                                };
                            }
                        }
                    }
                },
                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Io { input } => {
                        return SmtpAuthenticatePlainResult::Io { input };
                    }
                    SmtpEhloResult::Ok { .. } => {
                        return SmtpAuthenticatePlainResult::Ok;
                    }
                    SmtpEhloResult::Err { err } => {
                        return SmtpAuthenticatePlainResult::Err { err: err.into() };
                    }
                },
            }
        }
    }
}
