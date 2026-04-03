//! I/O-free coroutine to authenticate using SMTP AUTH PLAIN then refresh
//! capabilities via EHLO.

use io_socket::{
    coroutines::{read::ReadSocketError, write::WriteSocketError},
    io::{SocketInput, SocketOutput},
};
use log::trace;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use thiserror::Error;

use bounded_static::IntoBoundedStatic;

use crate::{
    rfc4954::types::auth_mechanism::AuthMechanism,
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError, SmtpEhloResult},
        types::{
            command::Command, ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response,
        },
    },
    send_bytes::{SmtpBytesSend, SmtpBytesSendResult},
    utils::escape_byte_string,
};

/// Errors that can occur during AUTH PLAIN.
#[derive(Debug, Error)]
pub enum SmtpAuthenticatePlainError {
    #[error("Write AUTH PLAIN command error")]
    Write(#[from] WriteSocketError),
    #[error("Write AUTH PLAIN command error (unexpected EOF)")]
    WriteEof,
    #[error("Read AUTH PLAIN response error")]
    Read(#[from] ReadSocketError),
    #[error("Read AUTH PLAIN response error (unexpected EOF)")]
    ReadEof,
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
    Auth(SmtpBytesSend),
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
        // Build SASL PLAIN payload: authzid\0authcid\0password
        // authzid is typically empty for SMTP
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
            state: State::Auth(SmtpBytesSend::new(encoded)),
            domain: Some(domain.into_static()),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpAuthenticatePlainResult {
        loop {
            match &mut self.state {
                State::Auth(io) => match io.resume(arg.take()) {
                    SmtpBytesSendResult::Io { input } => {
                        return SmtpAuthenticatePlainResult::Io { input };
                    }
                    SmtpBytesSendResult::WriteErr { err } => {
                        return SmtpAuthenticatePlainResult::Err {
                            err: SmtpAuthenticatePlainError::Write(err),
                        };
                    }
                    SmtpBytesSendResult::WriteEof => {
                        return SmtpAuthenticatePlainResult::Err {
                            err: SmtpAuthenticatePlainError::WriteEof,
                        };
                    }
                    SmtpBytesSendResult::ReadErr { err } => {
                        return SmtpAuthenticatePlainResult::Err {
                            err: SmtpAuthenticatePlainError::Read(err),
                        };
                    }
                    SmtpBytesSendResult::ReadEof => {
                        return SmtpAuthenticatePlainResult::Err {
                            err: SmtpAuthenticatePlainError::ReadEof,
                        };
                    }
                    SmtpBytesSendResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::Auth(SmtpBytesSend::new(vec![]));
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
