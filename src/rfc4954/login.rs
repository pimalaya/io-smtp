//! I/O-free coroutine to authenticate using SMTP AUTH LOGIN then refresh
//! capabilities via EHLO.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use bounded_static::IntoBoundedStatic;
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{
    read::{SmtpRead, SmtpReadError, SmtpReadResult},
    rfc4954::types::{auth_mechanism::AuthMechanism, authenticate_data::AuthenticateData},
    rfc5321::{
        ehlo::*,
        types::{
            command::Command, ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response,
        },
    },
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// Errors that can occur during AUTH LOGIN.
#[derive(Debug, Error)]
pub enum SmtpAuthenticateLoginError {
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH LOGIN rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpAuthenticateLoginResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpAuthenticateLoginError },
}

enum State {
    AuthWrite(SmtpWrite),
    AuthRead(SmtpRead),
    UsernameWrite(SmtpWrite),
    UsernameRead(SmtpRead),
    PasswordWrite(SmtpWrite),
    PasswordRead(SmtpRead),
    Ehlo(SmtpEhlo),
}

/// I/O-free coroutine to authenticate using SMTP AUTH LOGIN then refresh
/// capabilities via EHLO.
pub struct SmtpAuthenticateLogin {
    state: State,
    domain: Option<EhloDomain<'static>>,
    username_bytes: Vec<u8>,
    password_bytes: Vec<u8>,
    buffer: Vec<u8>,
}

impl SmtpAuthenticateLogin {
    /// Creates a new AUTH LOGIN coroutine.
    pub fn new(login: &str, password: &SecretString, domain: EhloDomain<'_>) -> Self {
        let encoded = Command::Auth {
            mechanism: AuthMechanism::Login,
            initial_response: None,
        }
        .to_bytes();
        trace!("AUTH LOGIN command to send: {} bytes", encoded.len());

        let username_bytes = AuthenticateData::r#continue(login.as_bytes()).to_bytes();
        let password_bytes =
            AuthenticateData::r#continue(password.expose_secret().as_bytes()).to_bytes();

        Self {
            state: State::AuthWrite(SmtpWrite::new(encoded)),
            domain: Some(domain.into_static()),
            username_bytes,
            password_bytes,
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpAuthenticateLoginResult {
        loop {
            match &mut self.state {
                State::AuthWrite(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::AuthRead(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpAuthenticateLoginResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        return SmtpAuthenticateLoginResult::Err { err: err.into() };
                    }
                },
                State::AuthRead(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpAuthenticateLoginResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        return SmtpAuthenticateLoginResult::Err { err: err.into() };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::AuthRead(SmtpRead::new());
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Ok(response) => {
                                let response = response.into_static();
                                if response.code == ReplyCode::AUTH_CONTINUE {
                                    self.buffer.clear();
                                    let username = core::mem::take(&mut self.username_bytes);
                                    self.state = State::UsernameWrite(SmtpWrite::new(username));
                                    continue;
                                } else {
                                    let message = response.text().to_string();
                                    return SmtpAuthenticateLoginResult::Err {
                                        err: SmtpAuthenticateLoginError::Rejected {
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
                                return SmtpAuthenticateLoginResult::Err {
                                    err: SmtpAuthenticateLoginError::ParseResponse(reason),
                                };
                            }
                        }
                    }
                },
                State::UsernameWrite(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::UsernameRead(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpAuthenticateLoginResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        return SmtpAuthenticateLoginResult::Err { err: err.into() };
                    }
                },
                State::UsernameRead(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpAuthenticateLoginResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        return SmtpAuthenticateLoginResult::Err { err: err.into() };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::UsernameRead(SmtpRead::new());
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Ok(response) => {
                                let response = response.into_static();
                                if response.code == ReplyCode::AUTH_CONTINUE {
                                    self.buffer.clear();
                                    let password = core::mem::take(&mut self.password_bytes);
                                    self.state = State::PasswordWrite(SmtpWrite::new(password));
                                    continue;
                                } else {
                                    let message = response.text().to_string();
                                    return SmtpAuthenticateLoginResult::Err {
                                        err: SmtpAuthenticateLoginError::Rejected {
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
                                return SmtpAuthenticateLoginResult::Err {
                                    err: SmtpAuthenticateLoginError::ParseResponse(reason),
                                };
                            }
                        }
                    }
                },
                State::PasswordWrite(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::PasswordRead(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpAuthenticateLoginResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        return SmtpAuthenticateLoginResult::Err { err: err.into() };
                    }
                },
                State::PasswordRead(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpAuthenticateLoginResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        return SmtpAuthenticateLoginResult::Err { err: err.into() };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::PasswordRead(SmtpRead::new());
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Ok(response) => {
                                let response = response.into_static();
                                if response.code == ReplyCode::AUTH_SUCCESSFUL {
                                    let domain = self.domain.take().unwrap();
                                    self.state = State::Ehlo(SmtpEhlo::new(domain));
                                    continue;
                                } else {
                                    let message = response.text().to_string();
                                    return SmtpAuthenticateLoginResult::Err {
                                        err: SmtpAuthenticateLoginError::Rejected {
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
                                return SmtpAuthenticateLoginResult::Err {
                                    err: SmtpAuthenticateLoginError::ParseResponse(reason),
                                };
                            }
                        }
                    }
                },
                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Io { input } => {
                        return SmtpAuthenticateLoginResult::Io { input };
                    }
                    SmtpEhloResult::Ok { .. } => {
                        return SmtpAuthenticateLoginResult::Ok;
                    }
                    SmtpEhloResult::Err { err } => {
                        return SmtpAuthenticateLoginResult::Err { err: err.into() };
                    }
                },
            }
        }
    }
}
