//! I/O-free coroutine to authenticate using SMTP AUTH LOGIN then refresh
//! capabilities via EHLO.

use io_stream::{
    coroutines::{read::ReadStreamError, write::WriteStreamError},
    io::StreamIo,
};
use log::trace;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use bounded_static::IntoBoundedStatic;

use crate::{
    rfc4954::types::{auth_mechanism::AuthMechanism, authenticate_data::AuthenticateData},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError, SmtpEhloResult},
        types::{
            command::Command, ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response,
        },
    },
    send_bytes::{SmtpBytesSend, SmtpBytesSendResult},
    utils::escape_byte_string,
};

/// Errors that can occur during AUTH LOGIN.
#[derive(Debug, Error)]
pub enum SmtpAuthenticateLoginError {
    #[error("Write AUTH LOGIN command error")]
    Write(#[from] WriteStreamError),
    #[error("Write AUTH LOGIN command error (unexpected EOF)")]
    WriteEof,
    #[error("Read AUTH LOGIN response error")]
    Read(#[from] ReadStreamError),
    #[error("Read AUTH LOGIN response error (unexpected EOF)")]
    ReadEof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH LOGIN rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpAuthenticateLoginResult {
    Io { io: StreamIo },
    Ok,
    Err { err: SmtpAuthenticateLoginError },
}

enum State {
    Auth(SmtpBytesSend),
    Username(SmtpBytesSend),
    Password(SmtpBytesSend),
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
            state: State::Auth(SmtpBytesSend::new(encoded)),
            domain: Some(domain.into_static()),
            username_bytes,
            password_bytes,
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpAuthenticateLoginResult {
        loop {
            match &mut self.state {
                // Step 1: Send AUTH LOGIN command, read 334 response
                State::Auth(io) => match io.resume(arg.take()) {
                    SmtpBytesSendResult::Io { io } => {
                        return SmtpAuthenticateLoginResult::Io { io };
                    }
                    SmtpBytesSendResult::WriteErr { err } => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::Write(err),
                        };
                    }
                    SmtpBytesSendResult::WriteEof => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::WriteEof,
                        };
                    }
                    SmtpBytesSendResult::ReadErr { err } => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::Read(err),
                        };
                    }
                    SmtpBytesSendResult::ReadEof => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::ReadEof,
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
                                let response = response.into_static();
                                if response.code == ReplyCode::AUTH_CONTINUE {
                                    self.buffer.clear();
                                    let username = std::mem::take(&mut self.username_bytes);
                                    self.state = State::Username(SmtpBytesSend::new(username));
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

                // Step 2: Send base64(username), read 334 response
                State::Username(io) => match io.resume(arg.take()) {
                    SmtpBytesSendResult::Io { io } => {
                        return SmtpAuthenticateLoginResult::Io { io };
                    }
                    SmtpBytesSendResult::WriteErr { err } => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::Write(err),
                        };
                    }
                    SmtpBytesSendResult::WriteEof => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::WriteEof,
                        };
                    }
                    SmtpBytesSendResult::ReadErr { err } => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::Read(err),
                        };
                    }
                    SmtpBytesSendResult::ReadEof => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::ReadEof,
                        };
                    }
                    SmtpBytesSendResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::Username(SmtpBytesSend::new(vec![]));
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Ok(response) => {
                                let response = response.into_static();
                                if response.code == ReplyCode::AUTH_CONTINUE {
                                    self.buffer.clear();
                                    let password = std::mem::take(&mut self.password_bytes);
                                    self.state = State::Password(SmtpBytesSend::new(password));
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

                // Step 3: Send base64(password), read 235 response
                State::Password(io) => match io.resume(arg.take()) {
                    SmtpBytesSendResult::Io { io } => {
                        return SmtpAuthenticateLoginResult::Io { io };
                    }
                    SmtpBytesSendResult::WriteErr { err } => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::Write(err),
                        };
                    }
                    SmtpBytesSendResult::WriteEof => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::WriteEof,
                        };
                    }
                    SmtpBytesSendResult::ReadErr { err } => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::Read(err),
                        };
                    }
                    SmtpBytesSendResult::ReadEof => {
                        return SmtpAuthenticateLoginResult::Err {
                            err: SmtpAuthenticateLoginError::ReadEof,
                        };
                    }
                    SmtpBytesSendResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::Password(SmtpBytesSend::new(vec![]));
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

                // Step 4: Refresh capabilities via EHLO
                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Io { io } => {
                        return SmtpAuthenticateLoginResult::Io { io };
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
