//! AUTH LOGIN command and coroutine (no formal RFC).
//!
//! LOGIN is a legacy de-facto SASL mechanism. It performs a two-step
//! challenge/response exchange: the server asks for the username,
//! then the password, each base64-encoded. Prefer PLAIN or
//! SCRAM-SHA-256 when the server supports them.

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
    read::*,
    rfc4954::auth_data::SmtpAuthData,
    rfc5321::{
        ehlo::*,
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response},
    },
    utils::escape_byte_string,
    write::*,
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
pub enum SmtpLoginResult {
    Ok,
    Io { input: SocketInput },
    Err { err: SmtpLoginError },
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
pub struct SmtpLogin {
    state: State,
    domain: Option<EhloDomain<'static>>,
    username_bytes: Vec<u8>,
    password_bytes: Vec<u8>,
    buffer: Vec<u8>,
}

impl SmtpLogin {
    /// Creates a new AUTH LOGIN coroutine.
    pub fn new(login: &str, password: &SecretString, domain: EhloDomain<'_>) -> Self {
        trace!("sending AUTH LOGIN command");

        let username_bytes: Vec<u8> = SmtpAuthData::r#continue(login.as_bytes()).into();
        let password_bytes: Vec<u8> =
            SmtpAuthData::r#continue(password.expose_secret().as_bytes()).into();

        Self {
            state: State::AuthWrite(SmtpWrite::new(SmtpLoginCommand)),
            domain: Some(domain.into_static()),
            username_bytes,
            password_bytes,
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpLoginResult {
        loop {
            match &mut self.state {
                State::AuthWrite(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::AuthRead(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpLoginResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        let err = err.into();
                        return SmtpLoginResult::Err { err };
                    }
                },
                State::AuthRead(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpLoginResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpLoginResult::Err { err };
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
                                }

                                let message = response.text().to_string();
                                let code = response.code.code();
                                let err = SmtpLoginError::Rejected { code, message };
                                return SmtpLoginResult::Err { err };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpLoginError::ParseResponse(reason);
                                return SmtpLoginResult::Err { err };
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
                        return SmtpLoginResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        let err = err.into();
                        return SmtpLoginResult::Err { err };
                    }
                },
                State::UsernameRead(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpLoginResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpLoginResult::Err { err };
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
                                }

                                let message = response.text().to_string();
                                let code = response.code.code();
                                let err = SmtpLoginError::Rejected { code, message };
                                return SmtpLoginResult::Err { err };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpLoginError::ParseResponse(reason);
                                return SmtpLoginResult::Err { err };
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
                        return SmtpLoginResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        let err = err.into();
                        return SmtpLoginResult::Err { err };
                    }
                },
                State::PasswordRead(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpLoginResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpLoginResult::Err { err };
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
                                }

                                let message = response.text().to_string();
                                let code = response.code.code();
                                let err = SmtpLoginError::Rejected { code, message };
                                return SmtpLoginResult::Err { err };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpLoginError::ParseResponse(reason);
                                return SmtpLoginResult::Err { err };
                            }
                        }
                    }
                },
                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Io { input } => {
                        return SmtpLoginResult::Io { input };
                    }
                    SmtpEhloResult::Ok { .. } => {
                        return SmtpLoginResult::Ok;
                    }
                    SmtpEhloResult::Err { err } => {
                        let err = err.into();
                        return SmtpLoginResult::Err { err };
                    }
                },
            }
        }
    }
}
