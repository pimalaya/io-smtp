//! I/O-free coroutine to authenticate using SMTP AUTH PLAIN then refresh
//! capabilities via EHLO.

use alloc::{
    borrow::Cow,
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
    rfc4954::authenticate_data::SmtpAuthCommand,
    rfc5321::{
        ehlo::*,
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response},
    },
    utils::escape_byte_string,
    write::{SmtpWrite, SmtpWriteError, SmtpWriteResult},
};

/// The SASL mechanism name as it appears on the wire.
pub const PLAIN: &str = "PLAIN";

/// Errors that can occur during AUTH PLAIN.
#[derive(Debug, Error)]
pub enum SmtpPlainError {
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
pub enum SmtpPlainResult {
    Io { input: SocketInput },
    Ok,
    Err { err: SmtpPlainError },
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
pub struct SmtpPlain {
    state: State,
    domain: Option<EhloDomain<'static>>,
    buffer: Vec<u8>,
}

impl SmtpPlain {
    /// Creates a new AUTH PLAIN coroutine.
    ///
    /// Uses initial response (IR) to send credentials in a single round-trip.
    pub fn new(login: &str, password: &SecretString, domain: EhloDomain<'_>) -> Self {
        let mut payload = Vec::new();
        payload.push(0); // empty authzid
        payload.extend_from_slice(login.as_bytes());
        payload.push(0);
        payload.extend_from_slice(password.expose_secret().as_bytes());

        trace!("sending AUTH PLAIN command");

        Self {
            state: State::Write(SmtpWrite::new(SmtpAuthCommand {
                mechanism: Cow::Borrowed(PLAIN),
                initial_response: Some(SecretBox::new(payload.into_boxed_slice())),
            })),
            domain: Some(domain.into_static()),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpPlainResult {
        loop {
            match &mut self.state {
                State::Write(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::Read(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpPlainResult::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        return SmtpPlainResult::Err { err: err.into() };
                    }
                },
                State::Read(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpPlainResult::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        return SmtpPlainResult::Err { err: err.into() };
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
                                }

                                let code = response.code.code();
                                let message = response.text().to_string();
                                let err = SmtpPlainError::Rejected { code, message };
                                return SmtpPlainResult::Err { err };
                            }
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpPlainError::ParseResponse(reason);
                                return SmtpPlainResult::Err { err };
                            }
                        }
                    }
                },
                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Io { input } => {
                        return SmtpPlainResult::Io { input };
                    }
                    SmtpEhloResult::Ok { .. } => {
                        return SmtpPlainResult::Ok;
                    }
                    SmtpEhloResult::Err { err } => {
                        return SmtpPlainResult::Err { err: err.into() };
                    }
                },
            }
        }
    }
}
