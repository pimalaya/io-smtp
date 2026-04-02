//! I/O-free coroutine to authenticate an SMTP session.

use std::collections::VecDeque;

use io_stream::io::StreamIo;
use log::debug;
use secrecy::SecretString;
use thiserror::Error;

use crate::rfc5321::types::ehlo_domain::EhloDomain;

use super::{
    login::{SmtpAuthenticateLogin, SmtpAuthenticateLoginError, SmtpAuthenticateLoginResult},
    plain::{SmtpAuthenticatePlain, SmtpAuthenticatePlainError, SmtpAuthenticatePlainResult},
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpAuthenticateError {
    #[error("At least one SASL candidate is required to perform SMTP authentication")]
    MissingCandidate,

    #[error(transparent)]
    Plain(#[from] SmtpAuthenticatePlainError),
    #[error(transparent)]
    Login(#[from] SmtpAuthenticateLoginError),

    #[error(transparent)]
    Attempted(#[from] Box<Self>),
}

/// Output emitted when the coroutine terminates its progression.
#[derive(Debug)]
pub enum SmtpAuthenticateResult {
    Io { io: StreamIo },
    Ok,
    Err { err: SmtpAuthenticateError },
}

pub enum SmtpAuthenticateCandidate {
    Plain {
        login: String,
        password: SecretString,
        domain: EhloDomain<'static>,
    },
    Login {
        login: String,
        password: SecretString,
        domain: EhloDomain<'static>,
    },
}

enum State {
    Unauthenticated,
    Plain(SmtpAuthenticatePlain),
    Login(SmtpAuthenticateLogin),
}

/// I/O-free coroutine to authenticate an SMTP session.
pub struct SmtpAuthenticate {
    state: State,
    candidates: VecDeque<SmtpAuthenticateCandidate>,
    err: Option<SmtpAuthenticateError>,
}

impl SmtpAuthenticate {
    /// Creates a new coroutine.
    pub fn new(candidates: impl IntoIterator<Item = SmtpAuthenticateCandidate>) -> Self {
        let mut candidates: VecDeque<_> = candidates.into_iter().collect();
        let state = Self::build_state_from_candidate(candidates.pop_front());

        Self {
            state,
            candidates,
            err: None,
        }
    }

    fn build_state_from_candidate(candidate: Option<SmtpAuthenticateCandidate>) -> State {
        match candidate {
            None => {
                debug!("no more SASL method available");
                State::Unauthenticated
            }
            Some(SmtpAuthenticateCandidate::Plain {
                login,
                password,
                domain,
            }) => {
                debug!("try SMTP PLAIN SASL method");
                State::Plain(SmtpAuthenticatePlain::new(&login, &password, domain))
            }
            Some(SmtpAuthenticateCandidate::Login {
                login,
                password,
                domain,
            }) => {
                debug!("try SMTP LOGIN SASL method");
                State::Login(SmtpAuthenticateLogin::new(&login, &password, domain))
            }
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpAuthenticateResult {
        loop {
            match &mut self.state {
                State::Plain(coroutine) => match coroutine.resume(arg.take()) {
                    SmtpAuthenticatePlainResult::Io { io } => {
                        break SmtpAuthenticateResult::Io { io };
                    }
                    SmtpAuthenticatePlainResult::Ok => {
                        break SmtpAuthenticateResult::Ok;
                    }
                    SmtpAuthenticatePlainResult::Err { err } => {
                        let err = SmtpAuthenticateError::Plain(err);
                        let err = SmtpAuthenticateError::Attempted(err.into());
                        self.err.replace(err);

                        let candidate = self.candidates.pop_front();
                        self.state = Self::build_state_from_candidate(candidate);
                        continue;
                    }
                },
                State::Login(coroutine) => match coroutine.resume(arg.take()) {
                    SmtpAuthenticateLoginResult::Io { io } => {
                        break SmtpAuthenticateResult::Io { io };
                    }
                    SmtpAuthenticateLoginResult::Ok => {
                        break SmtpAuthenticateResult::Ok;
                    }
                    SmtpAuthenticateLoginResult::Err { err } => {
                        let err = SmtpAuthenticateError::Login(err);
                        let err = SmtpAuthenticateError::Attempted(err.into());
                        self.err.replace(err);

                        let candidate = self.candidates.pop_front();
                        self.state = Self::build_state_from_candidate(candidate);
                        continue;
                    }
                },
                State::Unauthenticated => {
                    break match self.err.take() {
                        Some(err) => SmtpAuthenticateResult::Err {
                            err: SmtpAuthenticateError::Attempted(err.into()),
                        },
                        None => SmtpAuthenticateResult::Err {
                            err: SmtpAuthenticateError::MissingCandidate,
                        },
                    };
                }
            }
        }
    }
}
