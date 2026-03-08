//! I/O-free coroutine to authenticate an SMTP session.

use std::collections::VecDeque;

use io_stream::io::StreamIo;
use log::debug;
use secrecy::SecretString;
use smtp_codec::smtp_types::core::EhloDomain;
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::{
        authenticate_login_with_capability::*,
        authenticate_plain_with_capability::*,
    },
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpAuthenticateError {
    #[error("At least one SASL candidate is required to perform SMTP authentication")]
    MissingCandidate,

    #[error(transparent)]
    Plain(#[from] SmtpAuthenticatePlainWithCapabilityError),
    #[error(transparent)]
    Login(#[from] SmtpAuthenticateLoginWithCapabilityError),

    #[error(transparent)]
    Attempted(#[from] Box<Self>),
}

/// Output emitted when the coroutine terminates its progression.
#[derive(Debug)]
pub enum SmtpAuthenticateResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err {
        context: SmtpContext,
        err: SmtpAuthenticateError,
    },
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
    Unauthenticated(Option<SmtpContext>),
    Plain(SmtpAuthenticatePlainWithCapability),
    Login(SmtpAuthenticateLoginWithCapability),
}

/// I/O-free coroutine to authenticate an SMTP session.
pub struct SmtpAuthenticate {
    state: State,
    candidates: VecDeque<SmtpAuthenticateCandidate>,
    err: Option<SmtpAuthenticateError>,
}

impl SmtpAuthenticate {
    /// Creates a new coroutine.
    pub fn new(
        context: SmtpContext,
        candidates: impl IntoIterator<Item = SmtpAuthenticateCandidate>,
    ) -> Self {
        let mut candidates: VecDeque<_> = candidates.into_iter().collect();
        let candidate = candidates.pop_front();
        let state = Self::build_state_from_candidate(context, candidate);

        Self {
            state,
            candidates,
            err: None,
        }
    }

    fn build_state_from_candidate(
        context: SmtpContext,
        candidate: Option<SmtpAuthenticateCandidate>,
    ) -> State {
        match candidate {
            None => {
                debug!("no more SASL method available");
                State::Unauthenticated(Some(context))
            }
            Some(SmtpAuthenticateCandidate::Plain {
                login,
                password,
                domain,
            }) => {
                debug!("try SMTP PLAIN SASL method");
                State::Plain(SmtpAuthenticatePlainWithCapability::new(
                    context, &login, &password, domain,
                ))
            }
            Some(SmtpAuthenticateCandidate::Login {
                login,
                password,
                domain,
            }) => {
                debug!("try SMTP LOGIN SASL method");
                State::Login(SmtpAuthenticateLoginWithCapability::new(
                    context, &login, &password, domain,
                ))
            }
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpAuthenticateResult {
        loop {
            match &mut self.state {
                State::Plain(coroutine) => match coroutine.resume(arg.take()) {
                    SmtpAuthenticatePlainWithCapabilityResult::Io { io } => {
                        break SmtpAuthenticateResult::Io { io };
                    }
                    SmtpAuthenticatePlainWithCapabilityResult::Ok { context } => {
                        break SmtpAuthenticateResult::Ok { context };
                    }
                    SmtpAuthenticatePlainWithCapabilityResult::Err { context, err } => {
                        let err = SmtpAuthenticateError::Plain(err);
                        let err = SmtpAuthenticateError::Attempted(err.into());
                        self.err.replace(err);

                        let candidate = self.candidates.pop_front();
                        self.state = Self::build_state_from_candidate(context, candidate);
                        continue;
                    }
                },
                State::Login(coroutine) => match coroutine.resume(arg.take()) {
                    SmtpAuthenticateLoginWithCapabilityResult::Io { io } => {
                        break SmtpAuthenticateResult::Io { io };
                    }
                    SmtpAuthenticateLoginWithCapabilityResult::Ok { context } => {
                        break SmtpAuthenticateResult::Ok { context };
                    }
                    SmtpAuthenticateLoginWithCapabilityResult::Err { context, err } => {
                        let err = SmtpAuthenticateError::Login(err);
                        let err = SmtpAuthenticateError::Attempted(err.into());
                        self.err.replace(err);

                        let candidate = self.candidates.pop_front();
                        self.state = Self::build_state_from_candidate(context, candidate);
                        continue;
                    }
                },
                State::Unauthenticated(context) => {
                    let context = context.take().unwrap();
                    break match self.err.take() {
                        Some(err) => SmtpAuthenticateResult::Err {
                            context,
                            err: SmtpAuthenticateError::Attempted(err.into()),
                        },
                        None => SmtpAuthenticateResult::Err {
                            context,
                            err: SmtpAuthenticateError::MissingCandidate,
                        },
                    };
                }
            }
        }
    }
}
