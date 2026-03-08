//! I/O-free coroutine to authenticate using SMTP AUTH PLAIN then
//! refresh capabilities via EHLO.

use io_stream::io::StreamIo;
use secrecy::SecretString;
use smtp_codec::smtp_types::{core::EhloDomain, IntoStatic};
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::{authenticate_plain::*, ehlo::*},
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum SmtpAuthenticatePlainWithCapabilityError {
    #[error(transparent)]
    Authenticate(#[from] SmtpAuthenticatePlainError),
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

enum State {
    Authenticate(SmtpAuthenticatePlain),
    Ehlo(SmtpEhlo),
}

/// Output emitted when the coroutine terminates its progression.
pub enum SmtpAuthenticatePlainWithCapabilityResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err {
        context: SmtpContext,
        err: SmtpAuthenticatePlainWithCapabilityError,
    },
}

/// I/O-free coroutine to authenticate using SMTP AUTH PLAIN then
/// refresh capabilities via EHLO.
pub struct SmtpAuthenticatePlainWithCapability {
    state: State,
    domain: Option<EhloDomain<'static>>,
}

impl SmtpAuthenticatePlainWithCapability {
    /// Creates a new coroutine.
    pub fn new(
        context: SmtpContext,
        login: &str,
        password: &SecretString,
        domain: EhloDomain,
    ) -> Self {
        Self {
            state: State::Authenticate(SmtpAuthenticatePlain::new(context, login, password)),
            domain: Some(domain.into_static()),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpAuthenticatePlainWithCapabilityResult {
        loop {
            match &mut self.state {
                State::Authenticate(auth) => {
                    let context = match auth.resume(arg.take()) {
                        SmtpAuthenticatePlainResult::Io { io } => {
                            break SmtpAuthenticatePlainWithCapabilityResult::Io { io }
                        }
                        SmtpAuthenticatePlainResult::Ok { context } => context,
                        SmtpAuthenticatePlainResult::Err { context, err } => {
                            break SmtpAuthenticatePlainWithCapabilityResult::Err {
                                context,
                                err: err.into(),
                            }
                        }
                    };

                    let domain = self.domain.take().unwrap();
                    self.state = State::Ehlo(SmtpEhlo::new(context, domain));
                }
                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Io { io } => {
                        break SmtpAuthenticatePlainWithCapabilityResult::Io { io }
                    }
                    SmtpEhloResult::Ok { context } => {
                        break SmtpAuthenticatePlainWithCapabilityResult::Ok { context }
                    }
                    SmtpEhloResult::Err { context, err } => {
                        break SmtpAuthenticatePlainWithCapabilityResult::Err {
                            context,
                            err: err.into(),
                        }
                    }
                },
            }
        }
    }
}
