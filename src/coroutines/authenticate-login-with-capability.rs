//! I/O-free coroutine to authenticate using SMTP AUTH LOGIN then
//! refresh capabilities via EHLO.

use io_stream::io::StreamIo;
use secrecy::SecretString;
use smtp_codec::smtp_types::{core::EhloDomain, IntoStatic};
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::{authenticate_login::*, ehlo::*},
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum SmtpAuthenticateLoginWithCapabilityError {
    #[error(transparent)]
    Authenticate(#[from] SmtpAuthenticateLoginError),
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

enum State {
    Authenticate(SmtpAuthenticateLogin),
    Ehlo(SmtpEhlo),
}

/// Output emitted when the coroutine terminates its progression.
pub enum SmtpAuthenticateLoginWithCapabilityResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err {
        context: SmtpContext,
        err: SmtpAuthenticateLoginWithCapabilityError,
    },
}

/// I/O-free coroutine to authenticate using SMTP AUTH LOGIN then
/// refresh capabilities via EHLO.
pub struct SmtpAuthenticateLoginWithCapability {
    state: State,
    domain: Option<EhloDomain<'static>>,
}

impl SmtpAuthenticateLoginWithCapability {
    /// Creates a new coroutine.
    pub fn new(
        context: SmtpContext,
        login: &str,
        password: &SecretString,
        domain: EhloDomain,
    ) -> Self {
        Self {
            state: State::Authenticate(SmtpAuthenticateLogin::new(context, login, password)),
            domain: Some(domain.into_static()),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(
        &mut self,
        mut arg: Option<StreamIo>,
    ) -> SmtpAuthenticateLoginWithCapabilityResult {
        loop {
            match &mut self.state {
                State::Authenticate(auth) => {
                    let context = match auth.resume(arg.take()) {
                        SmtpAuthenticateLoginResult::Io { io } => {
                            break SmtpAuthenticateLoginWithCapabilityResult::Io { io }
                        }
                        SmtpAuthenticateLoginResult::Ok { context } => context,
                        SmtpAuthenticateLoginResult::Err { context, err } => {
                            break SmtpAuthenticateLoginWithCapabilityResult::Err {
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
                        break SmtpAuthenticateLoginWithCapabilityResult::Io { io }
                    }
                    SmtpEhloResult::Ok { context } => {
                        break SmtpAuthenticateLoginWithCapabilityResult::Ok { context }
                    }
                    SmtpEhloResult::Err { context, err } => {
                        break SmtpAuthenticateLoginWithCapabilityResult::Err {
                            context,
                            err: err.into(),
                        }
                    }
                },
            }
        }
    }
}
