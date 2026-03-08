//! I/O-free coroutine to read greeting then capabilities of an SMTP
//! server.

use io_stream::io::StreamIo;
use smtp_codec::smtp_types::{core::EhloDomain, IntoStatic};
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::{ehlo::*, greeting::*},
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum GetSmtpGreetingWithCapabilityError {
    #[error(transparent)]
    Greeting(#[from] GetSmtpGreetingError),
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

enum State {
    Greeting(GetSmtpGreeting),
    Ehlo(SmtpEhlo),
}

/// Output emitted when the coroutine terminates its progression.
#[derive(Debug)]
pub enum GetSmtpGreetingWithCapabilityResult {
    Io {
        io: StreamIo,
    },
    Ok {
        context: SmtpContext,
    },
    Err {
        context: SmtpContext,
        err: GetSmtpGreetingWithCapabilityError,
    },
}

/// I/O-free coroutine to read greeting then capabilities of an SMTP
/// server.
pub struct GetSmtpGreetingWithCapability {
    state: State,
    domain: Option<EhloDomain<'static>>,
}

impl GetSmtpGreetingWithCapability {
    /// Creates a new coroutine.
    pub fn new(context: SmtpContext, domain: EhloDomain) -> Self {
        Self {
            state: State::Greeting(GetSmtpGreeting::new(context)),
            domain: Some(domain.into_static()),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> GetSmtpGreetingWithCapabilityResult {
        loop {
            match &mut self.state {
                State::Greeting(greeting) => {
                    let context = match greeting.resume(arg.take()) {
                        GetSmtpGreetingResult::Io { io } => {
                            break GetSmtpGreetingWithCapabilityResult::Io { io }
                        }
                        GetSmtpGreetingResult::Ok { context, .. } => context,
                        GetSmtpGreetingResult::Err { context, err } => {
                            break GetSmtpGreetingWithCapabilityResult::Err {
                                context,
                                err: err.into(),
                            }
                        }
                    };

                    let domain = self.domain.take().unwrap();
                    self.state = State::Ehlo(SmtpEhlo::new(context, domain));
                }
                State::Ehlo(capability) => match capability.resume(arg.take()) {
                    SmtpEhloResult::Io { io } => {
                        break GetSmtpGreetingWithCapabilityResult::Io { io }
                    }
                    SmtpEhloResult::Ok { context } => {
                        break GetSmtpGreetingWithCapabilityResult::Ok { context };
                    }
                    SmtpEhloResult::Err { context, err } => {
                        break GetSmtpGreetingWithCapabilityResult::Err {
                            context,
                            err: err.into(),
                        }
                    }
                },
            }
        }
    }
}
