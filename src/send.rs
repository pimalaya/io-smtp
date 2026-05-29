//! I/O-free coroutine to send a complete SMTP message.

use alloc::{collections::VecDeque, vec::Vec};

use bounded_static::IntoBoundedStatic;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::{
        data::{SmtpData, SmtpDataError},
        mail::{SmtpMail, SmtpMailError},
        rcpt::{SmtpRcpt, SmtpRcptError},
        types::{forward_path::ForwardPath, reverse_path::ReversePath},
    },
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum SmtpMessageSendError {
    #[error(transparent)]
    MailFrom(#[from] SmtpMailError),
    #[error(transparent)]
    RcptTo(#[from] SmtpRcptError),
    #[error(transparent)]
    Data(#[from] SmtpDataError),
}

enum State {
    MailFrom(SmtpMail),
    PrepareRcptTo,
    RcptTo(SmtpRcpt),
    Data(SmtpData),
}

/// I/O-free coroutine to send a complete SMTP message.
pub struct SmtpMessageSend {
    state: State,
    forward_paths: VecDeque<ForwardPath<'static>>,
    message: Option<Vec<u8>>,
}

impl SmtpMessageSend {
    /// Creates a new coroutine.
    pub fn new<'a>(
        reverse_path: ReversePath,
        forward_paths: impl IntoIterator<Item = ForwardPath<'a>>,
        message: Vec<u8>,
    ) -> Self {
        let coroutine = SmtpMail::new(reverse_path.into_static());
        let forward_paths = forward_paths
            .into_iter()
            .map(IntoBoundedStatic::into_static)
            .collect();

        Self {
            state: State::MailFrom(coroutine),
            forward_paths,
            message: Some(message),
        }
    }
}

impl SmtpCoroutine for SmtpMessageSend {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpMessageSendError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::MailFrom(mail) => match mail.resume(arg.take()) {
                    SmtpCoroutineState::Complete(Ok(())) => self.state = State::PrepareRcptTo,
                    SmtpCoroutineState::Complete(Err(err)) => {
                        return SmtpCoroutineState::Complete(Err(SmtpMessageSendError::MailFrom(
                            err,
                        )));
                    }
                    SmtpCoroutineState::Yielded(y) => return SmtpCoroutineState::Yielded(y),
                },
                State::PrepareRcptTo => {
                    self.state = match self.forward_paths.pop_front() {
                        Some(path) => State::RcptTo(SmtpRcpt::new(path)),
                        None => {
                            let body = self.message.take().expect("message taken twice");
                            State::Data(SmtpData::new(body))
                        }
                    };
                }
                State::RcptTo(rcpt) => match rcpt.resume(arg.take()) {
                    SmtpCoroutineState::Complete(Ok(())) => self.state = State::PrepareRcptTo,
                    SmtpCoroutineState::Complete(Err(err)) => {
                        return SmtpCoroutineState::Complete(Err(SmtpMessageSendError::RcptTo(
                            err,
                        )));
                    }
                    SmtpCoroutineState::Yielded(y) => return SmtpCoroutineState::Yielded(y),
                },
                State::Data(data) => match data.resume(arg.take()) {
                    SmtpCoroutineState::Complete(Ok(())) => {
                        return SmtpCoroutineState::Complete(Ok(()));
                    }
                    SmtpCoroutineState::Complete(Err(err)) => {
                        return SmtpCoroutineState::Complete(Err(SmtpMessageSendError::Data(err)));
                    }
                    SmtpCoroutineState::Yielded(y) => return SmtpCoroutineState::Yielded(y),
                },
            }
        }
    }
}
