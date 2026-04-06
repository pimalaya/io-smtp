//! I/O-free coroutine to send a complete SMTP message.

use alloc::{collections::VecDeque, vec::Vec};

use bounded_static::IntoBoundedStatic;
use io_socket::io::{SocketInput, SocketOutput};
use thiserror::Error;

use crate::rfc5321::{
    data::*,
    mail::*,
    rcpt::*,
    types::{forward_path::ForwardPath, reverse_path::ReversePath},
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

/// Output emitted when the coroutine terminates its progression.
#[derive(Debug)]
pub enum SmtpMessageSendResult {
    Ok,
    Io { input: SocketInput },
    Err { err: SmtpMessageSendError },
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

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpMessageSendResult {
        loop {
            match &mut self.state {
                State::MailFrom(coroutine) => {
                    match coroutine.resume(arg.take()) {
                        SmtpMailResult::Io { input } => {
                            break SmtpMessageSendResult::Io { input };
                        }
                        SmtpMailResult::Ok => (),
                        SmtpMailResult::Err { err } => {
                            break SmtpMessageSendResult::Err { err: err.into() };
                        }
                    };

                    self.state = State::PrepareRcptTo;
                }
                State::PrepareRcptTo => {
                    self.state = match self.forward_paths.pop_front() {
                        Some(path) => State::RcptTo(SmtpRcpt::new(path)),
                        None => State::Data(SmtpData::new(self.message.take().unwrap())),
                    };
                }
                State::RcptTo(coroutine) => {
                    match coroutine.resume(arg.take()) {
                        SmtpRcptResult::Io { input } => {
                            break SmtpMessageSendResult::Io { input };
                        }
                        SmtpRcptResult::Ok => (),
                        SmtpRcptResult::Err { err } => {
                            break SmtpMessageSendResult::Err { err: err.into() };
                        }
                    };

                    self.state = State::PrepareRcptTo;
                }
                State::Data(coroutine) => {
                    match coroutine.resume(arg.take()) {
                        SmtpDataResult::Io { input } => {
                            break SmtpMessageSendResult::Io { input };
                        }
                        SmtpDataResult::Ok => break SmtpMessageSendResult::Ok,
                        SmtpDataResult::Err { err } => {
                            break SmtpMessageSendResult::Err { err: err.into() };
                        }
                    };
                }
            }
        }
    }
}
