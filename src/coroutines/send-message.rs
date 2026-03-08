//! I/O-free coroutine to read greeting then capabilities of an SMTP
//! server.

use std::collections::VecDeque;

use io_stream::io::StreamIo;
use smtp_codec::smtp_types::{
    core::{ForwardPath, ReversePath},
    IntoStatic,
};
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::{data::*, mail::*, rcpt::*},
};

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum SendSmtpMessageError {
    #[error(transparent)]
    MailFrom(#[from] SmtpMailError),
    #[error(transparent)]
    RcptTo(#[from] SmtpRcptError),
    #[error(transparent)]
    Data(#[from] SmtpDataError),
}

enum State {
    MailFrom(SmtpMail),
    PrepareRcptTo(Option<SmtpContext>),
    RcptTo(SmtpRcpt),
    Data(SmtpData),
}

/// Output emitted when the coroutine terminates its progression.
#[derive(Debug)]
pub enum SendSmtpMessageResult {
    Io {
        io: StreamIo,
    },
    Ok {
        context: SmtpContext,
    },
    Err {
        context: SmtpContext,
        err: SendSmtpMessageError,
    },
}

/// I/O-free coroutine to read greeting then capabilities of an SMTP
/// server.
pub struct SendSmtpMessage {
    state: State,
    forward_paths: VecDeque<ForwardPath<'static>>,
    message: Option<Vec<u8>>,
}

impl SendSmtpMessage {
    /// Creates a new coroutine.
    pub fn new<'a>(
        context: SmtpContext,
        reverse_path: ReversePath,
        forward_paths: impl IntoIterator<Item = ForwardPath<'a>>,
        message: Vec<u8>,
    ) -> Self {
        let coroutine = SmtpMail::new(context, reverse_path.into_static());
        let forward_paths = forward_paths
            .into_iter()
            .map(IntoStatic::into_static)
            .collect();

        Self {
            state: State::MailFrom(coroutine),
            forward_paths,
            message: Some(message),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SendSmtpMessageResult {
        loop {
            match &mut self.state {
                State::MailFrom(coroutine) => {
                    let context = match coroutine.resume(arg.take()) {
                        SmtpMailResult::Io { io } => break SendSmtpMessageResult::Io { io },
                        SmtpMailResult::Ok { context, .. } => context,
                        SmtpMailResult::Err { context, err } => {
                            break SendSmtpMessageResult::Err {
                                context,
                                err: err.into(),
                            }
                        }
                    };

                    self.state = State::PrepareRcptTo(Some(context));
                }
                State::PrepareRcptTo(context) => {
                    let context = context.take().unwrap();
                    self.state = match self.forward_paths.pop_front() {
                        Some(path) => State::RcptTo(SmtpRcpt::new(context, path)),
                        None => State::Data(SmtpData::new(context, self.message.take().unwrap())),
                    };
                }
                State::RcptTo(coroutine) => {
                    let context = match coroutine.resume(arg.take()) {
                        SmtpRcptResult::Io { io } => break SendSmtpMessageResult::Io { io },
                        SmtpRcptResult::Ok { context, .. } => context,
                        SmtpRcptResult::Err { context, err } => {
                            break SendSmtpMessageResult::Err {
                                context,
                                err: err.into(),
                            }
                        }
                    };

                    self.state = State::PrepareRcptTo(Some(context));
                }
                State::Data(coroutine) => {
                    let context = match coroutine.resume(arg.take()) {
                        SmtpDataResult::Io { io } => break SendSmtpMessageResult::Io { io },
                        SmtpDataResult::Ok { context, .. } => context,
                        SmtpDataResult::Err { context, err } => {
                            break SendSmtpMessageResult::Err {
                                context,
                                err: err.into(),
                            }
                        }
                    };

                    break SendSmtpMessageResult::Ok { context };
                }
            }
        }
    }
}
