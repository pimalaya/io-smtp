//! I/O-free coroutine to send a complete SMTP message.

use alloc::{collections::VecDeque, vec::Vec};

use bounded_static::IntoBoundedStatic;
use thiserror::Error;

use crate::rfc5321::{
    data::{SmtpData, SmtpDataError, SmtpDataResult},
    mail::{SmtpMail, SmtpMailError, SmtpMailResult},
    rcpt::{SmtpRcpt, SmtpRcptError, SmtpRcptResult},
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

/// Result returned by [`SmtpMessageSend::resume`].
#[derive(Debug)]
pub enum SmtpMessageSendResult {
    Ok,
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SmtpMessageSendError),
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

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpMessageSendResult {
        loop {
            match &mut self.state {
                State::MailFrom(mail) => match mail.resume(arg.take()) {
                    SmtpMailResult::Ok => self.state = State::PrepareRcptTo,
                    SmtpMailResult::WantsRead => return SmtpMessageSendResult::WantsRead,
                    SmtpMailResult::WantsWrite(bytes) => {
                        return SmtpMessageSendResult::WantsWrite(bytes);
                    }
                    SmtpMailResult::Err(err) => {
                        return SmtpMessageSendResult::Err(SmtpMessageSendError::MailFrom(err));
                    }
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
                    SmtpRcptResult::Ok => self.state = State::PrepareRcptTo,
                    SmtpRcptResult::WantsRead => return SmtpMessageSendResult::WantsRead,
                    SmtpRcptResult::WantsWrite(bytes) => {
                        return SmtpMessageSendResult::WantsWrite(bytes);
                    }
                    SmtpRcptResult::Err(err) => {
                        return SmtpMessageSendResult::Err(SmtpMessageSendError::RcptTo(err));
                    }
                },
                State::Data(data) => match data.resume(arg.take()) {
                    SmtpDataResult::Ok => return SmtpMessageSendResult::Ok,
                    SmtpDataResult::WantsRead => return SmtpMessageSendResult::WantsRead,
                    SmtpDataResult::WantsWrite(bytes) => {
                        return SmtpMessageSendResult::WantsWrite(bytes);
                    }
                    SmtpDataResult::Err(err) => {
                        return SmtpMessageSendResult::Err(SmtpMessageSendError::Data(err));
                    }
                },
            }
        }
    }
}
