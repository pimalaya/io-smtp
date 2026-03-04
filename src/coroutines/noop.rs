//! I/O-free coroutine to send SMTP NOOP command.

use io_stream::io::StreamIo;
use smtp_codec::smtp_types::{command::Command, response::ReplyCode};
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::send::{SendSmtpCommand, SendSmtpCommandError, SendSmtpCommandResult},
};

/// Errors that can occur during NOOP.
#[derive(Clone, Debug, Error)]
pub enum SmtpNoopError {
    #[error("NOOP rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Send NOOP command error")]
    Send(#[from] SendSmtpCommandError),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpNoopResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err { context: SmtpContext, err: SmtpNoopError },
}

/// I/O-free coroutine to send SMTP NOOP command.
pub struct SmtpNoop {
    send: SendSmtpCommand,
}

impl SmtpNoop {
    /// Creates a new NOOP coroutine.
    pub fn new(context: SmtpContext) -> Self {
        let command = Command::noop();
        Self {
            send: SendSmtpCommand::new(context, &command),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<StreamIo>) -> SmtpNoopResult {
        match self.send.resume(arg) {
            SendSmtpCommandResult::Io { io } => SmtpNoopResult::Io { io },
            SendSmtpCommandResult::Ok { context, response } => {
                if response.code == ReplyCode::OK {
                    SmtpNoopResult::Ok { context }
                } else {
                    let message = response.text().inner().to_string();
                    SmtpNoopResult::Err {
                        context,
                        err: SmtpNoopError::Rejected {
                            code: response.code.code(),
                            message,
                        },
                    }
                }
            }
            SendSmtpCommandResult::Err { context, err } => SmtpNoopResult::Err {
                context,
                err: err.into(),
            },
        }
    }
}
