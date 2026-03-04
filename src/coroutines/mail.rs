//! I/O-free coroutine to send SMTP MAIL FROM command.

use io_stream::io::StreamIo;
use smtp_codec::smtp_types::{
    command::Command,
    core::{Parameter, ReversePath},
    response::ReplyCode,
    state::State,
};
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::send::{SendSmtpCommand, SendSmtpCommandError, SendSmtpCommandResult},
};

/// Errors that can occur during MAIL FROM.
#[derive(Clone, Debug, Error)]
pub enum SmtpMailError {
    #[error("MAIL FROM rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Send MAIL FROM command error")]
    Send(#[from] SendSmtpCommandError),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpMailResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err { context: SmtpContext, err: SmtpMailError },
}

/// I/O-free coroutine to send SMTP MAIL FROM command.
pub struct SmtpMail {
    send: SendSmtpCommand,
}

impl SmtpMail {
    /// Creates a new MAIL FROM coroutine.
    pub fn new(context: SmtpContext, reverse_path: ReversePath<'_>) -> Self {
        let command = Command::mail(reverse_path);
        Self {
            send: SendSmtpCommand::new(context, &command),
        }
    }

    /// Creates a new MAIL FROM coroutine with parameters.
    pub fn with_params(
        context: SmtpContext,
        reverse_path: ReversePath<'_>,
        parameters: Vec<Parameter<'_>>,
    ) -> Self {
        let command = Command::mail_with_params(reverse_path, parameters);
        Self {
            send: SendSmtpCommand::new(context, &command),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<StreamIo>) -> SmtpMailResult {
        match self.send.resume(arg) {
            SendSmtpCommandResult::Io { io } => SmtpMailResult::Io { io },
            SendSmtpCommandResult::Ok { mut context, response } => {
                if response.code == ReplyCode::OK {
                    context.state = State::Mail;
                    SmtpMailResult::Ok { context }
                } else {
                    let message = response.text().inner().to_string();
                    SmtpMailResult::Err {
                        context,
                        err: SmtpMailError::Rejected {
                            code: response.code.code(),
                            message,
                        },
                    }
                }
            }
            SendSmtpCommandResult::Err { context, err } => SmtpMailResult::Err {
                context,
                err: err.into(),
            },
        }
    }
}
