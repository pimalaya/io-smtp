//! I/O-free coroutine to send SMTP RCPT TO command.

use io_stream::io::StreamIo;
use smtp_codec::smtp_types::{
    command::Command,
    core::{ForwardPath, Parameter},
    response::ReplyCode,
    state::State,
};
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::send::{SendSmtpCommand, SendSmtpCommandError, SendSmtpCommandResult},
};

/// Errors that can occur during RCPT TO.
#[derive(Clone, Debug, Error)]
pub enum SmtpRcptError {
    #[error("RCPT TO rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Send RCPT TO command error")]
    Send(#[from] SendSmtpCommandError),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpRcptResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err { context: SmtpContext, err: SmtpRcptError },
}

/// I/O-free coroutine to send SMTP RCPT TO command.
pub struct SmtpRcpt {
    send: SendSmtpCommand,
}

impl SmtpRcpt {
    /// Creates a new RCPT TO coroutine.
    pub fn new(context: SmtpContext, forward_path: ForwardPath<'_>) -> Self {
        let command = Command::rcpt(forward_path);
        Self {
            send: SendSmtpCommand::new(context, &command),
        }
    }

    /// Creates a new RCPT TO coroutine with parameters.
    pub fn with_params(
        context: SmtpContext,
        forward_path: ForwardPath<'_>,
        parameters: Vec<Parameter<'_>>,
    ) -> Self {
        let command = Command::rcpt_with_params(forward_path, parameters);
        Self {
            send: SendSmtpCommand::new(context, &command),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<StreamIo>) -> SmtpRcptResult {
        match self.send.resume(arg) {
            SendSmtpCommandResult::Io { io } => SmtpRcptResult::Io { io },
            SendSmtpCommandResult::Ok { mut context, response } => {
                if response.code == ReplyCode::OK {
                    context.state = State::Rcpt;
                    SmtpRcptResult::Ok { context }
                } else {
                    let message = response.text().inner().to_string();
                    SmtpRcptResult::Err {
                        context,
                        err: SmtpRcptError::Rejected {
                            code: response.code.code(),
                            message,
                        },
                    }
                }
            }
            SendSmtpCommandResult::Err { context, err } => SmtpRcptResult::Err {
                context,
                err: err.into(),
            },
        }
    }
}
