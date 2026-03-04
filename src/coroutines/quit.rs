//! I/O-free coroutine to send SMTP QUIT command.

use io_stream::io::StreamIo;
use smtp_codec::smtp_types::{command::Command, response::ReplyCode, state::State};
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::send::{SendSmtpCommand, SendSmtpCommandError, SendSmtpCommandResult},
};

/// Errors that can occur during QUIT.
#[derive(Clone, Debug, Error)]
pub enum SmtpQuitError {
    #[error("QUIT rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Send QUIT command error")]
    Send(#[from] SendSmtpCommandError),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpQuitResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err { context: SmtpContext, err: SmtpQuitError },
}

/// I/O-free coroutine to send SMTP QUIT command.
pub struct SmtpQuit {
    send: SendSmtpCommand,
}

impl SmtpQuit {
    /// Creates a new QUIT coroutine.
    pub fn new(context: SmtpContext) -> Self {
        let command = Command::quit();
        Self {
            send: SendSmtpCommand::new(context, &command),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<StreamIo>) -> SmtpQuitResult {
        match self.send.resume(arg) {
            SendSmtpCommandResult::Io { io } => SmtpQuitResult::Io { io },
            SendSmtpCommandResult::Ok { mut context, response } => {
                // 221 = SERVICE_CLOSING
                if response.code == ReplyCode::SERVICE_CLOSING {
                    context.state = State::Quit;
                    SmtpQuitResult::Ok { context }
                } else {
                    let message = response.text().inner().to_string();
                    SmtpQuitResult::Err {
                        context,
                        err: SmtpQuitError::Rejected {
                            code: response.code.code(),
                            message,
                        },
                    }
                }
            }
            SendSmtpCommandResult::Err { context, err } => SmtpQuitResult::Err {
                context,
                err: err.into(),
            },
        }
    }
}
