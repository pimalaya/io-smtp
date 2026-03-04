//! I/O-free coroutine to send SMTP RSET command.

use io_stream::io::StreamIo;
use smtp_codec::smtp_types::{command::Command, response::ReplyCode, state::State};
use thiserror::Error;

use crate::{
    context::SmtpContext,
    coroutines::send::{SendSmtpCommand, SendSmtpCommandError, SendSmtpCommandResult},
};

/// Errors that can occur during RSET.
#[derive(Clone, Debug, Error)]
pub enum SmtpRsetError {
    #[error("RSET rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("Send RSET command error")]
    Send(#[from] SendSmtpCommandError),
}

/// Output emitted when the coroutine terminates.
pub enum SmtpRsetResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err { context: SmtpContext, err: SmtpRsetError },
}

/// I/O-free coroutine to send SMTP RSET command.
///
/// RSET aborts the current mail transaction and returns to Ready state.
pub struct SmtpRset {
    send: SendSmtpCommand,
}

impl SmtpRset {
    /// Creates a new RSET coroutine.
    pub fn new(context: SmtpContext) -> Self {
        let command = Command::rset();
        Self {
            send: SendSmtpCommand::new(context, &command),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<StreamIo>) -> SmtpRsetResult {
        match self.send.resume(arg) {
            SendSmtpCommandResult::Io { io } => SmtpRsetResult::Io { io },
            SendSmtpCommandResult::Ok { mut context, response } => {
                if response.code == ReplyCode::OK {
                    // Reset to Ready state
                    context.state = State::Ready;
                    SmtpRsetResult::Ok { context }
                } else {
                    let message = response.text().inner().to_string();
                    SmtpRsetResult::Err {
                        context,
                        err: SmtpRsetError::Rejected {
                            code: response.code.code(),
                            message,
                        },
                    }
                }
            }
            SendSmtpCommandResult::Err { context, err } => SmtpRsetResult::Err {
                context,
                err: err.into(),
            },
        }
    }
}
