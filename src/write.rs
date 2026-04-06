//! I/O-free primitive to write bytes to a socket.

use alloc::vec::Vec;

use io_socket::{
    coroutines::write::{SocketWrite, SocketWriteError, SocketWriteResult},
    io::{SocketInput, SocketOutput},
};
use thiserror::Error;

/// Errors that can occur during a socket write.
#[derive(Debug, Error)]
pub enum SmtpWriteError {
    #[error("Write SMTP bytes error")]
    Write(#[from] SocketWriteError),
    #[error("Write SMTP bytes error: unexpected EOF")]
    WriteEof,
}

/// Output emitted when the coroutine terminates.
pub enum SmtpWriteResult {
    Ok,
    Io { input: SocketInput },
    Err { err: SmtpWriteError },
}

/// Writes bytes to the socket.
pub struct SmtpWrite {
    state: SocketWrite,
}

impl SmtpWrite {
    /// Creates a new coroutine that will write the given bytes to the socket.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            state: SocketWrite::new(bytes.into()),
        }
    }

    pub fn resume(&mut self, arg: Option<SocketOutput>) -> SmtpWriteResult {
        match self.state.resume(arg) {
            SocketWriteResult::Ok { .. } => SmtpWriteResult::Ok,
            SocketWriteResult::Io { input } => SmtpWriteResult::Io { input },
            SocketWriteResult::Eof => SmtpWriteResult::Err {
                err: SmtpWriteError::WriteEof,
            },
            SocketWriteResult::Err { err } => SmtpWriteResult::Err {
                err: SmtpWriteError::Write(err),
            },
        }
    }
}
