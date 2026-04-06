//! I/O-free primitive to read bytes from a socket.

use alloc::vec::Vec;

use io_socket::{
    coroutines::read::{SocketRead, SocketReadError, SocketReadResult},
    io::{SocketInput, SocketOutput},
};
use thiserror::Error;

/// Errors that can occur during a socket read.
#[derive(Debug, Error)]
pub enum SmtpReadError {
    #[error("Read SMTP bytes error")]
    Read(#[from] SocketReadError),
    #[error("Read SMTP bytes error: unexpected EOF")]
    ReadEof,
}

/// Output emitted when the coroutine terminates.
pub enum SmtpReadResult {
    Io { input: SocketInput },
    Ok { bytes: Vec<u8> },
    Err { err: SmtpReadError },
}

/// Reads one chunk of bytes from the socket.
pub struct SmtpRead {
    state: SocketRead,
}

impl SmtpRead {
    pub fn new() -> Self {
        Self {
            state: SocketRead::new(),
        }
    }

    pub fn resume(&mut self, arg: Option<SocketOutput>) -> SmtpReadResult {
        match self.state.resume(arg) {
            SocketReadResult::Ok { mut buf, n } => {
                buf.truncate(n);
                SmtpReadResult::Ok { bytes: buf }
            }
            SocketReadResult::Io { input } => SmtpReadResult::Io { input },
            SocketReadResult::Eof => SmtpReadResult::Err {
                err: SmtpReadError::ReadEof,
            },
            SocketReadResult::Err { err } => SmtpReadResult::Err {
                err: SmtpReadError::Read(err),
            },
        }
    }
}

impl Default for SmtpRead {
    fn default() -> Self {
        Self::new()
    }
}
