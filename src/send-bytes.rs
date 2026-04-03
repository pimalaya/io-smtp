//! I/O-free primitive to write bytes then read bytes from a socket.

use io_socket::{
    coroutines::{
        read::{ReadSocket, ReadSocketError, ReadSocketResult},
        write::{WriteSocket, WriteSocketError, WriteSocketResult},
    },
    io::{SocketInput, SocketOutput},
};

/// Output emitted when the coroutine terminates.
pub enum SmtpBytesSendResult {
    Io { input: SocketInput },
    Ok { bytes: Vec<u8> },
    WriteErr { err: WriteSocketError },
    WriteEof,
    ReadErr { err: ReadSocketError },
    ReadEof,
}

enum State {
    Write(WriteSocket),
    Read(ReadSocket),
}

/// Writes bytes to the socket, then reads bytes from the socket.
/// Pass an empty slice to only read (skip the write step).
pub struct SmtpBytesSend {
    state: State,
}

impl SmtpBytesSend {
    pub fn new(bytes: Vec<u8>) -> Self {
        let state = if bytes.is_empty() {
            State::Read(ReadSocket::new())
        } else {
            State::Write(WriteSocket::new(bytes))
        };

        Self { state }
    }

    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpBytesSendResult {
        loop {
            match &mut self.state {
                State::Write(write) => match write.resume(arg.take()) {
                    WriteSocketResult::Ok { .. } => {
                        self.state = State::Read(ReadSocket::new());
                        continue;
                    }
                    WriteSocketResult::Io { input } => {
                        return SmtpBytesSendResult::Io { input };
                    }
                    WriteSocketResult::Eof => return SmtpBytesSendResult::WriteEof,
                    WriteSocketResult::Err { err } => {
                        return SmtpBytesSendResult::WriteErr { err };
                    }
                },
                State::Read(read) => match read.resume(arg.take()) {
                    ReadSocketResult::Ok { buf, n } => {
                        return SmtpBytesSendResult::Ok {
                            bytes: buf[..n].to_vec(),
                        };
                    }
                    ReadSocketResult::Io { input } => {
                        return SmtpBytesSendResult::Io { input };
                    }
                    ReadSocketResult::Eof => return SmtpBytesSendResult::ReadEof,
                    ReadSocketResult::Err { err } => {
                        return SmtpBytesSendResult::ReadErr { err };
                    }
                },
            }
        }
    }
}
