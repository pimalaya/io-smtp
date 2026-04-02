//! I/O-free primitive to send bytes then receive bytes.

use io_stream::{
    coroutines::{
        read::{ReadStream, ReadStreamError, ReadStreamResult},
        write::{WriteStream, WriteStreamError, WriteStreamResult},
    },
    io::StreamIo,
};

/// Output emitted when the coroutine terminates.
pub enum SmtpBytesSendResult {
    Io { io: StreamIo },
    Ok { bytes: Vec<u8> },
    WriteErr { err: WriteStreamError },
    WriteEof,
    ReadErr { err: ReadStreamError },
    ReadEof,
}

enum State {
    Write(WriteStream),
    Read(ReadStream),
}

/// Writes bytes to the stream, then reads bytes from the stream.
/// Pass an empty slice to only read (skip the write step).
pub struct SmtpBytesSend {
    state: State,
}

impl SmtpBytesSend {
    pub fn new(bytes: Vec<u8>) -> Self {
        let state = if bytes.is_empty() {
            State::Read(ReadStream::new())
        } else {
            State::Write(WriteStream::new(bytes))
        };

        Self { state }
    }

    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpBytesSendResult {
        loop {
            match &mut self.state {
                State::Write(write) => match write.resume(arg.take()) {
                    WriteStreamResult::Ok(_) => {
                        self.state = State::Read(ReadStream::new());
                        continue;
                    }
                    WriteStreamResult::Io(io) => return SmtpBytesSendResult::Io { io },
                    WriteStreamResult::Eof => return SmtpBytesSendResult::WriteEof,
                    WriteStreamResult::Err(err) => return SmtpBytesSendResult::WriteErr { err },
                },
                State::Read(read) => match read.resume(arg.take()) {
                    ReadStreamResult::Ok(mut output) => {
                        return SmtpBytesSendResult::Ok {
                            bytes: output.buffer.drain(..output.bytes_count).collect(),
                        }
                    }
                    ReadStreamResult::Io(io) => return SmtpBytesSendResult::Io { io },
                    ReadStreamResult::Eof => return SmtpBytesSendResult::ReadEof,
                    ReadStreamResult::Err(err) => return SmtpBytesSendResult::ReadErr { err },
                },
            }
        }
    }
}
