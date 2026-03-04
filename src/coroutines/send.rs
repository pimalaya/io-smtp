//! I/O-free coroutine to send SMTP commands and receive responses.

use io_stream::{
    coroutines::{
        read::{ReadStream, ReadStreamError, ReadStreamResult},
        write::{WriteStream, WriteStreamError, WriteStreamResult},
    },
    io::StreamIo,
};
use log::trace;
use smtp_codec::{
    decode::{Decoder, ResponseDecodeError},
    encode::Encoder,
    smtp_types::{response::Response, secret::Secret, utils::escape_byte_string},
    CommandCodec, ResponseCodec,
};
use thiserror::Error;

use crate::context::SmtpContext;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum SendSmtpCommandError {
    #[error("Write command to SMTP stream error")]
    Write(#[from] WriteStreamError),
    #[error("Write command to SMTP stream error (unexpected EOF)")]
    WriteEof,
    #[error("Read response from SMTP stream error")]
    Read(#[from] ReadStreamError),
    #[error("Read response from SMTP stream error (unexpected EOF)")]
    ReadEof,
    #[error("Decode SMTP response error")]
    DecodingFailure { discarded_bytes: Secret<Box<[u8]>> },
}

/// Output emitted when the coroutine terminates its progression.
pub enum SendSmtpCommandResult {
    Io { io: StreamIo },
    Ok {
        context: SmtpContext,
        response: Response<'static>,
    },
    Err {
        context: SmtpContext,
        err: SendSmtpCommandError,
    },
}

enum State {
    Write(WriteStream),
    Read(ReadStream),
    Deserialize,
}

/// I/O-free coroutine to send an SMTP command and receive a response.
pub struct SendSmtpCommand {
    context: Option<SmtpContext>,
    state: State,
    codec: ResponseCodec,
    buffer: Vec<u8>,
}

impl SendSmtpCommand {
    /// Creates a new coroutine from the given command.
    pub fn new<'a>(
        context: SmtpContext,
        command: &smtp_codec::smtp_types::command::Command<'a>,
    ) -> Self {
        let encoded = CommandCodec::new().encode(command);
        trace!("command to send: {}", escape_byte_string(&encoded));

        Self {
            context: Some(context),
            state: State::Write(WriteStream::new(encoded)),
            codec: ResponseCodec::new(),
            buffer: Vec::new(),
        }
    }

    /// Creates a new coroutine from raw bytes (for DATA content).
    pub fn from_bytes(context: SmtpContext, bytes: Vec<u8>) -> Self {
        trace!("bytes to send: {} bytes", bytes.len());

        Self {
            context: Some(context),
            state: State::Write(WriteStream::new(bytes)),
            codec: ResponseCodec::new(),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SendSmtpCommandResult {
        loop {
            match &mut self.state {
                State::Write(write) => {
                    match write.resume(arg.take()) {
                        WriteStreamResult::Ok(_) => (),
                        WriteStreamResult::Eof => {
                            return SendSmtpCommandResult::Err {
                                context: self.context.take().unwrap(),
                                err: SendSmtpCommandError::WriteEof,
                            };
                        }
                        WriteStreamResult::Io(io) => {
                            return SendSmtpCommandResult::Io { io };
                        }
                        WriteStreamResult::Err(err) => {
                            return SendSmtpCommandResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    self.state = State::Read(ReadStream::new());
                    continue;
                }
                State::Read(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => {
                            return SendSmtpCommandResult::Io { io };
                        }
                        ReadStreamResult::Eof => {
                            return SendSmtpCommandResult::Err {
                                context: self.context.take().unwrap(),
                                err: SendSmtpCommandError::ReadEof,
                            };
                        }
                        ReadStreamResult::Err(err) => {
                            return SendSmtpCommandResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    trace!("read bytes: {}", escape_byte_string(output.bytes()));
                    self.buffer.extend_from_slice(output.bytes());
                    self.state = State::Deserialize;
                    continue;
                }
                State::Deserialize => {
                    match self.codec.decode_static(&self.buffer) {
                        Ok((remaining, response)) => {
                            // Clear buffer and store remaining bytes
                            let remaining_len = remaining.len();
                            let buffer_len = self.buffer.len();
                            self.buffer.drain(..buffer_len - remaining_len);

                            return SendSmtpCommandResult::Ok {
                                context: self.context.take().unwrap(),
                                response,
                            };
                        }
                        Err(ResponseDecodeError::Incomplete) => {
                            // Need more data
                            self.state = State::Read(ReadStream::new());
                            continue;
                        }
                        Err(ResponseDecodeError::Failed) => {
                            let discarded_bytes =
                                Secret::new(std::mem::take(&mut self.buffer).into_boxed_slice());
                            return SendSmtpCommandResult::Err {
                                context: self.context.take().unwrap(),
                                err: SendSmtpCommandError::DecodingFailure { discarded_bytes },
                            };
                        }
                    }
                }
            }
        }
    }
}
