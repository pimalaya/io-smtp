//! I/O-free coroutine to send SMTP EHLO command.

use io_stream::{
    coroutines::{
        read::{ReadStream, ReadStreamError, ReadStreamResult},
        write::{WriteStream, WriteStreamError, WriteStreamResult},
    },
    io::StreamIo,
};
use log::trace;
use smtp_codec::{
    decode::{Decoder, EhloResponseDecodeError},
    encode::Encoder,
    smtp_types::{
        command::Command,
        core::EhloDomain,
        response::EhloResponse,
        secret::Secret,
        state::State,
        utils::escape_byte_string,
        IntoStatic,
    },
    CommandCodec, EhloResponseCodec,
};
use thiserror::Error;

use crate::context::SmtpContext;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum SmtpEhloError {
    #[error("Write EHLO command to SMTP stream error")]
    Write(#[from] WriteStreamError),
    #[error("Write EHLO command to SMTP stream error (unexpected EOF)")]
    WriteEof,
    #[error("Read EHLO response from SMTP stream error")]
    Read(#[from] ReadStreamError),
    #[error("Read EHLO response from SMTP stream error (unexpected EOF)")]
    ReadEof,
    #[error("Decode EHLO response error")]
    DecodingFailure { discarded_bytes: Secret<Box<[u8]>> },
}

/// Output emitted when the coroutine terminates its progression.
pub enum SmtpEhloResult {
    Io { io: StreamIo },
    Ok {
        context: SmtpContext,
        response: EhloResponse<'static>,
    },
    Err {
        context: SmtpContext,
        err: SmtpEhloError,
    },
}

enum EhloState {
    Write(WriteStream),
    Read(ReadStream),
    Deserialize,
}

/// I/O-free coroutine to send SMTP EHLO command.
pub struct SmtpEhlo {
    context: Option<SmtpContext>,
    state: EhloState,
    codec: EhloResponseCodec,
    buffer: Vec<u8>,
}

impl SmtpEhlo {
    /// Creates a new coroutine.
    pub fn new(context: SmtpContext, domain: EhloDomain<'_>) -> Self {
        let command = Command::ehlo(domain);
        let encoded = CommandCodec::new().encode(&command);
        trace!("EHLO command to send: {}", escape_byte_string(&encoded));

        Self {
            context: Some(context),
            state: EhloState::Write(WriteStream::new(encoded)),
            codec: EhloResponseCodec::new(),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpEhloResult {
        loop {
            match &mut self.state {
                EhloState::Write(write) => {
                    match write.resume(arg.take()) {
                        WriteStreamResult::Ok(_) => (),
                        WriteStreamResult::Eof => {
                            return SmtpEhloResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpEhloError::WriteEof,
                            };
                        }
                        WriteStreamResult::Io(io) => {
                            return SmtpEhloResult::Io { io };
                        }
                        WriteStreamResult::Err(err) => {
                            return SmtpEhloResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    self.state = EhloState::Read(ReadStream::new());
                    continue;
                }
                EhloState::Read(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => {
                            return SmtpEhloResult::Io { io };
                        }
                        ReadStreamResult::Eof => {
                            return SmtpEhloResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpEhloError::ReadEof,
                            };
                        }
                        ReadStreamResult::Err(err) => {
                            return SmtpEhloResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    trace!("read bytes: {}", escape_byte_string(output.bytes()));
                    self.buffer.extend_from_slice(output.bytes());
                    self.state = EhloState::Deserialize;
                    continue;
                }
                EhloState::Deserialize => {
                    match self.codec.decode(&self.buffer) {
                        Ok((_, response)) => {
                            let response = response.into_static();
                            let mut context = self.context.take().unwrap();
                            context.state = State::Ready;
                            context.capabilities = response.capabilities.clone();

                            return SmtpEhloResult::Ok { context, response };
                        }
                        Err(EhloResponseDecodeError::Incomplete) => {
                            self.state = EhloState::Read(ReadStream::new());
                            continue;
                        }
                        Err(EhloResponseDecodeError::Failed) => {
                            let discarded_bytes =
                                Secret::new(std::mem::take(&mut self.buffer).into_boxed_slice());
                            return SmtpEhloResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpEhloError::DecodingFailure { discarded_bytes },
                            };
                        }
                    }
                }
            }
        }
    }
}
