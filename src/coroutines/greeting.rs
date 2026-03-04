//! I/O-free coroutine to read the greeting from an SMTP server.

use io_stream::{
    coroutines::read::{ReadStream, ReadStreamError, ReadStreamResult},
    io::StreamIo,
};
use log::trace;
use smtp_codec::{
    decode::{Decoder, GreetingDecodeError},
    smtp_types::{
        response::Greeting, secret::Secret, state::State, utils::escape_byte_string, IntoStatic,
    },
    GreetingCodec,
};
use thiserror::Error;

use crate::context::SmtpContext;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum GetSmtpGreetingError {
    #[error("Read greeting from SMTP stream error")]
    Read(#[from] ReadStreamError),
    #[error("Read greeting from SMTP stream error (unexpected EOF)")]
    ReadEof,
    #[error("Parse SMTP greeting error")]
    DecodingFailure { discarded_bytes: Secret<Box<[u8]>> },
}

/// Output emitted when the coroutine terminates its progression.
pub enum GetSmtpGreetingResult {
    Io { io: StreamIo },
    Ok {
        context: SmtpContext,
        greeting: Greeting<'static>,
    },
    Err {
        context: SmtpContext,
        err: GetSmtpGreetingError,
    },
}

enum GreetingState {
    Read(ReadStream),
    Deserialize,
}

/// I/O-free coroutine to read the greeting from an SMTP server.
pub struct GetSmtpGreeting {
    context: Option<SmtpContext>,
    codec: GreetingCodec,
    state: GreetingState,
    buffer: Vec<u8>,
}

impl GetSmtpGreeting {
    /// Creates a new coroutine.
    pub fn new(context: SmtpContext) -> Self {
        Self {
            context: Some(context),
            codec: GreetingCodec::new(),
            state: GreetingState::Read(ReadStream::new()),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> GetSmtpGreetingResult {
        loop {
            match &mut self.state {
                GreetingState::Read(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => return GetSmtpGreetingResult::Io { io },
                        ReadStreamResult::Eof => {
                            return GetSmtpGreetingResult::Err {
                                context: self.context.take().unwrap(),
                                err: GetSmtpGreetingError::ReadEof,
                            }
                        }
                        ReadStreamResult::Err(err) => {
                            return GetSmtpGreetingResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            }
                        }
                    };

                    trace!("read SMTP bytes: {}", escape_byte_string(output.bytes()));
                    self.buffer.extend_from_slice(output.bytes());
                    self.state = GreetingState::Deserialize;
                    continue;
                }
                GreetingState::Deserialize => {
                    match self.codec.decode(&self.buffer) {
                        Ok((_, greeting)) => {
                            let mut context = self.context.take().unwrap();
                            context.state = State::Greeted;

                            return GetSmtpGreetingResult::Ok {
                                context,
                                greeting: greeting.into_static(),
                            };
                        }
                        Err(GreetingDecodeError::Incomplete) => {
                            self.state = GreetingState::Read(ReadStream::new());
                            continue;
                        }
                        Err(GreetingDecodeError::Failed) => {
                            let discarded_bytes =
                                Secret::new(std::mem::take(&mut self.buffer).into_boxed_slice());
                            return GetSmtpGreetingResult::Err {
                                context: self.context.take().unwrap(),
                                err: GetSmtpGreetingError::DecodingFailure { discarded_bytes },
                            };
                        }
                    }
                }
            }
        }
    }
}
