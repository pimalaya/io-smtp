//! I/O-free coroutine to authenticate using SMTP AUTH PLAIN.

use std::borrow::Cow;

use io_stream::{
    coroutines::{
        read::{ReadStream, ReadStreamError, ReadStreamResult},
        write::{WriteStream, WriteStreamError, WriteStreamResult},
    },
    io::StreamIo,
};
use log::trace;
use secrecy::{ExposeSecret, SecretString};
use smtp_codec::{
    decode::{Decoder, ResponseDecodeError},
    encode::Encoder,
    smtp_types::{
        auth::AuthMechanism,
        command::Command,
        response::{ReplyCode, Response},
        secret::Secret,
        utils::escape_byte_string,
        IntoStatic,
    },
    CommandCodec, ResponseCodec,
};
use thiserror::Error;

use crate::context::SmtpContext;

/// Errors that can occur during AUTH PLAIN.
#[derive(Clone, Debug, Error)]
pub enum SmtpAuthenticatePlainError {
    #[error("Write AUTH PLAIN command error")]
    Write(#[from] WriteStreamError),
    #[error("Write AUTH PLAIN command error (unexpected EOF)")]
    WriteEof,
    #[error("Read AUTH PLAIN response error")]
    Read(#[from] ReadStreamError),
    #[error("Read AUTH PLAIN response error (unexpected EOF)")]
    ReadEof,
    #[error("Decode AUTH PLAIN response error")]
    DecodingFailure { discarded_bytes: Secret<Box<[u8]>> },
    #[error("AUTH PLAIN rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Output emitted when the coroutine terminates.
pub enum SmtpAuthenticatePlainResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err {
        context: SmtpContext,
        err: SmtpAuthenticatePlainError,
    },
}

enum AuthState {
    Write(WriteStream),
    Read(ReadStream),
    Deserialize,
}

/// I/O-free coroutine to authenticate using SMTP AUTH PLAIN.
///
/// AUTH PLAIN sends credentials as: base64(authzid\0authcid\0password)
/// where authzid is optional (usually empty), authcid is the username.
pub struct SmtpAuthenticatePlain {
    context: Option<SmtpContext>,
    state: AuthState,
    codec: ResponseCodec,
    buffer: Vec<u8>,
}

impl SmtpAuthenticatePlain {
    /// Creates a new AUTH PLAIN coroutine.
    ///
    /// Uses initial response (IR) to send credentials in a single round-trip.
    pub fn new(context: SmtpContext, login: &str, password: &SecretString) -> Self {
        // Build SASL PLAIN payload: authzid\0authcid\0password
        // authzid is typically empty for SMTP
        let mut payload = Vec::new();
        payload.push(0); // empty authzid
        payload.extend_from_slice(login.as_bytes());
        payload.push(0);
        payload.extend_from_slice(password.expose_secret().as_bytes());

        let command =
            Command::auth_with_initial_response(AuthMechanism::Plain, Cow::Owned(payload));
        let encoded = CommandCodec::new().encode(&command);
        trace!("AUTH PLAIN command to send: {} bytes", encoded.len());

        Self {
            context: Some(context),
            state: AuthState::Write(WriteStream::new(encoded)),
            codec: ResponseCodec::new(),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpAuthenticatePlainResult {
        loop {
            match &mut self.state {
                AuthState::Write(write) => {
                    match write.resume(arg.take()) {
                        WriteStreamResult::Ok(_) => (),
                        WriteStreamResult::Eof => {
                            return SmtpAuthenticatePlainResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticatePlainError::WriteEof,
                            };
                        }
                        WriteStreamResult::Io(io) => {
                            return SmtpAuthenticatePlainResult::Io { io };
                        }
                        WriteStreamResult::Err(err) => {
                            return SmtpAuthenticatePlainResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    self.state = AuthState::Read(ReadStream::new());
                    continue;
                }
                AuthState::Read(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => {
                            return SmtpAuthenticatePlainResult::Io { io };
                        }
                        ReadStreamResult::Eof => {
                            return SmtpAuthenticatePlainResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticatePlainError::ReadEof,
                            };
                        }
                        ReadStreamResult::Err(err) => {
                            return SmtpAuthenticatePlainResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    trace!("read bytes: {}", escape_byte_string(output.bytes()));
                    self.buffer.extend_from_slice(output.bytes());
                    self.state = AuthState::Deserialize;
                    continue;
                }
                AuthState::Deserialize => {
                    match self.codec.decode(&self.buffer) {
                        Ok((_, response)) => {
                            let response: Response<'static> = response.into_static();
                            let mut context = self.context.take().unwrap();

                            // Check if authentication succeeded (235 = AUTH_SUCCESSFUL)
                            if response.code == ReplyCode::AUTH_SUCCESSFUL {
                                context.authenticated = true;
                                // State remains Ready after successful auth
                                return SmtpAuthenticatePlainResult::Ok { context };
                            } else {
                                // Authentication failed
                                let message = response.text().inner().to_string();
                                return SmtpAuthenticatePlainResult::Err {
                                    context,
                                    err: SmtpAuthenticatePlainError::Rejected {
                                        code: response.code.code(),
                                        message,
                                    },
                                };
                            }
                        }
                        Err(ResponseDecodeError::Incomplete) => {
                            self.state = AuthState::Read(ReadStream::new());
                            continue;
                        }
                        Err(ResponseDecodeError::Failed) => {
                            let discarded_bytes =
                                Secret::new(std::mem::take(&mut self.buffer).into_boxed_slice());
                            return SmtpAuthenticatePlainResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticatePlainError::DecodingFailure { discarded_bytes },
                            };
                        }
                    }
                }
            }
        }
    }
}
