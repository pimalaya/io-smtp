//! I/O-free coroutine to authenticate using SMTP AUTH LOGIN.

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
        auth::{AuthMechanism, AuthenticateData},
        command::Command,
        response::{ReplyCode, Response},
        secret::Secret,
        utils::escape_byte_string,
        IntoStatic,
    },
    AuthenticateDataCodec, CommandCodec, ResponseCodec,
};
use thiserror::Error;

use crate::context::SmtpContext;

/// Errors that can occur during AUTH LOGIN.
#[derive(Clone, Debug, Error)]
pub enum SmtpAuthenticateLoginError {
    #[error("Write AUTH LOGIN command error")]
    Write(#[from] WriteStreamError),
    #[error("Write AUTH LOGIN command error (unexpected EOF)")]
    WriteEof,
    #[error("Read AUTH LOGIN response error")]
    Read(#[from] ReadStreamError),
    #[error("Read AUTH LOGIN response error (unexpected EOF)")]
    ReadEof,
    #[error("Decode AUTH LOGIN response error")]
    DecodingFailure { discarded_bytes: Secret<Box<[u8]>> },
    #[error("AUTH LOGIN rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Output emitted when the coroutine terminates.
pub enum SmtpAuthenticateLoginResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err {
        context: SmtpContext,
        err: SmtpAuthenticateLoginError,
    },
}

enum AuthLoginState {
    SendAuth(WriteStream),
    ReadAuthResponse(ReadStream),
    DeserializeAuthResponse,
    SendUsername(WriteStream),
    ReadUsernameResponse(ReadStream),
    DeserializeUsernameResponse,
    SendPassword(WriteStream),
    ReadPasswordResponse(ReadStream),
    DeserializePasswordResponse,
}

/// I/O-free coroutine to authenticate using SMTP AUTH LOGIN.
///
/// AUTH LOGIN is a multi-step SASL mechanism:
/// 1. Client sends AUTH LOGIN
/// 2. Server responds 334 (base64 "Username:")
/// 3. Client sends base64(username)
/// 4. Server responds 334 (base64 "Password:")
/// 5. Client sends base64(password)
/// 6. Server responds 235 (success)
pub struct SmtpAuthenticateLogin {
    context: Option<SmtpContext>,
    state: AuthLoginState,
    username_bytes: Vec<u8>,
    password_bytes: Vec<u8>,
    codec: ResponseCodec,
    buffer: Vec<u8>,
}

impl SmtpAuthenticateLogin {
    /// Creates a new AUTH LOGIN coroutine.
    pub fn new(context: SmtpContext, login: &str, password: &SecretString) -> Self {
        let command = Command::auth(AuthMechanism::Login);
        let encoded = CommandCodec::new().encode(&command);
        trace!("AUTH LOGIN command to send: {} bytes", encoded.len());

        let auth_data_codec = AuthenticateDataCodec::new();

        let username_bytes = auth_data_codec
            .encode(&AuthenticateData::r#continue(Cow::Borrowed(
                login.as_bytes(),
            )));
        let password_bytes = auth_data_codec
            .encode(&AuthenticateData::r#continue(Cow::Borrowed(
                password.expose_secret().as_bytes(),
            )));

        Self {
            context: Some(context),
            state: AuthLoginState::SendAuth(WriteStream::new(encoded)),
            username_bytes,
            password_bytes,
            codec: ResponseCodec::new(),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpAuthenticateLoginResult {
        loop {
            match &mut self.state {
                // Step 1: Send AUTH LOGIN command
                AuthLoginState::SendAuth(write) => {
                    match write.resume(arg.take()) {
                        WriteStreamResult::Ok(_) => (),
                        WriteStreamResult::Eof => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticateLoginError::WriteEof,
                            };
                        }
                        WriteStreamResult::Io(io) => {
                            return SmtpAuthenticateLoginResult::Io { io };
                        }
                        WriteStreamResult::Err(err) => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    self.state = AuthLoginState::ReadAuthResponse(ReadStream::new());
                    continue;
                }
                AuthLoginState::ReadAuthResponse(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => {
                            return SmtpAuthenticateLoginResult::Io { io };
                        }
                        ReadStreamResult::Eof => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticateLoginError::ReadEof,
                            };
                        }
                        ReadStreamResult::Err(err) => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    trace!("read bytes: {}", escape_byte_string(output.bytes()));
                    self.buffer.extend_from_slice(output.bytes());
                    self.state = AuthLoginState::DeserializeAuthResponse;
                    continue;
                }
                AuthLoginState::DeserializeAuthResponse => {
                    match self.codec.decode(&self.buffer) {
                        Ok((_, response)) => {
                            let response: Response<'static> = response.into_static();

                            if response.code == ReplyCode::AUTH_CONTINUE {
                                self.buffer.clear();
                                let username = std::mem::take(&mut self.username_bytes);
                                self.state =
                                    AuthLoginState::SendUsername(WriteStream::new(username));
                                continue;
                            } else {
                                let message = response.text().inner().to_string();
                                return SmtpAuthenticateLoginResult::Err {
                                    context: self.context.take().unwrap(),
                                    err: SmtpAuthenticateLoginError::Rejected {
                                        code: response.code.code(),
                                        message,
                                    },
                                };
                            }
                        }
                        Err(ResponseDecodeError::Incomplete) => {
                            self.state =
                                AuthLoginState::ReadAuthResponse(ReadStream::new());
                            continue;
                        }
                        Err(ResponseDecodeError::Failed) => {
                            let discarded_bytes =
                                Secret::new(std::mem::take(&mut self.buffer).into_boxed_slice());
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticateLoginError::DecodingFailure {
                                    discarded_bytes,
                                },
                            };
                        }
                    }
                }

                // Step 2: Send base64(username)
                AuthLoginState::SendUsername(write) => {
                    match write.resume(arg.take()) {
                        WriteStreamResult::Ok(_) => (),
                        WriteStreamResult::Eof => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticateLoginError::WriteEof,
                            };
                        }
                        WriteStreamResult::Io(io) => {
                            return SmtpAuthenticateLoginResult::Io { io };
                        }
                        WriteStreamResult::Err(err) => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    self.state = AuthLoginState::ReadUsernameResponse(ReadStream::new());
                    continue;
                }
                AuthLoginState::ReadUsernameResponse(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => {
                            return SmtpAuthenticateLoginResult::Io { io };
                        }
                        ReadStreamResult::Eof => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticateLoginError::ReadEof,
                            };
                        }
                        ReadStreamResult::Err(err) => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    trace!("read bytes: {}", escape_byte_string(output.bytes()));
                    self.buffer.extend_from_slice(output.bytes());
                    self.state = AuthLoginState::DeserializeUsernameResponse;
                    continue;
                }
                AuthLoginState::DeserializeUsernameResponse => {
                    match self.codec.decode(&self.buffer) {
                        Ok((_, response)) => {
                            let response: Response<'static> = response.into_static();

                            if response.code == ReplyCode::AUTH_CONTINUE {
                                self.buffer.clear();
                                let password = std::mem::take(&mut self.password_bytes);
                                self.state =
                                    AuthLoginState::SendPassword(WriteStream::new(password));
                                continue;
                            } else {
                                let message = response.text().inner().to_string();
                                return SmtpAuthenticateLoginResult::Err {
                                    context: self.context.take().unwrap(),
                                    err: SmtpAuthenticateLoginError::Rejected {
                                        code: response.code.code(),
                                        message,
                                    },
                                };
                            }
                        }
                        Err(ResponseDecodeError::Incomplete) => {
                            self.state =
                                AuthLoginState::ReadUsernameResponse(ReadStream::new());
                            continue;
                        }
                        Err(ResponseDecodeError::Failed) => {
                            let discarded_bytes =
                                Secret::new(std::mem::take(&mut self.buffer).into_boxed_slice());
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticateLoginError::DecodingFailure {
                                    discarded_bytes,
                                },
                            };
                        }
                    }
                }

                // Step 3: Send base64(password)
                AuthLoginState::SendPassword(write) => {
                    match write.resume(arg.take()) {
                        WriteStreamResult::Ok(_) => (),
                        WriteStreamResult::Eof => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticateLoginError::WriteEof,
                            };
                        }
                        WriteStreamResult::Io(io) => {
                            return SmtpAuthenticateLoginResult::Io { io };
                        }
                        WriteStreamResult::Err(err) => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    self.state = AuthLoginState::ReadPasswordResponse(ReadStream::new());
                    continue;
                }
                AuthLoginState::ReadPasswordResponse(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => {
                            return SmtpAuthenticateLoginResult::Io { io };
                        }
                        ReadStreamResult::Eof => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticateLoginError::ReadEof,
                            };
                        }
                        ReadStreamResult::Err(err) => {
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    trace!("read bytes: {}", escape_byte_string(output.bytes()));
                    self.buffer.extend_from_slice(output.bytes());
                    self.state = AuthLoginState::DeserializePasswordResponse;
                    continue;
                }
                AuthLoginState::DeserializePasswordResponse => {
                    match self.codec.decode(&self.buffer) {
                        Ok((_, response)) => {
                            let response: Response<'static> = response.into_static();
                            let mut context = self.context.take().unwrap();

                            if response.code == ReplyCode::AUTH_SUCCESSFUL {
                                context.authenticated = true;
                                return SmtpAuthenticateLoginResult::Ok { context };
                            } else {
                                let message = response.text().inner().to_string();
                                return SmtpAuthenticateLoginResult::Err {
                                    context,
                                    err: SmtpAuthenticateLoginError::Rejected {
                                        code: response.code.code(),
                                        message,
                                    },
                                };
                            }
                        }
                        Err(ResponseDecodeError::Incomplete) => {
                            self.state =
                                AuthLoginState::ReadPasswordResponse(ReadStream::new());
                            continue;
                        }
                        Err(ResponseDecodeError::Failed) => {
                            let discarded_bytes =
                                Secret::new(std::mem::take(&mut self.buffer).into_boxed_slice());
                            return SmtpAuthenticateLoginResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpAuthenticateLoginError::DecodingFailure {
                                    discarded_bytes,
                                },
                            };
                        }
                    }
                }
            }
        }
    }
}
