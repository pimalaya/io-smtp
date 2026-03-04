//! I/O-free coroutine to send SMTP DATA command and message body.

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
    smtp_types::{
        command::Command, response::ReplyCode, secret::Secret, state::State,
        utils::escape_byte_string, IntoStatic,
    },
    CommandCodec, ResponseCodec,
};
use thiserror::Error;

use crate::context::SmtpContext;

/// Errors that can occur during DATA.
#[derive(Clone, Debug, Error)]
pub enum SmtpDataError {
    #[error("Write DATA command error")]
    WriteCommand(#[source] WriteStreamError),
    #[error("Write DATA command error (unexpected EOF)")]
    WriteCommandEof,
    #[error("Write message body error")]
    WriteBody(#[source] WriteStreamError),
    #[error("Write message body error (unexpected EOF)")]
    WriteBodyEof,
    #[error("Read response error")]
    Read(#[from] ReadStreamError),
    #[error("Read response error (unexpected EOF)")]
    ReadEof,
    #[error("Decode response error")]
    DecodingFailure { discarded_bytes: Secret<Box<[u8]>> },
    #[error("DATA rejected: {code} {message}")]
    Rejected { code: u16, message: String },
}

/// Output emitted when the coroutine terminates.
pub enum SmtpDataResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err { context: SmtpContext, err: SmtpDataError },
}

enum DataState {
    /// Send DATA command
    WriteCommand(WriteStream),
    /// Read 354 response
    ReadIntermediate(ReadStream),
    /// Parse 354 response
    DeserializeIntermediate,
    /// Send message body
    WriteBody(WriteStream),
    /// Read final response
    ReadFinal(ReadStream),
    /// Parse final response
    DeserializeFinal,
}

/// I/O-free coroutine to send SMTP DATA command and message body.
///
/// The message body should be the raw email content. This coroutine handles
/// dot-stuffing (prepending dots to lines starting with dots) automatically.
pub struct SmtpData {
    context: Option<SmtpContext>,
    state: DataState,
    message_body: Option<Vec<u8>>,
    codec: ResponseCodec,
    buffer: Vec<u8>,
}

impl SmtpData {
    /// Creates a new DATA coroutine.
    ///
    /// The `message` should be the complete email message (headers + body).
    /// Dot-stuffing will be applied automatically.
    pub fn new(context: SmtpContext, message: Vec<u8>) -> Self {
        let command = Command::data();
        let encoded = CommandCodec::new().encode(&command);
        trace!("DATA command to send: {}", escape_byte_string(&encoded));

        Self {
            context: Some(context),
            state: DataState::WriteCommand(WriteStream::new(encoded)),
            message_body: Some(message),
            codec: ResponseCodec::new(),
            buffer: Vec::new(),
        }
    }

    /// Apply dot-stuffing to the message body and append terminator.
    fn prepare_body(message: Vec<u8>) -> Vec<u8> {
        let mut result = Vec::with_capacity(message.len() + 5);

        // Apply dot-stuffing: lines starting with a dot get an extra dot
        let mut at_line_start = true;
        for &byte in &message {
            if at_line_start && byte == b'.' {
                result.push(b'.');
            }
            result.push(byte);
            at_line_start = byte == b'\n';
        }

        // Ensure message ends with CRLF
        if !result.ends_with(b"\r\n") {
            if result.ends_with(b"\n") {
                // Replace \n with \r\n
                result.pop();
                result.extend_from_slice(b"\r\n");
            } else if result.ends_with(b"\r") {
                result.push(b'\n');
            } else {
                result.extend_from_slice(b"\r\n");
            }
        }

        // Add terminator: CRLF.CRLF (but we already have CRLF, so just .CRLF)
        result.extend_from_slice(b".\r\n");

        result
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpDataResult {
        loop {
            match &mut self.state {
                DataState::WriteCommand(write) => {
                    match write.resume(arg.take()) {
                        WriteStreamResult::Ok(_) => (),
                        WriteStreamResult::Eof => {
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpDataError::WriteCommandEof,
                            };
                        }
                        WriteStreamResult::Io(io) => {
                            return SmtpDataResult::Io { io };
                        }
                        WriteStreamResult::Err(err) => {
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpDataError::WriteCommand(err),
                            };
                        }
                    };

                    self.buffer.clear();
                    self.state = DataState::ReadIntermediate(ReadStream::new());
                    continue;
                }
                DataState::ReadIntermediate(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => {
                            return SmtpDataResult::Io { io };
                        }
                        ReadStreamResult::Eof => {
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpDataError::ReadEof,
                            };
                        }
                        ReadStreamResult::Err(err) => {
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    trace!("read bytes: {}", escape_byte_string(output.bytes()));
                    self.buffer.extend_from_slice(output.bytes());
                    self.state = DataState::DeserializeIntermediate;
                    continue;
                }
                DataState::DeserializeIntermediate => {
                    match self.codec.decode(&self.buffer) {
                        Ok((_, response)) => {
                            let response = response.into_static();

                            // Expect 354 START_MAIL_INPUT
                            if response.code != ReplyCode::START_MAIL_INPUT {
                                let message = response.text().inner().to_string();
                                return SmtpDataResult::Err {
                                    context: self.context.take().unwrap(),
                                    err: SmtpDataError::Rejected {
                                        code: response.code.code(),
                                        message,
                                    },
                                };
                            }

                            // Prepare and send message body
                            let body = self.message_body.take().unwrap();
                            let prepared = Self::prepare_body(body);
                            trace!("message body prepared: {} bytes", prepared.len());

                            self.buffer.clear();
                            self.state = DataState::WriteBody(WriteStream::new(prepared));
                            continue;
                        }
                        Err(ResponseDecodeError::Incomplete) => {
                            self.state = DataState::ReadIntermediate(ReadStream::new());
                            continue;
                        }
                        Err(ResponseDecodeError::Failed) => {
                            let discarded_bytes =
                                Secret::new(std::mem::take(&mut self.buffer).into_boxed_slice());
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpDataError::DecodingFailure { discarded_bytes },
                            };
                        }
                    }
                }
                DataState::WriteBody(write) => {
                    match write.resume(arg.take()) {
                        WriteStreamResult::Ok(_) => (),
                        WriteStreamResult::Eof => {
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpDataError::WriteBodyEof,
                            };
                        }
                        WriteStreamResult::Io(io) => {
                            return SmtpDataResult::Io { io };
                        }
                        WriteStreamResult::Err(err) => {
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpDataError::WriteBody(err),
                            };
                        }
                    };

                    self.buffer.clear();
                    self.state = DataState::ReadFinal(ReadStream::new());
                    continue;
                }
                DataState::ReadFinal(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => {
                            return SmtpDataResult::Io { io };
                        }
                        ReadStreamResult::Eof => {
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpDataError::ReadEof,
                            };
                        }
                        ReadStreamResult::Err(err) => {
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: err.into(),
                            };
                        }
                    };

                    trace!("read bytes: {}", escape_byte_string(output.bytes()));
                    self.buffer.extend_from_slice(output.bytes());
                    self.state = DataState::DeserializeFinal;
                    continue;
                }
                DataState::DeserializeFinal => {
                    match self.codec.decode(&self.buffer) {
                        Ok((_, response)) => {
                            let response = response.into_static();
                            let mut context = self.context.take().unwrap();

                            if response.code == ReplyCode::OK {
                                // Transaction complete, back to Ready state
                                context.state = State::Ready;
                                return SmtpDataResult::Ok { context };
                            } else {
                                let message = response.text().inner().to_string();
                                return SmtpDataResult::Err {
                                    context,
                                    err: SmtpDataError::Rejected {
                                        code: response.code.code(),
                                        message,
                                    },
                                };
                            }
                        }
                        Err(ResponseDecodeError::Incomplete) => {
                            self.state = DataState::ReadFinal(ReadStream::new());
                            continue;
                        }
                        Err(ResponseDecodeError::Failed) => {
                            let discarded_bytes =
                                Secret::new(std::mem::take(&mut self.buffer).into_boxed_slice());
                            return SmtpDataResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpDataError::DecodingFailure { discarded_bytes },
                            };
                        }
                    }
                }
            }
        }
    }
}
