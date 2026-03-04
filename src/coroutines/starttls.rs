//! I/O-free coroutine to perform SMTP STARTTLS negotiation.

use io_stream::{
    coroutines::{
        read::{ReadStream, ReadStreamError, ReadStreamResult},
        write::{WriteStream, WriteStreamError, WriteStreamResult},
    },
    io::StreamIo,
};
use log::trace;
use memchr::memchr;
use smtp_codec::{
    encode::Encoder,
    smtp_types::{command::Command, response::ReplyCode, utils::escape_byte_string},
    CommandCodec,
};
use thiserror::Error;

use crate::context::SmtpContext;

/// Errors that can occur during the coroutine progression.
#[derive(Clone, Debug, Error)]
pub enum SmtpStartTlsError {
    #[error("Write STARTTLS command to SMTP stream error")]
    WriteStartTls(#[source] WriteStreamError),
    #[error("Write STARTTLS command to SMTP stream error (unexpected EOF)")]
    WriteStartTlsEof,
    #[error("Read STARTTLS response from SMTP stream error")]
    ReadStartTls(#[source] ReadStreamError),
    #[error("Read STARTTLS response from SMTP stream error (unexpected EOF)")]
    ReadStartTlsEof,
    #[error("STARTTLS rejected by server: {0}")]
    Rejected(String),
}

/// Output emitted when the coroutine terminates its progression.
#[derive(Debug)]
pub enum SmtpStartTlsResult {
    Io { io: StreamIo },
    Ok { context: SmtpContext },
    Err { context: SmtpContext, err: SmtpStartTlsError },
}

enum State {
    /// The STARTTLS command needs to be written.
    WriteStartTls(WriteStream),
    /// The STARTTLS response needs to be read.
    ReadStartTls(ReadStream),
}

/// I/O-free coroutine to perform SMTP STARTTLS negotiation.
pub struct SmtpStartTls {
    context: Option<SmtpContext>,
    state: State,
    buffer: Vec<u8>,
}

impl SmtpStartTls {
    /// Creates a new coroutine.
    pub fn new(context: SmtpContext) -> Self {
        let command = Command::starttls();
        let encoded = CommandCodec::new().encode(&command);
        trace!("STARTTLS command to send: {}", escape_byte_string(&encoded));

        Self {
            context: Some(context),
            state: State::WriteStartTls(WriteStream::new(encoded)),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpStartTlsResult {
        loop {
            match &mut self.state {
                State::WriteStartTls(write) => {
                    match write.resume(arg.take()) {
                        WriteStreamResult::Ok(_) => (),
                        WriteStreamResult::Io(io) => return SmtpStartTlsResult::Io { io },
                        WriteStreamResult::Eof => {
                            return SmtpStartTlsResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpStartTlsError::WriteStartTlsEof,
                            };
                        }
                        WriteStreamResult::Err(err) => {
                            return SmtpStartTlsResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpStartTlsError::WriteStartTls(err),
                            };
                        }
                    };

                    self.state = State::ReadStartTls(ReadStream::new());
                    continue;
                }
                State::ReadStartTls(read) => {
                    let output = match read.resume(arg.take()) {
                        ReadStreamResult::Ok(output) => output,
                        ReadStreamResult::Io(io) => return SmtpStartTlsResult::Io { io },
                        ReadStreamResult::Eof => {
                            return SmtpStartTlsResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpStartTlsError::ReadStartTlsEof,
                            };
                        }
                        ReadStreamResult::Err(err) => {
                            return SmtpStartTlsResult::Err {
                                context: self.context.take().unwrap(),
                                err: SmtpStartTlsError::ReadStartTls(err),
                            };
                        }
                    };

                    self.buffer.extend_from_slice(output.bytes());

                    // Look for complete response line
                    let Some(newline_pos) = memchr(b'\n', &self.buffer) else {
                        // Need more data
                        continue;
                    };

                    let response_line = &self.buffer[..=newline_pos];
                    trace!(
                        "STARTTLS response: {}",
                        escape_byte_string(response_line)
                    );

                    // Parse the reply code (first 3 bytes)
                    if response_line.len() >= 3 {
                        if let Ok(code_str) = std::str::from_utf8(&response_line[..3]) {
                            if let Ok(code) = code_str.parse::<u16>() {
                                if let Some(reply_code) = ReplyCode::new(code) {
                                    if reply_code == ReplyCode::SERVICE_READY {
                                        // 220 = Ready to start TLS
                                        return SmtpStartTlsResult::Ok {
                                            context: self.context.take().unwrap(),
                                        };
                                    } else {
                                        // Server rejected STARTTLS
                                        let msg = String::from_utf8_lossy(response_line)
                                            .trim()
                                            .to_string();
                                        return SmtpStartTlsResult::Err {
                                            context: self.context.take().unwrap(),
                                            err: SmtpStartTlsError::Rejected(msg),
                                        };
                                    }
                                }
                            }
                        }
                    }

                    // Failed to parse response
                    let msg = String::from_utf8_lossy(response_line).trim().to_string();
                    return SmtpStartTlsResult::Err {
                        context: self.context.take().unwrap(),
                        err: SmtpStartTlsError::Rejected(msg),
                    };
                }
            }
        }
    }
}
