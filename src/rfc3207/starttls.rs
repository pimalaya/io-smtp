//! I/O-free coroutine to perform SMTP STARTTLS negotiation.

use io_stream::{
    coroutines::{read::ReadStreamError, write::WriteStreamError},
    io::StreamIo,
};
use log::trace;
use thiserror::Error;

use crate::{
    rfc5321::types::{command::Command, reply_code::ReplyCode},
    send_bytes::{SmtpBytesSend, SmtpBytesSendResult},
    utils::escape_byte_string,
};

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
    Ok,
    Err { err: SmtpStartTlsError },
}

/// I/O-free coroutine to perform SMTP STARTTLS negotiation.
pub struct SmtpStartTls {
    io: SmtpBytesSend,
    buffer: Vec<u8>,
}

impl SmtpStartTls {
    /// Creates a new coroutine.
    pub fn new() -> Self {
        let encoded = Command::StartTls.to_bytes();
        trace!("STARTTLS command to send: {}", escape_byte_string(&encoded));

        Self {
            io: SmtpBytesSend::new(encoded),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<StreamIo>) -> SmtpStartTlsResult {
        loop {
            match self.io.resume(arg.take()) {
                SmtpBytesSendResult::Io { io } => return SmtpStartTlsResult::Io { io },
                SmtpBytesSendResult::WriteErr { err } => {
                    return SmtpStartTlsResult::Err {
                        err: SmtpStartTlsError::WriteStartTls(err),
                    };
                }
                SmtpBytesSendResult::WriteEof => {
                    return SmtpStartTlsResult::Err {
                        err: SmtpStartTlsError::WriteStartTlsEof,
                    };
                }
                SmtpBytesSendResult::ReadErr { err } => {
                    return SmtpStartTlsResult::Err {
                        err: SmtpStartTlsError::ReadStartTls(err),
                    };
                }
                SmtpBytesSendResult::ReadEof => {
                    return SmtpStartTlsResult::Err {
                        err: SmtpStartTlsError::ReadStartTlsEof,
                    };
                }
                SmtpBytesSendResult::Ok { bytes } => {
                    self.buffer.extend_from_slice(&bytes);

                    // Look for complete response line
                    let Some(newline_pos) = self.buffer.iter().position(|&b| b == b'\n') else {
                        // Need more data
                        self.io = SmtpBytesSend::new(vec![]);
                        continue;
                    };

                    let response_line = &self.buffer[..=newline_pos];
                    trace!("STARTTLS response: {}", escape_byte_string(response_line));

                    // Parse the reply code (first 3 bytes)
                    if response_line.len() >= 3 {
                        if let Ok(reply_code) = ReplyCode::parse(&response_line[..3]) {
                            if reply_code == ReplyCode::SERVICE_READY {
                                // 220 = Ready to start TLS
                                return SmtpStartTlsResult::Ok;
                            } else {
                                // Server rejected STARTTLS
                                let msg = String::from_utf8_lossy(response_line).trim().to_string();
                                return SmtpStartTlsResult::Err {
                                    err: SmtpStartTlsError::Rejected(msg),
                                };
                            }
                        }
                    }

                    // Failed to parse response
                    let msg = String::from_utf8_lossy(response_line).trim().to_string();
                    return SmtpStartTlsResult::Err {
                        err: SmtpStartTlsError::Rejected(msg),
                    };
                }
            }
        }
    }
}
