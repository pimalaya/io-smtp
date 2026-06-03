//! SMTP DATA coroutine; sends the message body terminated by
//! `<CR><LF>.<CR><LF>` with dot-stuffing applied.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
//!     rfc5321::data::SmtpData,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, MAIL/RCPT done)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let message = b"Subject: hi\r\n\r\nhello\r\n".to_vec();
//! let mut coroutine = SmtpData::new(message);
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(arg.take()) {
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         SmtpCoroutineState::Complete(Ok(())) => break,
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::fmt;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::trace;
use thiserror::Error;

use crate::{coroutine::*, rfc5321::types::reply_code::ReplyCode, send::*, smtp_try};

/// The DATA command (RFC 5321 §4.1.1.4).
pub struct SmtpDataCommand;

impl From<SmtpDataCommand> for Vec<u8> {
    fn from(_: SmtpDataCommand) -> Vec<u8> {
        b"DATA\r\n".to_vec()
    }
}

/// The message body terminated by `<CR><LF>.<CR><LF>` with
/// dot-stuffing applied to any line starting with `.`.
pub struct SmtpDataBody(pub Vec<u8>);

impl From<SmtpDataBody> for Vec<u8> {
    fn from(body: SmtpDataBody) -> Vec<u8> {
        body.0
    }
}

/// Failure causes during the SMTP DATA exchange.
#[derive(Clone, Debug, Error)]
pub enum SmtpDataError {
    #[error("SMTP DATA command failed: rejected {code} {message}")]
    CommandRejected { code: u16, message: String },
    #[error("SMTP DATA body failed: rejected {code} {message}")]
    BodyRejected { code: u16, message: String },
    #[error("SMTP DATA failed: {0}")]
    Send(#[from] SendSmtpCommandError),
}

/// I/O-free SMTP DATA coroutine.
pub struct SmtpData {
    state: State,
    body: Option<Vec<u8>>,
}

impl SmtpData {
    /// `message` is the complete email (headers + body);
    /// dot-stuffing and the terminator are appended internally.
    pub fn new(message: Vec<u8>) -> Self {
        Self {
            state: State::SendCommand(SendSmtpCommand::new(SmtpDataCommand)),
            body: Some(message),
        }
    }

    /// Apply dot-stuffing to `message`, normalise line endings, and
    /// append the `<CR><LF>.<CR><LF>` terminator.
    fn prepare_body(message: Vec<u8>) -> Vec<u8> {
        let mut result = Vec::with_capacity(message.len() + 5);

        let mut at_line_start = true;
        for &byte in &message {
            if at_line_start && byte == b'.' {
                result.push(b'.');
            }
            result.push(byte);
            at_line_start = byte == b'\n';
        }

        if !result.ends_with(b"\r\n") {
            if result.ends_with(b"\n") {
                result.pop();
                result.extend_from_slice(b"\r\n");
            } else if result.ends_with(b"\r") {
                result.push(b'\n');
            } else {
                result.extend_from_slice(b"\r\n");
            }
        }

        result.extend_from_slice(b".\r\n");

        result
    }
}

impl SmtpCoroutine for SmtpData {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpDataError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("data: {}", self.state);

            match &mut self.state {
                State::SendCommand(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != ReplyCode::START_MAIL_INPUT {
                        let code = out.response.code.code();
                        let message = out.response.text().to_string();
                        return SmtpCoroutineState::Complete(Err(SmtpDataError::CommandRejected {
                            code,
                            message,
                        }));
                    }

                    let body = self.body.take().expect("body taken twice");
                    let prepared = Self::prepare_body(body);
                    trace!("message body prepared: {} bytes", prepared.len());

                    self.state = State::SendBody(SendSmtpCommand::new(SmtpDataBody(prepared)));
                }
                State::SendBody(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code == ReplyCode::OK {
                        return SmtpCoroutineState::Complete(Ok(()));
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpDataError::BodyRejected {
                        code,
                        message,
                    }));
                }
            }
        }
    }
}

enum State {
    SendCommand(SendSmtpCommand<SmtpDataCommand>),
    SendBody(SendSmtpCommand<SmtpDataBody>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendCommand(_) => f.write_str("send data"),
            Self::SendBody(_) => f.write_str("send body"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_returns_ok() {
        let mut data = SmtpData::new(b"Subject: hi\r\n\r\nbody\r\n".to_vec());

        let bytes = expect_wants_write(&mut data, None);
        assert_eq!(bytes, b"DATA\r\n");

        expect_wants_read(&mut data);
        let body_bytes = expect_wants_write(&mut data, Some(b"354 send body\r\n"));
        assert!(body_bytes.ends_with(b"\r\n.\r\n"));

        expect_wants_read(&mut data);
        expect_complete_ok(&mut data, b"250 message accepted\r\n");
    }

    #[test]
    fn command_rejected_returns_command_error() {
        let mut data = SmtpData::new(b"hi\r\n".to_vec());
        let _ = expect_wants_write(&mut data, None);
        expect_wants_read(&mut data);

        let err = expect_complete_err(&mut data, b"503 bad sequence\r\n");
        let SmtpDataError::CommandRejected { code, message } = err else {
            panic!("expected SmtpDataError::CommandRejected, got {err:?}");
        };
        assert_eq!(code, 503);
        assert_eq!(message, "bad sequence");
    }

    #[test]
    fn body_rejected_returns_body_error() {
        let mut data = SmtpData::new(b"hi\r\n".to_vec());
        let _ = expect_wants_write(&mut data, None);
        expect_wants_read(&mut data);
        let _ = expect_wants_write(&mut data, Some(b"354 send body\r\n"));
        expect_wants_read(&mut data);

        let err = expect_complete_err(&mut data, b"552 too large\r\n");
        let SmtpDataError::BodyRejected { code, message } = err else {
            panic!("expected SmtpDataError::BodyRejected, got {err:?}");
        };
        assert_eq!(code, 552);
        assert_eq!(message, "too large");
    }

    #[test]
    fn dot_stuffs_leading_dot_lines() {
        let body = SmtpData::prepare_body(b".hello\r\n".to_vec());
        assert_eq!(body, b"..hello\r\n.\r\n");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut data = SmtpData::new(b"hi\r\n".to_vec());
        let _ = expect_wants_write(&mut data, None);
        expect_wants_read(&mut data);

        let err = expect_complete_err(&mut data, b"");
        assert!(matches!(
            err,
            SmtpDataError::Send(SendSmtpCommandError::Eof)
        ));
    }

    // --- utils

    fn expect_wants_write(cor: &mut SmtpData, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpData) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpData, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpData, reply: &[u8]) -> SmtpDataError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
