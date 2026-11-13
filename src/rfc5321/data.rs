//! SMTP DATA coroutine; sends the message body terminated by
//! `<CR><LF>.<CR><LF>`, every line ending as CRLF and dot-stuffing applied.
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

use alloc::{string::String, vec::Vec};

use log::{debug, trace};
use thiserror::Error;

use crate::{coroutine::*, rfc5321::SmtpReplyCode, scan::position, send::*, smtp_try};

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const CRLF: &[u8] = b"\r\n";

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
    /// The server rejected the DATA command itself.
    #[error("SMTP DATA command failed: rejected {code} {message}")]
    CommandRejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The server rejected the message body.
    #[error("SMTP DATA body failed: rejected {code} {message}")]
    BodyRejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The underlying command exchange failed.
    #[error("SMTP DATA failed: {0}")]
    Send(#[from] SmtpCommandSendError),
}

/// I/O-free SMTP DATA coroutine.
pub struct SmtpData {
    state: State,
    body: Option<Vec<u8>>,
}

impl SmtpData {
    /// `message` is the complete email (headers + body); line endings,
    /// dot-stuffing and the terminator are taken care of internally.
    pub fn new(message: Vec<u8>) -> Self {
        Self {
            state: State::SendCommand(SmtpCommandSend::new(SmtpDataCommand)),
            body: Some(message),
        }
    }

    /// Turns every bare CR and bare LF of `message` into CRLF, doubles the
    /// dot starting a line, ends the last line, then appends the `.` line.
    ///
    /// `message` is reused as is when it needs none of the first two.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc5321#section-2.3.8>,
    /// <https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.2>
    pub(crate) fn prepare_body(message: Vec<u8>) -> Vec<u8> {
        let mut out = Vec::new();
        // NOTE: message[..copied] is in out already, once out is used.
        let mut copied = 0;
        let mut at = 0;

        if message.first() == Some(&b'.') {
            out.push(b'.');
        }

        while let Some(i) = position(&message[at..], |b| (b == CR) | (b == LF)) {
            let i = at + i;

            let (end, bare) = match message.get(i..i + 2) {
                Some(CRLF) => (i + 2, false),
                _ => (i + 1, true),
            };

            let dot = message.get(end) == Some(&b'.');

            if bare || dot {
                if out.is_empty() {
                    out.reserve(message.len() + message.len() / 32 + 8);
                }

                out.extend_from_slice(&message[copied..i]);
                out.extend_from_slice(CRLF);

                if dot {
                    out.push(b'.');
                }

                copied = end;
            }

            at = end;
        }

        let mut body = match out.is_empty() {
            true => message,
            false => {
                out.extend_from_slice(&message[copied..]);
                out
            }
        };

        if !body.ends_with(CRLF) {
            body.extend_from_slice(CRLF);
        }

        body.extend_from_slice(b".\r\n");
        body
    }
}

impl SmtpCoroutine for SmtpData {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpDataError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::SendCommand(send) => {
                    let out = smtp_try!(send, arg.take());

                    if out.response.code != SmtpReplyCode::START_MAIL_INPUT {
                        let code = out.response.code.code();
                        let message = out.response.message();
                        return SmtpCoroutineState::Complete(Err(SmtpDataError::CommandRejected {
                            code,
                            message,
                        }));
                    }

                    let body = self.body.take().expect("body taken twice");
                    let prepared = Self::prepare_body(body);

                    let len = prepared.len();
                    self.state = State::SendBody(SmtpCommandSend::new(SmtpDataBody(prepared)));
                    debug!("data accepted, sending body");
                    trace!("prepared body: {len} bytes");
                }
                State::SendBody(send) => {
                    let out = smtp_try!(send, arg.take());

                    if out.response.code == SmtpReplyCode::OK {
                        debug!("body accepted");
                        return SmtpCoroutineState::Complete(Ok(()));
                    }

                    let code = out.response.code.code();
                    let message = out.response.message();
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
    SendCommand(SmtpCommandSend<SmtpDataCommand>),
    SendBody(SmtpCommandSend<SmtpDataBody>),
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
    use alloc::vec::Vec;

    use crate::{rfc5321::data::*, send::SmtpCommandSendError};

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
        let body = SmtpData::prepare_body(b".hello\r\n.\r\nx\r\n".to_vec());
        assert_eq!(body, b"..hello\r\n..\r\nx\r\n.\r\n");
    }

    #[test]
    fn turns_bare_line_endings_into_crlf() {
        let body = SmtpData::prepare_body(b"a\nb\rc\r\nd".to_vec());
        assert_eq!(body, b"a\r\nb\r\nc\r\nd\r\n.\r\n");
    }

    /// A bare CR or LF before a dot cannot end the data early on a server
    /// reading bare line endings.
    #[test]
    fn dot_stuffs_after_bare_line_endings() {
        let body = SmtpData::prepare_body(b"a\r.\r\nb\n.\nc".to_vec());
        assert_eq!(body, b"a\r\n..\r\nb\r\n..\r\nc\r\n.\r\n");
    }

    #[test]
    fn ends_an_empty_message() {
        assert_eq!(SmtpData::prepare_body(Vec::new()), b"\r\n.\r\n");
    }

    #[test]
    fn matches_a_byte_by_byte_rewrite() {
        let alphabet = *b"a.\r\n";
        let mut message = Vec::new();

        for len in 0..=8u32 {
            for mut n in 0..4usize.pow(len) {
                message.clear();

                for _ in 0..len {
                    message.push(alphabet[n % 4]);
                    n /= 4;
                }

                let expected = byte_by_byte(&message);
                assert_eq!(SmtpData::prepare_body(message.clone()), expected);
            }
        }
    }

    /// The rewrite of RFC 5321 sections 2.3.8 and 4.5.2, one byte at a time.
    fn byte_by_byte(message: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut line_start = true;
        let mut bytes = message.iter().peekable();

        while let Some(&byte) = bytes.next() {
            if line_start && byte == b'.' {
                out.push(b'.');
            }

            line_start = byte == b'\r' || byte == b'\n';

            if line_start {
                out.extend_from_slice(b"\r\n");

                if byte == b'\r' && bytes.peek() == Some(&&b'\n') {
                    bytes.next();
                }
            } else {
                out.push(byte);
            }
        }

        if !line_start || out.is_empty() {
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(b".\r\n");
        out
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut data = SmtpData::new(b"hi\r\n".to_vec());
        let _ = expect_wants_write(&mut data, None);
        expect_wants_read(&mut data);

        let err = expect_complete_err(&mut data, b"");
        assert!(matches!(
            err,
            SmtpDataError::Send(SmtpCommandSendError::Eof)
        ));
    }

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
