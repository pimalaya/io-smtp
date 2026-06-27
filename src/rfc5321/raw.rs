//! SMTP raw passthrough coroutine; sends an arbitrary command line
//! and returns the server reply verbatim.
//!
//! Reserved for simple request/reply commands (`NOOP`, `VRFY`, `HELP`,
//! `RSET`, ...); do not use for `DATA` or `STARTTLS`, which switch the
//! stream into a different mode.
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
//!     rfc5321::raw::SmtpRaw,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, SMTP-handshaked)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = SmtpRaw::new("VRFY postmaster");
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
//!         SmtpCoroutineState::Complete(Ok(reply)) => {
//!             print!("{reply}");
//!             break;
//!         }
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::fmt::{self, Write};

use alloc::{borrow::Cow, string::String, vec::Vec};

use log::trace;
use thiserror::Error;

use crate::{coroutine::*, send::*, smtp_try};

/// An arbitrary raw SMTP command line, without the trailing CRLF.
pub struct SmtpRawCommand<'a> {
    /// The command line to send; CRLF is appended on serialisation.
    pub line: Cow<'a, str>,
}

impl<'a> From<SmtpRawCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpRawCommand<'a>) -> Vec<u8> {
        let mut buf = cmd.line.into_owned();
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Failure causes during the SMTP raw exchange.
#[derive(Clone, Debug, Error)]
pub enum SmtpRawError {
    #[error("SMTP raw command failed: {0}")]
    Send(#[from] SendSmtpCommandError),
}

/// I/O-free SMTP raw passthrough coroutine.
pub struct SmtpRaw {
    state: State,
}

impl SmtpRaw {
    /// `command` is a single SMTP command line without the trailing
    /// CRLF (e.g. `NOOP`, `VRFY foo@bar`, `HELP`).
    pub fn new(command: impl Into<Cow<'static, str>>) -> Self {
        Self {
            state: State::Send(SendSmtpCommand::new(SmtpRawCommand {
                line: command.into(),
            })),
        }
    }
}

impl SmtpCoroutine for SmtpRaw {
    type Yield = SmtpYield;
    type Return = Result<String, SmtpRawError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("raw: {}", self.state);

            match &mut self.state {
                State::Send(send) => {
                    let out = smtp_try!(send, arg);

                    // Reconstruct the full reply text from the parsed
                    // response: every line carries the same 3-digit code,
                    // continuation lines use `-`, the final line a space.
                    // Any reply code is a valid answer here, including 4xx
                    // and 5xx; only transport/parse failures are errors.
                    let response = out.response;
                    let lines = response.lines.as_ref();
                    let last = lines.len() - 1;

                    let mut reply = String::new();
                    for (i, line) in lines.iter().enumerate() {
                        let sep = if i == last { ' ' } else { '-' };
                        let _ = write!(reply, "{}{sep}{line}\r\n", response.code);
                    }

                    return SmtpCoroutineState::Complete(Ok(reply));
                }
            }
        }
    }
}

enum State {
    Send(SendSmtpCommand<SmtpRawCommand<'static>>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send raw command"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_returns_reply() {
        let mut raw = SmtpRaw::new("NOOP");

        let bytes = expect_wants_write(&mut raw, None);
        assert_eq!(bytes, b"NOOP\r\n");

        expect_wants_read(&mut raw);
        let reply = expect_complete_ok(&mut raw, b"250 OK\r\n");
        assert_eq!(reply, "250 OK\r\n");
    }

    #[test]
    fn multiline_reply_is_returned_verbatim() {
        let mut raw = SmtpRaw::new("EHLO host");
        let _ = expect_wants_write(&mut raw, None);
        expect_wants_read(&mut raw);

        let reply = expect_complete_ok(&mut raw, b"250-host greets you\r\n250 HELP\r\n");
        assert_eq!(reply, "250-host greets you\r\n250 HELP\r\n");
    }

    #[test]
    fn error_reply_is_returned_not_failed() {
        let mut raw = SmtpRaw::new("FOOBAR");
        let _ = expect_wants_write(&mut raw, None);
        expect_wants_read(&mut raw);

        let reply = expect_complete_ok(&mut raw, b"500 command unrecognized\r\n");
        assert_eq!(reply, "500 command unrecognized\r\n");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut raw = SmtpRaw::new("NOOP");
        let _ = expect_wants_write(&mut raw, None);
        expect_wants_read(&mut raw);

        let err = expect_complete_err(&mut raw, b"");
        assert!(matches!(err, SmtpRawError::Send(SendSmtpCommandError::Eof)));
    }

    // --- utils

    fn expect_wants_write(cor: &mut SmtpRaw, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpRaw) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpRaw, reply: &[u8]) -> String {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(out)) => out,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpRaw, reply: &[u8]) -> SmtpRawError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
