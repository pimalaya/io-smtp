//! SMTP STARTTLS coroutine; returns any bytes received past the
//! `220` reply. RFC 3207 §6 forbids trailing bytes, so a non-empty
//! return value is a STARTTLS-injection signal: refuse the upgrade.
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
//!     rfc3207::starttls::SmtpStartTls,
//! };
//!
//! // Ready stream needed (TCP-connected, plain SMTP, greeting + EHLO done)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = SmtpStartTls::new();
//! let mut arg = None;
//!
//! let remaining = loop {
//!     match coroutine.resume(arg.take()) {
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         SmtpCoroutineState::Complete(Ok(remaining)) => break remaining,
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! assert!(remaining.is_empty(), "STARTTLS-injection: refuse the upgrade");
//! // Now upgrade `stream` to TLS before sending further SMTP commands.
//! ```

use core::{fmt, mem};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::{SmtpReplyCode, SmtpResponse},
    send::*,
    utils::{escape_byte_string, parsers::format_rich_errors},
};

/// The STARTTLS command (RFC 3207).
pub struct SmtpStartTlsCommand;

impl From<SmtpStartTlsCommand> for Vec<u8> {
    fn from(_: SmtpStartTlsCommand) -> Vec<u8> {
        b"STARTTLS\r\n".to_vec()
    }
}

/// Failure causes during the SMTP STARTTLS handshake.
#[derive(Clone, Debug, Error)]
pub enum SmtpStartTlsError {
    /// The server rejected the STARTTLS command.
    #[error("SMTP STARTTLS failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The underlying command exchange failed.
    #[error("SMTP STARTTLS failed: {0}")]
    Send(#[from] SmtpCommandSendError),
}

/// I/O-free SMTP STARTTLS coroutine.
pub struct SmtpStartTls {
    state: State,
    wants_write: Option<Vec<u8>>,
    wants_read: bool,
    buf: Vec<u8>,
    trailing: Vec<u8>,
}

impl SmtpStartTls {
    /// Creates the coroutine.
    pub fn new() -> Self {
        Self {
            state: State::Read,
            wants_write: Some(SmtpStartTlsCommand.into()),
            wants_read: false,
            buf: Vec::new(),
            trailing: Vec::new(),
        }
    }
}

impl Default for SmtpStartTls {
    fn default() -> Self {
        Self::new()
    }
}

// NOTE: the exchange owns its read loop rather than delegating to
// SmtpCommandSend, which consumes everything it read: the bytes past the
// reply are the whole point here, and they have to survive parsing.
impl SmtpCoroutine for SmtpStartTls {
    type Yield = SmtpYield;
    type Return = Result<Vec<u8>, SmtpStartTlsError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                self.state = State::Read;
                debug!("starttls sent, awaiting response");
                return SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes));
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::Yielded(SmtpYield::WantsRead);
            }

            match &mut self.state {
                State::Read => match arg.take() {
                    Some(&[]) => {
                        let err = SmtpStartTlsError::Send(SmtpCommandSendError::Eof);
                        return SmtpCoroutineState::Complete(Err(err));
                    }
                    Some(data) => {
                        trace!("read bytes: {}", escape_byte_string(data));
                        self.buf.extend_from_slice(data);

                        let Some(end) = reply_end(&self.buf) else {
                            self.wants_read = true;
                            continue;
                        };

                        self.trailing = self.buf.split_off(end);
                        self.state = State::Parse;
                        debug!("starttls response complete, parsing");
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::Parse => {
                    return match SmtpResponse::parse(&self.buf) {
                        Ok(response) if response.code == SmtpReplyCode::SERVICE_READY => {
                            debug!("starttls accepted, ready to upgrade");
                            SmtpCoroutineState::Complete(Ok(mem::take(&mut self.trailing)))
                        }
                        Ok(response) => {
                            let code = response.code.code();
                            let message = response.text().to_string();
                            let err = SmtpStartTlsError::Rejected { code, message };
                            SmtpCoroutineState::Complete(Err(err))
                        }
                        Err(errors) => {
                            let reason = format_rich_errors(errors);
                            let err = SmtpCommandSendError::ParseResponse(reason);
                            SmtpCoroutineState::Complete(Err(SmtpStartTlsError::Send(err)))
                        }
                    };
                }
            }
        }
    }
}

/// Finds where the first complete reply ends in `buf`.
///
/// A reply ends at the first line whose fourth byte is a space (RFC 5321
/// §4.2.1); a hyphen there continues it. Returns the index just past
/// that line's CRLF, or [`None`] while the reply is still incomplete.
/// Anything past that index arrived early and, for STARTTLS, arrived
/// from an attacker.
fn reply_end(buf: &[u8]) -> Option<usize> {
    let mut start = 0;

    while let Some(rel) = buf[start..].iter().position(|&b| b == b'\n') {
        let end = start + rel + 1;
        let line = &buf[start..end];

        if line.len() >= 4 && line[3] == b' ' {
            return Some(end);
        }

        start = end;
    }

    None
}

enum State {
    Read,
    Parse,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read starttls response"),
            Self::Parse => f.write_str("parse starttls response"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{coroutine::*, rfc3207::starttls::*, send::SmtpCommandSendError};

    #[test]
    fn success_returns_empty_remaining() {
        let mut starttls = SmtpStartTls::new();

        let bytes = expect_wants_write(&mut starttls, None);
        assert_eq!(bytes, b"STARTTLS\r\n");

        expect_wants_read(&mut starttls);
        let remaining = expect_complete_ok(&mut starttls, b"220 ready\r\n");
        assert!(remaining.is_empty());
    }

    #[test]
    fn multi_line_success_returns_empty_remaining() {
        let mut starttls = SmtpStartTls::new();
        let _ = expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        let reply = b"220-server.example.com\r\n220 ready\r\n";
        let remaining = expect_complete_ok(&mut starttls, reply);
        assert!(remaining.is_empty());
    }

    #[test]
    fn bytes_past_the_reply_are_returned_verbatim() {
        let mut starttls = SmtpStartTls::new();
        let _ = expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        // NOTE: the injected command rides in the same TCP segment as
        // the 220 reply, so the server would replay it inside the TLS
        // session; the caller must refuse the upgrade.
        let remaining = expect_complete_ok(&mut starttls, b"220 ready\r\nRSET\r\n");
        assert_eq!(remaining, b"RSET\r\n");
    }

    #[test]
    fn partial_reply_re_yields_read() {
        let mut starttls = SmtpStartTls::new();
        let _ = expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        match starttls.resume(Some(b"220 rea")) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }

        let remaining = expect_complete_ok(&mut starttls, b"dy\r\n");
        assert!(remaining.is_empty());
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut starttls = SmtpStartTls::new();
        let _ = expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        let err = expect_complete_err(&mut starttls, b"454 TLS not available\r\n");
        let SmtpStartTlsError::Rejected { code, message } = err else {
            panic!("expected SmtpStartTlsError::Rejected, got {err:?}");
        };
        assert_eq!(code, 454);
        assert_eq!(message, "TLS not available");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut starttls = SmtpStartTls::new();
        let _ = expect_wants_write(&mut starttls, None);
        expect_wants_read(&mut starttls);

        let err = expect_complete_err(&mut starttls, b"");
        assert!(matches!(
            err,
            SmtpStartTlsError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpStartTls, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpStartTls) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpStartTls, reply: &[u8]) -> Vec<u8> {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(remaining)) => remaining,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpStartTls, reply: &[u8]) -> SmtpStartTlsError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
