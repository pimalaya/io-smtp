//! SMTP greeting coroutine; reads the initial `220 <domain> …`
//! banner sent right after the transport handshake.
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
//!     rfc5321::greeting::SmtpGreetingGet,
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated if implicit)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let mut coroutine = SmtpGreetingGet::new();
//! let mut arg = None;
//!
//! let greeting = loop {
//!     match coroutine.resume(arg.take()) {
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         SmtpCoroutineState::Complete(Ok(greeting)) => break greeting,
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{greeting:?}");
//! ```

use core::{fmt, mem};

use alloc::{string::String, vec::Vec};

use bounded_static::IntoBoundedStatic;
use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::SmtpGreeting,
    utils::{escape_byte_string, parsers::format_rich_errors},
};

/// Failure causes while reading the SMTP greeting.
#[derive(Clone, Debug, Error)]
pub enum SmtpGreetingGetError {
    /// The stream reached EOF before a complete greeting arrived.
    #[error("SMTP greeting failed: reached unexpected EOF on stream")]
    Eof,
    /// The banner could not be parsed as an SMTP greeting.
    #[error("SMTP greeting failed: parse error: {0}")]
    ParseResponse(String),
}

/// I/O-free SMTP greeting-read coroutine.
pub struct SmtpGreetingGet {
    state: State,
    wants_read: bool,
    buf: Vec<u8>,
}

impl SmtpGreetingGet {
    /// Creates the coroutine.
    pub fn new() -> Self {
        Self {
            state: State::Read,
            wants_read: false,
            buf: Vec::new(),
        }
    }
}

impl Default for SmtpGreetingGet {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpCoroutine for SmtpGreetingGet {
    type Yield = SmtpYield;
    type Return = Result<SmtpGreeting<'static>, SmtpGreetingGetError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::Yielded(SmtpYield::WantsRead);
            }

            match &mut self.state {
                State::Read => match arg.take() {
                    Some(&[]) => {
                        return SmtpCoroutineState::Complete(Err(SmtpGreetingGetError::Eof));
                    }
                    Some(data) => {
                        trace!("read bytes: {}", escape_byte_string(data));
                        self.buf.extend_from_slice(data);

                        if !SmtpGreeting::is_complete(&self.buf) {
                            self.wants_read = true;
                            continue;
                        }

                        self.state = State::Parse;
                        debug!("greeting complete, parsing");
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::Parse => {
                    return match SmtpGreeting::parse(&self.buf) {
                        Ok(greeting) => {
                            let greeting = greeting.into_static();
                            let _ = mem::take(&mut self.buf);
                            debug!("greeting parsed");
                            trace!("{greeting:?}");
                            SmtpCoroutineState::Complete(Ok(greeting))
                        }
                        Err(errors) => {
                            let reason = format_rich_errors(errors);
                            SmtpCoroutineState::Complete(Err(SmtpGreetingGetError::ParseResponse(
                                reason,
                            )))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    Read,
    Parse,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read greeting"),
            Self::Parse => f.write_str("parse greeting"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{coroutine::*, rfc5321::greeting::*};

    #[test]
    fn single_line_success_returns_ok() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        let g = expect_complete_ok(&mut greeting, b"220 server.example.com ready\r\n");
        assert_eq!(g.domain.0.as_ref(), "server.example.com");
    }

    #[test]
    fn multi_line_success_returns_ok() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        let reply = b"220-server.example.com hello\r\n220-extra info\r\n220 ready\r\n";
        let g = expect_complete_ok(&mut greeting, reply);
        assert_eq!(g.domain.0.as_ref(), "server.example.com");
    }

    #[test]
    fn incomplete_greeting_re_yields_read() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        // NOTE: partial line: missing CRLF
        match greeting.resume(Some(b"220 server.example.com")) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    #[test]
    fn parse_error_returns_parse_error() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        // NOTE: 250 is not a valid greeting code
        let err = expect_complete_err(&mut greeting, b"250 wrong code\r\n");
        assert!(matches!(err, SmtpGreetingGetError::ParseResponse(_)));
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        let err = expect_complete_err(&mut greeting, b"");
        assert!(matches!(err, SmtpGreetingGetError::Eof));
    }

    fn expect_wants_read(cor: &mut SmtpGreetingGet) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpGreetingGet, reply: &[u8]) -> SmtpGreeting<'static> {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpGreetingGet, reply: &[u8]) -> SmtpGreetingGetError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
