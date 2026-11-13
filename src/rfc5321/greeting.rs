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
    rfc5321::{SmtpGreeting, SmtpReplyCode, SmtpResponse},
    send::SMTP_MAX_REPLY_LEN,
    utils::{escape_byte_string, parsers::format_rich_errors},
};

/// Failure causes while reading the SMTP greeting.
#[derive(Clone, Debug, Error)]
pub enum SmtpGreetingGetError {
    /// The stream reached EOF before a complete greeting arrived.
    #[error("SMTP greeting failed: reached unexpected EOF on stream")]
    Eof,
    /// The greeting grew past the given limit before it completed.
    #[error("SMTP greeting failed: greeting exceeds {0} bytes")]
    TooLarge(usize),
    /// The server answered with another code than 220.
    #[error("SMTP greeting failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text, every line joined by a space.
        message: String,
    },
    /// The banner could not be parsed as an SMTP reply.
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

                        if self.buf.len() > SMTP_MAX_REPLY_LEN {
                            let err = SmtpGreetingGetError::TooLarge(SMTP_MAX_REPLY_LEN);
                            return SmtpCoroutineState::Complete(Err(err));
                        }

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
                    return match SmtpResponse::parse(&self.buf) {
                        Ok(response) if response.code == SmtpReplyCode::SERVICE_READY => {
                            let greeting = SmtpGreeting::from_response(response).into_static();
                            let _ = mem::take(&mut self.buf);
                            debug!("greeting parsed");
                            trace!("{greeting:?}");
                            SmtpCoroutineState::Complete(Ok(greeting))
                        }
                        Ok(response) => {
                            let code = response.code.code();
                            let message = response.message();
                            debug!("greeting rejected");
                            let err = SmtpGreetingGetError::Rejected { code, message };
                            SmtpCoroutineState::Complete(Err(err))
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
    use crate::rfc5321::greeting::*;

    #[test]
    fn single_line_success_returns_ok() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        let g = expect_complete_ok(&mut greeting, b"220 server.example.com ready\r\n");
        assert_eq!(g.domain.as_ref(), "server.example.com");
    }

    #[test]
    fn multi_line_success_returns_ok() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        let reply = b"220-server.example.com hello\r\n220-extra info\r\n220 ready\r\n";
        let g = expect_complete_ok(&mut greeting, reply);
        assert_eq!(g.domain.as_ref(), "server.example.com");
    }

    #[test]
    fn endless_greeting_returns_too_large() {
        let mut greeting = SmtpGreetingGet::new();
        let line = [b"220-".as_slice(), &[b'x'; 1018], b"\r\n"].concat();
        let mut arg = None;

        let err = (0..100)
            .find_map(|_| match greeting.resume(arg.take()) {
                SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                    arg = Some(line.as_slice());
                    None
                }
                SmtpCoroutineState::Complete(Err(err)) => Some(err),
                state => panic!("expected WantsRead or Complete(Err), got {state:?}"),
            })
            .expect("the reply never hit the limit");

        assert!(matches!(
            err,
            SmtpGreetingGetError::TooLarge(SMTP_MAX_REPLY_LEN)
        ));
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
    fn server_name_outside_the_grammar_returns_ok() {
        let names = [
            "[192.0.2.1]",
            "mail_gw.corp.local",
            "mail.example.org.",
            "***",
        ];

        for name in names {
            let mut greeting = SmtpGreetingGet::new();
            expect_wants_read(&mut greeting);

            let reply = [b"220 ", name.as_bytes(), b" ESMTP ready\r\n"].concat();
            let g = expect_complete_ok(&mut greeting, &reply);
            assert_eq!(g.domain.as_ref(), name);
            assert_eq!(g.text.unwrap().as_ref(), "ESMTP ready");
        }
    }

    #[test]
    fn bare_code_returns_ok() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        let g = expect_complete_ok(&mut greeting, b"220\r\n");
        assert_eq!(g.domain.as_ref(), "");
        assert_eq!(g.text, None);
    }

    #[test]
    fn refused_connection_returns_rejected_error() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        let reply = b"554-5.7.1 Service unavailable\r\n554 5.7.1 client host blocked\r\n";
        let err = expect_complete_err(&mut greeting, reply);
        let SmtpGreetingGetError::Rejected { code, message } = err else {
            panic!("expected SmtpGreetingGetError::Rejected, got {err:?}");
        };
        assert_eq!(code, 554);
        assert_eq!(
            message,
            "5.7.1 Service unavailable 5.7.1 client host blocked"
        );
    }

    #[test]
    fn parse_error_returns_parse_error() {
        let mut greeting = SmtpGreetingGet::new();
        expect_wants_read(&mut greeting);

        let err = expect_complete_err(&mut greeting, b"999 not a reply code\r\n");
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
