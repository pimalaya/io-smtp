//! SMTP EHLO coroutine; returns the raw capability lines the
//! server advertises in its multi-line `250` reply.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     borrow::Cow,
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
//!     rfc5321::{
//!         ehlo::SmtpEhlo,
//!         types::{domain::SmtpDomain, ehlo_domain::SmtpEhloDomain},
//!     },
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, greeting consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com")));
//! let mut coroutine = SmtpEhlo::new(domain);
//! let mut arg = None;
//!
//! let capabilities = loop {
//!     match coroutine.resume(arg.take()) {
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         SmtpCoroutineState::Complete(Ok(caps)) => break caps,
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{capabilities:?}");
//! ```

use core::{fmt, mem};

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::types::{ehlo_domain::SmtpEhloDomain, ehlo_response::SmtpEhloResponse},
    utils::{escape_byte_string, parsers::format_rich_errors},
};

/// The EHLO command (RFC 5321 §4.1.1.1).
pub struct SmtpEhloCommand<'a> {
    /// The client's domain or address literal.
    pub domain: SmtpEhloDomain<'a>,
}

impl<'a> From<SmtpEhloCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpEhloCommand<'a>) -> Vec<u8> {
        let mut buf = String::from("EHLO ");
        buf.push_str(&cmd.domain.to_string());
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Failure causes during the SMTP EHLO exchange.
#[derive(Clone, Debug, Error)]
pub enum SmtpEhloError {
    /// The stream reached EOF before a complete reply arrived.
    #[error("SMTP EHLO failed: reached unexpected EOF on stream")]
    Eof,
    /// The reply could not be parsed as an EHLO response.
    #[error("SMTP EHLO failed: parse error: {0}")]
    ParseResponse(String),
}

/// I/O-free SMTP EHLO coroutine.
pub struct SmtpEhlo {
    state: State,
    wants_write: Option<Vec<u8>>,
    wants_read: bool,
    buf: Vec<u8>,
}

impl SmtpEhlo {
    /// Creates the coroutine from the client identity sent to the
    /// server.
    pub fn new(domain: SmtpEhloDomain<'_>) -> Self {
        let bytes = SmtpEhloCommand {
            domain: domain.into_static(),
        }
        .into();

        Self {
            state: State::Write,
            wants_write: Some(bytes),
            wants_read: false,
            buf: Vec::new(),
        }
    }
}

impl SmtpCoroutine for SmtpEhlo {
    type Yield = SmtpYield;
    type Return = Result<Vec<Cow<'static, str>>, SmtpEhloError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                self.state = State::Read;
                debug!("ehlo sent, awaiting response");
                return SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes));
            }

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::Yielded(SmtpYield::WantsRead);
            }

            match &mut self.state {
                State::Write => unreachable!("Write state handled above"),
                State::Read => match arg.take() {
                    Some(&[]) => {
                        return SmtpCoroutineState::Complete(Err(SmtpEhloError::Eof));
                    }
                    Some(data) => {
                        trace!("read bytes: {}", escape_byte_string(data));
                        self.buf.extend_from_slice(data);

                        if !SmtpEhloResponse::is_complete(&self.buf) {
                            self.wants_read = true;
                            continue;
                        }

                        self.state = State::Parse;
                        debug!("ehlo response complete, parsing");
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::Parse => {
                    return match SmtpEhloResponse::parse(&self.buf) {
                        Ok(response) => {
                            let capabilities = response.into_static().capabilities;
                            let _ = mem::take(&mut self.buf);
                            debug!("ehlo response parsed");
                            trace!("{capabilities:?}");
                            SmtpCoroutineState::Complete(Ok(capabilities))
                        }
                        Err(errors) => {
                            let reason = format_rich_errors(errors);
                            SmtpCoroutineState::Complete(Err(SmtpEhloError::ParseResponse(reason)))
                        }
                    };
                }
            }
        }
    }
}

enum State {
    Write,
    Read,
    Parse,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write => f.write_str("send ehlo"),
            Self::Read => f.write_str("read ehlo response"),
            Self::Parse => f.write_str("parse ehlo response"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, vec::Vec};

    use crate::{
        coroutine::*,
        rfc5321::{
            ehlo::*,
            types::{domain::SmtpDomain, ehlo_domain::SmtpEhloDomain},
        },
    };

    fn ehlo_domain() -> SmtpEhloDomain<'static> {
        SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com")))
    }

    #[test]
    fn single_line_success_returns_empty_capabilities() {
        let mut ehlo = SmtpEhlo::new(ehlo_domain());

        let bytes = expect_wants_write(&mut ehlo, None);
        assert_eq!(bytes, b"EHLO example.com\r\n");

        expect_wants_read(&mut ehlo);
        let caps = expect_complete_ok(&mut ehlo, b"250 server.example.com\r\n");
        assert!(caps.is_empty());
    }

    #[test]
    fn multi_line_success_returns_capabilities() {
        let mut ehlo = SmtpEhlo::new(ehlo_domain());
        let _ = expect_wants_write(&mut ehlo, None);
        expect_wants_read(&mut ehlo);

        let reply = b"250-server.example.com\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10485760\r\n";
        let caps = expect_complete_ok(&mut ehlo, reply);
        assert_eq!(caps.len(), 2);
        assert!(caps.iter().any(|c| c.as_ref() == "AUTH PLAIN LOGIN"));
        assert!(caps.iter().any(|c| c.as_ref() == "SIZE 10485760"));
    }

    #[test]
    fn incomplete_response_re_yields_read() {
        let mut ehlo = SmtpEhlo::new(ehlo_domain());
        let _ = expect_wants_write(&mut ehlo, None);
        expect_wants_read(&mut ehlo);

        match ehlo.resume(Some(b"250-server.example.com\r\n250-AUTH PLAIN")) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    #[test]
    fn parse_error_returns_parse_error() {
        let mut ehlo = SmtpEhlo::new(ehlo_domain());
        let _ = expect_wants_write(&mut ehlo, None);
        expect_wants_read(&mut ehlo);

        let err = expect_complete_err(&mut ehlo, b"500 syntax error\r\n");
        assert!(matches!(err, SmtpEhloError::ParseResponse(_)));
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut ehlo = SmtpEhlo::new(ehlo_domain());
        let _ = expect_wants_write(&mut ehlo, None);
        expect_wants_read(&mut ehlo);

        let err = expect_complete_err(&mut ehlo, b"");
        assert!(matches!(err, SmtpEhloError::Eof));
    }

    fn expect_wants_write(cor: &mut SmtpEhlo, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpEhlo) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpEhlo, reply: &[u8]) -> Vec<Cow<'static, str>> {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(value)) => value,
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpEhlo, reply: &[u8]) -> SmtpEhloError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
