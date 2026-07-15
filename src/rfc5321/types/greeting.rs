//! SMTP greeting (RFC 5321 §4.2).
//!
//! The 220 banner the server sends right after the transport
//! handshake, carrying its domain and an optional text.

use core::fmt;

use alloc::vec::Vec;

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use crate::rfc5321::types::{domain::SmtpDomain, text::SmtpText};

/// Server greeting sent upon connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpGreeting<'a> {
    /// The server's domain name
    pub domain: SmtpDomain<'a>,
    /// Optional greeting text (from the first greeting line)
    pub text: Option<SmtpText<'a>>,
}

impl SmtpGreeting<'_> {
    /// Returns true if `buf` contains a complete greeting.
    ///
    /// A greeting is complete when the last CRLF-terminated line begins with
    /// `220 ` (space, not dash). This correctly handles both single-line and
    /// multi-line greetings.
    pub fn is_complete(buf: &[u8]) -> bool {
        if !buf.ends_with(b"\r\n") {
            return false;
        }

        let body = &buf[..buf.len() - 2];
        let line_start = body
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(0);

        let last_line = &body[line_start..];
        last_line.len() >= 4 && last_line[3] == b' '
    }

    /// Parses a greeting from raw bytes.
    pub fn parse<'a>(buf: &'a [u8]) -> Result<SmtpGreeting<'a>, Vec<Rich<'a, u8>>> {
        parsers::greeting().parse(buf).into_result()
    }

    /// Creates a new greeting.
    pub fn new<'a>(domain: SmtpDomain<'a>, text: Option<SmtpText<'a>>) -> SmtpGreeting<'a> {
        SmtpGreeting { domain, text }
    }
}

impl fmt::Display for SmtpGreeting<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "220 {}", self.domain)?;

        if let Some(ref text) = self.text {
            write!(f, " {text}")?;
        }

        Ok(())
    }
}

pub(crate) mod parsers {
    //! Chumsky parser for the SMTP greeting.

    use alloc::vec::Vec;

    use chumsky::prelude::*;

    use crate::{
        rfc5321::types::{domain::parsers::domain, greeting::SmtpGreeting, text::parsers::text},
        utils::parsers::{Extra, crlf, sp},
    };

    /// SMTP greeting parser.
    ///
    /// Handles both single-line and multi-line greetings per RFC 5321:
    ///
    /// ```abnf
    /// Greeting       = ( "220" ( SP / "-" ) Domain [ SP textstring ] CRLF ) /
    ///                  ( "220-" Domain [ SP textstring ] CRLF
    ///                    *( "220-" [ textstring ] CRLF )
    ///                    "220" SP [ textstring ] CRLF )
    /// ```
    ///
    /// Only the domain and text from the first line are retained; continuation
    /// lines carry informational text that clients do not need to act on.
    pub(crate) fn greeting<'a>() -> impl Parser<'a, &'a [u8], SmtpGreeting<'a>, Extra<'a>> + Clone {
        // NOTE: single-line: "220 " domain [SP text] CRLF
        let single = just(b"220" as &[u8])
            .ignore_then(sp())
            .ignore_then(domain())
            .then(sp().ignore_then(text()).or_not())
            .then_ignore(crlf())
            .map(|(domain, text)| SmtpGreeting { domain, text });

        // NOTE: multi-line first line: "220-" domain [SP text] CRLF
        let multi_first = just(b"220" as &[u8])
            .ignore_then(just(b'-'))
            .ignore_then(domain())
            .then(sp().ignore_then(text()).or_not())
            .then_ignore(crlf());

        // NOTE: continuation lines: "220-" [text] CRLF
        let multi_cont = just(b"220" as &[u8])
            .then_ignore(just(b'-'))
            .ignore_then(text().or_not())
            .then_ignore(crlf());

        // NOTE: final line: "220 " [text] CRLF
        let multi_last = just(b"220" as &[u8])
            .ignore_then(sp())
            .ignore_then(text().or_not())
            .then_ignore(crlf());

        let multi = multi_first
            .then(multi_cont.repeated().collect::<Vec<_>>())
            .then(multi_last)
            .map(|((first, _conts), _last)| {
                let (domain, text) = first;
                SmtpGreeting { domain, text }
            });

        choice((multi, single)).labelled("greeting")
    }
}
