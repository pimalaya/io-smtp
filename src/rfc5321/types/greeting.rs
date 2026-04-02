//! Module dedicated to the SMTP greeting.

use std::fmt;

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use super::{domain::Domain, text::Text};

/// Server greeting sent upon connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Greeting<'a> {
    /// The server's domain name
    pub domain: Domain<'a>,
    /// Optional greeting text
    pub text: Option<Text<'a>>,
}

impl Greeting<'_> {
    /// Returns true if `buf` contains a complete greeting (ends with CRLF).
    pub fn is_complete(buf: &[u8]) -> bool {
        buf.ends_with(b"\r\n")
    }

    pub fn parse<'a>(buf: &'a [u8]) -> Result<Greeting<'a>, Vec<Rich<'a, u8>>> {
        parsers::greeting().parse(buf).into_result()
    }

    /// Creates a new greeting.
    pub fn new<'a>(domain: Domain<'a>, text: Option<Text<'a>>) -> Greeting<'a> {
        Greeting { domain, text }
    }
}

impl fmt::Display for Greeting<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "220 {}", self.domain)?;

        if let Some(ref text) = self.text {
            write!(f, " {text}")?;
        }

        Ok(())
    }
}

pub(crate) mod parsers {
    use chumsky::prelude::*;

    use crate::{
        rfc5321::types::{domain::parsers::domain, text::parsers::text},
        utils::parsers::{crlf, sp, Extra},
    };

    use super::Greeting;

    /// SMTP greeting parser.
    ///
    /// ```abnf
    /// Greeting       = ( "220" ( SP / "-" ) Domain SP textstring CRLF ) /
    ///                  ( "220-" Domain SP textstring CRLF
    ///                    *( "220-" [ textstring ] CRLF )
    ///                    "220" SP [ textstring ] CRLF )
    /// ```
    pub(crate) fn greeting<'a>() -> impl Parser<'a, &'a [u8], Greeting<'a>, Extra<'a>> + Clone {
        just(b"220" as &[u8])
            .ignore_then(sp())
            .ignore_then(domain())
            .then(sp().ignore_then(text()).or_not())
            .then_ignore(crlf())
            .map(|(domain, text)| Greeting { domain, text })
            .labelled("greeting")
    }
}
