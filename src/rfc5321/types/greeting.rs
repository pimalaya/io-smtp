//! SMTP greeting (RFC 5321 §4.2).
//!
//! The 220 banner the server sends right after the transport
//! handshake, carrying its domain and an optional text.

use core::fmt;

use alloc::{borrow::Cow, vec::Vec};

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use crate::rfc5321::types::{response::SmtpResponse, text::SmtpText};

/// Server greeting sent upon connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpGreeting<'a> {
    /// The name the server gives itself, taken as given: the first
    /// word of the first line, empty when the line is
    pub domain: SmtpText<'a>,
    /// Optional greeting text (from the first greeting line)
    pub text: Option<SmtpText<'a>>,
}

impl<'a> SmtpGreeting<'a> {
    /// Reads the greeting out of a reply, whatever its code.
    pub(crate) fn from_response(response: SmtpResponse<'a>) -> Self {
        let first = response.lines.into_iter().next();
        let first = first.unwrap_or(SmtpText(Cow::Borrowed("")));
        let (domain, text) = first.split_identity();

        Self { domain, text }
    }
}

impl SmtpGreeting<'_> {
    /// Returns true if `buf` contains a complete greeting.
    ///
    /// A greeting completes as any response does, see
    /// [`SmtpResponse::is_complete`].
    pub fn is_complete(buf: &[u8]) -> bool {
        SmtpResponse::is_complete(buf)
    }

    /// Parses a greeting from raw bytes.
    pub fn parse<'a>(buf: &'a [u8]) -> Result<SmtpGreeting<'a>, Vec<Rich<'a, u8>>> {
        parsers::greeting().parse(buf).into_result()
    }

    /// Creates a new greeting.
    pub fn new<'a>(domain: SmtpText<'a>, text: Option<SmtpText<'a>>) -> SmtpGreeting<'a> {
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

    use chumsky::prelude::*;

    use crate::{
        rfc5321::types::{
            greeting::SmtpGreeting, reply_code::SmtpReplyCode, response::parsers::response,
        },
        utils::parsers::Extra,
    };

    /// SMTP greeting parser.
    ///
    /// A reply of code 220, single-line or multi-line:
    ///
    /// ```abnf
    /// Greeting       = ( "220 " (Domain / address-literal)
    ///                [ SP textstring ] CRLF ) /
    ///                ( "220-" (Domain / address-literal)
    ///                [ SP textstring ] CRLF
    ///                *( "220-" [ textstring ] CRLF )
    ///                "220" [ SP textstring ] CRLF )
    /// ```
    ///
    /// The server name is not checked against the grammar: it is the first
    /// word of the first line. Only the first line is retained;
    /// continuation lines carry text clients do not need to act on.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc5321#section-4.2>
    pub(crate) fn greeting<'a>() -> impl Parser<'a, &'a [u8], SmtpGreeting<'a>, Extra<'a>> + Clone {
        response()
            .try_map(|response, span| {
                if response.code == SmtpReplyCode::SERVICE_READY {
                    Ok(SmtpGreeting::from_response(response))
                } else {
                    Err(Rich::custom(span, "expected reply code 220"))
                }
            })
            .labelled("greeting")
    }
}
