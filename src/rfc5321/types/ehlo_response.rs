//! SMTP EHLO response (RFC 5321 §4.1.1.1).
//!
//! The multi-line reply to EHLO carrying the server domain and its
//! capability lines.

use alloc::{borrow::Cow, vec::Vec};

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use crate::rfc5321::types::{response::SmtpResponse, text::SmtpText};

/// EHLO response containing server capabilities.
///
/// Each capability is stored as a raw string exactly as advertised by
/// the server (e.g. `"AUTH PLAIN LOGIN"`, `"SIZE 10485760"`,
/// `"STARTTLS"`).  Individual RFC modules are responsible for parsing
/// the parameters of their own capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpEhloResponse<'a> {
    /// The name the server gives itself, taken as given: the first
    /// word of the first line, empty when the line is
    pub domain: SmtpText<'a>,
    /// Optional greeting text on the first line.
    pub greet: Option<SmtpText<'a>>,
    /// Server capabilities as raw keyword strings.
    pub capabilities: Vec<Cow<'a, str>>,
}

impl<'a> SmtpEhloResponse<'a> {
    /// Reads the EHLO response out of a reply, whatever its code.
    pub(crate) fn from_response(response: SmtpResponse<'a>) -> Self {
        let mut lines = response.lines.into_iter();

        let first = lines.next().unwrap_or(SmtpText(Cow::Borrowed("")));
        let (domain, greet) = first.split_identity();

        let capabilities = lines
            .filter(|line| !line.as_ref().is_empty())
            .map(Cow::from)
            .collect();

        Self {
            domain,
            greet,
            capabilities,
        }
    }
}

impl SmtpEhloResponse<'_> {
    /// Returns true if `buf` contains a complete EHLO response.
    ///
    /// It completes as any response does, see [`SmtpResponse::is_complete`].
    pub fn is_complete(buf: &[u8]) -> bool {
        SmtpResponse::is_complete(buf)
    }

    /// Parses an EHLO response from raw bytes.
    pub fn parse<'a>(buf: &'a [u8]) -> Result<SmtpEhloResponse<'a>, Vec<Rich<'a, u8>>> {
        parsers::ehlo_response().parse(buf).into_result()
    }

    /// Returns true if the server advertised the given capability keyword.
    ///
    /// The comparison is case-insensitive and matches only the keyword part
    /// (e.g. `"AUTH"` matches `"AUTH PLAIN LOGIN"`).
    pub fn has_capability(&self, keyword: &str) -> bool {
        self.get_capability(keyword).is_some()
    }

    /// Returns the full capability line for the given keyword, if
    /// advertised.
    ///
    /// The returned string is the raw line including the keyword and
    /// any parameters (e.g. `"AUTH PLAIN LOGIN"`, `"SIZE 52428800"`).
    /// Parse capability-specific values with `str::parse::<T>()`
    /// using the type from the relevant RFC module.
    ///
    /// The keyword comparison is case-insensitive.
    pub fn get_capability(&self, keyword: &str) -> Option<&str> {
        self.capabilities
            .iter()
            .find(|cap| {
                cap.split_ascii_whitespace()
                    .next()
                    .is_some_and(|k| k.eq_ignore_ascii_case(keyword))
            })
            .map(|cap| cap.as_ref())
    }
}

pub(crate) mod parsers {
    //! Chumsky parser for the SMTP EHLO response.

    use chumsky::prelude::*;

    use crate::{
        rfc5321::types::{
            ehlo_response::SmtpEhloResponse, reply_code::SmtpReplyCode, response::parsers::response,
        },
        utils::parsers::Extra,
    };

    /// SMTP EHLO response parser.
    ///
    /// A reply of code 250, single-line or multi-line:
    ///
    /// ```abnf
    /// ehlo-ok-rsp    = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
    ///                / ( "250-" Domain [ SP ehlo-greet ] CRLF
    ///                  *( "250-" ehlo-line CRLF )
    ///                  "250" [ SP ehlo-line ] CRLF )
    /// ehlo-line      = ehlo-keyword *( SP ehlo-param )
    /// ```
    ///
    /// The server name is not checked against the grammar: it is the first
    /// word of the first line. Every other line that is not empty is a
    /// capability.
    pub(crate) fn ehlo_response<'a>() -> impl Parser<'a, &'a [u8], SmtpEhloResponse<'a>, Extra<'a>>
    {
        response().try_map(|response, span| {
            if response.code == SmtpReplyCode::OK {
                Ok(SmtpEhloResponse::from_response(response))
            } else {
                Err(Rich::custom(span, "expected reply code 250"))
            }
        })
    }
}
