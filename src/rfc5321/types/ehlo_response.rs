//! Module dedicated to the SMTP EHLO response.

use alloc::{borrow::Cow, vec::Vec};

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use super::{domain::Domain, text::Text};

/// EHLO response containing server capabilities.
///
/// Each capability is stored as a raw string exactly as advertised by
/// the server (e.g. `"AUTH PLAIN LOGIN"`, `"SIZE 10485760"`,
/// `"STARTTLS"`).  Individual RFC modules are responsible for parsing
/// the parameters of their own capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct EhloResponse<'a> {
    /// The server's domain name.
    pub domain: Domain<'a>,
    /// Optional greeting text on the first line.
    pub greet: Option<Text<'a>>,
    /// Server capabilities as raw keyword strings.
    pub capabilities: Vec<Cow<'a, str>>,
}

impl EhloResponse<'_> {
    /// Returns true if `buf` contains a complete EHLO response.
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

    pub fn parse<'a>(buf: &'a [u8]) -> Result<EhloResponse<'a>, Vec<Rich<'a, u8>>> {
        parsers::ehlo_response().parse(buf).into_result()
    }

    /// Returns true if the server advertised the given capability keyword.
    ///
    /// The comparison is case-insensitive and matches only the keyword part
    /// (e.g. `"AUTH"` matches `"AUTH PLAIN LOGIN"`).
    pub fn has_capability(&self, keyword: &str) -> bool {
        self.capabilities.iter().any(|cap| {
            let cap_keyword = cap.split_ascii_whitespace().next().unwrap_or("");
            cap_keyword.eq_ignore_ascii_case(keyword)
        })
    }
}

pub(crate) mod parsers {
    use alloc::{borrow::Cow, vec::Vec};
    use core::str::from_utf8;

    use chumsky::prelude::*;

    use crate::{
        rfc5321::types::{
            domain::parsers::domain as domain_parser, text::parsers::text as text_parser,
        },
        utils::parsers::{Extra, crlf, sp},
    };

    use super::EhloResponse;

    /// Parses a single EHLO capability line as a raw string.
    pub(crate) fn capability<'a>() -> impl Parser<'a, &'a [u8], Cow<'a, str>, Extra<'a>> + Clone {
        any()
            .filter(|b: &u8| matches!(*b, 0x20..=0x7e))
            .repeated()
            .at_least(1)
            .to_slice()
            .try_map(|bytes: &[u8], span| {
                from_utf8(bytes)
                    .map_err(|_| Rich::custom(span, "invalid UTF-8 in capability line"))
                    .map(Cow::from)
            })
    }

    /// SMTP EHLO response parser.
    ///
    /// ```abnf
    /// ehlo-ok-rsp    = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
    ///                / ( "250-" Domain [ SP ehlo-greet ] CRLF
    ///                  *( "250-" ehlo-line CRLF )
    ///                  "250" SP ehlo-line CRLF )
    /// ehlo-line      = ehlo-keyword *( SP ehlo-param )
    /// ```
    pub(crate) fn ehlo_response<'a>() -> impl Parser<'a, &'a [u8], EhloResponse<'a>, Extra<'a>> {
        just(b"250" as &[u8])
            .ignore_then(choice((just(b'-').to(true), just(b' ').to(false))))
            .then(domain_parser())
            .then(sp().ignore_then(text_parser()).or_not())
            .then_ignore(crlf())
            .then(
                just(b"250" as &[u8])
                    .then_ignore(just(b'-'))
                    .ignore_then(capability())
                    .then_ignore(crlf())
                    .repeated()
                    .collect::<Vec<_>>(),
            )
            .then(
                just(b"250" as &[u8])
                    .then_ignore(sp())
                    .ignore_then(capability())
                    .then_ignore(crlf())
                    .or_not(),
            )
            .map(|((((is_multi, domain), greet), cont_caps), final_cap)| {
                let mut capabilities = Vec::new();

                if is_multi {
                    capabilities.extend(cont_caps);

                    if let Some(cap) = final_cap {
                        capabilities.push(cap);
                    }
                }

                EhloResponse {
                    domain,
                    greet,
                    capabilities,
                }
            })
    }
}
