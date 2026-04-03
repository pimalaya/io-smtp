//! Module dedicated to the SMTP EHLO response.

use std::{borrow::Cow, fmt};

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use super::{atom::Atom, domain::Domain, text::Text};
use crate::rfc4954::types::auth_mechanism::AuthMechanism;

/// An SMTP server capability announced in EHLO response.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
#[non_exhaustive]
pub enum Capability<'a> {
    /// SIZE extension with optional maximum size.
    Size(Option<u64>),

    /// 8BITMIME extension.
    EightBitMime,

    /// PIPELINING extension.
    Pipelining,

    /// STARTTLS extension.
    StartTls,

    /// SMTPUTF8 extension.
    SmtpUtf8,

    /// ENHANCEDSTATUSCODES extension.
    EnhancedStatusCodes,

    /// AUTH extension with supported mechanisms.
    Auth(Vec<AuthMechanism<'a>>),

    /// Other/unknown capability.
    Other {
        /// The capability keyword
        keyword: Atom<'a>,
        /// Optional parameters
        params: Option<Cow<'a, str>>,
    },
}

impl fmt::Display for Capability<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Capability::Size(Some(size)) => write!(f, "SIZE {size}"),
            Capability::Size(None) => write!(f, "SIZE"),
            Capability::EightBitMime => write!(f, "8BITMIME"),
            Capability::Pipelining => write!(f, "PIPELINING"),
            Capability::StartTls => write!(f, "STARTTLS"),
            Capability::SmtpUtf8 => write!(f, "SMTPUTF8"),
            Capability::EnhancedStatusCodes => write!(f, "ENHANCEDSTATUSCODES"),
            Capability::Auth(mechanisms) => {
                write!(f, "AUTH")?;
                for mech in mechanisms {
                    write!(f, " {}", mech.as_ref())?;
                }
                Ok(())
            }
            Capability::Other { keyword, params } => {
                write!(f, "{keyword}")?;
                if let Some(params) = params {
                    write!(f, " {params}")?;
                }
                Ok(())
            }
        }
    }
}

/// EHLO response containing server capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct EhloResponse<'a> {
    /// The server's domain name
    pub domain: Domain<'a>,
    /// Optional greeting text on the first line
    pub greet: Option<Text<'a>>,
    /// Server capabilities
    pub capabilities: Vec<Capability<'a>>,
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

    /// Returns true if the server supports the given capability.
    pub fn has_capability(&self, name: &str) -> bool {
        let name_upper = name.to_ascii_uppercase();
        self.capabilities.iter().any(|cap| match cap {
            Capability::Size(_) => name_upper == "SIZE",
            Capability::EightBitMime => name_upper == "8BITMIME",
            Capability::Pipelining => name_upper == "PIPELINING",
            Capability::StartTls => name_upper == "STARTTLS",
            Capability::SmtpUtf8 => name_upper == "SMTPUTF8",
            Capability::EnhancedStatusCodes => name_upper == "ENHANCEDSTATUSCODES",
            Capability::Auth(_) => name_upper == "AUTH",
            Capability::Other { keyword, .. } => keyword.to_ascii_uppercase() == name_upper,
        })
    }

    /// Returns the AUTH mechanisms if AUTH capability is present.
    pub fn auth_mechanisms(&self) -> Option<&[AuthMechanism<'_>]> {
        self.capabilities.iter().find_map(|cap| match cap {
            Capability::Auth(mechanisms) => Some(mechanisms.as_slice()),
            _ => None,
        })
    }

    /// Returns the maximum message size if SIZE capability is present.
    pub fn max_size(&self) -> Option<u64> {
        self.capabilities.iter().find_map(|cap| match cap {
            Capability::Size(size) => *size,
            _ => None,
        })
    }
}

pub(crate) mod parsers {
    use std::{borrow::Cow, str::from_utf8};

    use chumsky::prelude::*;

    use crate::rfc4954::types::auth_mechanism::parsers::auth_mechanism as auth_mechanism_parser;
    use crate::rfc5321::types::{
        atom::parsers::atom as atom_parser, domain::parsers::domain as domain_parser,
        text::parsers::text as text_parser,
    };
    use crate::utils::parsers::{Extra, crlf, sp, tag_no_case};

    use super::{Capability, EhloResponse};

    /// SMTP capability parser.
    ///
    /// ```abnf
    /// ehlo-ok-rsp    = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
    ///                / ( "250-" Domain [ SP ehlo-greet ] CRLF
    ///                  *( "250-" ehlo-line CRLF )
    ///                  "250" SP ehlo-line CRLF )
    /// ehlo-line      = ehlo-keyword *( SP ehlo-param )
    /// ehlo-keyword   = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
    /// ehlo-param     = 1*(%d33-126)
    /// ```
    pub(crate) fn capability<'a>() -> impl Parser<'a, &'a [u8], Capability<'a>, Extra<'a>> + Clone {
        let size = tag_no_case(b"SIZE")
            .ignore_then(
                sp().ignore_then(
                    any()
                        .filter(|b: &u8| b.is_ascii_digit())
                        .repeated()
                        .at_least(1)
                        .to_slice()
                        .map(from_utf8)
                        .map(Result::unwrap)
                        .map(|s: &str| s.parse::<u64>().unwrap()),
                )
                .or_not(),
            )
            .map(Capability::Size);

        let eightbitmime = tag_no_case(b"8BITMIME").to(Capability::EightBitMime);
        let pipelining = tag_no_case(b"PIPELINING").to(Capability::Pipelining);
        let starttls = tag_no_case(b"STARTTLS").to(Capability::StartTls);
        let smtputf8 = tag_no_case(b"SMTPUTF8").to(Capability::SmtpUtf8);
        let enhanced = tag_no_case(b"ENHANCEDSTATUSCODES").to(Capability::EnhancedStatusCodes);

        let auth = tag_no_case(b"AUTH")
            .ignore_then(
                sp().ignore_then(auth_mechanism_parser())
                    .repeated()
                    .at_least(1)
                    .collect::<Vec<_>>(),
            )
            .map(Capability::Auth);

        let other = atom_parser()
            .then(
                sp().ignore_then(
                    any()
                        .filter(|b: &u8| *b == 0x09 || matches!(*b, 0x20..=0x7e))
                        .repeated()
                        .to_slice()
                        .map(from_utf8)
                        .map(Result::unwrap)
                        .map(Cow::from),
                )
                .or_not(),
            )
            .map(|(keyword, params)| Capability::Other { keyword, params });

        choice((
            size,
            eightbitmime,
            pipelining,
            starttls,
            smtputf8,
            enhanced,
            auth,
            other,
        ))
    }

    /// SMTP EHLO response parser.
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
                let mut ehlo = match greet {
                    Some(g) => EhloResponse {
                        domain,
                        greet: Some(g),
                        capabilities: Vec::new(),
                    },
                    None => EhloResponse {
                        domain,
                        greet: None,
                        capabilities: Vec::new(),
                    },
                };
                if is_multi {
                    for cap in cont_caps {
                        ehlo.capabilities.push(cap);
                    }
                    if let Some(cap) = final_cap {
                        ehlo.capabilities.push(cap);
                    }
                }
                ehlo
            })
    }
}
