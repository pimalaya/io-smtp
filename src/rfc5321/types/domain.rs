//! SMTP domain (RFC 5321 §4.1.2).
//!
//! The dotted hostname production used by greetings, hello commands
//! and mailbox addresses.

use core::fmt;

use alloc::{borrow::Cow, vec::Vec};

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

/// A domain name (hostname).
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct SmtpDomain<'a>(pub Cow<'a, str>);

impl SmtpDomain<'_> {
    /// Parses a domain from raw bytes, consuming the whole input.
    pub fn parse<'a>(bytes: &'a [u8]) -> Result<SmtpDomain<'a>, Vec<Rich<'a, u8>>> {
        parsers::domain()
            .then_ignore(end())
            .parse(bytes)
            .into_result()
    }
}

impl fmt::Display for SmtpDomain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> From<SmtpDomain<'a>> for Cow<'a, str> {
    fn from(domain: SmtpDomain<'a>) -> Self {
        domain.0
    }
}

impl AsRef<str> for SmtpDomain<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

pub(crate) mod parsers {
    //! Chumsky parser for the SMTP domain.

    use core::str::from_utf8;

    use alloc::borrow::Cow;

    use chumsky::prelude::*;

    use crate::{rfc5321::types::domain::SmtpDomain, utils::parsers::Extra};

    /// SMTP domain parser.
    ///
    /// ```abnf
    /// Domain         = sub-domain *("." sub-domain)
    /// sub-domain     = Let-dig [Ldh-str]
    /// Let-dig        = ALPHA / DIGIT
    /// Ldh-str        = *( ALPHA / DIGIT / "-" ) Let-dig
    /// ```
    pub(crate) fn domain<'a>() -> impl Parser<'a, &'a [u8], SmtpDomain<'a>, Extra<'a>> + Clone {
        // NOTE: sub-domain = Let-dig [Ldh-str]
        let sub_domain = any()
            .filter(|b: &u8| b.is_ascii_alphanumeric())
            .then(
                any()
                    .filter(|b: &u8| b.is_ascii_alphanumeric() || *b == b'-')
                    .repeated()
                    .to_slice(),
            )
            .to_slice();

        // NOTE: Domain = sub-domain *("." sub-domain)
        sub_domain
            .then(
                just(b'.')
                    .then(any().filter(|b: &u8| b.is_ascii_alphanumeric()))
                    .then(
                        any()
                            .filter(|b: &u8| b.is_ascii_alphanumeric() || *b == b'-')
                            .repeated()
                            .to_slice(),
                    )
                    .to_slice()
                    .repeated()
                    .to_slice(),
            )
            .to_slice()
            .try_map(|bytes: &[u8], span| {
                from_utf8(bytes)
                    .map_err(|_| Rich::custom(span, "invalid UTF-8 in domain"))
                    .map(Cow::from)
                    .map(SmtpDomain)
            })
            .labelled("domain")
    }
}
