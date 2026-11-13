//! SMTP domain (RFC 5321 §4.1.2).
//!
//! The dotted hostname production used by greetings, hello commands
//! and mailbox addresses.

use core::fmt;

use alloc::{borrow::Cow, vec::Vec};

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use crate::rfc5321::SmtpSyntaxError;

/// A domain name (hostname).
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct SmtpDomain<'a>(Cow<'a, str>);

impl SmtpDomain<'_> {
    /// Parses a domain from raw bytes, consuming the whole input.
    pub fn parse<'a>(bytes: &'a [u8]) -> Result<SmtpDomain<'a>, Vec<Rich<'a, u8>>> {
        parsers::domain()
            .then_ignore(end())
            .parse(bytes)
            .into_result()
    }
}

/// Validates a domain the client sends, where non-ASCII characters
/// count as Let-dig (RFC 6531 §3.3).
impl<'a> TryFrom<&'a str> for SmtpDomain<'a> {
    type Error = SmtpSyntaxError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let let_dig = |b: &u8| b.is_ascii_alphanumeric() || !b.is_ascii();

        let sub_domain = |label: &str| {
            let bytes = label.as_bytes();

            bytes.first().is_some_and(let_dig)
                && bytes.last().is_some_and(let_dig)
                && bytes.iter().all(|b| let_dig(b) || *b == b'-')
        };

        if s.split('.').all(sub_domain) {
            Ok(Self(Cow::Borrowed(s)))
        } else {
            Err(SmtpSyntaxError::Domain)
        }
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

#[cfg(test)]
mod tests {
    use crate::rfc5321::{SmtpDomain, SmtpSyntaxError};

    #[test]
    fn domain_is_accepted() {
        for s in [
            "x",
            "example.com",
            "smtp-relay.example.com",
            "1.2",
            "bücher.example",
        ] {
            assert_eq!(SmtpDomain::try_from(s).unwrap().as_ref(), s);
        }
    }

    #[test]
    fn other_strings_are_refused() {
        let cases = [
            "",
            ".",
            "example.com.",
            ".example.com",
            "a..b",
            "-a.example",
            "a-.example",
            "a_b.example",
            "a b",
            "a>b",
            "[192.0.2.1]",
            "a\r\nb",
            "a\nb",
            "a\0b",
        ];

        for s in cases {
            let err = SmtpDomain::try_from(s).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::Domain, "{s:?}");
        }
    }
}
