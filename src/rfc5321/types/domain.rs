//! Module dedicated to the SMTP domain.

use alloc::{borrow::Cow, vec::Vec};
use core::fmt;

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

/// A domain name (hostname).
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct Domain<'a>(pub Cow<'a, str>);

impl Domain<'_> {
    pub fn parse<'a>(bytes: &'a [u8]) -> Result<Domain<'a>, Vec<Rich<'a, u8>>> {
        parsers::domain()
            .then_ignore(end())
            .parse(bytes)
            .into_result()
    }
}

impl fmt::Display for Domain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> From<Domain<'a>> for Cow<'a, str> {
    fn from(domain: Domain<'a>) -> Self {
        domain.0
    }
}

impl AsRef<str> for Domain<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

pub(crate) mod parsers {
    use alloc::borrow::Cow;
    use core::str::from_utf8;

    use chumsky::prelude::*;

    use crate::utils::parsers::Extra;

    use super::Domain;

    /// SMTP domain parser.
    ///
    /// ```abnf
    /// Domain         = sub-domain *("." sub-domain)
    /// sub-domain     = Let-dig [Ldh-str]
    /// Let-dig        = ALPHA / DIGIT
    /// Ldh-str        = *( ALPHA / DIGIT / "-" ) Let-dig
    /// ```
    pub(crate) fn domain<'a>() -> impl Parser<'a, &'a [u8], Domain<'a>, Extra<'a>> + Clone {
        // sub-domain = Let-dig [Ldh-str]
        let sub_domain = any()
            .filter(|b: &u8| b.is_ascii_alphanumeric())
            .then(
                any()
                    .filter(|b: &u8| b.is_ascii_alphanumeric() || *b == b'-')
                    .repeated()
                    .to_slice(),
            )
            .to_slice();

        // Domain = sub-domain *("." sub-domain)
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
                    .map(Domain)
            })
            .labelled("domain")
    }
}
