//! SMTP atom (RFC 5321 §4.1.2).
//!
//! The bare unquoted string production used by local parts and ESMTP
//! parameter keywords.

use core::{fmt, ops::Deref};

use alloc::{borrow::Cow, vec::Vec};

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

/// An SMTP atom.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct SmtpAtom<'a>(pub(crate) Cow<'a, str>);

impl SmtpAtom<'_> {
    /// Parses an atom from raw bytes, consuming the whole input.
    pub fn parse<'a>(bytes: &'a [u8]) -> Result<SmtpAtom<'a>, Vec<Rich<'a, u8>>> {
        parsers::atom()
            .then_ignore(end())
            .parse(bytes)
            .into_result()
    }
}

impl fmt::Display for SmtpAtom<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> Deref for SmtpAtom<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

pub(crate) mod parsers {
    //! Chumsky parser for the SMTP atom.

    use core::str::from_utf8;

    use alloc::borrow::Cow;

    use chumsky::prelude::*;

    use crate::{rfc5321::SmtpAtom, utils::parsers::Extra};

    /// SMTP atom parser.
    ///
    /// ```abnf
    /// Atom           = 1*atext
    /// atext          = ALPHA / DIGIT /
    ///                  "!" / "#" / "$" / "%" / "&" / "'" / "*" /
    ///                  "+" / "-" / "/" / "=" / "?" / "^" / "_" /
    ///                  "`" / "{" / "|" / "}" / "~"
    /// ```
    pub(crate) fn atom<'a>() -> impl Parser<'a, &'a [u8], SmtpAtom<'a>, Extra<'a>> + Clone {
        any()
            .filter(|b| match b {
                b if b.is_ascii_alphanumeric() => true,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' => true,
                b'+' | b'-' | b'/' | b'=' | b'?' | b'^' | b'_' => true,
                b'`' | b'{' | b'|' | b'}' | b'~' => true,
                _ => false,
            })
            .repeated()
            .at_least(1)
            .to_slice()
            .try_map(|bytes: &[u8], span| {
                from_utf8(bytes)
                    .map_err(|_| Rich::custom(span, "invalid UTF-8 in atom"))
                    .map(Cow::from)
                    .map(SmtpAtom)
            })
            .labelled("atom")
    }
}
