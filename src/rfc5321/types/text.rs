//! Module dedicated to the SMTP text.

use std::{borrow::Cow, fmt};

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

/// A human-readable text string used in SMTP responses.
#[derive(Clone, Debug, PartialEq, Eq, Hash, ToStatic)]
pub struct Text<'a>(pub(crate) Cow<'a, str>);

impl Text<'_> {
    pub fn parse<'a>(bytes: &'a [u8]) -> Result<Text<'a>, Vec<Rich<'a, u8>>> {
        parsers::text()
            .then_ignore(end())
            .parse(bytes)
            .into_result()
    }
}

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.as_ref())
    }
}

impl<'a> From<Text<'a>> for Cow<'a, str> {
    fn from(text: Text<'a>) -> Self {
        text.0
    }
}

impl AsRef<str> for Text<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

pub(crate) mod parsers {
    use std::{borrow::Cow, str::from_utf8};

    use chumsky::prelude::*;

    use crate::utils::parsers::Extra;

    use super::Text;

    /// SMTP text string parser.
    ///
    /// ```abnf
    /// textstring     = 1*(%d09 / %d32-126)
    ///                ; HT, SP, Printable US-ASCII
    /// ```
    pub(crate) fn text<'a>() -> impl Parser<'a, &'a [u8], Text<'a>, Extra<'a>> + Clone {
        any()
            .filter(|b| matches!(*b, 0x09 | 0x20..=0x7e))
            .repeated()
            .at_least(1)
            .to_slice()
            .map(from_utf8)
            .map(Result::unwrap)
            .map(Cow::from)
            .map(Text)
    }
}
