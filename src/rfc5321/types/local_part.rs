//! Module dedicated to the SMTP local part.

use alloc::borrow::Cow;
use core::fmt;

use bounded_static_derive::ToStatic;

/// The local part of an email address (before the @).
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct LocalPart<'a>(pub Cow<'a, str>);

impl fmt::Display for LocalPart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> From<LocalPart<'a>> for Cow<'a, str> {
    fn from(part: LocalPart<'a>) -> Self {
        part.0
    }
}

impl AsRef<str> for LocalPart<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
