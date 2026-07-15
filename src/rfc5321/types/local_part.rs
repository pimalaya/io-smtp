//! SMTP local part (RFC 5321 §4.1.2).
//!
//! The part of a mailbox address before the at sign.

use core::fmt;

use alloc::borrow::Cow;

use bounded_static_derive::ToStatic;

/// The local part of an email address (before the @).
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct SmtpLocalPart<'a>(pub Cow<'a, str>);

impl fmt::Display for SmtpLocalPart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> From<SmtpLocalPart<'a>> for Cow<'a, str> {
    fn from(part: SmtpLocalPart<'a>) -> Self {
        part.0
    }
}

impl AsRef<str> for SmtpLocalPart<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
