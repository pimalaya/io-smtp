//! ESMTP parameter (RFC 5321 §4.1.2).
//!
//! The keyword and optional value pair appended to MAIL FROM and
//! RCPT TO commands by SMTP extensions.

use core::fmt;

use alloc::borrow::Cow;

use bounded_static_derive::ToStatic;

use crate::rfc5321::SmtpAtom;

/// An ESMTP parameter (keyword[=value]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpParameter<'a> {
    /// The parameter keyword
    pub keyword: SmtpAtom<'a>,
    /// The optional parameter value
    pub value: Option<Cow<'a, str>>,
}

impl fmt::Display for SmtpParameter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{}={}", self.keyword, value),
            None => write!(f, "{}", self.keyword),
        }
    }
}
