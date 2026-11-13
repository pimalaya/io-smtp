//! SMTP string (RFC 5321 §4.1.2).
//!
//! The atom or quoted string a command such as NOOP takes as its
//! argument.

use core::fmt;

use alloc::borrow::Cow;

use bounded_static_derive::ToStatic;

use crate::rfc5321::{SmtpLocalPart, SmtpSyntaxError};

/// A string argument, in wire form.
///
/// ```abnf
/// String         = Atom / Quoted-string
/// ```
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc5321#section-4.1.2>
#[derive(Clone, Debug, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpString<'a>(Cow<'a, str>);

impl<'a> TryFrom<&'a str> for SmtpString<'a> {
    type Error = SmtpSyntaxError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        // NOTE: a String is a local part whose Dot-string has no dot
        let dotted = !s.starts_with('"') && s.contains('.');

        match SmtpLocalPart::split(s) {
            Some((_, "")) if !dotted => Ok(Self(Cow::Borrowed(s))),
            _ => Err(SmtpSyntaxError::String),
        }
    }
}

impl fmt::Display for SmtpString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for SmtpString<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::rfc5321::{SmtpString, SmtpSyntaxError};

    #[test]
    fn atom_and_quoted_string_are_accepted() {
        for s in [
            "keep-alive",
            "a+b",
            r#""""#,
            r#""still here.""#,
            r#""a\"b""#,
        ] {
            assert_eq!(SmtpString::try_from(s).unwrap().as_ref(), s);
        }
    }

    #[test]
    fn other_strings_are_refused() {
        for s in [
            "",
            "a.b",
            "a b",
            "a\r\nb",
            "a\nb",
            "a\0b",
            r#""a"#,
            "\"a\r\nb\"",
        ] {
            let err = SmtpString::try_from(s).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::String, "{s:?}");
        }
    }
}
