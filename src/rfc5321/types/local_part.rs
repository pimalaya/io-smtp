//! SMTP local part (RFC 5321 §4.1.2).
//!
//! The part of a mailbox address before the at sign.

use core::fmt;

use alloc::{borrow::Cow, string::String};

use bounded_static_derive::ToStatic;

use crate::rfc5321::SmtpSyntaxError;

/// The local part of an email address (before the @), in wire form.
///
/// ```abnf
/// Local-part     = Dot-string / Quoted-string
/// Dot-string     = Atom *("."  Atom)
/// Atom           = 1*atext
/// Quoted-string  = DQUOTE *QcontentSMTP DQUOTE
/// QcontentSMTP   = qtextSMTP / quoted-pairSMTP
/// quoted-pairSMTP  = %d92 %d32-126
/// qtextSMTP      = %d32-33 / %d35-91 / %d93-126
/// ```
///
/// Non-ASCII characters count as atext and qtextSMTP (RFC 6531 §3.3).
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc5321#section-4.1.2>
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct SmtpLocalPart<'a>(Cow<'a, str>);

impl<'a> SmtpLocalPart<'a> {
    /// Builds the local part from its unquoted content, quoting it
    /// when it is not a Dot-string.
    pub fn quote(content: &'a str) -> Result<Self, SmtpSyntaxError> {
        if !content.starts_with('"')
            && let Some((local_part, "")) = Self::split(content)
        {
            return Ok(local_part);
        }

        let mut quoted = String::with_capacity(content.len() + 2);
        quoted.push('"');

        for c in content.chars() {
            match c {
                '"' | '\\' => quoted.extend(['\\', c]),
                ' '..='~' => quoted.push(c),
                c if !c.is_ascii() => quoted.push(c),
                _ => return Err(SmtpSyntaxError::LocalPart),
            }
        }

        quoted.push('"');
        Ok(Self(Cow::Owned(quoted)))
    }

    /// Splits the local part starting the string from what follows.
    pub(crate) fn split(s: &'a str) -> Option<(Self, &'a str)> {
        let bytes = s.as_bytes();
        let mut len = 0;

        if bytes.first() == Some(&b'"') {
            len += 1;

            loop {
                match *bytes.get(len)? {
                    b'"' => break,
                    b'\\' if matches!(*bytes.get(len + 1)?, b' '..=b'~') => len += 2,
                    b'\\' => return None,
                    b' '..=b'~' | 0x80..=0xff => len += 1,
                    _ => return None,
                }
            }

            len += 1;
        } else {
            loop {
                let atom = bytes[len..].iter().take_while(|b| is_atext(**b)).count();

                if atom == 0 {
                    return None;
                }

                len += atom;

                if bytes.get(len) != Some(&b'.') {
                    break;
                }

                len += 1;
            }
        }

        // NOTE: the scan stops on an ASCII byte, a char boundary
        let (local_part, rest) = s.split_at(len);
        Some((Self(Cow::Borrowed(local_part)), rest))
    }
}

impl<'a> TryFrom<&'a str> for SmtpLocalPart<'a> {
    type Error = SmtpSyntaxError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        match Self::split(s) {
            Some((local_part, "")) => Ok(local_part),
            _ => Err(SmtpSyntaxError::LocalPart),
        }
    }
}

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

fn is_atext(byte: u8) -> bool {
    match byte {
        b if b.is_ascii_alphanumeric() => true,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' => true,
        b'+' | b'-' | b'/' | b'=' | b'?' | b'^' | b'_' => true,
        b'`' | b'{' | b'|' | b'}' | b'~' => true,
        b => !b.is_ascii(),
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::rfc5321::{SmtpLocalPart, SmtpSyntaxError};

    #[test]
    fn dot_string_is_accepted() {
        for s in ["a", "john.doe", "a+b", "!#$%&'*+-/=?^_`{|}~", "jörg"] {
            assert_eq!(SmtpLocalPart::try_from(s).unwrap().as_ref(), s);
        }
    }

    #[test]
    fn quoted_string_is_accepted() {
        for s in [r#""""#, r#""john doe""#, r#""a@b>""#, r#""a\"b\\c""#] {
            assert_eq!(SmtpLocalPart::try_from(s).unwrap().as_ref(), s);
        }
    }

    #[test]
    fn neither_production_is_refused() {
        let cases = [
            "",
            ".a",
            "a.",
            "a..b",
            "john doe",
            "a@b",
            "a<b",
            "a>b",
            "a\rb",
            "a\nb",
            "a\0b",
            r#"""#,
            r#""a"#,
            r#""a"b"#,
            r#""a\""#,
            "\"a\rb\"",
            "\"a\nb\"",
            "\"a\\\nb\"",
            "\"a\\é\"",
            "\"a\tb\"",
            "\"a\x7fb\"",
        ];

        for s in cases {
            let err = SmtpLocalPart::try_from(s).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::LocalPart, "{s:?}");
        }
    }

    #[test]
    fn quote_keeps_a_dot_string() {
        let local_part = SmtpLocalPart::quote("john.doe").unwrap();
        assert_eq!(local_part.as_ref(), "john.doe");
    }

    #[test]
    fn quote_wraps_and_escapes() {
        let cases = [
            ("", r#""""#),
            ("john doe", r#""john doe""#),
            ("a@b>", r#""a@b>""#),
            (r#"a"b\c"#, r#""a\"b\\c""#),
            (r#""a""#, r#""\"a\"""#),
            ("jörg müller", r#""jörg müller""#),
        ];

        for (content, wire) in cases {
            let local_part = SmtpLocalPart::quote(content).unwrap();
            assert_eq!(local_part.to_string(), wire);
            assert_eq!(SmtpLocalPart::try_from(wire).unwrap(), local_part);
        }
    }

    #[test]
    fn quote_refuses_control_characters() {
        for content in ["a\rb", "a\nb", "a\0b", "a\tb", "a\x7fb"] {
            let err = SmtpLocalPart::quote(content).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::LocalPart, "{content:?}");
        }
    }
}
