//! ESMTP parameter (RFC 5321 §4.1.2).
//!
//! The keyword and optional value pair appended to MAIL FROM and
//! RCPT TO commands by SMTP extensions.

use core::fmt;

use alloc::borrow::Cow;

use bounded_static_derive::ToStatic;

use crate::rfc5321::SmtpSyntaxError;

/// An ESMTP parameter (keyword[=value]).
///
/// ```abnf
/// esmtp-param    = esmtp-keyword ["=" esmtp-value]
/// esmtp-keyword  = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
/// esmtp-value    = 1*(%d33-60 / %d62-126)
/// ```
///
/// Non-ASCII characters count as esmtp-value (RFC 6531 §3.3).
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc5321#section-4.1.2>
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpParameter<'a> {
    pub(crate) keyword: Cow<'a, str>,
    pub(crate) value: Option<Cow<'a, str>>,
}

impl<'a> SmtpParameter<'a> {
    /// Builds the parameter from its keyword and its optional value.
    pub fn new(keyword: &'a str, value: Option<&'a str>) -> Result<Self, SmtpSyntaxError> {
        let esmtp_keyword = keyword
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && keyword.bytes().next().is_some_and(|b| b != b'-');

        if !esmtp_keyword {
            return Err(SmtpSyntaxError::ParameterKeyword);
        }

        let esmtp_value = |b: u8| matches!(b, b'!'..=b'<' | b'>'..=b'~' | 0x80..=0xff);

        if value.is_some_and(|v| v.is_empty() || !v.bytes().all(esmtp_value)) {
            return Err(SmtpSyntaxError::ParameterValue);
        }

        Ok(Self {
            keyword: Cow::Borrowed(keyword),
            value: value.map(Cow::Borrowed),
        })
    }

    /// The parameter keyword.
    pub fn keyword(&self) -> &str {
        &self.keyword
    }

    /// The optional parameter value.
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl fmt::Display for SmtpParameter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{}={}", self.keyword, value),
            None => write!(f, "{}", self.keyword),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::rfc5321::{SmtpParameter, SmtpSyntaxError};

    #[test]
    fn parameter_is_accepted() {
        let cases = [
            ("SMTPUTF8", None, "SMTPUTF8"),
            ("SIZE", Some("1024"), "SIZE=1024"),
            ("BODY", Some("8BITMIME"), "BODY=8BITMIME"),
            ("AUTH", Some("<>"), "AUTH=<>"),
            ("X-A1", Some("é"), "X-A1=é"),
        ];

        for (keyword, value, wire) in cases {
            let parameter = SmtpParameter::new(keyword, value).unwrap();
            assert_eq!(parameter.keyword(), keyword);
            assert_eq!(parameter.value(), value);
            assert_eq!(parameter.to_string(), wire);
        }
    }

    #[test]
    fn keyword_outside_the_production_is_refused() {
        for keyword in ["", "-A", "A=B", "A B", "A_B", "A\r\nB", "É"] {
            let err = SmtpParameter::new(keyword, None).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::ParameterKeyword, "{keyword:?}");
        }
    }

    #[test]
    fn value_outside_the_production_is_refused() {
        for value in ["", "a b", "a=b", "a\tb", "a\rb", "a\nb", "a\0b", "a\x7fb"] {
            let err = SmtpParameter::new("SIZE", Some(value)).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::ParameterValue, "{value:?}");
        }
    }
}
