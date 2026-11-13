//! SMTP address literal (RFC 5321 §4.1.3).
//!
//! The bracketed IP form a client may use instead of a domain name,
//! in EHLO identities and mailbox addresses.

use core::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use alloc::borrow::Cow;

use bounded_static::{IntoBoundedStatic, ToBoundedStatic};
use bounded_static_derive::ToStatic;

use crate::rfc5321::SmtpSyntaxError;

/// SMTP address literal.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SmtpAddressLiteral<'a> {
    /// IPv4 address.
    Ipv4(Ipv4Addr),
    /// IPv6 address.
    Ipv6(Ipv6Addr),
    /// General address literal.
    General(SmtpGeneralAddressLiteral<'a>),
}

/// Parses the bracketed form, such as `[192.0.2.1]` or `[IPv6:::1]`.
impl<'a> TryFrom<&'a str> for SmtpAddressLiteral<'a> {
    type Error = SmtpSyntaxError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let Some(literal) = s.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
            return Err(SmtpSyntaxError::AddressLiteral);
        };

        let Some((tag, content)) = literal.split_once(':') else {
            let Ok(addr) = literal.parse() else {
                return Err(SmtpSyntaxError::AddressLiteral);
            };

            return Ok(Self::Ipv4(addr));
        };

        if !tag.eq_ignore_ascii_case("IPv6") {
            return SmtpGeneralAddressLiteral::new(tag, content).map(Self::General);
        }

        let Ok(addr) = content.parse() else {
            return Err(SmtpSyntaxError::AddressLiteral);
        };

        Ok(Self::Ipv6(addr))
    }
}

impl fmt::Display for SmtpAddressLiteral<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmtpAddressLiteral::Ipv4(addr) => write!(f, "[{addr}]"),
            SmtpAddressLiteral::Ipv6(addr) => write!(f, "[IPv6:{addr}]"),
            SmtpAddressLiteral::General(literal) => write!(f, "[{literal}]"),
        }
    }
}

impl ToBoundedStatic for SmtpAddressLiteral<'_> {
    type Static = SmtpAddressLiteral<'static>;

    fn to_static(&self) -> Self::Static {
        match self {
            SmtpAddressLiteral::Ipv4(addr) => SmtpAddressLiteral::Ipv4(*addr),
            SmtpAddressLiteral::Ipv6(addr) => SmtpAddressLiteral::Ipv6(*addr),
            SmtpAddressLiteral::General(literal) => {
                SmtpAddressLiteral::General(literal.to_static())
            }
        }
    }
}

impl IntoBoundedStatic for SmtpAddressLiteral<'_> {
    type Static = SmtpAddressLiteral<'static>;

    fn into_static(self) -> Self::Static {
        match self {
            SmtpAddressLiteral::Ipv4(addr) => SmtpAddressLiteral::Ipv4(addr),
            SmtpAddressLiteral::Ipv6(addr) => SmtpAddressLiteral::Ipv6(addr),
            SmtpAddressLiteral::General(literal) => {
                SmtpAddressLiteral::General(literal.into_static())
            }
        }
    }
}

impl From<Ipv4Addr> for SmtpAddressLiteral<'_> {
    fn from(v4: Ipv4Addr) -> Self {
        Self::Ipv4(v4)
    }
}

impl From<Ipv6Addr> for SmtpAddressLiteral<'_> {
    fn from(v6: Ipv6Addr) -> Self {
        Self::Ipv6(v6)
    }
}

/// SMTP general address literal, without its brackets.
///
/// ```abnf
/// General-address-literal  = Standardized-tag ":" 1*dcontent
/// Standardized-tag  = Ldh-str
/// dcontent       = %d33-90 / %d94-126
/// ```
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc5321#section-4.1.3>
#[derive(Clone, Debug, Eq, PartialEq, Hash, ToStatic)]
pub struct SmtpGeneralAddressLiteral<'a> {
    tag: Cow<'a, str>,
    content: Cow<'a, str>,
}

impl<'a> SmtpGeneralAddressLiteral<'a> {
    /// Builds the literal from its standardized tag and its content.
    pub fn new(tag: &'a str, content: &'a str) -> Result<Self, SmtpSyntaxError> {
        let ldh_str = tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && tag.bytes().last().is_some_and(|b| b != b'-');

        let dcontent = |b: u8| matches!(b, b'!'..=b'Z' | b'^'..=b'~');

        if !ldh_str || content.is_empty() || !content.bytes().all(dcontent) {
            return Err(SmtpSyntaxError::AddressLiteral);
        }

        Ok(Self {
            tag: Cow::Borrowed(tag),
            content: Cow::Borrowed(content),
        })
    }

    /// The standardized tag naming the address family.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The address content following the tag.
    pub fn content(&self) -> &str {
        &self.content
    }
}

impl fmt::Display for SmtpGeneralAddressLiteral<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.tag, self.content)
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use alloc::string::ToString;

    use crate::rfc5321::{SmtpAddressLiteral, SmtpGeneralAddressLiteral, SmtpSyntaxError};

    #[test]
    fn ipv4_is_parsed() {
        let literal = SmtpAddressLiteral::try_from("[192.0.2.1]").unwrap();
        assert_eq!(
            literal,
            SmtpAddressLiteral::Ipv4(Ipv4Addr::new(192, 0, 2, 1))
        );
    }

    #[test]
    fn ipv6_is_parsed() {
        for s in ["[IPv6:2001:db8::1]", "[ipv6:2001:db8::1]"] {
            let literal = SmtpAddressLiteral::try_from(s).unwrap();
            let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
            assert_eq!(literal, SmtpAddressLiteral::Ipv6(addr));
            assert_eq!(literal.to_string(), "[IPv6:2001:db8::1]");
        }
    }

    #[test]
    fn general_is_parsed() {
        let literal = SmtpAddressLiteral::try_from("[x-tag:a:b@c]").unwrap();
        let SmtpAddressLiteral::General(general) = &literal else {
            panic!("expected a general address literal, got {literal:?}");
        };

        assert_eq!(general.tag(), "x-tag");
        assert_eq!(general.content(), "a:b@c");
        assert_eq!(literal.to_string(), "[x-tag:a:b@c]");
    }

    #[test]
    fn other_strings_are_refused() {
        let cases = [
            "",
            "[]",
            "192.0.2.1",
            "[192.0.2.1",
            "[192.0.2]",
            "[192.0.2.256]",
            "[192.0.2.1]\r\n",
            "[IPv6:]",
            "[IPv6:192.0.2.1]",
            "[IPv6:::1]\r\nNOOP]",
            "[tag:]",
            "[:x]",
            "[tag-:x]",
            "[t_g:x]",
            "[tag:a b]",
            "[tag:a]b]",
            "[tag:a[b]",
            "[tag:a\\b]",
            "[tag:a\r\nb]",
            "[tag:a\0b]",
            "[tag:é]",
        ];

        for s in cases {
            let err = SmtpAddressLiteral::try_from(s).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::AddressLiteral, "{s:?}");
        }
    }

    #[test]
    fn general_content_cannot_close_the_bracket() {
        let err = SmtpGeneralAddressLiteral::new("tag", "x]\r\nMAIL FROM:<>").unwrap_err();
        assert_eq!(err, SmtpSyntaxError::AddressLiteral);
    }
}
