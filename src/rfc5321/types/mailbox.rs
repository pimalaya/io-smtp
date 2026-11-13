//! SMTP mailbox (RFC 5321 §4.1.2).
//!
//! A full email address: a local part, an at sign and a domain or
//! address literal.

use core::fmt;

use bounded_static_derive::ToStatic;

use crate::rfc5321::{
    SmtpSyntaxError,
    types::{ehlo_domain::SmtpEhloDomain, local_part::SmtpLocalPart},
};

/// A full email address: local-part@domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpMailbox<'a> {
    /// The local part (before @)
    pub local_part: SmtpLocalPart<'a>,
    /// The domain (after @)
    pub domain: SmtpEhloDomain<'a>,
}

/// Parses an address in wire form, such as `alice@example.org`.
impl<'a> TryFrom<&'a str> for SmtpMailbox<'a> {
    type Error = SmtpSyntaxError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let Some((local_part, rest)) = SmtpLocalPart::split(s) else {
            return Err(SmtpSyntaxError::LocalPart);
        };

        let Some(domain) = rest.strip_prefix('@') else {
            return Err(if rest.is_empty() {
                SmtpSyntaxError::Mailbox
            } else {
                SmtpSyntaxError::LocalPart
            });
        };

        let domain = domain.try_into()?;

        Ok(Self { local_part, domain })
    }
}

impl fmt::Display for SmtpMailbox<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.local_part, self.domain)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::rfc5321::{SmtpEhloDomain, SmtpMailbox, SmtpSyntaxError};

    #[test]
    fn address_is_parsed() {
        let cases = [
            ("alice@example.org", "alice", "example.org"),
            ("john.doe+tag@example.org", "john.doe+tag", "example.org"),
            (r#""john doe"@example.org"#, r#""john doe""#, "example.org"),
            (r#""a@b"@example.org"#, r#""a@b""#, "example.org"),
            ("jörg@bücher.example", "jörg", "bücher.example"),
            ("a@[192.0.2.1]", "a", "[192.0.2.1]"),
            ("a@[tag:b@c]", "a", "[tag:b@c]"),
        ];

        for (address, local_part, domain) in cases {
            let mailbox = SmtpMailbox::try_from(address).unwrap();
            assert_eq!(mailbox.local_part.as_ref(), local_part);
            assert_eq!(mailbox.domain.to_string(), domain);
            assert_eq!(mailbox.to_string(), address);
        }
    }

    #[test]
    fn address_literal_is_told_from_a_domain() {
        let mailbox = SmtpMailbox::try_from("a@[IPv6:::1]").unwrap();
        assert!(matches!(
            mailbox.domain,
            SmtpEhloDomain::SmtpAddressLiteral(_)
        ));
    }

    #[test]
    fn other_strings_are_refused() {
        let cases = [
            ("", SmtpSyntaxError::LocalPart),
            ("@example.org", SmtpSyntaxError::LocalPart),
            ("john doe@example.org", SmtpSyntaxError::LocalPart),
            ("a@b@example.org", SmtpSyntaxError::Domain),
            ("a\r\n@example.org", SmtpSyntaxError::LocalPart),
            ("alice", SmtpSyntaxError::Mailbox),
            (r#""a@b""#, SmtpSyntaxError::Mailbox),
            ("a@", SmtpSyntaxError::Domain),
            ("a@example.org>", SmtpSyntaxError::Domain),
            ("<a@example.org>", SmtpSyntaxError::LocalPart),
            ("a@example.org\r\n", SmtpSyntaxError::Domain),
            ("a@x>\r\nRCPT TO:<eve@evil.example", SmtpSyntaxError::Domain),
            ("a@[192.0.2.1", SmtpSyntaxError::AddressLiteral),
        ];

        for (address, expected) in cases {
            let err = SmtpMailbox::try_from(address).unwrap_err();
            assert_eq!(err, expected, "{address:?}");
        }
    }
}
