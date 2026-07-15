//! SMTP EHLO domain (RFC 5321 §4.1.1.1).
//!
//! The client identity sent in EHLO and HELO commands: either a
//! domain name or an address literal.

use core::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use bounded_static_derive::ToStatic;

use crate::rfc5321::types::{address_literal::SmtpAddressLiteral, domain::SmtpDomain};

/// The domain identifier used in EHLO/HELO commands.
///
/// Can be either a domain name or an address literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum SmtpEhloDomain<'a> {
    /// A domain name
    SmtpDomain(SmtpDomain<'a>),
    /// An address literal (IPv4, IPv6, or general)
    SmtpAddressLiteral(SmtpAddressLiteral<'a>),
}

impl fmt::Display for SmtpEhloDomain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::SmtpDomain(domain) => write!(f, "{domain}"),
            Self::SmtpAddressLiteral(addr) => write!(f, "{addr}"),
        }
    }
}

impl<'a> From<SmtpDomain<'a>> for SmtpEhloDomain<'a> {
    fn from(domain: SmtpDomain<'a>) -> Self {
        Self::SmtpDomain(domain)
    }
}

impl<'a> From<SmtpAddressLiteral<'a>> for SmtpEhloDomain<'a> {
    fn from(addr: SmtpAddressLiteral<'a>) -> Self {
        Self::SmtpAddressLiteral(addr)
    }
}

impl From<Ipv4Addr> for SmtpEhloDomain<'_> {
    fn from(v4: Ipv4Addr) -> Self {
        Self::SmtpAddressLiteral(v4.into())
    }
}

impl From<Ipv6Addr> for SmtpEhloDomain<'_> {
    fn from(v6: Ipv6Addr) -> Self {
        Self::SmtpAddressLiteral(v6.into())
    }
}
