//! Module dedicated to the SMTP EHLO domain.

use core::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use bounded_static_derive::ToStatic;

use super::{address_literal::AddressLiteral, domain::Domain};

/// The domain identifier used in EHLO/HELO commands.
///
/// Can be either a domain name or an address literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum EhloDomain<'a> {
    /// A domain name
    Domain(Domain<'a>),
    /// An address literal (IPv4, IPv6, or general)
    AddressLiteral(AddressLiteral<'a>),
}

impl fmt::Display for EhloDomain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Domain(domain) => write!(f, "{domain}"),
            Self::AddressLiteral(addr) => write!(f, "{addr}"),
        }
    }
}

impl<'a> From<Domain<'a>> for EhloDomain<'a> {
    fn from(domain: Domain<'a>) -> Self {
        Self::Domain(domain)
    }
}

impl<'a> From<AddressLiteral<'a>> for EhloDomain<'a> {
    fn from(addr: AddressLiteral<'a>) -> Self {
        Self::AddressLiteral(addr)
    }
}

impl From<Ipv4Addr> for EhloDomain<'_> {
    fn from(v4: Ipv4Addr) -> Self {
        Self::AddressLiteral(v4.into())
    }
}

impl From<Ipv6Addr> for EhloDomain<'_> {
    fn from(v6: Ipv6Addr) -> Self {
        Self::AddressLiteral(v6.into())
    }
}
