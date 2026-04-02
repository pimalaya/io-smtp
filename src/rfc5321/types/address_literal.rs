//! Module dedicated to the SMTP address literal.

use std::{
    borrow::Cow,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use bounded_static::{IntoBoundedStatic, ToBoundedStatic};

use crate::rfc5321::types::atom::Atom;

/// SMTP address literal.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AddressLiteral<'a> {
    /// IPv4 address.
    Ipv4(Ipv4Addr),

    /// IPv6 address.
    Ipv6(Ipv6Addr),

    /// General address literal.
    General {
        tag: Atom<'a>,
        content: Cow<'a, str>,
    },
}

impl fmt::Display for AddressLiteral<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddressLiteral::Ipv4(addr) => write!(f, "[{addr}]"),
            AddressLiteral::Ipv6(addr) => write!(f, "[IPv6:{addr}]"),
            AddressLiteral::General { tag, content } => write!(f, "[{tag}:{content}]"),
        }
    }
}

impl ToBoundedStatic for AddressLiteral<'_> {
    type Static = AddressLiteral<'static>;

    fn to_static(&self) -> Self::Static {
        match self {
            AddressLiteral::Ipv4(addr) => AddressLiteral::Ipv4(*addr),
            AddressLiteral::Ipv6(addr) => AddressLiteral::Ipv6(*addr),
            AddressLiteral::General { tag, content } => AddressLiteral::General {
                tag: tag.to_static(),
                content: Cow::Owned(content.clone().into_owned()),
            },
        }
    }
}

impl IntoBoundedStatic for AddressLiteral<'_> {
    type Static = AddressLiteral<'static>;

    fn into_static(self) -> Self::Static {
        match self {
            AddressLiteral::Ipv4(addr) => AddressLiteral::Ipv4(addr),
            AddressLiteral::Ipv6(addr) => AddressLiteral::Ipv6(addr),
            AddressLiteral::General { tag, content } => AddressLiteral::General {
                tag: tag.into_static(),
                content: Cow::Owned(content.into_owned()),
            },
        }
    }
}

impl From<Ipv4Addr> for AddressLiteral<'_> {
    fn from(v4: Ipv4Addr) -> Self {
        Self::Ipv4(v4)
    }
}

impl From<Ipv6Addr> for AddressLiteral<'_> {
    fn from(v6: Ipv6Addr) -> Self {
        Self::Ipv6(v6)
    }
}
