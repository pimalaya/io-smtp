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

use crate::rfc5321::SmtpAtom;

/// SMTP address literal.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SmtpAddressLiteral<'a> {
    /// IPv4 address.
    Ipv4(Ipv4Addr),
    /// IPv6 address.
    Ipv6(Ipv6Addr),
    /// General address literal.
    General {
        /// The standardized tag naming the address family.
        tag: SmtpAtom<'a>,
        /// The address content following the tag.
        content: Cow<'a, str>,
    },
}

impl fmt::Display for SmtpAddressLiteral<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmtpAddressLiteral::Ipv4(addr) => write!(f, "[{addr}]"),
            SmtpAddressLiteral::Ipv6(addr) => write!(f, "[IPv6:{addr}]"),
            SmtpAddressLiteral::General { tag, content } => write!(f, "[{tag}:{content}]"),
        }
    }
}

impl ToBoundedStatic for SmtpAddressLiteral<'_> {
    type Static = SmtpAddressLiteral<'static>;

    fn to_static(&self) -> Self::Static {
        match self {
            SmtpAddressLiteral::Ipv4(addr) => SmtpAddressLiteral::Ipv4(*addr),
            SmtpAddressLiteral::Ipv6(addr) => SmtpAddressLiteral::Ipv6(*addr),
            SmtpAddressLiteral::General { tag, content } => SmtpAddressLiteral::General {
                tag: tag.to_static(),
                content: Cow::Owned(content.clone().into_owned()),
            },
        }
    }
}

impl IntoBoundedStatic for SmtpAddressLiteral<'_> {
    type Static = SmtpAddressLiteral<'static>;

    fn into_static(self) -> Self::Static {
        match self {
            SmtpAddressLiteral::Ipv4(addr) => SmtpAddressLiteral::Ipv4(addr),
            SmtpAddressLiteral::Ipv6(addr) => SmtpAddressLiteral::Ipv6(addr),
            SmtpAddressLiteral::General { tag, content } => SmtpAddressLiteral::General {
                tag: tag.into_static(),
                content: Cow::Owned(content.into_owned()),
            },
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
