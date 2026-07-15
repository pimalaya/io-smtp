//! SMTP mailbox (RFC 5321 §4.1.2).
//!
//! A full email address: a local part, an at sign and a domain or
//! address literal.

use core::fmt;

use bounded_static_derive::ToStatic;

use crate::rfc5321::types::{ehlo_domain::SmtpEhloDomain, local_part::SmtpLocalPart};

/// A full email address: local-part@domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpMailbox<'a> {
    /// The local part (before @)
    pub local_part: SmtpLocalPart<'a>,
    /// The domain (after @)
    pub domain: SmtpEhloDomain<'a>,
}

impl fmt::Display for SmtpMailbox<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.local_part, self.domain)
    }
}
