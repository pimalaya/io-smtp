//! Module dedicated to the SMTP mailbox.

use std::fmt;

use bounded_static_derive::ToStatic;

use super::{ehlo_domain::EhloDomain, local_part::LocalPart};

/// A full email address: local-part@domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Mailbox<'a> {
    /// The local part (before @)
    pub local_part: LocalPart<'a>,
    /// The domain (after @)
    pub domain: EhloDomain<'a>,
}

impl fmt::Display for Mailbox<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.local_part, self.domain)
    }
}
