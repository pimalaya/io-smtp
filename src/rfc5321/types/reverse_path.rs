//! Module dedicated to the SMTP reverse path.

use std::fmt;

use bounded_static_derive::ToStatic;

use super::mailbox::Mailbox;

/// The reverse path for MAIL FROM (can be null <>).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic, Default)]
pub enum ReversePath<'a> {
    /// Null reverse path (<>)
    #[default]
    Null,
    /// A mailbox address
    Mailbox(Mailbox<'a>),
}

impl fmt::Display for ReversePath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReversePath::Null => write!(f, "<>"),
            ReversePath::Mailbox(mailbox) => write!(f, "<{mailbox}>"),
        }
    }
}

impl<'a> From<Mailbox<'a>> for ReversePath<'a> {
    fn from(mailbox: Mailbox<'a>) -> Self {
        ReversePath::Mailbox(mailbox)
    }
}
