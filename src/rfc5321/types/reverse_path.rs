//! SMTP reverse path (RFC 5321 §4.1.1.2).
//!
//! The sender mailbox declared by a MAIL FROM command, possibly the
//! null path.

use core::fmt;

use bounded_static_derive::ToStatic;

use crate::rfc5321::types::mailbox::SmtpMailbox;

/// The reverse path for MAIL FROM (can be null <>).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic, Default)]
pub enum SmtpReversePath<'a> {
    /// Null reverse path (<>)
    #[default]
    Null,
    /// A mailbox address
    SmtpMailbox(SmtpMailbox<'a>),
}

impl fmt::Display for SmtpReversePath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmtpReversePath::Null => write!(f, "<>"),
            SmtpReversePath::SmtpMailbox(mailbox) => write!(f, "<{mailbox}>"),
        }
    }
}

impl<'a> From<SmtpMailbox<'a>> for SmtpReversePath<'a> {
    fn from(mailbox: SmtpMailbox<'a>) -> Self {
        SmtpReversePath::SmtpMailbox(mailbox)
    }
}
