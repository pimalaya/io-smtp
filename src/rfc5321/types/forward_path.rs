//! SMTP forward path (RFC 5321 §4.1.1.3).
//!
//! The recipient mailbox declared by a RCPT TO command.

use core::fmt;

use bounded_static_derive::ToStatic;

use crate::rfc5321::SmtpMailbox;

/// The forward path for RCPT TO.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpForwardPath<'a>(pub SmtpMailbox<'a>);

impl fmt::Display for SmtpForwardPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}>", self.0)
    }
}

impl<'a> From<SmtpMailbox<'a>> for SmtpForwardPath<'a> {
    fn from(mailbox: SmtpMailbox<'a>) -> Self {
        SmtpForwardPath(mailbox)
    }
}
