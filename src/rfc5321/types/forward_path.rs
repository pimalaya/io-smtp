//! Module dedicated to the SMTP forward path.

use core::fmt;

use bounded_static_derive::ToStatic;

use super::mailbox::Mailbox;

/// The forward path for RCPT TO.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct ForwardPath<'a>(pub Mailbox<'a>);

impl fmt::Display for ForwardPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}>", self.0)
    }
}

impl<'a> From<Mailbox<'a>> for ForwardPath<'a> {
    fn from(mailbox: Mailbox<'a>) -> Self {
        ForwardPath(mailbox)
    }
}
