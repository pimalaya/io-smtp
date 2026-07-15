//! DSN ESMTP parameter constructors for MAIL FROM and RCPT TO.
//!
//! # Example
//!
//! ```rust,ignore
//! use io_smtp::{
//!     rfc3461::parameter::{SmtpDsnNotify, SmtpDsnRet},
//!     rfc5321::{mail::SmtpMail, rcpt::SmtpRcpt, types::parameter::SmtpParameter},
//! };
//!
//! // NOTE: MAIL FROM with RET=HDRS and ENVID
//! let params = vec![SmtpDsnRet::Hdrs.into_parameter(), SmtpParameter::envid("abc123")];
//! let coroutine = SmtpMail::new(reverse_path, params);
//!
//! // NOTE: RCPT TO with NOTIFY=SUCCESS,FAILURE
//! let params = vec![(SmtpDsnNotify::SUCCESS | SmtpDsnNotify::FAILURE).into_parameter()];
//! let coroutine = SmtpRcpt::new(forward_path, params);
//! ```

use core::ops::BitOr;

use alloc::{borrow::Cow, string::String, vec::Vec};

use crate::rfc5321::types::{atom::SmtpAtom, parameter::SmtpParameter};

/// The value of the `RET` ESMTP parameter on `MAIL FROM`.
///
/// Controls how much of the original message is included in a DSN.
///
/// # Reference
///
/// RFC 3461 §4.3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpDsnRet {
    /// Include the full original message in any DSN.
    Full,
    /// Include only the headers of the original message in any DSN.
    Hdrs,
}

impl SmtpDsnRet {
    /// Build the `RET=FULL` or `RET=HDRS` [`SmtpParameter`] for `MAIL FROM`.
    pub fn into_parameter(self) -> SmtpParameter<'static> {
        let value = match self {
            Self::Full => "FULL",
            Self::Hdrs => "HDRS",
        };
        SmtpParameter {
            keyword: SmtpAtom(Cow::Borrowed("RET")),
            value: Some(Cow::Borrowed(value)),
        }
    }
}

/// DSN parameter constructors for `MAIL FROM` and `RCPT TO`
/// (RFC 3461).
impl SmtpParameter<'static> {
    /// Build the `ENVID=<id>` parameter for `MAIL FROM`.
    ///
    /// The envelope identifier is an opaque string chosen by the
    /// sender that uniquely identifies this mail transaction. It is
    /// included in any DSN generated for the message.
    ///
    /// The value must contain only printable US-ASCII characters
    /// excluding `=` and whitespace (xtext encoding, RFC 3461 §4).
    ///
    /// # Reference
    ///
    /// RFC 3461 §4.4
    pub fn envid(id: impl Into<String>) -> SmtpParameter<'static> {
        SmtpParameter {
            keyword: SmtpAtom(Cow::Borrowed("ENVID")),
            value: Some(Cow::Owned(id.into())),
        }
    }
}

/// The `NOTIFY` conditions for a single `RCPT TO`.
///
/// Flags may be combined (e.g. `SmtpDsnNotify::SUCCESS |
/// SmtpDsnNotify::FAILURE`), except that `NEVER` must not be combined
/// with any other value.
///
/// # Reference
///
/// RFC 3461 §4.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmtpDsnNotify(u8);

impl SmtpDsnNotify {
    /// Never send a DSN for this recipient.
    pub const NEVER: Self = Self(0);
    /// Send a DSN on successful delivery.
    pub const SUCCESS: Self = Self(1);
    /// Send a DSN on delivery failure.
    pub const FAILURE: Self = Self(2);
    /// Send a DSN if delivery is delayed.
    pub const DELAY: Self = Self(4);

    /// Combine two notify flags.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Build the `NOTIFY=...` [`SmtpParameter`] for `RCPT TO`.
    pub fn into_parameter(self) -> SmtpParameter<'static> {
        let value = if self.0 == 0 {
            Cow::Borrowed("NEVER")
        } else {
            let mut parts: Vec<&str> = Vec::new();
            if self.0 & 1 != 0 {
                parts.push("SUCCESS");
            }
            if self.0 & 2 != 0 {
                parts.push("FAILURE");
            }
            if self.0 & 4 != 0 {
                parts.push("DELAY");
            }
            Cow::Owned(parts.join(","))
        };
        SmtpParameter {
            keyword: SmtpAtom(Cow::Borrowed("NOTIFY")),
            value: Some(value),
        }
    }
}

impl BitOr for SmtpDsnNotify {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Original recipient parameter constructor for `RCPT TO`
/// (RFC 3461).
impl SmtpParameter<'static> {
    /// Build the `ORCPT=rfc822;<address>` parameter for `RCPT TO`.
    ///
    /// Specifies the original recipient address, before any aliasing
    /// or forwarding, so that DSNs can reference it.
    ///
    /// # Reference
    ///
    /// RFC 3461 §4.2
    pub fn orcpt_rfc822(address: impl Into<String>) -> SmtpParameter<'static> {
        let value = {
            let mut s = String::from("rfc822;");
            s.push_str(&address.into());
            s
        };
        SmtpParameter {
            keyword: SmtpAtom(Cow::Borrowed("ORCPT")),
            value: Some(Cow::Owned(value)),
        }
    }
}
