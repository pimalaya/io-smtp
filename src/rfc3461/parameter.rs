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
//! let envid = SmtpParameter::envid("abc123")?;
//! let params = vec![SmtpDsnRet::Hdrs.into_parameter(), envid];
//! let coroutine = SmtpMail::new(reverse_path, params);
//!
//! // NOTE: RCPT TO with NOTIFY=SUCCESS,FAILURE
//! let params = vec![(SmtpDsnNotify::SUCCESS | SmtpDsnNotify::FAILURE).into_parameter()];
//! let coroutine = SmtpRcpt::new(forward_path, params);
//! ```

use core::ops::BitOr;

use alloc::{borrow::Cow, string::String, vec::Vec};

use crate::rfc5321::{SmtpParameter, SmtpSyntaxError};

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
            keyword: Cow::Borrowed("RET"),
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
    /// The identifier is given as is and sent xtext-encoded. It must
    /// hold printable US-ASCII characters only, and at least one.
    ///
    /// # Reference
    ///
    /// RFC 3461 §4.4
    pub fn envid(id: impl AsRef<str>) -> Result<SmtpParameter<'static>, SmtpSyntaxError> {
        let mut value = String::new();
        xtext(id.as_ref(), &mut value)?;

        Ok(SmtpParameter {
            keyword: Cow::Borrowed("ENVID"),
            value: Some(Cow::Owned(value)),
        })
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

    /// Whether this is `NEVER`.
    pub const fn is_never(self) -> bool {
        self.0 == 0
    }

    /// Whether every condition of `other` is set, `NEVER` never being
    /// contained.
    pub const fn contains(self, other: Self) -> bool {
        other.0 != 0 && self.0 & other.0 == other.0
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
            keyword: Cow::Borrowed("NOTIFY"),
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
    /// The address is given as is and sent xtext-encoded. It must
    /// hold printable US-ASCII characters only, and at least one.
    ///
    /// # Reference
    ///
    /// RFC 3461 §4.2
    pub fn orcpt_rfc822(
        address: impl AsRef<str>,
    ) -> Result<SmtpParameter<'static>, SmtpSyntaxError> {
        let mut value = String::from("rfc822;");
        xtext(address.as_ref(), &mut value)?;

        Ok(SmtpParameter {
            keyword: Cow::Borrowed("ORCPT"),
            value: Some(Cow::Owned(value)),
        })
    }
}

/// Decodes an xtext string (RFC 3461 section 4), as found in the `ENVID`
/// and `ORCPT` parameters, or `None` when it is not valid xtext or does
/// not decode to UTF-8.
pub fn xtext_decode(s: &str) -> Option<String> {
    let hex = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                let hi = hex(*bytes.get(i + 1)?)?;
                let lo = hex(*bytes.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'=' => return None,
            b @ b'!'..=b'~' => {
                out.push(b);
                i += 1;
            }
            _ => return None,
        }
    }

    String::from_utf8(out).ok()
}

/// Appends the xtext encoding of a printable US-ASCII string.
///
/// ```abnf
/// xtext = *( xchar / hexchar )
/// xchar = any ASCII CHAR between "!" (33) and "~" (126) inclusive,
///         except for "+" and "=".
/// hexchar = "+" 2(%x30-39 / %x41-46)
/// ```
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc3461#section-4>
fn xtext(s: &str, out: &mut String) -> Result<(), SmtpSyntaxError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    if s.is_empty() {
        return Err(SmtpSyntaxError::ParameterValue);
    }

    for b in s.bytes() {
        match b {
            b' ' | b'+' | b'=' => {
                out.push('+');
                out.push(HEX[usize::from(b >> 4)] as char);
                out.push(HEX[usize::from(b & 0xf)] as char);
            }
            b'!'..=b'~' => out.push(b as char),
            _ => return Err(SmtpSyntaxError::ParameterValue),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::{
        rfc3461::parameter::xtext_decode,
        rfc5321::{SmtpParameter, SmtpSyntaxError},
    };

    #[test]
    fn envid_is_xtext_encoded() {
        let cases = [
            ("abc123", "ENVID=abc123"),
            ("a b", "ENVID=a+20b"),
            ("a+b=c", "ENVID=a+2Bb+3Dc"),
        ];

        for (id, wire) in cases {
            assert_eq!(SmtpParameter::envid(id).unwrap().to_string(), wire);
        }
    }

    #[test]
    fn orcpt_is_xtext_encoded() {
        let parameter = SmtpParameter::orcpt_rfc822("a+b@example.org").unwrap();
        assert_eq!(parameter.to_string(), "ORCPT=rfc822;a+2Bb@example.org");
    }

    #[test]
    fn xtext_is_decoded() {
        assert_eq!(xtext_decode("a+2Bb+3Dc+20d").as_deref(), Some("a+b=c d"));
        assert_eq!(xtext_decode("QQ314159").as_deref(), Some("QQ314159"));

        for s in ["a+2", "a+2b", "a=b", "a b", "+C3+28"] {
            assert_eq!(xtext_decode(s), None, "{s:?}");
        }
    }

    #[test]
    fn unprintable_value_is_refused() {
        for s in ["", "a\rb", "a\nb", "a\0b", "a\tb", "a\x7fb", "é"] {
            let err = SmtpParameter::envid(s).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::ParameterValue, "{s:?}");

            let err = SmtpParameter::orcpt_rfc822(s).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::ParameterValue, "{s:?}");
        }
    }
}
