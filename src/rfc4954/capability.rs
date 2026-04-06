//! AUTH EHLO capability (RFC 4954 §4).

use alloc::vec::Vec;

use thiserror::Error;

/// EHLO capability keyword for SMTP authentication.
pub const AUTH: &str = "AUTH";

/// The AUTH EHLO capability: the set of SASL mechanisms offered by the server.
///
/// Borrows directly from the raw capability line returned by
/// `EhloResponse::get_capability(AUTH)`.
///
/// # Example
///
/// ```ignore
/// use io_smtp::rfc4954::capability::{AUTH, SmtpAuthCapability};
/// use io_smtp::rfc4616::plain::PLAIN;
/// use io_smtp::login::LOGIN;
///
/// let cap = SmtpAuthCapability::parse(ehlo.get_capability(AUTH).unwrap()).unwrap();
/// assert!(cap.has(PLAIN));
/// assert!(cap.has(LOGIN));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpAuthCapability<'a>(Vec<&'a str>);

impl<'a> SmtpAuthCapability<'a> {
    /// Parses the raw AUTH capability line (e.g. `"AUTH PLAIN LOGIN"`).
    pub fn parse(s: &'a str) -> Result<Self, SmtpAuthCapabilityError> {
        let mut parts = s.split_ascii_whitespace();

        match parts.next() {
            Some(kw) if kw.eq_ignore_ascii_case(AUTH) => {}
            _ => return Err(SmtpAuthCapabilityError),
        }

        Ok(SmtpAuthCapability(parts.collect()))
    }

    /// Returns `true` if the given SASL mechanism is advertised.
    ///
    /// The comparison is case-insensitive.
    pub fn has(&self, mechanism: &str) -> bool {
        self.0.iter().any(|m| m.eq_ignore_ascii_case(mechanism))
    }

    /// Returns an iterator over the advertised mechanism names.
    pub fn mechanisms(&self) -> impl Iterator<Item = &str> {
        self.0.iter().copied()
    }
}

/// Error returned when parsing an AUTH capability string fails.
#[derive(Debug, Error)]
#[error("invalid AUTH capability string")]
pub struct SmtpAuthCapabilityError;
