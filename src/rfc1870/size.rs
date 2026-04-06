//! SIZE EHLO capability (RFC 1870).

use thiserror::Error;

/// EHLO capability keyword for message size declaration.
pub const SIZE: &str = "SIZE";

/// The SIZE EHLO capability: the maximum message size the server will accept,
/// in octets.
///
/// A value of `0` means the server places no declared limit on message size
/// (RFC 1870 §5).
///
/// # Example
///
/// ```ignore
/// use io_smtp::rfc1870::size::{SIZE, SmtpSizeCapability};
///
/// let cap = SmtpSizeCapability::parse(ehlo.get_capability(SIZE).unwrap()).unwrap();
/// println!("max size: {}", cap.0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmtpSizeCapability(pub u64);

/// Error returned when parsing a SIZE capability string fails.
#[derive(Debug, Error)]
#[error("invalid SIZE capability string")]
pub struct SmtpSizeCapabilityError;

impl SmtpSizeCapability {
    /// Parses the raw SIZE capability line (e.g. `"SIZE 52428800"` or `"SIZE"`).
    pub fn parse(s: &str) -> Result<Self, SmtpSizeCapabilityError> {
        let mut parts = s.split_ascii_whitespace();

        match parts.next() {
            Some(kw) if kw.eq_ignore_ascii_case(SIZE) => {}
            _ => return Err(SmtpSizeCapabilityError),
        }

        match parts.next() {
            None => Ok(SmtpSizeCapability(0)),
            Some(v) => v
                .parse::<u64>()
                .map(SmtpSizeCapability)
                .map_err(|_| SmtpSizeCapabilityError),
        }
    }
}
