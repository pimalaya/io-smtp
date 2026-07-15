//! SIZE EHLO capability (RFC 1870).

use core::num::ParseIntError;

use alloc::{
    borrow::{Cow, ToOwned},
    string::String,
};

use thiserror::Error;

/// EHLO capability keyword for message size declaration.
pub const SIZE: &str = "SIZE";

/// The SIZE EHLO capability: the maximum message size the server will
/// accept, in octets.
///
/// A value of `0` means the server places no declared limit on
/// message size (RFC 1870 §5).
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
pub enum SmtpSizeCapabilityError {
    /// The capability line does not start with the SIZE keyword.
    #[error("Invalid capability: expected SIZE, got {0}")]
    InvalidKey(Cow<'static, str>),
    /// The SIZE value is not a valid integer.
    #[error("Invalid capability SIZE value `{1}`")]
    InvalidValue(#[source] ParseIntError, String),
}

impl SmtpSizeCapability {
    /// Parses the raw SIZE capability line (e.g. `"SIZE 52428800"` or
    /// `"SIZE"`).
    pub fn parse(s: &str) -> Result<Self, SmtpSizeCapabilityError> {
        let mut parts = s.split_ascii_whitespace();

        match parts.next() {
            Some(key) if key.eq_ignore_ascii_case(SIZE) => {}
            Some(key) => return Err(SmtpSizeCapabilityError::InvalidKey(key.to_owned().into())),
            None => return Err(SmtpSizeCapabilityError::InvalidKey("nothing".into())),
        }

        let size = parts.next().unwrap_or("0");

        match size.parse::<u64>() {
            Ok(size) => Ok(Self(size)),
            Err(err) => {
                let size = size.to_owned();
                Err(SmtpSizeCapabilityError::InvalidValue(err, size))
            }
        }
    }
}
