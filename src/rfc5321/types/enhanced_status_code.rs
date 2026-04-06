//! Module dedicated to the SMTP enhanced status code.

use core::fmt;

use bounded_static_derive::ToStatic;

/// Enhanced status code (RFC 3463).
///
/// Format: class.subject.detail (e.g., 2.1.0, 5.7.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToStatic)]
pub struct EnhancedStatusCode {
    /// Class: 2 (success), 4 (temporary failure), or 5 (permanent failure)
    pub class: u8,
    /// Subject: 0-999
    pub subject: u16,
    /// Detail: 0-999
    pub detail: u16,
}

impl EnhancedStatusCode {
    /// Creates a new enhanced status code.
    ///
    /// Returns `None` if class is not 2, 4, or 5.
    pub fn new(class: u8, subject: u16, detail: u16) -> Option<Self> {
        if matches!(class, 2 | 4 | 5) && subject < 1000 && detail < 1000 {
            Some(Self {
                class,
                subject,
                detail,
            })
        } else {
            None
        }
    }

    /// Returns true if this indicates success.
    pub fn is_success(&self) -> bool {
        self.class == 2
    }

    /// Returns true if this indicates a temporary failure.
    pub fn is_temporary_failure(&self) -> bool {
        self.class == 4
    }

    /// Returns true if this indicates a permanent failure.
    pub fn is_permanent_failure(&self) -> bool {
        self.class == 5
    }
}

impl fmt::Display for EnhancedStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}
