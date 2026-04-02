//! Module dedicated to the SMTP reply code.

use std::fmt;

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

/// A 3-digit SMTP reply code.
///
/// Each digit carries independent meaning: `class` (1st digit) signals the
/// broad outcome, `subject` (2nd digit) and `detail` (3rd digit) refine it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct ReplyCode {
    /// First digit: 2 (positive completion), 3 (positive intermediate),
    /// 4 (transient negative), or 5 (permanent negative).
    pub class: u8,
    /// Second digit: 0–9.
    pub subject: u8,
    /// Third digit: 0–9.
    pub detail: u8,
}

impl ReplyCode {
    // Positive Completion (2xx)
    /// 211 System status
    pub const SYSTEM_STATUS: Self = Self {
        class: 2,
        subject: 1,
        detail: 1,
    };

    /// 214 Help message
    pub const HELP_MESSAGE: Self = Self {
        class: 2,
        subject: 1,
        detail: 4,
    };

    /// 220 Service ready
    pub const SERVICE_READY: Self = Self {
        class: 2,
        subject: 2,
        detail: 0,
    };

    /// 221 Service closing transmission channel
    pub const SERVICE_CLOSING: Self = Self {
        class: 2,
        subject: 2,
        detail: 1,
    };

    /// 235 Authentication successful (RFC 4954)
    pub const AUTH_SUCCESSFUL: Self = Self {
        class: 2,
        subject: 3,
        detail: 5,
    };

    /// 250 Requested mail action okay, completed
    pub const OK: Self = Self {
        class: 2,
        subject: 5,
        detail: 0,
    };

    /// 251 User not local; will forward
    pub const USER_NOT_LOCAL_WILL_FORWARD: Self = Self {
        class: 2,
        subject: 5,
        detail: 1,
    };

    /// 252 Cannot VRFY user, but will accept message
    pub const CANNOT_VRFY_USER: Self = Self {
        class: 2,
        subject: 5,
        detail: 2,
    };

    /// 334 Server challenge (AUTH continuation)
    pub const AUTH_CONTINUE: Self = Self {
        class: 3,
        subject: 3,
        detail: 4,
    };

    /// 354 Start mail input
    pub const START_MAIL_INPUT: Self = Self {
        class: 3,
        subject: 5,
        detail: 4,
    };

    /// 421 Service not available, closing transmission channel
    pub const SERVICE_NOT_AVAILABLE: Self = Self {
        class: 4,
        subject: 2,
        detail: 1,
    };

    /// 450 Requested mail action not taken: mailbox unavailable
    pub const MAILBOX_UNAVAILABLE_TEMP: Self = Self {
        class: 4,
        subject: 5,
        detail: 0,
    };

    /// 451 Requested action aborted: local error in processing
    pub const LOCAL_ERROR: Self = Self {
        class: 4,
        subject: 5,
        detail: 1,
    };

    /// 452 Requested action not taken: insufficient system storage
    pub const INSUFFICIENT_STORAGE: Self = Self {
        class: 4,
        subject: 5,
        detail: 2,
    };

    /// 455 Server unable to accommodate parameters
    pub const UNABLE_TO_ACCOMMODATE: Self = Self {
        class: 4,
        subject: 5,
        detail: 5,
    };

    /// 500 Syntax error, command unrecognized
    pub const SYNTAX_ERROR: Self = Self {
        class: 5,
        subject: 0,
        detail: 0,
    };

    /// 501 Syntax error in parameters or arguments
    pub const SYNTAX_ERROR_PARAMS: Self = Self {
        class: 5,
        subject: 0,
        detail: 1,
    };

    /// 502 Command not implemented
    pub const COMMAND_NOT_IMPLEMENTED: Self = Self {
        class: 5,
        subject: 0,
        detail: 2,
    };

    /// 503 Bad sequence of commands
    pub const BAD_SEQUENCE: Self = Self {
        class: 5,
        subject: 0,
        detail: 3,
    };

    /// 504 Command parameter not implemented
    pub const PARAM_NOT_IMPLEMENTED: Self = Self {
        class: 5,
        subject: 0,
        detail: 4,
    };

    /// 530 Authentication required (RFC 4954)
    pub const AUTH_REQUIRED: Self = Self {
        class: 5,
        subject: 3,
        detail: 0,
    };

    /// 534 Authentication mechanism is too weak (RFC 4954)
    pub const AUTH_TOO_WEAK: Self = Self {
        class: 5,
        subject: 3,
        detail: 4,
    };

    /// 535 Authentication credentials invalid (RFC 4954)
    pub const AUTH_INVALID: Self = Self {
        class: 5,
        subject: 3,
        detail: 5,
    };

    /// 550 Requested action not taken: mailbox unavailable
    pub const MAILBOX_UNAVAILABLE: Self = Self {
        class: 5,
        subject: 5,
        detail: 0,
    };

    /// 551 User not local; please try forwarding
    pub const USER_NOT_LOCAL: Self = Self {
        class: 5,
        subject: 5,
        detail: 1,
    };

    /// 552 Requested mail action aborted: exceeded storage allocation
    pub const EXCEEDED_STORAGE: Self = Self {
        class: 5,
        subject: 5,
        detail: 2,
    };

    /// 553 Requested action not taken: mailbox name not allowed
    pub const MAILBOX_NAME_NOT_ALLOWED: Self = Self {
        class: 5,
        subject: 5,
        detail: 3,
    };

    /// 554 Transaction failed
    pub const TRANSACTION_FAILED: Self = Self {
        class: 5,
        subject: 5,
        detail: 4,
    };

    /// 555 MAIL FROM/RCPT TO parameters not recognized or not implemented
    pub const PARAMS_NOT_RECOGNIZED: Self = Self {
        class: 5,
        subject: 5,
        detail: 5,
    };

    pub fn parse<'a>(bytes: &'a [u8]) -> Result<ReplyCode, Vec<Rich<'a, u8>>> {
        parsers::reply_code()
            .then_ignore(end())
            .parse(bytes)
            .into_result()
    }

    /// Returns the numeric value of the reply code.
    pub fn code(&self) -> u16 {
        self.class as u16 * 100 + self.subject as u16 * 10 + self.detail as u16
    }

    /// Returns true if this is a positive completion reply (2xx).
    pub fn is_positive_completion(&self) -> bool {
        self.class == 2
    }

    /// Returns true if this is a positive intermediate reply (3xx).
    pub fn is_positive_intermediate(&self) -> bool {
        self.class == 3
    }

    /// Returns true if this is a transient negative reply (4xx).
    pub fn is_transient_negative(&self) -> bool {
        self.class == 4
    }

    /// Returns true if this is a permanent negative reply (5xx).
    pub fn is_permanent_negative(&self) -> bool {
        self.class == 5
    }

    /// Returns true if this is a success reply (2xx or 3xx).
    pub fn is_success(&self) -> bool {
        self.is_positive_completion() || self.is_positive_intermediate()
    }

    /// Returns true if this is an error reply (4xx or 5xx).
    pub fn is_error(&self) -> bool {
        self.is_transient_negative() || self.is_permanent_negative()
    }
}

impl fmt::Display for ReplyCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}{}", self.class, self.subject, self.detail)
    }
}

pub(crate) mod parsers {
    use chumsky::prelude::*;

    use crate::utils::parsers::Extra;

    use super::ReplyCode;

    /// SMTP reply code parser.
    ///
    /// ```abnf
    /// Reply-code = %x32-35 %x30-39 %x30-39
    /// ```
    pub(crate) fn reply_code<'a>() -> impl Parser<'a, &'a [u8], ReplyCode, Extra<'a>> + Clone {
        any()
            .filter(|b| matches!(b, b'2'..=b'5'))
            .then(any().filter(|b: &u8| b.is_ascii_digit()))
            .then(any().filter(|b: &u8| b.is_ascii_digit()))
            .map(|((class, subject), detail)| ReplyCode {
                class: class - b'0',
                subject: subject - b'0',
                detail: detail - b'0',
            })
            .labelled("reply code")
    }
}
