//! STARTTLS EHLO capability (RFC 3207 §2).

/// EHLO capability keyword for STARTTLS.
///
/// Use with `SmtpEhloResponse::has_capability(STARTTLS)` to check whether the
/// server supports upgrading the connection to TLS.
pub const STARTTLS: &str = "STARTTLS";
