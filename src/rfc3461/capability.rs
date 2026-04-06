//! DSN EHLO capability (RFC 3461 §4).

/// EHLO capability keyword for Delivery Status Notifications.
///
/// Use with `EhloResponse::has_capability(DSN)` to check whether the server
/// supports the DSN ESMTP parameters on MAIL FROM and RCPT TO.
pub const DSN: &str = "DSN";
