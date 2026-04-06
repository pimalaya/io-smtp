//! ENHANCEDSTATUSCODES EHLO capability (RFC 3463 §4).

/// EHLO capability keyword for enhanced status codes.
///
/// Use with `EhloResponse::has_capability(ENHANCEDSTATUSCODES)` to check
/// whether the server includes RFC 3463 enhanced status codes in its replies.
pub const ENHANCEDSTATUSCODES: &str = "ENHANCEDSTATUSCODES";
