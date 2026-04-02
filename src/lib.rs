//! I/O-free SMTP client library.
//!
//! This library provides I/O-free coroutines for managing SMTP streams.

pub mod rfc3207;
pub mod rfc4954;
pub mod rfc5321;
#[path = "send-bytes.rs"]
pub mod send_bytes;
#[path = "send-message.rs"]
pub mod send_message;
pub mod utils;
