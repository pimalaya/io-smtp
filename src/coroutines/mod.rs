//! SMTP coroutines.
//!
//! This module contains I/O-free coroutines for SMTP protocol operations.

#[cfg(feature = "ext_auth")]
#[path = "authenticate-plain.rs"]
pub mod authenticate_plain;
pub mod data;
pub mod ehlo;
pub mod greeting;
pub mod mail;
pub mod noop;
pub mod quit;
pub mod rcpt;
pub mod rset;
pub mod send;
#[cfg(feature = "starttls")]
pub mod starttls;
