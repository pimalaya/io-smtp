//! SMTP coroutines.
//!
//! This module contains I/O-free coroutines for SMTP protocol operations.

#[cfg(feature = "ext_auth")]
pub mod authenticate;
#[cfg(feature = "ext_auth")]
#[path = "authenticate-login.rs"]
pub mod authenticate_login;
#[cfg(feature = "ext_auth")]
#[path = "authenticate-login-with-capability.rs"]
pub mod authenticate_login_with_capability;
#[cfg(feature = "ext_auth")]
#[path = "authenticate-plain.rs"]
pub mod authenticate_plain;
#[cfg(feature = "ext_auth")]
#[path = "authenticate-plain-with-capability.rs"]
pub mod authenticate_plain_with_capability;
pub mod data;
pub mod ehlo;
pub mod greeting;
#[path = "greeting-with-capability.rs"]
pub mod greeting_with_capability;
pub mod mail;
pub mod noop;
pub mod quit;
pub mod rcpt;
pub mod rset;
pub mod send;
#[path = "send-message.rs"]
pub mod send_message;
#[cfg(feature = "starttls")]
pub mod starttls;
