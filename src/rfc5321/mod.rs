//! RFC 5321: Simple Mail Transfer Protocol.
//!
//! Each sub-module pairs a command type, serialisable to wire bytes,
//! with the I/O-free coroutine running the full request/response
//! exchange. The [`types`] module covers the shared wire-format
//! primitives: reply codes, responses, paths, domains and greetings.

pub mod data;
pub mod ehlo;
pub mod greeting;
pub mod helo;
pub mod mail;
pub mod noop;
pub mod quit;
pub mod raw;
pub mod rcpt;
pub mod rset;
pub mod types;
