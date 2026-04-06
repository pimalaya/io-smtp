//! RFC 5321 — Simple Mail Transfer Protocol.
//!
//! Coroutines for each SMTP command and a types module covering the
//! wire-format primitives: reply codes, responses, paths, domains,
//! and greeting messages.

pub mod data;
pub mod ehlo;
pub mod greeting;
pub mod mail;
pub mod noop;
pub mod quit;
pub mod rcpt;
pub mod rset;
pub mod types;
