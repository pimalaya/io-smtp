//! RFC 5321 — Simple Mail Transfer Protocol.
//!
//! Coroutines for each SMTP command (EHLO, HELO, MAIL FROM, RCPT TO,
//! DATA, NOOP, RSET, QUIT) and a types module covering the
//! wire-format primitives: reply codes, responses, paths, domains,
//! and greetings.

pub mod data;
pub mod ehlo;
pub mod greeting;
pub mod helo;
pub mod mail;
pub mod noop;
pub mod quit;
pub mod rcpt;
pub mod rset;
pub mod types;
