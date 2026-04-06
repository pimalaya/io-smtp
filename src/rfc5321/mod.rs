//! RFC 5321 — Simple Mail Transfer Protocol.
//!
//! Each sub-module exposes a command type (`SmtpEhloCommand`, `SmtpHeloCommand`,
//! `SmtpMailCommand`, `SmtpRcptCommand`, `SmtpDataCommand`, `SmtpNoopCommand`,
//! `SmtpRsetCommand`, `SmtpQuitCommand`) that implements `From<T> for Vec<u8>`
//! for wire serialisation, alongside the I/O-free coroutine that drives the
//! full request/response exchange.  The `types` module covers shared
//! wire-format primitives: reply codes, responses, paths, domains, and
//! greetings.

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
