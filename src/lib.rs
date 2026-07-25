#![no_std]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # io-smtp
//!
//! I/O-free SMTP client coroutines: every network exchange is a
//! resumable state machine emitting read and write requests instead
//! of performing I/O itself, so the caller owns the socket and pumps
//! the coroutine (see the client feature for a ready-made
//! std-blocking pump).
//!
//! ## The coroutine contract
//!
//! Every coroutine implements [`coroutine::SmtpCoroutine`], whose
//! resume method takes an optional byte slice and yields a
//! [`coroutine::SmtpCoroutineState`]: either an intermediate
//! [`coroutine::SmtpYield`] asking the caller to read bytes from the
//! stream (fed back on the next resume, an empty slice signalling
//! EOF) or to write the yielded bytes, or a terminal value carrying
//! the result. Each module ships a runnable example of the pump loop,
//! and [`client::SmtpClientStd`] implements it once for blocking std
//! streams.
//!
//! Most coroutines delegate their wire exchange to
//! [`send::SmtpCommandSend`], the base coroutine owning the
//! serialise, write, read and parse cycle; they only interpret the
//! parsed reply code. The exceptions are the pure read coroutines
//! (the greeting and EHLO ones), which own their read loop because
//! nothing is written first, or because the multi-line reply needs
//! dedicated parsing.
//!
//! ## Layout: one folder per RFC
//!
//! The source tree mirrors the SMTP specification landscape, one
//! module per RFC. [`rfc5321`] hosts the SMTP core: the coroutines
//! for the greeting, the EHLO and HELO handshakes, the mail
//! transaction (MAIL FROM, RCPT TO, DATA with dot-stuffing), NOOP,
//! RSET, QUIT and a raw passthrough, next to the flattened
//! wire-format types (reply codes, responses, paths, domains,
//! parameters). The extensions follow: [`rfc1870`] (message size
//! declaration), [`rfc3207`] (STARTTLS), [`rfc3461`] (delivery status
//! notifications), [`rfc3463`] (enhanced status codes) and [`rfc4954`]
//! (the AUTH command and its continuation data).
//!
//! Authentication mechanisms split in two. [`rfc7628`] (OAUTHBEARER)
//! and [`rfc7677`] (SCRAM-SHA-256, behind the scram feature) specify
//! cryptographic or transport behaviour beyond plain SASL framing, so
//! they live under their own RFC module. [`sasl`] hosts the
//! mechanisms with no such glue: PLAIN, LOGIN, ANONYMOUS and XOAUTH2.
//!
//! Code spanning the RFC modules lives at the crate root:
//! [`coroutine`] defines the coroutine contract and the smtp_try
//! macro, [`send`] the base send-one-command coroutine, [`message`]
//! the composite whole-message send coroutine, the private utils module the shared
//! byte-escaping and parser helpers, and [`client`] the optional
//! std-blocking client (client feature) exposing one method per
//! coroutine plus, with a TLS feature enabled, an end-to-end connect
//! covering transport, STARTTLS and SASL.
//!
//! ## Conventions
//!
//! The crate is unconditionally no_std; alloc is always required,
//! std only under the client feature. Public items carry the bare
//! Smtp domain prefix (SMTP is not versioned). Coroutine errors
//! normalise to the shape "SMTP operation failed: cause", and RFC
//! wire tokens (mechanism names, capability keywords) keep their
//! exact spelling.

extern crate alloc;
#[cfg(feature = "client")]
extern crate std;

#[cfg(feature = "client")]
pub mod client;
pub mod coroutine;
pub mod message;
pub mod rfc1870;
pub mod rfc3207;
pub mod rfc3461;
pub mod rfc3463;
pub mod rfc4954;
pub mod rfc5321;
pub mod rfc7628;
#[cfg(feature = "scram")]
pub mod rfc7677;
pub mod sasl;
pub mod send;
pub(crate) mod utils;
