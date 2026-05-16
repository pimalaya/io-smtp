//! RFC 4505 — Anonymous Simple Authentication and Security Layer
//! (SASL) Mechanism.
//!
//! Provides the ANONYMOUS SASL mechanism for unauthenticated SMTP
//! sessions carrying an optional human-readable trace token the
//! server can log.

pub mod anonymous;
