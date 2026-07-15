//! RFC 7677: SCRAM-SHA-256 and SCRAM-SHA-256-PLUS SASL Mechanisms.
//!
//! Provides the SCRAM-SHA-256 SASL mechanism, a salted
//! challenge-response authentication verifying the server signature.
//! The whole module is gated behind the scram cargo feature at the
//! crate root.

pub mod auth_scram_sha_256;
