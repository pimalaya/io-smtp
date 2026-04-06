//! RFC 4954 — SMTP Service Extension for Authentication.
//!
//! Coroutines and types for the SMTP AUTH command, covering PLAIN,
//! LOGIN, and SCRAM SASL mechanisms.

pub mod authenticate;
pub mod login;
pub mod plain;
pub mod types;
