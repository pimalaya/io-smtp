//! RFC 1870: SMTP Service Extension for Message Size Declaration.
//!
//! Parses the SIZE capability advertised in the EHLO response, the
//! maximum message size the server accepts.

pub mod size;
