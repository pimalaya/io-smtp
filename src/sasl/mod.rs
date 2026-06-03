//! SASL mechanisms wrapped behind the SMTP AUTH verb (RFC 4954).
//!
//! Mechanisms whose RFC defines no protocol-specific glue
//! (PLAIN/LOGIN/ANONYMOUS/XOAUTH2) live here. Mechanisms whose RFC
//! specifies extra cryptographic or transport behaviour
//! (OAUTHBEARER, SCRAM-SHA-256) live under their own RFC folder.

pub mod auth_anonymous;
pub mod auth_login;
pub mod auth_plain;
pub mod auth_xoauth2;
