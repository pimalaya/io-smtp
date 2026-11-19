//! RFC 4954: SMTP Service Extension for Authentication.
//!
//! Defines the AUTH command and continuation data types used by all
//! SASL mechanisms.

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod auth;
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod auth_data;
pub mod capability;
