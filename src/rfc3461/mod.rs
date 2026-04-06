//! RFC 3461 — Simple Mail Transfer Protocol (SMTP) Service Extension for
//! Delivery Status Notifications (DSNs).
//!
//! Provides type-safe ESMTP parameter constructors for MAIL FROM and RCPT TO
//! commands. The server must announce the `DSN` capability in its EHLO
//! response before these parameters may be used.

pub mod capability;
pub mod parameter;
