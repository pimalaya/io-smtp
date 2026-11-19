//! I/O-free SMTP and LMTP server side.
//!
//! Three layers, each usable on its own:
//!
//! - [`command`] parses one command line into a
//!   [`command::SmtpServerCommand`];
//! - [`reply`] writes a [`reply::SmtpServerReply`], multiline and with
//!   an optional enhanced status code;
//! - [`session`] holds [`session::SmtpServerSession`], the state machine
//!   of a whole SMTP submission or LMTP session, fed the bytes the
//!   caller reads and yielding the bytes to write and the decisions to
//!   take (credentials, sender, recipients, message, TLS upgrade).
//!
//! Authentication runs through the server side of io-sasl (PLAIN and
//! LOGIN), the caller checking the credentials. The crate stays no_std:
//! no socket, no TLS, no storage.

pub mod command;
pub mod reply;
pub mod session;
