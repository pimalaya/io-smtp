//! I/O-free SMTP client library.
//!
//! This library provides I/O-free coroutines for managing SMTP streams.
//! It is based on the [smtp-codec] crate for protocol encoding/decoding.
//!
//! ## Overview
//!
//! The library uses a coroutine-based design that separates protocol logic
//! from I/O operations. Each coroutine handles a specific SMTP command or
//! interaction, and returns I/O requests that the caller must fulfill.
//!
//! ## Example
//!
//! ```ignore
//! use io_smtp::{context::SmtpContext, coroutines::greeting::GetSmtpGreeting};
//!
//! let context = SmtpContext::new();
//! let mut coroutine = GetSmtpGreeting::new(context);
//!
//! loop {
//!     match coroutine.resume(io_result) {
//!         GetSmtpGreetingResult::Ok { context, greeting } => {
//!             // Connection established, server ready
//!             break;
//!         }
//!         GetSmtpGreetingResult::Io { io } => {
//!             // Perform I/O operation and feed result back
//!             io_result = Some(perform_io(&mut stream, io));
//!         }
//!         GetSmtpGreetingResult::Err { err, .. } => {
//!             panic!("Error: {err}");
//!         }
//!     }
//! }
//! ```

pub mod context;
pub mod coroutines;

pub use smtp_codec as codec;
pub use smtp_codec::smtp_types as types;
