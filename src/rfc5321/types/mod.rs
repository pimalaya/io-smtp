//! Shared SMTP wire-format types (RFC 5321 §4.1.2 and §4.2).
//!
//! One module per grammar production: reply codes, responses, paths,
//! domains, mailboxes, parameters and greetings, each pairing the
//! owned type with its byte-slice parser.

pub mod address_literal;
pub mod atom;
pub mod domain;
pub mod ehlo_domain;
pub mod ehlo_response;
pub mod forward_path;
pub mod greeting;
pub mod local_part;
pub mod mailbox;
pub mod parameter;
pub mod reply_code;
pub mod response;
pub mod reverse_path;
pub mod text;
pub mod vec1;
