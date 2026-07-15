//! Shared SMTP wire-format types (RFC 5321 §4.1.2 and §4.2).
//!
//! One module per grammar production: reply codes, responses, paths,
//! domains, mailboxes, parameters and greetings, each pairing the
//! owned type with its byte-slice parser. The modules are an internal
//! organization detail: every type flattens into the rfc5321 path.

mod address_literal;
mod atom;
mod domain;
mod ehlo_domain;
mod ehlo_response;
mod forward_path;
mod greeting;
mod local_part;
mod mailbox;
mod parameter;
mod reply_code;
mod response;
mod reverse_path;
mod text;
mod vec1;

#[doc(inline)]
pub use address_literal::SmtpAddressLiteral;
#[doc(inline)]
pub use atom::SmtpAtom;
#[doc(inline)]
pub use domain::SmtpDomain;
#[doc(inline)]
pub use ehlo_domain::SmtpEhloDomain;
#[doc(inline)]
pub use ehlo_response::SmtpEhloResponse;
#[doc(inline)]
pub use forward_path::SmtpForwardPath;
#[doc(inline)]
pub use greeting::SmtpGreeting;
#[doc(inline)]
pub use local_part::SmtpLocalPart;
#[doc(inline)]
pub use mailbox::SmtpMailbox;
#[doc(inline)]
pub use parameter::SmtpParameter;
#[doc(inline)]
pub use reply_code::SmtpReplyCode;
#[doc(inline)]
pub use response::SmtpResponse;
#[doc(inline)]
pub use reverse_path::SmtpReversePath;
#[doc(inline)]
pub use text::SmtpText;
#[doc(inline)]
pub use vec1::SmtpVec1;
