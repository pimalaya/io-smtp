//! SMTP syntax error (RFC 5321 §4.1.2).
//!
//! What the validating constructors of the command arguments return
//! when a string is not the production it should be.

use thiserror::Error;

/// Failure causes when validating a command argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum SmtpSyntaxError {
    /// The string is neither a Dot-string nor a Quoted-string.
    #[error("Invalid SMTP local part")]
    LocalPart,
    /// The string is not a dotted sequence of sub-domains.
    #[error("Invalid SMTP domain")]
    Domain,
    /// The string is not a bracketed IPv4, IPv6 or general address.
    #[error("Invalid SMTP address literal")]
    AddressLiteral,
    /// No at sign follows the local part.
    #[error("Invalid SMTP mailbox: missing at sign")]
    Mailbox,
    /// The string is not an esmtp-keyword.
    #[error("Invalid ESMTP parameter keyword")]
    ParameterKeyword,
    /// The string is not an esmtp-value.
    #[error("Invalid ESMTP parameter value")]
    ParameterValue,
    /// The string is neither an Atom nor a Quoted-string.
    #[error("Invalid SMTP string")]
    String,
    /// The string is not a sasl-mech (RFC 4422 §3.1).
    #[error("Invalid SASL mechanism name")]
    AuthMechanism,
}
