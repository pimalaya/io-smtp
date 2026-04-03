//! Module dedicated to the SMTP command.

use std::{borrow::Cow, io::Write};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use secrecy::{ExposeSecret, SecretBox};

use crate::rfc4954::types::auth_mechanism::AuthMechanism;
use crate::rfc5321::types::{
    domain::Domain, ehlo_domain::EhloDomain, forward_path::ForwardPath, parameter::Parameter,
    reverse_path::ReversePath,
};

/// An SMTP command.
///
/// # Reference
///
/// RFC 5321 Section 4.1: SMTP Commands
#[derive(Debug)]
#[non_exhaustive]
pub enum Command<'a> {
    /// Extended HELLO - identifies the client and requests extended features.
    Ehlo {
        /// The client's domain or address literal
        domain: EhloDomain<'a>,
    },

    /// HELLO - identifies the client to the server (legacy).
    Helo {
        /// The client's domain
        domain: Domain<'a>,
    },

    /// MAIL FROM - initiates a mail transaction with the sender's address.
    Mail {
        /// The sender's reverse path (can be null <>)
        reverse_path: ReversePath<'a>,
        /// Optional ESMTP parameters (e.g., SIZE, BODY)
        parameters: Vec<Parameter<'a>>,
    },

    /// RCPT TO - specifies a recipient for the mail.
    Rcpt {
        /// The recipient's forward path
        forward_path: ForwardPath<'a>,
        /// Optional ESMTP parameters
        parameters: Vec<Parameter<'a>>,
    },

    /// DATA - begins the mail data transfer.
    Data,

    /// RSET - aborts the current mail transaction.
    Rset,

    /// QUIT - requests connection termination.
    Quit,

    /// NOOP - no operation (used to keep connection alive).
    Noop {
        /// Optional string argument (ignored by server)
        string: Option<Cow<'a, str>>,
    },

    /// VRFY - verifies a user or mailbox name.
    Vrfy {
        /// The string to verify (usually a user name or address)
        string: Cow<'a, str>,
    },

    /// EXPN - expands a mailing list.
    Expn {
        /// The mailing list name to expand
        string: Cow<'a, str>,
    },

    /// HELP - requests help information.
    Help {
        /// Optional topic for specific help
        topic: Option<Cow<'a, str>>,
    },

    /// STARTTLS - initiates TLS encryption.
    ///
    /// # Reference
    ///
    /// RFC 3207: SMTP Service Extension for Secure SMTP over Transport Layer Security
    StartTls,

    /// AUTH - initiates SASL authentication.
    ///
    /// # Reference
    ///
    /// RFC 4954: SMTP Service Extension for Authentication
    Auth {
        /// The SASL mechanism to use
        mechanism: AuthMechanism<'a>,
        /// Optional initial response (base64-encoded by encoder)
        initial_response: Option<SecretBox<Box<[u8]>>>,
    },
}

impl<'a> Command<'a> {
    /// Returns the command name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Ehlo { .. } => "EHLO",
            Command::Helo { .. } => "HELO",
            Command::Mail { .. } => "MAIL",
            Command::Rcpt { .. } => "RCPT",
            Command::Data => "DATA",
            Command::Rset => "RSET",
            Command::Quit => "QUIT",
            Command::Noop { .. } => "NOOP",
            Command::Vrfy { .. } => "VRFY",
            Command::Expn { .. } => "EXPN",
            Command::Help { .. } => "HELP",
            Command::StartTls => "STARTTLS",
            Command::Auth { .. } => "AUTH",
        }
    }

    /// Serialize this command to wire bytes (includes CRLF).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            Command::Ehlo { domain } => {
                write!(buf, "EHLO {domain}").unwrap();
            }
            Command::Helo { domain } => {
                write!(buf, "HELO {domain}").unwrap();
            }
            Command::Mail {
                reverse_path,
                parameters,
            } => {
                write!(buf, "MAIL FROM:{reverse_path}").unwrap();
                for p in parameters {
                    write!(buf, " {p}").unwrap();
                }
            }
            Command::Rcpt {
                forward_path,
                parameters,
            } => {
                write!(buf, "RCPT TO:{forward_path}").unwrap();
                for p in parameters {
                    write!(buf, " {p}").unwrap();
                }
            }
            Command::Data => buf.write_all(b"DATA").unwrap(),
            Command::Rset => buf.write_all(b"RSET").unwrap(),
            Command::Quit => buf.write_all(b"QUIT").unwrap(),
            Command::Noop { string } => {
                buf.write_all(b"NOOP").unwrap();
                if let Some(s) = string {
                    write!(buf, " {s}").unwrap();
                }
            }
            Command::Vrfy { string } => {
                write!(buf, "VRFY {string}").unwrap();
            }
            Command::Expn { string } => {
                write!(buf, "EXPN {string}").unwrap();
            }
            Command::Help { topic } => {
                buf.write_all(b"HELP").unwrap();
                if let Some(t) = topic {
                    write!(buf, " {t}").unwrap();
                }
            }
            Command::StartTls => buf.write_all(b"STARTTLS").unwrap(),
            Command::Auth {
                mechanism,
                initial_response,
            } => {
                write!(buf, "AUTH {}", mechanism.as_ref()).unwrap();
                if let Some(ir) = initial_response {
                    let data = ir.expose_secret();
                    if data.is_empty() {
                        buf.write_all(b" =").unwrap();
                    } else {
                        write!(buf, " {}", base64.encode(data.as_ref())).unwrap();
                    }
                }
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("Unknown command variant"),
        }
        buf.write_all(b"\r\n").unwrap();
        buf
    }
}
