//! The SMTP AUTH command (RFC 4954 §4).

use alloc::{borrow::Cow, vec::Vec};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use secrecy::{ExposeSecret, SecretBox};

/// The AUTH command (RFC 4954 §4).
///
/// Serializes to `AUTH <mechanism> [<base64-ir>]\r\n`.
pub struct SmtpAuthCommand<'a> {
    /// The SASL mechanism name as it appears on the wire (e.g. `"PLAIN"`).
    pub mechanism: Cow<'a, str>,
    /// Optional initial response (base64-encoded on serialization).
    pub initial_response: Option<SecretBox<[u8]>>,
}

impl<'a> From<SmtpAuthCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpAuthCommand<'a>) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(b"AUTH ");
        buf.extend_from_slice(cmd.mechanism.as_bytes());

        if let Some(ir) = cmd.initial_response {
            let data = ir.expose_secret();

            if data.is_empty() {
                buf.extend_from_slice(b" =");
            } else {
                buf.push(b' ');
                buf.extend_from_slice(base64.encode(data).as_bytes());
            }
        }

        buf.extend_from_slice(b"\r\n");
        buf
    }
}
