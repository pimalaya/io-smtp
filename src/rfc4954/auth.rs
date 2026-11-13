//! The SMTP AUTH command (RFC 4954 §4).

use core::fmt;

use alloc::{borrow::Cow, vec::Vec};

use base64_codec::codec::Base64Codec;
use bounded_static_derive::ToStatic;
use secrecy::{ExposeSecret, SecretBox};

use crate::rfc5321::SmtpSyntaxError;

/// The AUTH command (RFC 4954 §4).
///
/// Serializes to `AUTH <mechanism> [<base64-ir>]\r\n`.
pub struct SmtpAuthCommand<'a> {
    /// The SASL mechanism name as it appears on the wire (e.g. `"PLAIN"`).
    pub mechanism: SmtpAuthMechanism<'a>,
    /// Optional initial response (base64-encoded on serialization).
    pub initial_response: Option<SecretBox<[u8]>>,
}

impl<'a> From<SmtpAuthCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpAuthCommand<'a>) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(b"AUTH ");
        buf.extend_from_slice(cmd.mechanism.0.as_bytes());

        if let Some(ir) = cmd.initial_response {
            let data = ir.expose_secret();

            if data.is_empty() {
                buf.extend_from_slice(b" =");
            } else {
                buf.push(b' ');
                Base64Codec::default().encode_vec(data, &mut buf);
            }
        }

        buf.extend_from_slice(b"\r\n");
        buf
    }
}

/// The name of a SASL mechanism.
///
/// ```abnf
/// sasl-mech    = 1*20mech-char
/// mech-char    = UPPER-ALPHA / DIGIT / HYPHEN / UNDERSCORE
/// ```
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc4422#section-3.1>
#[derive(Clone, Debug, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpAuthMechanism<'a>(pub(crate) Cow<'a, str>);

impl<'a> TryFrom<&'a str> for SmtpAuthMechanism<'a> {
    type Error = SmtpSyntaxError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let mech_char = |b: u8| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_');

        if !(1..=20).contains(&s.len()) || !s.bytes().all(mech_char) {
            return Err(SmtpSyntaxError::AuthMechanism);
        }

        Ok(Self(Cow::Borrowed(s)))
    }
}

impl fmt::Display for SmtpAuthMechanism<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for SmtpAuthMechanism<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "scram")]
    use crate::rfc7677::auth_scram_sha_256::SCRAM_SHA_256;
    use crate::{
        rfc4954::auth::SmtpAuthMechanism,
        rfc5321::SmtpSyntaxError,
        rfc7628::auth_oauthbearer::OAUTHBEARER,
        sasl::{
            auth_anonymous::ANONYMOUS, auth_login::LOGIN, auth_plain::PLAIN, auth_xoauth2::XOAUTH2,
        },
    };

    #[test]
    fn framed_mechanisms_are_accepted() {
        for name in [ANONYMOUS, LOGIN, PLAIN, OAUTHBEARER, XOAUTH2, "X_1-A"] {
            assert_eq!(SmtpAuthMechanism::try_from(name).unwrap().as_ref(), name);
        }

        #[cfg(feature = "scram")]
        assert!(SmtpAuthMechanism::try_from(SCRAM_SHA_256).is_ok());
    }

    #[test]
    fn other_strings_are_refused() {
        let cases = [
            "",
            "plain",
            "PLAIN ",
            "PLAIN =",
            "PLAIN\r\n",
            "PLAIN\r\nMAIL FROM:<>",
            "A\0B",
            "ABCDEFGHIJKLMNOPQRSTU",
        ];

        for name in cases {
            let err = SmtpAuthMechanism::try_from(name).unwrap_err();
            assert_eq!(err, SmtpSyntaxError::AuthMechanism, "{name:?}");
        }
    }
}
