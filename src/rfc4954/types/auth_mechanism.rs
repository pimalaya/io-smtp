//! Module dedicated to the SMTP authentication mechanism.

use std::fmt;

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use crate::rfc5321::types::atom::Atom;

/// Authentication mechanism for SMTP AUTH.
///
/// # Reference
///
/// RFC 4954: SMTP Service Extension for Authentication
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
#[non_exhaustive]
pub enum AuthMechanism<'a> {
    /// The PLAIN SASL mechanism.
    Plain,

    /// The (non-standardized) LOGIN SASL mechanism.
    Login,

    /// OAuth 2.0 bearer token mechanism.
    OAuthBearer,

    /// Google's OAuth 2.0 mechanism.
    XOAuth2,

    /// SCRAM-SHA-1
    ScramSha1,

    /// SCRAM-SHA-1-PLUS
    ScramSha1Plus,

    /// SCRAM-SHA-256
    ScramSha256,

    /// SCRAM-SHA-256-PLUS
    ScramSha256Plus,

    /// SCRAM-SHA3-512
    ScramSha3_512,

    /// SCRAM-SHA3-512-PLUS
    ScramSha3_512Plus,

    /// CRAM-MD5 (legacy mechanism)
    CramMd5,

    /// Some other (unknown) mechanism.
    Other(AuthMechanismOther<'a>),
}

impl AuthMechanism<'_> {
    pub fn parse<'a>(bytes: &'a [u8]) -> Result<AuthMechanism<'a>, Vec<Rich<'a, u8>>> {
        parsers::auth_mechanism()
            .then_ignore(end())
            .parse(bytes)
            .into_result()
    }
}

impl<'a> From<Atom<'a>> for AuthMechanism<'a> {
    fn from(atom: Atom<'a>) -> Self {
        match atom.to_ascii_uppercase().as_str() {
            "PLAIN" => Self::Plain,
            "LOGIN" => Self::Login,
            "OAUTHBEARER" => Self::OAuthBearer,
            "XOAUTH2" => Self::XOAuth2,
            "SCRAM-SHA-1" => Self::ScramSha1,
            "SCRAM-SHA-1-PLUS" => Self::ScramSha1Plus,
            "SCRAM-SHA-256" => Self::ScramSha256,
            "SCRAM-SHA-256-PLUS" => Self::ScramSha256Plus,
            "SCRAM-SHA3-512" => Self::ScramSha3_512,
            "SCRAM-SHA3-512-PLUS" => Self::ScramSha3_512Plus,
            "CRAM-MD5" => Self::CramMd5,
            _ => Self::Other(AuthMechanismOther(atom)),
        }
    }
}

impl fmt::Display for AuthMechanism<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl AsRef<str> for AuthMechanism<'_> {
    fn as_ref(&self) -> &str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
            Self::OAuthBearer => "OAUTHBEARER",
            Self::XOAuth2 => "XOAUTH2",
            Self::ScramSha1 => "SCRAM-SHA-1",
            Self::ScramSha1Plus => "SCRAM-SHA-1-PLUS",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha256Plus => "SCRAM-SHA-256-PLUS",
            Self::ScramSha3_512 => "SCRAM-SHA3-512",
            Self::ScramSha3_512Plus => "SCRAM-SHA3-512-PLUS",
            Self::CramMd5 => "CRAM-MD5",
            Self::Other(other) => other.0.as_ref(),
        }
    }
}

/// An (unknown) authentication mechanism.
///
/// It's guaranteed that this type can't represent any known mechanism from [`AuthMechanism`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct AuthMechanismOther<'a>(pub(crate) Atom<'a>);

pub(crate) mod parsers {
    use chumsky::prelude::*;

    use crate::rfc5321::types::atom::parsers::atom as atom_parser;
    use crate::utils::parsers::Extra;

    use super::AuthMechanism;

    /// SMTP AUTH mechanism parser.
    ///
    /// ```abnf
    /// auth-type      = ATOM
    /// ```
    pub(crate) fn auth_mechanism<'a>(
    ) -> impl Parser<'a, &'a [u8], AuthMechanism<'a>, Extra<'a>> + Clone {
        atom_parser().map(AuthMechanism::from)
    }
}
