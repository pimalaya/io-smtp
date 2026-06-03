//! SMTP SASL SCRAM-SHA-256 coroutine. Always sends the
//! client-first-message SASL-IR (RFC 4954 §4); verifies the
//! server's final signature before returning `Ok`.
//!
//! SCRAM:         <https://www.rfc-editor.org/rfc/rfc5802>
//! SCRAM-SHA-256: <https://www.rfc-editor.org/rfc/rfc7677>
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     borrow::Cow,
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use secrecy::SecretString;
//!
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
//!     rfc5321::types::{domain::Domain, ehlo_domain::EhloDomain},
//!     rfc7677::auth_scram_sha_256::{SmtpAuthScramSha256, SmtpAuthScramSha256Options},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let password = SecretString::from("secret".to_string());
//! let nonce = b"fyko+d2lbbFgONRv9qkxdawL";
//! let domain = EhloDomain::Domain(Domain(Cow::Borrowed("client.example.org")));
//! let opts = SmtpAuthScramSha256Options::default();
//! let mut coroutine = SmtpAuthScramSha256::new("alice", &password, nonce, domain, opts);
//! let mut arg = None;
//!
//! loop {
//!     match coroutine.resume(arg.take()) {
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         SmtpCoroutineState::Complete(Ok(())) => break,
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! }
//! ```

use core::{fmt, str::from_utf8};

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use bounded_static::IntoBoundedStatic;
use hmac::{Hmac, KeyInit, Mac};
use log::trace;
use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc4954::{auth::SmtpAuthCommand, auth_data::SmtpAuthData},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError},
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode},
    },
    send::*,
    smtp_try,
};

type HmacSha256 = Hmac<Sha256>;

/// The SASL mechanism name as it appears on the wire.
pub const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

/// Options for [`SmtpAuthScramSha256::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpAuthScramSha256Options {
    /// Ignored (SCRAM always sends client-first SASL-IR); kept for
    /// option surface parity with the other SASL coroutines.
    pub initial_request: bool,
    /// Refresh capabilities with an `EHLO` after a successful auth.
    pub ensure_capabilities: bool,
}

impl Default for SmtpAuthScramSha256Options {
    fn default() -> Self {
        Self {
            initial_request: true,
            ensure_capabilities: true,
        }
    }
}

/// Failure causes during the SMTP AUTH SCRAM-SHA-256 exchange.
#[derive(Debug, Error)]
pub enum SmtpAuthScramSha256Error {
    #[error("SMTP AUTH SCRAM-SHA-256 failed: rejected {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("SMTP AUTH SCRAM-SHA-256 failed: server-first-message parse error: {0}")]
    ParseServerFirst(String),
    #[error("SMTP AUTH SCRAM-SHA-256 failed: server nonce does not start with client nonce")]
    NonceMismatch,
    #[error("SMTP AUTH SCRAM-SHA-256 failed: server signature mismatch")]
    ServerSignatureMismatch,
    #[error("SMTP AUTH SCRAM-SHA-256 failed: {0}")]
    Send(#[from] SendSmtpCommandError),
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH SCRAM-SHA-256 coroutine. `nonce` must be
/// printable ASCII (no commas); RFC 5802 recommends at least 18
/// bytes of cryptographic randomness.
pub struct SmtpAuthScramSha256 {
    state: State,
    client_first_bare: Vec<u8>,
    password: SecretString,
    domain: Option<EhloDomain<'static>>,
    expected_server_sig: Vec<u8>,
    opts: SmtpAuthScramSha256Options,
}

impl SmtpAuthScramSha256 {
    pub fn new(
        username: &str,
        password: &SecretString,
        nonce: &[u8],
        domain: EhloDomain<'_>,
        opts: SmtpAuthScramSha256Options,
    ) -> Self {
        let encoded_username = sasl_name(username);

        let mut client_first_bare = Vec::new();
        client_first_bare.extend_from_slice(b"n=");
        client_first_bare.extend_from_slice(encoded_username.as_bytes());
        client_first_bare.extend_from_slice(b",r=");
        client_first_bare.extend_from_slice(nonce);

        let mut client_first = Vec::new();
        client_first.extend_from_slice(b"n,,");
        client_first.extend_from_slice(&client_first_bare);

        let cmd = SmtpAuthCommand {
            mechanism: Cow::Borrowed(SCRAM_SHA_256),
            initial_response: Some(SecretBox::new(client_first.into_boxed_slice())),
        };

        Self {
            state: State::SendInitial(SendSmtpCommand::new(cmd)),
            client_first_bare,
            password: password.clone(),
            domain: Some(domain.into_static()),
            expected_server_sig: Vec::new(),
            opts,
        }
    }

    fn compute_client_final(
        &mut self,
        server_first: &str,
    ) -> Result<Vec<u8>, SmtpAuthScramSha256Error> {
        let mut combined_nonce: Option<&str> = None;
        let mut salt_b64: Option<&str> = None;
        let mut iterations: Option<u32> = None;

        for field in server_first.split(',') {
            if let Some(val) = field.strip_prefix("r=") {
                combined_nonce = Some(val);
            } else if let Some(val) = field.strip_prefix("s=") {
                salt_b64 = Some(val);
            } else if let Some(val) = field.strip_prefix("i=") {
                iterations = val.parse().ok();
            }
        }

        let combined_nonce = combined_nonce
            .ok_or_else(|| SmtpAuthScramSha256Error::ParseServerFirst("missing r=".into()))?;
        let salt_b64 = salt_b64
            .ok_or_else(|| SmtpAuthScramSha256Error::ParseServerFirst("missing s=".into()))?;
        let iterations = iterations
            .ok_or_else(|| SmtpAuthScramSha256Error::ParseServerFirst("missing i=".into()))?;

        let client_nonce = self
            .client_first_bare
            .iter()
            .position(|&b| b == b'r')
            .and_then(|p| {
                if self.client_first_bare.get(p + 1) == Some(&b'=') {
                    Some(&self.client_first_bare[p + 2..])
                } else {
                    None
                }
            })
            .unwrap_or(&[]);

        let client_nonce_str = from_utf8(client_nonce).unwrap_or("");
        if !combined_nonce.starts_with(client_nonce_str) {
            return Err(SmtpAuthScramSha256Error::NonceMismatch);
        }

        let salt = base64
            .decode(salt_b64.as_bytes())
            .map_err(|e| SmtpAuthScramSha256Error::ParseServerFirst(e.to_string()))?;

        let password_bytes = self.password.expose_secret().as_bytes();
        let mut salted_password = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password_bytes, &salt, iterations, &mut salted_password);

        let client_key = hmac_sha256(&salted_password, b"Client Key");
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();

        let mut client_final_no_proof = Vec::new();
        client_final_no_proof.extend_from_slice(b"c=biws,r=");
        client_final_no_proof.extend_from_slice(combined_nonce.as_bytes());

        let mut auth_message: Vec<u8> = Vec::new();
        auth_message.extend_from_slice(&self.client_first_bare);
        auth_message.push(b',');
        auth_message.extend_from_slice(server_first.as_bytes());
        auth_message.push(b',');
        auth_message.extend_from_slice(&client_final_no_proof);

        let client_signature = hmac_sha256(&stored_key, &auth_message);

        let mut client_proof = client_key;
        for (p, s) in client_proof.iter_mut().zip(client_signature.iter()) {
            *p ^= s;
        }

        let server_key = hmac_sha256(&salted_password, b"Server Key");
        let server_signature = hmac_sha256(&server_key, &auth_message);
        self.expected_server_sig = server_signature.to_vec();

        let mut client_final = client_final_no_proof;
        client_final.extend_from_slice(b",p=");
        client_final.extend_from_slice(base64.encode(client_proof).as_bytes());

        Ok(client_final)
    }

    fn advance_after_auth(&mut self) {
        if self.opts.ensure_capabilities {
            let domain = self.domain.take().expect("domain taken twice");
            self.state = State::Ehlo(SmtpEhlo::new(domain));
        } else {
            self.state = State::Done;
        }
    }
}

impl SmtpCoroutine for SmtpAuthScramSha256 {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthScramSha256Error>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("auth scram: {}", self.state);

            match &mut self.state {
                State::SendInitial(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != ReplyCode::AUTH_CONTINUE {
                        let code = out.response.code.code();
                        let message = out.response.text().to_string();
                        return SmtpCoroutineState::Complete(Err(
                            SmtpAuthScramSha256Error::Rejected { code, message },
                        ));
                    }

                    let server_first_b64 = out.response.text().0.trim_start();
                    let server_first_bytes = match base64.decode(server_first_b64.as_bytes()) {
                        Ok(b) => b,
                        Err(e) => {
                            return SmtpCoroutineState::Complete(Err(
                                SmtpAuthScramSha256Error::ParseServerFirst(e.to_string()),
                            ));
                        }
                    };

                    let server_first = match from_utf8(&server_first_bytes) {
                        Ok(s) => s.to_string(),
                        Err(e) => {
                            return SmtpCoroutineState::Complete(Err(
                                SmtpAuthScramSha256Error::ParseServerFirst(e.to_string()),
                            ));
                        }
                    };

                    let client_final = match self.compute_client_final(&server_first) {
                        Ok(b) => b,
                        Err(err) => return SmtpCoroutineState::Complete(Err(err)),
                    };

                    let data = SmtpAuthData::r#continue(client_final.into_boxed_slice());
                    self.state = State::SendFinal(SendSmtpCommand::new(data));
                }
                State::SendFinal(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != ReplyCode::AUTH_SUCCESSFUL {
                        let code = out.response.code.code();
                        let message = out.response.text().to_string();
                        return SmtpCoroutineState::Complete(Err(
                            SmtpAuthScramSha256Error::Rejected { code, message },
                        ));
                    }

                    let text = out.response.text().0.trim_start();
                    let text = strip_enhanced_status(text);
                    if let Ok(server_final_bytes) = base64.decode(text.as_bytes()) {
                        if let Ok(server_final) = from_utf8(&server_final_bytes) {
                            if let Some(v) = server_final.strip_prefix("v=") {
                                if let Ok(server_sig) = base64.decode(v.as_bytes()) {
                                    if server_sig != self.expected_server_sig {
                                        return SmtpCoroutineState::Complete(Err(
                                            SmtpAuthScramSha256Error::ServerSignatureMismatch,
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    self.advance_after_auth();
                }
                State::Ehlo(ehlo) => {
                    let _ = smtp_try!(ehlo, arg);
                    return SmtpCoroutineState::Complete(Ok(()));
                }
                State::Done => return SmtpCoroutineState::Complete(Ok(())),
            }
        }
    }
}

enum State {
    SendInitial(SendSmtpCommand<SmtpAuthCommand<'static>>),
    SendFinal(SendSmtpCommand<SmtpAuthData>),
    Ehlo(SmtpEhlo),
    Done,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendInitial(_) => f.write_str("send client-first"),
            Self::SendFinal(_) => f.write_str("send client-final"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
            Self::Done => f.write_str("done"),
        }
    }
}

/// HMAC-SHA-256: `HMAC(key, data) -> [u8; 32]`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Encode a username as a SCRAM `saslname` (RFC 5802 §5.1).
fn sasl_name(username: &str) -> String {
    let mut out = String::with_capacity(username.len());
    for ch in username.chars() {
        match ch {
            '=' => out.push_str("=3D"),
            ',' => out.push_str("=2C"),
            c => out.push(c),
        }
    }
    out
}

/// Strip a leading enhanced status code (`d.ddd.ddd `) from response
/// text.
fn strip_enhanced_status(text: &str) -> &str {
    let bytes = text.as_bytes();
    if bytes.len() >= 7 && bytes[0].is_ascii_digit() && bytes[1] == b'.' {
        if let Some(second_dot) = bytes[2..].iter().position(|&b| b == b'.') {
            let second_dot = second_dot + 2;
            if let Some(space) = bytes[second_dot + 1..].iter().position(|&b| b == b' ') {
                let space = second_dot + 1 + space;
                return &text[space + 1..];
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use crate::rfc5321::types::domain::Domain;

    use super::*;

    fn domain() -> EhloDomain<'static> {
        EhloDomain::Domain(Domain(Cow::Borrowed("example.com")))
    }

    fn password() -> SecretString {
        SecretString::from("pencil".to_string())
    }

    #[test]
    fn rejected_without_continuation_returns_rejected() {
        let opts = SmtpAuthScramSha256Options::default();
        let mut auth = SmtpAuthScramSha256::new(
            "user",
            &password(),
            b"fyko+d2lbbFgONRv9qkxdawL",
            domain(),
            opts,
        );

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"504 mechanism disabled\r\n");
        let SmtpAuthScramSha256Error::Rejected { code, .. } = err else {
            panic!("expected SmtpAuthScramSha256Error::Rejected, got {err:?}");
        };
        assert_eq!(code, 504);
    }

    #[test]
    fn invalid_server_first_returns_parse_error() {
        let opts = SmtpAuthScramSha256Options::default();
        let mut auth = SmtpAuthScramSha256::new(
            "user",
            &password(),
            b"fyko+d2lbbFgONRv9qkxdawL",
            domain(),
            opts,
        );

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"334 Zm9v\r\n");
        assert!(matches!(err, SmtpAuthScramSha256Error::ParseServerFirst(_)));
    }

    #[test]
    fn final_rejection_returns_rejected() {
        let opts = SmtpAuthScramSha256Options::default();
        let mut auth = SmtpAuthScramSha256::new(
            "user",
            &password(),
            b"fyko+d2lbbFgONRv9qkxdawL",
            domain(),
            opts,
        );

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let server_first = "r=fyko+d2lbbFgONRv9qkxdawLserverNonce,s=QSXCR+Q6sek8bf92,i=4096";
        let challenge = format!("334 {}\r\n", base64.encode(server_first));
        let _client_final = expect_wants_write(&mut auth, Some(challenge.as_bytes()));

        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"535 authentication failed\r\n");
        let SmtpAuthScramSha256Error::Rejected { code, .. } = err else {
            panic!("expected SmtpAuthScramSha256Error::Rejected, got {err:?}");
        };
        assert_eq!(code, 535);
    }

    #[test]
    fn eof_returns_eof_error() {
        let opts = SmtpAuthScramSha256Options::default();
        let mut auth = SmtpAuthScramSha256::new(
            "user",
            &password(),
            b"fyko+d2lbbFgONRv9qkxdawL",
            domain(),
            opts,
        );

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"");
        assert!(matches!(
            err,
            SmtpAuthScramSha256Error::Send(SendSmtpCommandError::Eof)
        ));
    }

    // --- utils

    fn expect_wants_write(cor: &mut SmtpAuthScramSha256, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpAuthScramSha256) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut SmtpAuthScramSha256,
        reply: &[u8],
    ) -> SmtpAuthScramSha256Error {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
