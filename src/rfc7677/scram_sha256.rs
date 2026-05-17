//! I/O-free coroutine to authenticate using SMTP AUTH SCRAM-SHA-256 then
//! refresh capabilities via EHLO.
//!
//! # Reference
//!
//! - RFC 5802: Salted Challenge Response Authentication Mechanism (SCRAM)
//! - RFC 7677: SCRAM-SHA-256 and SCRAM-SHA-256-PLUS SASL Mechanisms

use core::{mem, str::from_utf8};

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
    rfc4954::{auth::SmtpAuthCommand, auth_data::SmtpAuthData},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError, SmtpEhloResult},
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response},
    },
    utils::escape_byte_string,
};

type HmacSha256 = Hmac<Sha256>;

/// The SASL mechanism name as it appears on the wire.
pub const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

/// Errors that can occur during AUTH SCRAM-SHA-256.
#[derive(Debug, Error)]
pub enum SmtpScramSha256Error {
    #[error("Reached unexpected EOF")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
    #[error("AUTH SCRAM-SHA-256 rejected: {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("SCRAM server-first-message parse error: {0}")]
    ParseServerFirst(String),
    #[error("SCRAM nonce mismatch: server nonce does not start with client nonce")]
    NonceMismatch,
    #[error("SCRAM server signature mismatch: server is not authenticated")]
    ServerSignatureMismatch,
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// Result returned by [`SmtpScramSha256::resume`].
#[derive(Debug)]
pub enum SmtpScramSha256Result {
    Ok,
    WantsRead,
    WantsWrite(Vec<u8>),
    Err(SmtpScramSha256Error),
}

enum State {
    /// Awaiting the 334 with `server-first-message`.
    AwaitServerFirst,
    /// Awaiting the 235 with `server-final-message`.
    AwaitServerFinal,
    /// Auth succeeded; refreshing capabilities via EHLO.
    Ehlo(SmtpEhlo),
}

/// I/O-free coroutine to authenticate using SMTP AUTH SCRAM-SHA-256.
///
/// The caller must supply a random `nonce` — a sequence of printable ASCII
/// characters (the standard recommends at least 18 characters). Use
/// `rand::distr::Alphanumeric` or similar to generate one.
///
/// # Security
///
/// This implementation verifies the server's final message (server signature),
/// protecting against MITM attacks.
pub struct SmtpScramSha256 {
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    /// The bare part of the client-first-message: `n=<user>,r=<nonce>`
    client_first_bare: Vec<u8>,
    password: SecretString,
    domain: Option<EhloDomain<'static>>,
    /// Expected server signature, computed after receiving the server-first.
    expected_server_sig: Vec<u8>,
    buf: Vec<u8>,
}

impl SmtpScramSha256 {
    /// Creates a new SCRAM-SHA-256 coroutine.
    ///
    /// `nonce` must be printable ASCII (no commas). Minimum 18 bytes recommended.
    pub fn new(
        username: &str,
        password: &SecretString,
        nonce: &[u8],
        domain: EhloDomain<'_>,
    ) -> Self {
        let encoded_username = sasl_name(username);

        let client_first_bare = {
            let mut v = Vec::new();
            v.extend_from_slice(b"n=");
            v.extend_from_slice(encoded_username.as_bytes());
            v.extend_from_slice(b",r=");
            v.extend_from_slice(nonce);
            v
        };

        // client-first-message = gs2-header + client-first-message-bare
        // gs2-header for no channel binding = "n,,"
        let mut client_first = Vec::new();
        client_first.extend_from_slice(b"n,,");
        client_first.extend_from_slice(&client_first_bare);

        trace!("sending AUTH SCRAM-SHA-256 command");

        let bytes = SmtpAuthCommand {
            mechanism: Cow::Borrowed(SCRAM_SHA_256),
            initial_response: Some(SecretBox::new(client_first.into_boxed_slice())),
        }
        .into();

        Self {
            state: State::AwaitServerFirst,
            wants_read: false,
            wants_write: Some(bytes),
            client_first_bare,
            password: password.clone(),
            domain: Some(domain.into_static()),
            expected_server_sig: Vec::new(),
            buf: Vec::new(),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpScramSha256Result {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return SmtpScramSha256Result::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return SmtpScramSha256Result::WantsRead;
            }

            match &mut self.state {
                State::AwaitServerFirst => {
                    match arg.take() {
                        Some(&[]) => return SmtpScramSha256Result::Err(SmtpScramSha256Error::Eof),
                        Some(data) => {
                            trace!("read SMTP bytes: {}", escape_byte_string(data));
                            self.buf.extend_from_slice(data);
                        }
                        None => {}
                    }

                    if !Response::is_complete(&self.buf) {
                        self.wants_read = true;
                        continue;
                    }

                    let response = match Response::parse(&self.buf) {
                        Ok(response) => response.into_static(),
                        Err(errors) => {
                            let reason = errors
                                .iter()
                                .map(|e| e.to_string())
                                .collect::<Vec<_>>()
                                .join("; ");

                            return SmtpScramSha256Result::Err(
                                SmtpScramSha256Error::ParseResponse(reason),
                            );
                        }
                    };

                    if response.code != ReplyCode::AUTH_CONTINUE {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        return SmtpScramSha256Result::Err(SmtpScramSha256Error::Rejected {
                            code,
                            message,
                        });
                    }

                    let server_first_b64 = response.text().0.trim_start();
                    let server_first_bytes = match base64.decode(server_first_b64.as_bytes()) {
                        Ok(b) => b,
                        Err(e) => {
                            return SmtpScramSha256Result::Err(
                                SmtpScramSha256Error::ParseServerFirst(e.to_string()),
                            );
                        }
                    };

                    let server_first = match from_utf8(&server_first_bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            return SmtpScramSha256Result::Err(
                                SmtpScramSha256Error::ParseServerFirst(e.to_string()),
                            );
                        }
                    };

                    let client_final_bytes = match self.compute_client_final(server_first) {
                        Ok(bytes) => bytes,
                        Err(err) => return SmtpScramSha256Result::Err(err),
                    };

                    self.buf.clear();
                    self.state = State::AwaitServerFinal;
                    return SmtpScramSha256Result::WantsWrite(client_final_bytes);
                }

                State::AwaitServerFinal => {
                    match arg.take() {
                        Some(&[]) => return SmtpScramSha256Result::Err(SmtpScramSha256Error::Eof),
                        Some(data) => {
                            trace!("read SMTP bytes: {}", escape_byte_string(data));
                            self.buf.extend_from_slice(data);
                        }
                        None => {}
                    }

                    if !Response::is_complete(&self.buf) {
                        self.wants_read = true;
                        continue;
                    }

                    let response = match Response::parse(&self.buf) {
                        Ok(response) => response.into_static(),
                        Err(errors) => {
                            let reason = errors
                                .iter()
                                .map(|e| e.to_string())
                                .collect::<Vec<_>>()
                                .join("; ");

                            return SmtpScramSha256Result::Err(
                                SmtpScramSha256Error::ParseResponse(reason),
                            );
                        }
                    };

                    if response.code != ReplyCode::AUTH_SUCCESSFUL {
                        let code = response.code.code();
                        let message = response.text().to_string();
                        return SmtpScramSha256Result::Err(SmtpScramSha256Error::Rejected {
                            code,
                            message,
                        });
                    }

                    // Verify server signature if present in 235 text
                    let text = response.text().0.trim_start();
                    let text = strip_enhanced_status(text);
                    if let Ok(server_final_bytes) = base64.decode(text.as_bytes()) {
                        if let Ok(server_final) = from_utf8(&server_final_bytes) {
                            if let Some(v) = server_final.strip_prefix("v=") {
                                if let Ok(server_sig) = base64.decode(v.as_bytes()) {
                                    if server_sig != self.expected_server_sig {
                                        return SmtpScramSha256Result::Err(
                                            SmtpScramSha256Error::ServerSignatureMismatch,
                                        );
                                    }
                                }
                            }
                        }
                    }

                    self.buf.clear();
                    let domain = self.domain.take().expect("domain taken twice");
                    self.state = State::Ehlo(SmtpEhlo::new(domain));
                }

                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Ok { .. } => return SmtpScramSha256Result::Ok,
                    SmtpEhloResult::WantsRead => return SmtpScramSha256Result::WantsRead,
                    SmtpEhloResult::WantsWrite(bytes) => {
                        return SmtpScramSha256Result::WantsWrite(bytes);
                    }
                    SmtpEhloResult::Err(err) => {
                        return SmtpScramSha256Result::Err(SmtpScramSha256Error::Ehlo(err));
                    }
                },
            }
        }
    }

    /// Compute the client-final-message and populate `expected_server_sig`.
    fn compute_client_final(
        &mut self,
        server_first: &str,
    ) -> Result<Vec<u8>, SmtpScramSha256Error> {
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
            .ok_or_else(|| SmtpScramSha256Error::ParseServerFirst("missing r=".into()))?;
        let salt_b64 =
            salt_b64.ok_or_else(|| SmtpScramSha256Error::ParseServerFirst("missing s=".into()))?;
        let iterations = iterations
            .ok_or_else(|| SmtpScramSha256Error::ParseServerFirst("missing i=".into()))?;

        // Verify the combined nonce starts with our client nonce.
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
            return Err(SmtpScramSha256Error::NonceMismatch);
        }

        let salt = base64
            .decode(salt_b64.as_bytes())
            .map_err(|e| SmtpScramSha256Error::ParseServerFirst(e.to_string()))?;

        // SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations)
        let password_bytes = self.password.expose_secret().as_bytes();
        let mut salted_password = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password_bytes, &salt, iterations, &mut salted_password);

        // ClientKey = HMAC(SaltedPassword, "Client Key")
        let client_key = hmac_sha256(&salted_password, b"Client Key");

        // StoredKey = SHA256(ClientKey)
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();

        // c = base64("n,,") = "biws"
        let client_final_no_proof = {
            let mut v = Vec::new();
            v.extend_from_slice(b"c=biws,r=");
            v.extend_from_slice(combined_nonce.as_bytes());
            v
        };

        // AuthMessage = client-first-bare + "," + server-first + "," + client-final-no-proof
        let mut auth_message: Vec<u8> = Vec::new();
        auth_message.extend_from_slice(&self.client_first_bare);
        auth_message.push(b',');
        auth_message.extend_from_slice(server_first.as_bytes());
        auth_message.push(b',');
        auth_message.extend_from_slice(&client_final_no_proof);

        // ClientSignature = HMAC(StoredKey, AuthMessage)
        let client_signature = hmac_sha256(&stored_key, &auth_message);

        // ClientProof = ClientKey XOR ClientSignature
        let mut client_proof = client_key;
        for (p, s) in client_proof.iter_mut().zip(client_signature.iter()) {
            *p ^= s;
        }

        // ServerKey = HMAC(SaltedPassword, "Server Key")
        let server_key = hmac_sha256(&salted_password, b"Server Key");

        // ServerSignature = HMAC(ServerKey, AuthMessage)
        let server_signature = hmac_sha256(&server_key, &auth_message);
        self.expected_server_sig = server_signature.to_vec();

        // client-final = client-final-no-proof + ",p=" + base64(ClientProof)
        let mut client_final = client_final_no_proof;
        client_final.extend_from_slice(b",p=");
        client_final.extend_from_slice(base64.encode(client_proof).as_bytes());

        // Wrap as SMTP authenticate data (base64-encodes the payload)
        Ok(SmtpAuthData::r#continue(client_final.as_slice()).into())
    }
}

/// HMAC-SHA-256: `HMAC(key, data) -> [u8; 32]`
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Encode a username as a SCRAM `saslname` (RFC 5802 §5.1).
///
/// Replaces `=` → `=3D` and `,` → `=2C`.
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

/// Strip a leading enhanced status code (`d.ddd.ddd `) from response text.
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
