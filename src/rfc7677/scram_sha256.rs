//! I/O-free coroutine to authenticate using SMTP AUTH SCRAM-SHA-256 then
//! refresh capabilities via EHLO.
//!
//! # Reference
//!
//! - RFC 5802: Salted Challenge Response Authentication Mechanism (SCRAM)
//! - RFC 7677: SCRAM-SHA-256 and SCRAM-SHA-256-PLUS SASL Mechanisms

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};
use base64::{Engine, engine::general_purpose::STANDARD as base64};
use bounded_static::IntoBoundedStatic;
use hmac::{Hmac, KeyInit, Mac};
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    read::*,
    rfc4954::{auth::SmtpAuthCommand, auth_data::SmtpAuthData},
    rfc5321::{
        ehlo::*,
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, response::Response},
    },
    utils::escape_byte_string,
    write::*,
};

type HmacSha256 = Hmac<Sha256>;

/// The SASL mechanism name as it appears on the wire.
pub const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

/// Errors that can occur during AUTH SCRAM-SHA-256.
#[derive(Debug, Error)]
pub enum SmtpScramSha256Error {
    #[error(transparent)]
    Write(#[from] SmtpWriteError),
    #[error(transparent)]
    Read(#[from] SmtpReadError),
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

/// Output emitted when the coroutine terminates.
pub enum SmtpScramSha256Result {
    Ok,
    Io { input: SocketInput },
    Err { err: SmtpScramSha256Error },
}

enum State {
    WriteInitial(SmtpWrite),
    ReadServerFirst(SmtpRead),
    WriteFinal(SmtpWrite),
    ReadServerFinal(SmtpRead),
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
    /// The bare part of the client-first-message: `n=<user>,r=<nonce>`
    client_first_bare: Vec<u8>,
    password: SecretString,
    domain: Option<EhloDomain<'static>>,
    /// Expected server signature, computed after receiving the server-first.
    expected_server_sig: Vec<u8>,
    buffer: Vec<u8>,
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

        Self {
            state: State::WriteInitial(SmtpWrite::new(SmtpAuthCommand {
                mechanism: Cow::Borrowed(SCRAM_SHA_256),
                initial_response: Some(SecretBox::new(client_first.into_boxed_slice())),
            })),
            client_first_bare,
            password: password.clone(),
            domain: Some(domain.into_static()),
            expected_server_sig: Vec::new(),
            buffer: Vec::new(),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, mut arg: Option<SocketOutput>) -> SmtpScramSha256Result {
        loop {
            match &mut self.state {
                State::WriteInitial(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::ReadServerFirst(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpScramSha256Result::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        let err = err.into();
                        return SmtpScramSha256Result::Err { err };
                    }
                },

                State::ReadServerFirst(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpScramSha256Result::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpScramSha256Result::Err { err };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::ReadServerFirst(SmtpRead::new());
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpScramSha256Error::ParseResponse(reason);
                                return SmtpScramSha256Result::Err { err };
                            }
                            Ok(response) => {
                                let response = response.into_static();
                                if response.code != ReplyCode::AUTH_CONTINUE {
                                    let message = response.text().to_string();
                                    let code = response.code.code();
                                    let err = SmtpScramSha256Error::Rejected { code, message };
                                    return SmtpScramSha256Result::Err { err };
                                }

                                // The 334 response text is base64(server-first-message)
                                let server_first_b64 = response.text().0.trim_start();
                                let server_first_bytes = match base64
                                    .decode(server_first_b64.as_bytes())
                                {
                                    Ok(b) => b,
                                    Err(e) => {
                                        let err =
                                            SmtpScramSha256Error::ParseServerFirst(e.to_string());
                                        return SmtpScramSha256Result::Err { err };
                                    }
                                };

                                let server_first = match core::str::from_utf8(&server_first_bytes) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        let err =
                                            SmtpScramSha256Error::ParseServerFirst(e.to_string());
                                        return SmtpScramSha256Result::Err { err };
                                    }
                                };

                                let write_final_result = self.compute_client_final(server_first);
                                match write_final_result {
                                    Err(err) => {
                                        return SmtpScramSha256Result::Err { err };
                                    }
                                    Ok(client_final_bytes) => {
                                        self.buffer.clear();
                                        self.state =
                                            State::WriteFinal(SmtpWrite::new(client_final_bytes));
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                },

                State::WriteFinal(w) => match w.resume(arg.take()) {
                    SmtpWriteResult::Ok => {
                        self.state = State::ReadServerFinal(SmtpRead::new());
                        continue;
                    }
                    SmtpWriteResult::Io { input } => {
                        return SmtpScramSha256Result::Io { input };
                    }
                    SmtpWriteResult::Err { err } => {
                        let err = err.into();
                        return SmtpScramSha256Result::Err { err };
                    }
                },

                State::ReadServerFinal(r) => match r.resume(arg.take()) {
                    SmtpReadResult::Io { input } => {
                        return SmtpScramSha256Result::Io { input };
                    }
                    SmtpReadResult::Err { err } => {
                        let err = err.into();
                        return SmtpScramSha256Result::Err { err };
                    }
                    SmtpReadResult::Ok { bytes } => {
                        trace!("read bytes: {}", escape_byte_string(&bytes));
                        self.buffer.extend_from_slice(&bytes);

                        if !Response::is_complete(&self.buffer) {
                            self.state = State::ReadServerFinal(SmtpRead::new());
                            continue;
                        }

                        match Response::parse(&self.buffer) {
                            Err(errors) => {
                                let reason = errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; ");

                                let err = SmtpScramSha256Error::ParseResponse(reason);
                                return SmtpScramSha256Result::Err { err };
                            }
                            Ok(response) => {
                                let response = response.into_static();
                                if response.code != ReplyCode::AUTH_SUCCESSFUL {
                                    let message = response.text().to_string();
                                    let code = response.code.code();
                                    let err = SmtpScramSha256Error::Rejected { code, message };
                                    return SmtpScramSha256Result::Err { err };
                                }

                                // Verify server signature if present in 235 text
                                let text = response.text().0.trim_start();
                                // Strip optional enhanced status code (e.g. "2.7.0 ")
                                let text = strip_enhanced_status(text);
                                if let Ok(server_final_bytes) = base64.decode(text.as_bytes()) {
                                    if let Ok(server_final) =
                                        core::str::from_utf8(&server_final_bytes)
                                    {
                                        if let Some(v) = server_final.strip_prefix("v=") {
                                            if let Ok(server_sig) = base64.decode(v.as_bytes()) {
                                                if server_sig != self.expected_server_sig {
                                                    let err = SmtpScramSha256Error::ServerSignatureMismatch;
                                                    return SmtpScramSha256Result::Err { err };
                                                }
                                            }
                                        }
                                    }
                                }

                                let domain = self.domain.take().unwrap();
                                self.state = State::Ehlo(SmtpEhlo::new(domain));
                                continue;
                            }
                        }
                    }
                },

                State::Ehlo(ehlo) => match ehlo.resume(arg.take()) {
                    SmtpEhloResult::Io { input } => {
                        return SmtpScramSha256Result::Io { input };
                    }
                    SmtpEhloResult::Ok { .. } => {
                        return SmtpScramSha256Result::Ok;
                    }
                    SmtpEhloResult::Err { err } => {
                        let err = err.into();
                        return SmtpScramSha256Result::Err { err };
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
        // Parse server-first-message fields: r=, s=, i=
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

        // Verify the combined nonce starts with our client nonce
        let client_nonce_start = self
            .client_first_bare
            .iter()
            .position(|&b| b == b',')
            .and_then(|p| {
                self.client_first_bare[p + 1..]
                    .iter()
                    .position(|&b| b == b',')
                    .map(|q| p + 1 + q)
                    .or(Some(p + 1))
            })
            .unwrap_or(0);
        // Extract client nonce from "n=user,r=<nonce>"
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

        let client_nonce_str = core::str::from_utf8(client_nonce).unwrap_or("");
        if !combined_nonce.starts_with(client_nonce_str) {
            return Err(SmtpScramSha256Error::NonceMismatch);
        }
        let _ = client_nonce_start; // suppress warning

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

        // client-final-message-without-proof
        // c = base64("n,,") = "biws"
        let client_final_no_proof = {
            let mut v = Vec::new();
            v.extend_from_slice(b"c=biws,r=");
            v.extend_from_slice(combined_nonce.as_bytes());
            v
        };

        // AuthMessage = client-first-message-bare + "," + server-first + "," + client-final-without-proof
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

        // client-final = client-final-without-proof + ",p=" + base64(ClientProof)
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
    // Pattern: digit '.' digits '.' digits ' '
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
