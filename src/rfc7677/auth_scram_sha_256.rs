//! SMTP SASL SCRAM-SHA-256 coroutine. Always sends the
//! client-first-message SASL-IR (RFC 4954 §4); verifies the
//! server's final signature before returning `Ok`.
//!
//! The mechanism itself lives in io-sasl: this coroutine holds the SMTP
//! half of the exchange, the `AUTH SCRAM-SHA-256` command, the
//! challenges, the final reply and the capability refresh, and asks
//! [`SaslScramSha256`] what to put in each response. RFC 5802 belongs
//! to the mechanism entirely: the salted password, the client proof,
//! the parsing of the server messages and the verification of the
//! server signature.
//!
//! A server ending the exchange without proving itself is refused
//! rather than believed, whether it skips the server-final-message or
//! sends one that does not verify.
//!
//! SCRAM:         <https://www.rfc-editor.org/rfc/rfc5802>
//! SCRAM-SHA-256: <https://www.rfc-editor.org/rfc/rfc7677>
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use secrecy::SecretString;
//!
//! use io_sasl::{rfc5801::SaslGs2ChannelBinding, rfc5802::SaslScramCreds};
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
//!     rfc5321::SmtpEhloDomain,
//!     rfc7677::auth_scram_sha_256::{SmtpAuthScramSha256, SmtpAuthScramSha256Options},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! // NOTE: a real client draws its nonce from a cryptographic source.
//! let creds = SaslScramCreds {
//!     username: "alice".into(),
//!     password: SecretString::from("secret".to_string()),
//!     nonce: b"fyko+d2lbbFgONRv9qkxdawL".to_vec(),
//!     channel_binding: SaslGs2ChannelBinding::Unsupported,
//! };
//!
//! let domain = SmtpEhloDomain::try_from("client.example.org").unwrap();
//! let opts = SmtpAuthScramSha256Options::default();
//! let mut coroutine = SmtpAuthScramSha256::new(creds, domain, opts);
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

use core::fmt;

use alloc::{borrow::Cow, string::String, vec::Vec};

use base64_codec::codec::Base64Codec;
use bounded_static::IntoBoundedStatic;
use io_sasl::{
    coroutine::*,
    rfc5802::{SaslScramCreds, SaslScramError},
    rfc7677::scram_sha_256::SaslScramSha256,
};
use log::debug;
use secrecy::SecretBox;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc4954::{
        auth::{SmtpAuthCommand, SmtpAuthMechanism},
        auth_data::{SmtpAuthChallengeError, SmtpAuthData, parse_challenge},
    },
    rfc5321::{
        SmtpEhloDomain, SmtpReplyCode,
        ehlo::{SmtpEhlo, SmtpEhloError},
    },
    send::*,
    smtp_try,
};

/// The SASL mechanism name as it appears on the wire.
pub const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

/// Options for [`SmtpAuthScramSha256::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpAuthScramSha256Options {
    /// Ignored (SCRAM always sends client-first SASL-IR); kept for
    /// option surface parity with the other SASL coroutines.
    pub initial_request: bool,
    /// Whether to refresh capabilities with an `EHLO` after a successful auth.
    /// Disabled by default because the mechanism does not add a security layer.
    pub ensure_capabilities: bool,
}

impl Default for SmtpAuthScramSha256Options {
    fn default() -> Self {
        Self {
            initial_request: true,
            ensure_capabilities: false,
        }
    }
}

/// Failure causes during the SMTP AUTH SCRAM-SHA-256 exchange.
#[derive(Debug, Error)]
pub enum SmtpAuthScramSha256Error {
    /// The server rejected the authentication.
    #[error("SMTP AUTH SCRAM-SHA-256 failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The challenge carried a payload that is not valid base64.
    #[error("SMTP AUTH SCRAM-SHA-256 failed: {0}")]
    Challenge(#[from] SmtpAuthChallengeError),
    /// The mechanism refused the exchange.
    ///
    /// Everything RFC 5802 defines lands here: a server message that
    /// does not parse, a nonce that does not extend the client one, a
    /// signature that does not verify, and an exchange the server ended
    /// before proving itself.
    #[error("SMTP AUTH SCRAM-SHA-256 failed: {0}")]
    Mechanism(#[from] SaslScramError),
    /// The underlying command exchange failed.
    #[error("SMTP AUTH SCRAM-SHA-256 failed: {0}")]
    Send(#[from] SmtpCommandSendError),
    /// The post-authentication capability refresh failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH SCRAM-SHA-256 coroutine.
pub struct SmtpAuthScramSha256 {
    state: State,
    mechanism: SaslScramSha256,
    domain: Option<SmtpEhloDomain<'static>>,
    opts: SmtpAuthScramSha256Options,
}

impl SmtpAuthScramSha256 {
    /// Creates the coroutine from the credentials and the client
    /// identity used by the capability refresh.
    ///
    /// The credentials carry the client nonce, which must be printable
    /// ASCII without commas and which RFC 5802 wants drawn from at
    /// least 18 bytes of cryptographic randomness. It is an input
    /// rather than something drawn here, an I/O-free coroutine having
    /// no source of randomness, and it makes the exchange
    /// deterministically testable.
    ///
    /// They also carry the channel binding, which decides whether the
    /// exchange announces `SCRAM-SHA-256` or `SCRAM-SHA-256-PLUS`. This
    /// crate never asks a TLS session what it exported, so a caller
    /// wanting a bound exchange extracts the material itself.
    pub fn new(
        creds: SaslScramCreds,
        domain: SmtpEhloDomain<'_>,
        opts: SmtpAuthScramSha256Options,
    ) -> Self {
        Self {
            state: State::Start,
            mechanism: SaslScramSha256::new(creds),
            domain: Some(domain.into_static()),
            opts,
        }
    }

    // helper that resumes the SASL coroutine
    fn resume_sasl(
        &mut self,
        arg: SaslArg<'_>,
    ) -> Result<Option<Vec<u8>>, SmtpAuthScramSha256Error> {
        match self.mechanism.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) => Ok(Some(payload)),
            SaslCoroutineState::Yielded(SaslYield::WantsRead) => Ok(None),
            SaslCoroutineState::Complete(result) => result.map(|()| None).map_err(Into::into),
        }
    }

    // helper that moves to the capability refresh, or completes
    fn advance_after_auth(&mut self) -> Option<State> {
        debug!("authenticated");

        let domain = self.domain.take()?;
        self.opts
            .ensure_capabilities
            .then(|| State::Ehlo(SmtpEhlo::new(domain)))
    }
}

impl SmtpCoroutine for SmtpAuthScramSha256 {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthScramSha256Error>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Start => {
                    let payload = match self.resume_sasl(SaslArg::None) {
                        Ok(payload) => payload.unwrap_or_default(),
                        Err(err) => return SmtpCoroutineState::Complete(Err(err)),
                    };

                    let cmd = SmtpAuthCommand {
                        mechanism: SmtpAuthMechanism(Cow::Borrowed(SCRAM_SHA_256)),
                        initial_response: Some(SecretBox::new(payload.into_boxed_slice())),
                    };

                    self.state = State::Send(SmtpCommandSend::new(cmd));
                    debug!("{}", self.state);
                }
                State::Send(send) => {
                    let out = smtp_try!(send, arg.take());

                    if out.response.code != SmtpReplyCode::AUTH_CONTINUE {
                        // NOTE: a server accepting here never sent its
                        // server-first-message, so the mechanism is told the
                        // exchange is over and refuses what it never verified.
                        if out.response.code == SmtpReplyCode::AUTH_SUCCESSFUL
                            && let Err(err) = self.resume_sasl(SaslArg::Done)
                        {
                            return SmtpCoroutineState::Complete(Err(err));
                        }

                        let code = out.response.code.code();
                        let message = out.response.message();
                        let err = SmtpAuthScramSha256Error::Rejected { code, message };
                        return SmtpCoroutineState::Complete(Err(err));
                    }

                    let challenge = match parse_challenge(&out.response.text().0) {
                        Ok(challenge) => challenge,
                        Err(err) => {
                            self.state = State::cancel(err.into());
                            debug!("{}", self.state);
                            continue;
                        }
                    };

                    let payload = match self.resume_sasl(SaslArg::Input(&challenge)) {
                        Ok(payload) => payload.unwrap_or_default(),
                        Err(err) => {
                            self.state = State::cancel(err);
                            debug!("{}", self.state);
                            continue;
                        }
                    };

                    let data = SmtpAuthData::r#continue(payload.into_boxed_slice());
                    self.state = State::Continue(SmtpCommandSend::new(data));
                    debug!("{}", self.state);
                }
                State::Continue(send) => {
                    let out = smtp_try!(send, arg.take());

                    if out.response.code == SmtpReplyCode::AUTH_CONTINUE {
                        let challenge = match parse_challenge(&out.response.text().0) {
                            Ok(challenge) => challenge,
                            Err(err) => {
                                self.state = State::cancel(err.into());
                                debug!("{}", self.state);
                                continue;
                            }
                        };

                        let payload = match self.resume_sasl(SaslArg::Input(&challenge)) {
                            Ok(payload) => payload.unwrap_or_default(),
                            Err(err) => {
                                self.state = State::cancel(err);
                                debug!("{}", self.state);
                                continue;
                            }
                        };

                        let data = SmtpAuthData::r#continue(payload.into_boxed_slice());
                        self.state = State::Continue(SmtpCommandSend::new(data));
                        debug!("{}", self.state);
                        continue;
                    }

                    if out.response.code == SmtpReplyCode::AUTH_SUCCESSFUL {
                        // NOTE: RFC 4954 section 4 lets a server put the
                        // server-final-message in the success reply instead of
                        // a last challenge, behind its enhanced status code.
                        // What decodes there is handed to the mechanism, and an
                        // empty reply leaves it with nothing to verify, which
                        // it refuses. This crate used to report that as a
                        // success.
                        let text = strip_enhanced_status(&out.response.text().0).trim();
                        let mut server_final = Vec::new();

                        // NOTE: the decoder skips blanks, so a text such as
                        // `Authentication successful` decodes too: only one
                        // token decoding to a server-final-message is one.
                        if !text.contains(char::is_whitespace)
                            && Base64Codec::default().decode_vec(text.as_bytes(), &mut server_final)
                            && (server_final.starts_with(b"v=") || server_final.starts_with(b"e="))
                            && let Err(err) = self.resume_sasl(SaslArg::Input(&server_final))
                        {
                            return SmtpCoroutineState::Complete(Err(err));
                        }

                        if let Err(err) = self.resume_sasl(SaslArg::Done) {
                            return SmtpCoroutineState::Complete(Err(err));
                        }

                        match self.advance_after_auth() {
                            Some(next) => {
                                self.state = next;
                                debug!("{}", self.state);
                                continue;
                            }
                            None => return SmtpCoroutineState::Complete(Ok(())),
                        }
                    }

                    let code = out.response.code.code();
                    let message = out.response.message();
                    let err = SmtpAuthScramSha256Error::Rejected { code, message };
                    return SmtpCoroutineState::Complete(Err(err));
                }
                State::Ehlo(ehlo) => {
                    let _ = smtp_try!(ehlo, arg.take());
                    debug!("capabilities refreshed");
                    return SmtpCoroutineState::Complete(Ok(()));
                }
                State::Cancel { send, error } => {
                    // NOTE: whatever the server answers, error is the outcome
                    if let SmtpCoroutineState::Yielded(y) = send.resume(arg.take()) {
                        return SmtpCoroutineState::Yielded(y);
                    }

                    let error = error.take().expect("error taken twice");
                    return SmtpCoroutineState::Complete(Err(error));
                }
            }
        }
    }
}

enum State {
    Start,
    Send(SmtpCommandSend<SmtpAuthCommand<'static>>),
    Continue(SmtpCommandSend<SmtpAuthData>),
    Ehlo(SmtpEhlo),
    Cancel {
        send: SmtpCommandSend<SmtpAuthData>,
        error: Option<SmtpAuthScramSha256Error>,
    },
}

impl State {
    /// The state cancelling the exchange (RFC 4954 §4) before it fails
    /// with `error`.
    fn cancel(error: SmtpAuthScramSha256Error) -> Self {
        Self::Cancel {
            send: SmtpCommandSend::new(SmtpAuthData::Cancel),
            error: Some(error),
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => f.write_str("start mechanism"),
            Self::Send(_) => f.write_str("send client-first"),
            Self::Continue(_) => f.write_str("send client-final"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
            Self::Cancel { .. } => f.write_str("cancel exchange"),
        }
    }
}

/// Strips the enhanced status code (RFC 3463) a reply may carry before
/// its text, so that what follows can be read as a SASL message.
fn strip_enhanced_status(text: &str) -> &str {
    let bytes = text.as_bytes();

    if bytes.len() >= 7
        && bytes[0].is_ascii_digit()
        && bytes[1] == b'.'
        && let Some(second_dot) = bytes[2..].iter().position(|&b| b == b'.')
    {
        let second_dot = second_dot + 2;
        if let Some(space) = bytes[second_dot + 1..].iter().position(|&b| b == b' ') {
            let space = second_dot + 1 + space;
            return &text[space + 1..];
        }
    }

    text
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::ToString, vec::Vec};

    use base64_codec::codec::Base64Codec;
    use hmac::{Hmac, KeyInit, Mac};
    use io_sasl::rfc5801::SaslGs2ChannelBinding;
    use secrecy::SecretString;
    use sha2::Sha256;

    use crate::{
        rfc5321::SmtpEhloDomain, rfc7677::auth_scram_sha_256::*, send::SmtpCommandSendError,
    };

    type HmacSha256 = Hmac<Sha256>;

    const NONCE: &[u8] = b"fyko+d2lbbFgONRv9qkxdawL";
    const SALT_B64: &str = "QSXCR+Q6sek8bf92";
    const ITERATIONS: u32 = 4096;

    fn domain() -> SmtpEhloDomain<'static> {
        SmtpEhloDomain::try_from("example.com").unwrap()
    }

    fn password() -> SecretString {
        SecretString::from("pencil".to_string())
    }

    fn auth(opts: SmtpAuthScramSha256Options) -> SmtpAuthScramSha256 {
        let creds = SaslScramCreds {
            username: "user".to_string(),
            password: password(),
            nonce: NONCE.to_vec(),
            channel_binding: SaslGs2ChannelBinding::Unsupported,
        };

        SmtpAuthScramSha256::new(creds, domain(), opts)
    }

    #[test]
    fn capabilities_are_not_refreshed_by_default() {
        assert!(!SmtpAuthScramSha256Options::default().ensure_capabilities);
    }

    #[test]
    fn success_with_server_final_in_a_challenge_returns_ok() {
        let replies: [&[u8]; 3] = [
            b"235 2.7.0 Authentication successful\r\n",
            b"235 2.7.0 Accepted\r\n",
            b"235 Ok\r\n",
        ];

        for reply in replies {
            let mut auth = auth(SmtpAuthScramSha256Options::default());

            let bytes = expect_wants_write(&mut auth, None);
            let client_first = decode_last_base64_token(&bytes);

            expect_wants_read(&mut auth);

            let server_first = server_first(&client_first);
            let challenge = format!("334 {}\r\n", encode(&server_first));
            let bytes = expect_wants_write(&mut auth, Some(challenge.as_bytes()));
            let client_final = decode_last_base64_token(&bytes);

            expect_wants_read(&mut auth);

            // NOTE: the server proves itself in a last challenge, which the
            // client answers with an empty response before the success
            // reply, whose text decodes as base64 or not.
            let server_final = server_final(&client_first, &server_first, &client_final);
            let challenge = format!("334 {}\r\n", encode(&server_final));
            let ack = expect_wants_write(&mut auth, Some(challenge.as_bytes()));
            assert_eq!(ack, b"\r\n");

            expect_wants_read(&mut auth);
            expect_complete_ok(&mut auth, reply);
        }
    }

    #[test]
    fn success_with_server_final_in_the_success_reply_returns_ok() {
        let mut auth = auth(SmtpAuthScramSha256Options::default());

        let bytes = expect_wants_write(&mut auth, None);
        let client_first = decode_last_base64_token(&bytes);

        expect_wants_read(&mut auth);

        let server_first = server_first(&client_first);
        let challenge = format!("334 {}\r\n", encode(&server_first));
        let bytes = expect_wants_write(&mut auth, Some(challenge.as_bytes()));
        let client_final = decode_last_base64_token(&bytes);

        expect_wants_read(&mut auth);

        // NOTE: RFC 4954 section 4 also lets the server prove itself in the
        // success reply, behind its enhanced status code.
        let server_final = server_final(&client_first, &server_first, &client_final);
        let reply = format!("235 2.7.0 {}\r\n", encode(&server_final));
        expect_complete_ok(&mut auth, reply.as_bytes());
    }

    #[test]
    fn success_without_server_final_returns_mechanism_error() {
        let mut auth = auth(SmtpAuthScramSha256Options::default());

        let bytes = expect_wants_write(&mut auth, None);
        let client_first = decode_last_base64_token(&bytes);

        expect_wants_read(&mut auth);

        let challenge = format!("334 {}\r\n", encode(server_first(&client_first)));
        let _client_final = expect_wants_write(&mut auth, Some(challenge.as_bytes()));

        expect_wants_read(&mut auth);

        // NOTE: a success reply arriving in place of the
        // server-final-message ends the exchange with the server signature
        // unchecked, which the mechanism refuses. This crate used to report
        // it as a success.
        let err = expect_complete_err(&mut auth, b"235 2.7.0 Authentication successful\r\n");
        let SmtpAuthScramSha256Error::Mechanism(SaslScramError::ServerSignatureNotVerified) = err
        else {
            panic!("expected SmtpAuthScramSha256Error::Mechanism, got {err:?}");
        };
    }

    #[test]
    fn forged_server_signature_returns_mechanism_error() {
        let mut auth = auth(SmtpAuthScramSha256Options::default());

        let bytes = expect_wants_write(&mut auth, None);
        let client_first = decode_last_base64_token(&bytes);

        expect_wants_read(&mut auth);

        let challenge = format!("334 {}\r\n", encode(server_first(&client_first)));
        let _client_final = expect_wants_write(&mut auth, Some(challenge.as_bytes()));

        expect_wants_read(&mut auth);

        let forged = format!("v={}", encode("not the signature"));
        let reply = format!("235 2.7.0 {}\r\n", encode(&forged));
        let err = expect_complete_err(&mut auth, reply.as_bytes());
        let SmtpAuthScramSha256Error::Mechanism(SaslScramError::ServerSignatureMismatch) = err
        else {
            panic!("expected SmtpAuthScramSha256Error::Mechanism, got {err:?}");
        };
    }

    #[test]
    fn rejected_without_continuation_returns_rejected() {
        let mut auth = auth(SmtpAuthScramSha256Options::default());

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"504 mechanism disabled\r\n");
        let SmtpAuthScramSha256Error::Rejected { code, .. } = err else {
            panic!("expected SmtpAuthScramSha256Error::Rejected, got {err:?}");
        };
        assert_eq!(code, 504);
    }

    #[test]
    fn invalid_server_first_is_cancelled_with_the_mechanism_error() {
        // NOTE: the last reply is the connection dying under the cancellation
        for reply in [b"501 5.7.0 cancelled\r\n".as_slice(), b""] {
            let mut auth = auth(SmtpAuthScramSha256Options::default());

            let _ = expect_wants_write(&mut auth, None);
            expect_wants_read(&mut auth);

            let cancel = expect_wants_write(&mut auth, Some(b"334 Zm9v\r\n"));
            assert_eq!(cancel, b"*\r\n");
            expect_wants_read(&mut auth);

            let err = expect_complete_err(&mut auth, reply);
            assert!(matches!(err, SmtpAuthScramSha256Error::Mechanism(_)));
        }
    }

    #[test]
    fn forged_server_final_in_a_challenge_is_cancelled() {
        let mut auth = auth(SmtpAuthScramSha256Options::default());

        let bytes = expect_wants_write(&mut auth, None);
        let client_first = decode_last_base64_token(&bytes);

        expect_wants_read(&mut auth);

        let challenge = format!("334 {}\r\n", encode(server_first(&client_first)));
        let _client_final = expect_wants_write(&mut auth, Some(challenge.as_bytes()));

        expect_wants_read(&mut auth);

        let forged = format!("v={}", encode("not the signature"));
        let challenge = format!("334 {}\r\n", encode(&forged));
        let cancel = expect_wants_write(&mut auth, Some(challenge.as_bytes()));
        assert_eq!(cancel, b"*\r\n");
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"501 5.7.0 cancelled\r\n");
        let SmtpAuthScramSha256Error::Mechanism(SaslScramError::ServerSignatureMismatch) = err
        else {
            panic!("expected SmtpAuthScramSha256Error::Mechanism, got {err:?}");
        };
    }

    #[test]
    fn final_rejection_returns_rejected() {
        let mut auth = auth(SmtpAuthScramSha256Options::default());

        let bytes = expect_wants_write(&mut auth, None);
        let client_first = decode_last_base64_token(&bytes);

        expect_wants_read(&mut auth);

        let challenge = format!("334 {}\r\n", encode(server_first(&client_first)));
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
        let mut auth = auth(SmtpAuthScramSha256Options::default());

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"");
        assert!(matches!(
            err,
            SmtpAuthScramSha256Error::Send(SmtpCommandSendError::Eof)
        ));
    }

    #[test]
    fn enhanced_status_code_is_stripped() {
        assert_eq!(strip_enhanced_status("2.7.0 dj1wYXlsb2Fk"), "dj1wYXlsb2Fk");
        assert_eq!(strip_enhanced_status("dj1wYXlsb2Fk"), "dj1wYXlsb2Fk");
    }

    fn server_first(client_first: &str) -> String {
        let client_nonce = client_first
            .rsplit_once("r=")
            .expect("client-first has r=")
            .1;

        format!("r={client_nonce}ServerExtra,s={SALT_B64},i={ITERATIONS}")
    }

    fn server_final(client_first: &str, server_first: &str, client_final: &str) -> String {
        let client_first_bare = client_first.strip_prefix("n,,").expect("gs2 header");
        let client_final_without_proof = client_final
            .rsplit_once(",p=")
            .expect("client-final has p=")
            .0;
        let auth_message =
            format!("{client_first_bare},{server_first},{client_final_without_proof}");
        let salt = decode(SALT_B64);

        // NOTE: SaltedPassword = PBKDF2(SHA-256, password, salt, iterations).
        let mut salted_password = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"pencil", &salt, ITERATIONS, &mut salted_password);

        // NOTE: ServerKey = HMAC(SaltedPassword, "Server Key").
        let mut mac = HmacSha256::new_from_slice(&salted_password).expect("any key length");
        mac.update(b"Server Key");
        let server_key = mac.finalize().into_bytes();

        // NOTE: ServerSignature = HMAC(ServerKey, AuthMessage).
        let mut mac = HmacSha256::new_from_slice(&server_key).expect("any key length");
        mac.update(auth_message.as_bytes());
        let server_signature = mac.finalize().into_bytes();

        format!("v={}", encode(server_signature))
    }

    fn encode(bytes: impl AsRef<[u8]>) -> String {
        let mut encoded = Vec::new();
        Base64Codec::default().encode_vec(bytes.as_ref(), &mut encoded);
        String::from_utf8(encoded).expect("ascii base64")
    }

    fn decode(text: &str) -> Vec<u8> {
        let mut decoded = Vec::new();
        assert!(Base64Codec::default().decode_vec(text.as_bytes(), &mut decoded));
        decoded
    }

    fn decode_last_base64_token(line: &[u8]) -> String {
        let line = core::str::from_utf8(line).expect("utf8 line");
        let token = line
            .trim_end()
            .rsplit_terminator(char::is_whitespace)
            .next()
            .expect("token");
        let bytes = decode(token);

        String::from_utf8(bytes).expect("valid utf8")
    }

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

    fn expect_complete_ok(cor: &mut SmtpAuthScramSha256, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
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
