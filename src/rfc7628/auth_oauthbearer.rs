//! SMTP SASL OAUTHBEARER coroutine; supports both the non-IR and
//! SASL-IR (RFC 4954 §4) flows.
//!
//! The mechanism itself lives in io-sasl: this coroutine holds the SMTP
//! half of the exchange, the `AUTH OAUTHBEARER` command, the
//! challenges, the final reply and the capability refresh, and asks
//! [`SaslOauthbearer`] what to put in each response. The rejection
//! dance is the mechanism's: a challenge carrying the error JSON is
//! answered with the single `%x01` of RFC 7628 section 3.2.3, and the
//! JSON comes back out when the exchange is declared over.
//!
//! OAUTHBEARER: <https://www.rfc-editor.org/rfc/rfc7628>
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
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
//!     rfc5321::SmtpEhloDomain,
//!     rfc7628::auth_oauthbearer::{SmtpAuthOauthbearer, SmtpAuthOauthbearerOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let token = SecretString::from("ya29.tokenvalue".to_string());
//! let domain = SmtpEhloDomain::try_from("client.example.org").unwrap();
//! let opts = SmtpAuthOauthbearerOptions::default();
//! let mut coroutine =
//!     SmtpAuthOauthbearer::new("alice@example.org", "smtp.example.org", 587, &token, domain, opts);
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

use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use io_sasl::{
    coroutine::*,
    rfc7628::oauthbearer::{SaslOauthbearer, SaslOauthbearerCreds, SaslOauthbearerError},
};
use log::debug;
use secrecy::{SecretBox, SecretString};
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
pub const OAUTHBEARER: &str = "OAUTHBEARER";

/// Options for [`SmtpAuthOauthbearer::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpAuthOauthbearerOptions {
    /// `true` selects SASL-IR (inline credentials); `false` selects
    /// the non-IR challenge-response flow.
    pub initial_request: bool,
    /// Whether to refresh capabilities with an `EHLO` after a successful auth.
    /// Disabled by default because the mechanism does not add a security layer.
    pub ensure_capabilities: bool,
}

impl Default for SmtpAuthOauthbearerOptions {
    fn default() -> Self {
        Self {
            initial_request: true,
            ensure_capabilities: false,
        }
    }
}

/// Failure causes during the SMTP AUTH OAUTHBEARER exchange.
#[derive(Debug, Error)]
pub enum SmtpAuthOauthbearerError {
    /// The server rejected the authentication.
    #[error("SMTP AUTH OAUTHBEARER failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The server rejected the authentication after describing why in
    /// a challenge.
    #[error("SMTP AUTH OAUTHBEARER failed: rejected {code} {message} ({err})")]
    RejectedWithError {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
        /// The error payload extracted from the challenge.
        err: String,
    },
    /// The server accepted before the expected challenge.
    #[error("SMTP AUTH OAUTHBEARER failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
    /// The challenge carried a payload that is not valid base64.
    #[error("SMTP AUTH OAUTHBEARER failed: {0}")]
    Challenge(#[from] SmtpAuthChallengeError),
    /// The mechanism refused the exchange.
    ///
    /// A rejected token whose exchange the server ended with a success
    /// reply lands here, carrying the JSON it sent, as does a challenge
    /// arriving out of order.
    #[error("SMTP AUTH OAUTHBEARER failed: {0}")]
    Mechanism(#[from] SaslOauthbearerError),
    /// The underlying command exchange failed.
    #[error("SMTP AUTH OAUTHBEARER failed: {0}")]
    Send(#[from] SmtpCommandSendError),
    /// The post-authentication capability refresh failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH OAUTHBEARER coroutine. The connection MUST be
/// TLS-protected, the bearer token travelling in the clear otherwise.
pub struct SmtpAuthOauthbearer {
    state: State,
    mechanism: SaslOauthbearer,
    domain: Option<SmtpEhloDomain<'static>>,
    opts: SmtpAuthOauthbearerOptions,
}

impl SmtpAuthOauthbearer {
    /// Creates the coroutine from the account identity, the server
    /// being contacted, the bearer token and the client identity used
    /// by the capability refresh.
    ///
    /// `host` and `port` travel verbatim in the GS2 header and should
    /// match the server the stream is connected to, RFC 7628 section
    /// 3.1 making them part of what the token is presented for.
    pub fn new(
        username: &str,
        host: &str,
        port: u16,
        token: &SecretString,
        domain: SmtpEhloDomain<'_>,
        opts: SmtpAuthOauthbearerOptions,
    ) -> Self {
        let mechanism = SaslOauthbearer::new(SaslOauthbearerCreds {
            username: username.to_string(),
            host: host.to_string(),
            port,
            token: token.clone(),
        });

        Self {
            state: State::Start,
            mechanism,
            domain: Some(domain.into_static()),
            opts,
        }
    }

    // helper that resumes the SASL coroutine
    fn resume_sasl(
        &mut self,
        arg: SaslArg<'_>,
    ) -> Result<Option<Vec<u8>>, SmtpAuthOauthbearerError> {
        match self.mechanism.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) => Ok(Some(payload)),
            SaslCoroutineState::Yielded(SaslYield::WantsRead) => Ok(None),
            SaslCoroutineState::Complete(result) => result.map(|()| None).map_err(Into::into),
        }
    }

    // helper that ends a rejected exchange, with the JSON the
    // mechanism captured when the server sent one
    fn rejected(&mut self, code: u16, message: String) -> SmtpAuthOauthbearerError {
        match self.mechanism.resume(SaslArg::Done) {
            SaslCoroutineState::Complete(Err(SaslOauthbearerError::Rejected(err))) => {
                SmtpAuthOauthbearerError::RejectedWithError { code, message, err }
            }
            _ => SmtpAuthOauthbearerError::Rejected { code, message },
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

impl SmtpCoroutine for SmtpAuthOauthbearer {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthOauthbearerError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Start => {
                    let payload = match self.resume_sasl(SaslArg::None) {
                        Ok(payload) => payload,
                        Err(err) => return SmtpCoroutineState::Complete(Err(err)),
                    };

                    let (initial_response, pending) = match payload {
                        Some(payload) if self.opts.initial_request => {
                            (Some(SecretBox::new(payload.into_boxed_slice())), None)
                        }
                        payload => (None, payload),
                    };

                    let cmd = SmtpAuthCommand {
                        mechanism: SmtpAuthMechanism(Cow::Borrowed(OAUTHBEARER)),
                        initial_response,
                    };

                    self.state = State::Send {
                        send: SmtpCommandSend::new(cmd),
                        pending,
                    };
                    debug!("{}", self.state);
                }
                State::Send { send, pending } => {
                    let out = smtp_try!(send, arg.take());

                    if out.response.code == SmtpReplyCode::AUTH_CONTINUE {
                        // NOTE: with the credentials still held back this is
                        // the empty challenge inviting them; with them already
                        // inlined it carries the rejection JSON, which only
                        // the mechanism reads and answers.
                        let payload = match pending.take() {
                            Some(payload) => payload,
                            None => {
                                let challenge = match parse_challenge(&out.response.text().0) {
                                    Ok(challenge) => challenge,
                                    Err(err) => {
                                        self.state = State::cancel(err.into());
                                        debug!("{}", self.state);
                                        continue;
                                    }
                                };

                                match self.resume_sasl(SaslArg::Input(&challenge)) {
                                    Ok(payload) => payload.unwrap_or_default(),
                                    Err(err) => {
                                        self.state = State::cancel(err);
                                        debug!("{}", self.state);
                                        continue;
                                    }
                                }
                            }
                        };

                        let data = SmtpAuthData::r#continue(payload.into_boxed_slice());
                        self.state = State::Continue(SmtpCommandSend::new(data));
                        debug!("{}", self.state);
                        continue;
                    }

                    // NOTE: with the credentials inlined there is nothing left
                    // to send, so the final reply ends the exchange here rather
                    // than after a continuation. Without them, a server
                    // accepting now never asked for what it is authenticating.
                    let inlined = pending.is_none();

                    if out.response.code == SmtpReplyCode::AUTH_SUCCESSFUL {
                        if !inlined {
                            let err = SmtpAuthOauthbearerError::ExpectedContinuationRequest;
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
                    let err = self.rejected(code, message);
                    return SmtpCoroutineState::Complete(Err(err));
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
                        // NOTE: the final reply ends the exchange, and the
                        // mechanism is told so rather than dropped: a token the
                        // server rejected mid-exchange is reported here, with
                        // the JSON that explained it, rather than read as a
                        // success.
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
                    let err = self.rejected(code, message);
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
    Send {
        send: SmtpCommandSend<SmtpAuthCommand<'static>>,
        pending: Option<Vec<u8>>,
    },
    Continue(SmtpCommandSend<SmtpAuthData>),
    Ehlo(SmtpEhlo),
    Cancel {
        send: SmtpCommandSend<SmtpAuthData>,
        error: Option<SmtpAuthOauthbearerError>,
    },
}

impl State {
    /// The state cancelling the exchange (RFC 4954 §4) before it fails
    /// with `error`.
    fn cancel(error: SmtpAuthOauthbearerError) -> Self {
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
            Self::Send { pending, .. } if pending.is_some() => f.write_str("send auth oauthbearer"),
            Self::Send { .. } => f.write_str("send auth oauthbearer with ir"),
            Self::Continue(_) => f.write_str("send credentials"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
            Self::Cancel { .. } => f.write_str("cancel exchange"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{
        rfc5321::SmtpEhloDomain, rfc7628::auth_oauthbearer::*, send::SmtpCommandSendError,
    };

    fn domain() -> SmtpEhloDomain<'static> {
        SmtpEhloDomain::try_from("example.com").unwrap()
    }

    fn token() -> SecretString {
        SecretString::from("ya29.tokenvalue".to_string())
    }

    fn auth(opts: SmtpAuthOauthbearerOptions) -> SmtpAuthOauthbearer {
        SmtpAuthOauthbearer::new(
            "alice@example.com",
            "smtp.example.com",
            587,
            &token(),
            domain(),
            opts,
        )
    }

    #[test]
    fn ir_success_does_not_send_ehlo_by_default() {
        let mut auth = auth(SmtpAuthOauthbearerOptions::default());

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn ir_success_with_ehlo_returns_ok() {
        let mut auth = auth(SmtpAuthOauthbearerOptions {
            initial_request: true,
            ensure_capabilities: true,
        });

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ehlo = expect_wants_write(&mut auth, Some(b"235 OK\r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"250 server.example.com\r\n");
    }

    #[test]
    fn ir_sends_the_gs2_header_with_host_and_port() {
        let mut auth = auth(SmtpAuthOauthbearerOptions::default());

        let bytes = expect_wants_write(&mut auth, None);
        let line = String::from_utf8(bytes).expect("utf8 command");
        let payload = line
            .trim_end()
            .rsplit_once(' ')
            .map(|(_, ir)| ir.to_string())
            .expect("inline initial response");
        let payload = base64_decode(&payload);

        assert!(payload.contains("n,a=alice@example.com,"));
        assert!(payload.contains("host=smtp.example.com"));
        assert!(payload.contains("port=587"));
    }

    #[test]
    fn error_detail_returns_rejected_with_error() {
        let mut auth = auth(SmtpAuthOauthbearerOptions::default());
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        // NOTE: the JSON is read and acknowledged by the mechanism, which
        // hands it back once the server ends the exchange.
        let challenge = b"334 eyJzdGF0dXMiOiI0MDEifQ==\r\n";
        let _ack = expect_wants_write(&mut auth, Some(challenge));
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"535 authentication failed\r\n");
        let SmtpAuthOauthbearerError::RejectedWithError { code, message, err } = err else {
            panic!("expected SmtpAuthOauthbearerError::RejectedWithError, got {err:?}");
        };
        assert_eq!(code, 535);
        assert_eq!(message, "authentication failed");
        assert_eq!(err, r#"{"status":"401"}"#);
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut auth = auth(SmtpAuthOauthbearerOptions::default());
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"504 mechanism disabled\r\n");
        let SmtpAuthOauthbearerError::Rejected { code, message } = err else {
            panic!("expected SmtpAuthOauthbearerError::Rejected, got {err:?}");
        };
        assert_eq!(code, 504);
        assert_eq!(message, "mechanism disabled");
    }

    #[test]
    fn invalid_challenge_is_cancelled_with_the_challenge_error() {
        let mut auth = auth(SmtpAuthOauthbearerOptions::default());
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let cancel = expect_wants_write(&mut auth, Some(b"334 not!base64\r\n"));
        assert_eq!(cancel, b"*\r\n");
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"501 5.7.0 cancelled\r\n");
        let SmtpAuthOauthbearerError::Challenge(SmtpAuthChallengeError::Base64) = err else {
            panic!("expected SmtpAuthOauthbearerError::Challenge, got {err:?}");
        };
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut auth = auth(SmtpAuthOauthbearerOptions::default());
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"");
        assert!(matches!(
            err,
            SmtpAuthOauthbearerError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn base64_decode(input: &str) -> String {
        use base64_codec::codec::Base64Codec;

        let mut bytes = Vec::new();
        assert!(Base64Codec::default().decode_vec(input.as_bytes(), &mut bytes));
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn expect_wants_write(cor: &mut SmtpAuthOauthbearer, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpAuthOauthbearer) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpAuthOauthbearer, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(
        cor: &mut SmtpAuthOauthbearer,
        reply: &[u8],
    ) -> SmtpAuthOauthbearerError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
