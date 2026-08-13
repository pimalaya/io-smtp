//! SMTP SASL XOAUTH2 coroutine (Google's pre-standard OAuth 2.0
//! mechanism, also accepted by Microsoft Exchange Online); supports
//! both the non-IR and SASL-IR (RFC 4954 §4) flows. Prefer
//! OAUTHBEARER (RFC 7628) on servers that support both.
//!
//! The mechanism itself lives in io-sasl: this coroutine holds the SMTP
//! half of the exchange, the `AUTH XOAUTH2` command, the challenges,
//! the final reply and the capability refresh, and asks [`SaslXoauth2`]
//! what to put in each response. The rejection dance is the
//! mechanism's: a challenge carrying the error JSON is answered with
//! the empty response Google documents, and the JSON comes back out
//! when the exchange is declared over.
//!
//! XOAUTH2: <https://developers.google.com/workspace/gmail/imap/xoauth2-protocol>
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
//!     rfc5321::{SmtpDomain, SmtpEhloDomain},
//!     sasl::auth_xoauth2::{SmtpAuthXoauth2, SmtpAuthXoauth2Options},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let token = SecretString::from("ya29.tokenvalue".to_string());
//! let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("client.example.org")));
//! let opts = SmtpAuthXoauth2Options::default();
//! let mut coroutine = SmtpAuthXoauth2::new("alice@example.org", &token, domain, opts);
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
    xoauth2::{SaslXoauth2, SaslXoauth2Creds, SaslXoauth2Error},
};
use log::debug;
use secrecy::{SecretBox, SecretString};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc4954::{
        auth::SmtpAuthCommand,
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
pub const XOAUTH2: &str = "XOAUTH2";

/// Options for [`SmtpAuthXoauth2::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpAuthXoauth2Options {
    /// `true` selects SASL-IR (inline credentials); `false` selects
    /// the non-IR challenge-response flow.
    pub initial_request: bool,
    /// Whether to refresh capabilities with an `EHLO` after a successful auth.
    /// Disabled by default because the mechanism does not add a security layer.
    pub ensure_capabilities: bool,
}

impl Default for SmtpAuthXoauth2Options {
    fn default() -> Self {
        Self {
            initial_request: true,
            ensure_capabilities: false,
        }
    }
}

/// Failure causes during the SMTP AUTH XOAUTH2 exchange.
#[derive(Debug, Error)]
pub enum SmtpAuthXoauth2Error {
    /// The server rejected the authentication.
    #[error("SMTP AUTH XOAUTH2 failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The server rejected the authentication after describing why in
    /// a challenge.
    #[error("SMTP AUTH XOAUTH2 failed: rejected {code} {message} ({err})")]
    RejectedWithError {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
        /// The error payload extracted from the challenge.
        err: String,
    },
    /// The server accepted before the expected challenge.
    #[error("SMTP AUTH XOAUTH2 failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
    /// The challenge carried a payload that is not valid base64.
    #[error("SMTP AUTH XOAUTH2 failed: {0}")]
    Challenge(#[from] SmtpAuthChallengeError),
    /// The mechanism refused the exchange.
    ///
    /// A rejected token whose exchange the server ended with a success
    /// reply lands here, carrying the JSON it sent, as does a challenge
    /// arriving out of order.
    #[error("SMTP AUTH XOAUTH2 failed: {0}")]
    Mechanism(#[from] SaslXoauth2Error),
    /// The underlying command exchange failed.
    #[error("SMTP AUTH XOAUTH2 failed: {0}")]
    Send(#[from] SmtpCommandSendError),
    /// The post-authentication capability refresh failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH XOAUTH2 coroutine.
pub struct SmtpAuthXoauth2 {
    state: State,
    mechanism: SaslXoauth2,
    domain: Option<SmtpEhloDomain<'static>>,
    opts: SmtpAuthXoauth2Options,
}

impl SmtpAuthXoauth2 {
    /// Creates the coroutine from the username, the bearer token and
    /// the client identity used by the capability refresh.
    pub fn new(
        username: &str,
        token: &SecretString,
        domain: SmtpEhloDomain<'_>,
        opts: SmtpAuthXoauth2Options,
    ) -> Self {
        let mechanism = SaslXoauth2::new(SaslXoauth2Creds {
            username: username.to_string(),
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
    fn resume_sasl(&mut self, arg: SaslArg<'_>) -> Result<Option<Vec<u8>>, SmtpAuthXoauth2Error> {
        match self.mechanism.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) => Ok(Some(payload)),
            SaslCoroutineState::Yielded(SaslYield::WantsRead) => Ok(None),
            SaslCoroutineState::Complete(result) => result.map(|()| None).map_err(Into::into),
        }
    }

    // helper that ends a rejected exchange, with the JSON the
    // mechanism captured when the server sent one
    fn rejected(&mut self, code: u16, message: String) -> SmtpAuthXoauth2Error {
        match self.mechanism.resume(SaslArg::Done) {
            SaslCoroutineState::Complete(Err(SaslXoauth2Error::Rejected(err))) => {
                SmtpAuthXoauth2Error::RejectedWithError { code, message, err }
            }
            _ => SmtpAuthXoauth2Error::Rejected { code, message },
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

impl SmtpCoroutine for SmtpAuthXoauth2 {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthXoauth2Error>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
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
                        mechanism: Cow::Borrowed(XOAUTH2),
                        initial_response,
                    };

                    self.state = State::Send {
                        send: SmtpCommandSend::new(cmd),
                        pending,
                    };
                    debug!("{}", self.state);
                }
                State::Send { send, pending } => {
                    let out = smtp_try!(send, arg);

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
                                        return SmtpCoroutineState::Complete(Err(err.into()));
                                    }
                                };

                                match self.resume_sasl(SaslArg::Input(&challenge)) {
                                    Ok(payload) => payload.unwrap_or_default(),
                                    Err(err) => return SmtpCoroutineState::Complete(Err(err)),
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
                            let err = SmtpAuthXoauth2Error::ExpectedContinuationRequest;
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
                    let message = out.response.text().to_string();
                    let err = self.rejected(code, message);
                    return SmtpCoroutineState::Complete(Err(err));
                }
                State::Continue(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code == SmtpReplyCode::AUTH_CONTINUE {
                        let challenge = match parse_challenge(&out.response.text().0) {
                            Ok(challenge) => challenge,
                            Err(err) => return SmtpCoroutineState::Complete(Err(err.into())),
                        };

                        let payload = match self.resume_sasl(SaslArg::Input(&challenge)) {
                            Ok(payload) => payload.unwrap_or_default(),
                            Err(err) => return SmtpCoroutineState::Complete(Err(err)),
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
                    let message = out.response.text().to_string();
                    let err = self.rejected(code, message);
                    return SmtpCoroutineState::Complete(Err(err));
                }
                State::Ehlo(ehlo) => {
                    let _ = smtp_try!(ehlo, arg);
                    debug!("capabilities refreshed");
                    return SmtpCoroutineState::Complete(Ok(()));
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
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => f.write_str("start mechanism"),
            Self::Send { pending, .. } if pending.is_some() => f.write_str("send auth xoauth2"),
            Self::Send { .. } => f.write_str("send auth xoauth2 with ir"),
            Self::Continue(_) => f.write_str("send credentials"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{
        coroutine::*,
        rfc5321::{SmtpDomain, SmtpEhloDomain},
        sasl::auth_xoauth2::*,
        send::SmtpCommandSendError,
    };

    fn domain() -> SmtpEhloDomain<'static> {
        SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com")))
    }

    fn token() -> SecretString {
        SecretString::from("ya29.tokenvalue".to_string())
    }

    #[test]
    fn ir_success_does_not_send_ehlo_by_default() {
        let opts = SmtpAuthXoauth2Options::default();
        let mut auth = SmtpAuthXoauth2::new("alice@example.com", &token(), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn ir_success_with_ehlo_returns_ok() {
        let opts = SmtpAuthXoauth2Options {
            initial_request: true,
            ensure_capabilities: true,
        };
        let mut auth = SmtpAuthXoauth2::new("alice@example.com", &token(), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ehlo = expect_wants_write(&mut auth, Some(b"235 OK\r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"250 server.example.com\r\n");
    }

    #[test]
    fn error_detail_returns_rejected_with_error() {
        let opts = SmtpAuthXoauth2Options::default();
        let mut auth = SmtpAuthXoauth2::new("alice@example.com", &token(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        // NOTE: the JSON is read and acknowledged by the mechanism, which
        // hands it back once the server ends the exchange.
        let challenge = b"334 eyJzdGF0dXMiOiI0MDEifQ==\r\n";
        let ack = expect_wants_write(&mut auth, Some(challenge));
        assert_eq!(ack, b"\r\n");

        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"535 authentication failed\r\n");
        let SmtpAuthXoauth2Error::RejectedWithError { code, message, err } = err else {
            panic!("expected SmtpAuthXoauth2Error::RejectedWithError, got {err:?}");
        };
        assert_eq!(code, 535);
        assert_eq!(message, "authentication failed");
        assert_eq!(err, r#"{"status":"401"}"#);
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let opts = SmtpAuthXoauth2Options::default();
        let mut auth = SmtpAuthXoauth2::new("alice@example.com", &token(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"504 mechanism disabled\r\n");
        let SmtpAuthXoauth2Error::Rejected { code, message } = err else {
            panic!("expected SmtpAuthXoauth2Error::Rejected, got {err:?}");
        };
        assert_eq!(code, 504);
        assert_eq!(message, "mechanism disabled");
    }

    #[test]
    fn eof_returns_eof_error() {
        let opts = SmtpAuthXoauth2Options::default();
        let mut auth = SmtpAuthXoauth2::new("alice@example.com", &token(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"");
        assert!(matches!(
            err,
            SmtpAuthXoauth2Error::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpAuthXoauth2, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpAuthXoauth2) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpAuthXoauth2, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpAuthXoauth2, reply: &[u8]) -> SmtpAuthXoauth2Error {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
