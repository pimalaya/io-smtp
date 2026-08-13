//! SMTP SASL PLAIN coroutine; supports both the non-IR and SASL-IR
//! (RFC 4954 §4) flows.
//!
//! The mechanism itself lives in io-sasl: this coroutine holds the SMTP
//! half of the exchange, the `AUTH PLAIN` command, the 334 challenge,
//! the final reply and the capability refresh, and asks [`SaslPlain`]
//! what to put in each response. So the NUL-separated triple, and the
//! refusal of a challenge once it has been sent, are the mechanism's
//! business, and nothing here knows what PLAIN puts on the wire.
//!
//! PLAIN: <https://www.rfc-editor.org/rfc/rfc4616>
//! AUTH:  <https://www.rfc-editor.org/rfc/rfc4954>
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
//!     sasl::auth_plain::{SmtpAuthPlain, SmtpAuthPlainOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let authzid: Option<&str> = None;
//! let password = SecretString::from("secret".to_string());
//! let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com")));
//! let opts = SmtpAuthPlainOptions::default();
//! let mut coroutine = SmtpAuthPlain::new(authzid, "alice", &password, domain, opts);
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
    rfc4616::plain::{SaslPlain, SaslPlainCreds, SaslPlainError},
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
pub const PLAIN: &str = "PLAIN";

/// Options for [`SmtpAuthPlain::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpAuthPlainOptions {
    /// `true` selects SASL-IR (inline credentials); `false` selects
    /// the non-IR challenge-response flow.
    pub initial_request: bool,
    /// Whether to refresh capabilities with an `EHLO` after a successful auth.
    /// Disabled by default because the mechanism does not add a security layer.
    pub ensure_capabilities: bool,
}

impl Default for SmtpAuthPlainOptions {
    fn default() -> Self {
        Self {
            initial_request: true,
            ensure_capabilities: false,
        }
    }
}

/// Failure causes during the SMTP AUTH PLAIN exchange.
#[derive(Debug, Error)]
pub enum SmtpAuthPlainError {
    /// The server rejected the authentication.
    #[error("SMTP AUTH PLAIN failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The server accepted before the expected challenge.
    #[error("SMTP AUTH PLAIN failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
    /// The challenge carried a payload that is not valid base64.
    #[error("SMTP AUTH PLAIN failed: {0}")]
    Challenge(#[from] SmtpAuthChallengeError),
    /// The mechanism refused the exchange.
    ///
    /// A challenge arriving once PLAIN has sent its credentials lands
    /// here rather than in a framing error of this crate's, only the
    /// mechanism knowing how many messages it exchanges.
    #[error("SMTP AUTH PLAIN failed: {0}")]
    Mechanism(#[from] SaslPlainError),
    /// The underlying command exchange failed.
    #[error("SMTP AUTH PLAIN failed: {0}")]
    Send(#[from] SmtpCommandSendError),
    /// The post-authentication capability refresh failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH PLAIN coroutine.
pub struct SmtpAuthPlain {
    state: State,
    mechanism: SaslPlain,
    domain: Option<SmtpEhloDomain<'static>>,
    opts: SmtpAuthPlainOptions,
}

impl SmtpAuthPlain {
    /// Creates the coroutine from the credentials and the client
    /// identity used by the capability refresh.
    ///
    /// `authzid` is the optional RFC 4616 authorization identity;
    /// `authcid` is the authentication identity (typically the
    /// username). Depending on `opts.initial_request`, the credentials
    /// go inline with the AUTH command (SASL-IR) or are uploaded after
    /// the server challenge.
    pub fn new(
        authzid: Option<impl AsRef<str>>,
        authcid: &str,
        password: &SecretString,
        domain: SmtpEhloDomain<'_>,
        opts: SmtpAuthPlainOptions,
    ) -> Self {
        let mechanism = SaslPlain::new(SaslPlainCreds {
            authzid: authzid.map(|zid| zid.as_ref().to_string()),
            authcid: authcid.to_string(),
            passwd: password.clone(),
        });

        Self {
            state: State::Start,
            mechanism,
            domain: Some(domain.into_static()),
            opts,
        }
    }

    // helper that resumes the SASL coroutine
    fn resume_sasl(&mut self, arg: SaslArg<'_>) -> Result<Option<Vec<u8>>, SmtpAuthPlainError> {
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

impl SmtpCoroutine for SmtpAuthPlain {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthPlainError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Start => {
                    let payload = match self.resume_sasl(SaslArg::None) {
                        Ok(payload) => payload,
                        Err(err) => return SmtpCoroutineState::Complete(Err(err)),
                    };

                    // NOTE: the initial response travels inline only when the
                    // caller asked for it; otherwise it waits for the empty
                    // challenge RFC 4954 section 4 defines.
                    let (initial_response, pending) = match payload {
                        Some(payload) if self.opts.initial_request => {
                            (Some(SecretBox::new(payload.into_boxed_slice())), None)
                        }
                        payload => (None, payload),
                    };

                    let cmd = SmtpAuthCommand {
                        mechanism: Cow::Borrowed(PLAIN),
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
                        // NOTE: the challenge PLAIN answers is empty, its
                        // credentials being the initial response, so it is
                        // answered from what the mechanism already yielded
                        // rather than fed back to it.
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
                            let err = SmtpAuthPlainError::ExpectedContinuationRequest;
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
                    let err = SmtpAuthPlainError::Rejected { code, message };
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
                        // mechanism is told so rather than dropped: a mechanism
                        // performing mutual authentication refuses here when it
                        // verified nothing, which is what stops a success reply
                        // from standing in for a proof the server never gave.
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
                    let err = SmtpAuthPlainError::Rejected { code, message };
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
            Self::Send { pending, .. } if pending.is_some() => f.write_str("send auth plain"),
            Self::Send { .. } => f.write_str("send auth plain with ir"),
            Self::Continue(_) => f.write_str("send credentials"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::from_utf8;

    use alloc::{borrow::Cow, string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{
        coroutine::*,
        rfc5321::{SmtpDomain, SmtpEhloDomain},
        sasl::auth_plain::*,
        send::SmtpCommandSendError,
    };

    fn domain() -> SmtpEhloDomain<'static> {
        SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com")))
    }

    fn password() -> SecretString {
        SecretString::from("secret".to_string())
    }

    #[test]
    fn ir_success_does_not_send_ehlo_by_default() {
        let opts = SmtpAuthPlainOptions::default();
        let mut auth = SmtpAuthPlain::new(None::<&str>, "alice", &password(), domain(), opts);

        let bytes = expect_wants_write(&mut auth, None);
        let line = from_utf8(&bytes).expect("utf8 command");
        assert!(line.starts_with("AUTH PLAIN "));

        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn ir_success_with_ehlo_returns_ok() {
        let opts = SmtpAuthPlainOptions {
            initial_request: true,
            ensure_capabilities: true,
        };
        let mut auth = SmtpAuthPlain::new(None::<&str>, "alice", &password(), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ehlo = expect_wants_write(&mut auth, Some(b"235 OK\r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"250-server.example.com\r\n250 AUTH PLAIN\r\n");
    }

    #[test]
    fn ir_invalid_credentials_returns_rejected_error() {
        let opts = SmtpAuthPlainOptions::default();
        let mut auth = SmtpAuthPlain::new(None::<&str>, "alice", &password(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"535 wrong password\r\n");
        let SmtpAuthPlainError::Rejected { code, message } = err else {
            panic!("expected SmtpAuthPlainError::Rejected, got {err:?}");
        };
        assert_eq!(code, 535);
        assert_eq!(message, "wrong password");
    }

    #[test]
    fn ir_extra_challenge_returns_mechanism_error() {
        let opts = SmtpAuthPlainOptions::default();
        let mut auth = SmtpAuthPlain::new(None::<&str>, "alice", &password(), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        // NOTE: a challenge, which PLAIN has nothing left to answer once its
        // credentials went inline. The refusal is the mechanism's, this crate
        // having no way to know how many messages a mechanism exchanges.
        let err = expect_complete_err(&mut auth, b"334 \r\n");
        let SmtpAuthPlainError::Mechanism(SaslPlainError::UnexpectedChallenge) = err else {
            panic!("expected SmtpAuthPlainError::Mechanism, got {err:?}");
        };
    }

    #[test]
    fn non_ir_success_returns_ok() {
        let opts = SmtpAuthPlainOptions {
            initial_request: false,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthPlain::new(None::<&str>, "alice", &password(), domain(), opts);

        let bytes = expect_wants_write(&mut auth, None);
        let line = from_utf8(&bytes).expect("utf8 command");
        assert!(line.trim_end().ends_with("AUTH PLAIN"));

        expect_wants_read(&mut auth);
        let creds = expect_wants_write(&mut auth, Some(b"334 \r\n"));
        assert!(creds.ends_with(b"\r\n"));

        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn non_ir_success_before_credentials_returns_expected_continuation_error() {
        let opts = SmtpAuthPlainOptions {
            initial_request: false,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthPlain::new(None::<&str>, "alice", &password(), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        // NOTE: nothing was inlined, so a server accepting here never asked
        // for what it claims to have authenticated.
        let err = expect_complete_err(&mut auth, b"235 OK\r\n");
        let SmtpAuthPlainError::ExpectedContinuationRequest = err else {
            panic!("expected SmtpAuthPlainError::ExpectedContinuationRequest, got {err:?}");
        };
    }

    #[test]
    fn eof_returns_eof_error() {
        let opts = SmtpAuthPlainOptions::default();
        let mut auth = SmtpAuthPlain::new(None::<&str>, "alice", &password(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"");
        assert!(matches!(
            err,
            SmtpAuthPlainError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpAuthPlain, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpAuthPlain) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpAuthPlain, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpAuthPlain, reply: &[u8]) -> SmtpAuthPlainError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
