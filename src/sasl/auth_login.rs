//! SMTP SASL LOGIN coroutine (legacy two-prompt mechanism,
//! pre-IETF). Prefer [`auth_plain`] or [`auth_scram_sha_256`] when
//! the server supports them.
//!
//! The mechanism itself lives in io-sasl: this coroutine holds the SMTP
//! half of the exchange, the `AUTH LOGIN` command, the two 334
//! challenges, the final reply and the capability refresh, and asks
//! [`SaslLogin`] what each prompt is answered with. Nothing here knows
//! that the username comes before the password.
//!
//! Background: <https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login>
//!
//! [`auth_plain`]: crate::sasl::auth_plain
//! [`auth_scram_sha_256`]: crate::rfc7677::auth_scram_sha_256
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
//!     sasl::auth_login::{SmtpAuthLogin, SmtpAuthLoginOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let password = SecretString::from("secret".to_string());
//! let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("client.example.org")));
//! let opts = SmtpAuthLoginOptions::default();
//! let mut coroutine = SmtpAuthLogin::new("alice", &password, domain, opts);
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
    login::{SaslLogin, SaslLoginCreds, SaslLoginError},
};
use log::debug;
use secrecy::SecretString;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc4954::{
        auth::SmtpAuthCommand,
        auth_data::{SmtpAuthChallengeError, SmtpAuthData, parse_challenge},
    },
    rfc5321::{
        SmtpEhloDomain, SmtpReplyCode, SmtpText,
        ehlo::{SmtpEhlo, SmtpEhloError},
    },
    send::*,
    smtp_try,
};

/// The SASL mechanism name as it appears on the wire.
pub const LOGIN: &str = "LOGIN";

/// Options for [`SmtpAuthLogin::new`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SmtpAuthLoginOptions {
    /// Ignored (LOGIN has no SASL-IR variant); kept for option
    /// surface parity with the other SASL coroutines.
    pub initial_request: bool,
    /// Whether to refresh capabilities with an `EHLO` after a successful auth.
    /// Disabled by default because the mechanism does not add a security layer.
    pub ensure_capabilities: bool,
}

/// Failure causes during the SMTP AUTH LOGIN exchange.
#[derive(Debug, Error)]
pub enum SmtpAuthLoginError {
    /// The server rejected the authentication.
    #[error("SMTP AUTH LOGIN failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The server accepted before the expected challenge.
    #[error("SMTP AUTH LOGIN failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
    /// The challenge carried a payload that is not valid base64.
    #[error("SMTP AUTH LOGIN failed: {0}")]
    Challenge(#[from] SmtpAuthChallengeError),
    /// The mechanism refused the exchange.
    ///
    /// A prompt arriving once LOGIN has nothing left to say lands here
    /// rather than in a framing error of this crate's, only the
    /// mechanism knowing how many prompts it answers.
    #[error("SMTP AUTH LOGIN failed: {0}")]
    Mechanism(#[from] SaslLoginError),
    /// The underlying command exchange failed.
    #[error("SMTP AUTH LOGIN failed: {0}")]
    Send(#[from] SmtpCommandSendError),
    /// The post-authentication capability refresh failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH LOGIN coroutine.
pub struct SmtpAuthLogin {
    state: State,
    mechanism: SaslLogin,
    domain: Option<SmtpEhloDomain<'static>>,
    opts: SmtpAuthLoginOptions,
}

impl SmtpAuthLogin {
    /// Creates the coroutine from the credentials and the client
    /// identity used by the capability refresh.
    pub fn new(
        login: &str,
        password: &SecretString,
        domain: SmtpEhloDomain<'_>,
        opts: SmtpAuthLoginOptions,
    ) -> Self {
        let mechanism = SaslLogin::new(SaslLoginCreds {
            username: login.to_string(),
            password: password.clone(),
        });

        Self {
            state: State::Start,
            mechanism,
            domain: Some(domain.into_static()),
            opts,
        }
    }

    // helper that resumes the SASL coroutine
    fn resume_sasl(&mut self, arg: SaslArg<'_>) -> Result<Option<Vec<u8>>, SmtpAuthLoginError> {
        match self.mechanism.resume(arg) {
            SaslCoroutineState::Yielded(SaslYield::WantsWrite(payload)) => Ok(Some(payload)),
            SaslCoroutineState::Yielded(SaslYield::WantsRead) => Ok(None),
            SaslCoroutineState::Complete(result) => result.map(|()| None).map_err(Into::into),
        }
    }

    // helper that answers a challenge with the next mechanism payload
    fn wants_continue(&mut self, text: &SmtpText<'_>) -> Result<State, SmtpAuthLoginError> {
        let challenge = parse_challenge(&text.0)?;
        let payload = self
            .resume_sasl(SaslArg::Input(&challenge))?
            .unwrap_or_default();
        let data = SmtpAuthData::r#continue(payload.into_boxed_slice());
        Ok(State::Password(SmtpCommandSend::new(data)))
    }

    // helper that moves to the capability refresh, or completes
    fn advance_after_auth(&mut self) -> Option<State> {
        debug!("authenticated");

        let domain = self.domain.take()?;
        self.opts
            .ensure_capabilities
            .then(|| State::Ehlo(SmtpEhlo::new(domain)))
    }

    // helper that tells a rejection from a premature acceptance
    fn rejected_or_missing_challenge(
        code: SmtpReplyCode,
        text: &SmtpText<'_>,
    ) -> SmtpAuthLoginError {
        if code.is_success() {
            // NOTE: 2xx where we expected 334, which would mean the server
            // accepted before it asked for the next prompt.
            SmtpAuthLoginError::ExpectedContinuationRequest
        } else {
            SmtpAuthLoginError::Rejected {
                code: code.code(),
                message: text.to_string(),
            }
        }
    }
}

impl SmtpCoroutine for SmtpAuthLogin {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthLoginError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Start => {
                    let cmd = SmtpAuthCommand {
                        mechanism: Cow::Borrowed(LOGIN),
                        initial_response: None,
                    };

                    self.state = State::Command(SmtpCommandSend::new(cmd));
                    debug!("{}", self.state);
                }
                State::Command(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != SmtpReplyCode::AUTH_CONTINUE {
                        let err = Self::rejected_or_missing_challenge(
                            out.response.code,
                            out.response.text(),
                        );
                        return SmtpCoroutineState::Complete(Err(err));
                    }

                    // NOTE: the first prompt is answered from the mechanism's
                    // opening payload rather than from the challenge, LOGIN
                    // speaking first whatever the server writes in it.
                    let payload = match self.resume_sasl(SaslArg::None) {
                        Ok(payload) => payload.unwrap_or_default(),
                        Err(err) => return SmtpCoroutineState::Complete(Err(err)),
                    };

                    let data = SmtpAuthData::r#continue(payload.into_boxed_slice());
                    self.state = State::Username(SmtpCommandSend::new(data));
                    debug!("{}", self.state);
                }
                State::Username(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != SmtpReplyCode::AUTH_CONTINUE {
                        let err = Self::rejected_or_missing_challenge(
                            out.response.code,
                            out.response.text(),
                        );
                        return SmtpCoroutineState::Complete(Err(err));
                    }

                    self.state = match self.wants_continue(out.response.text()) {
                        Ok(state) => state,
                        Err(err) => return SmtpCoroutineState::Complete(Err(err)),
                    };
                    debug!("{}", self.state);
                }
                State::Password(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != SmtpReplyCode::AUTH_SUCCESSFUL {
                        let code = out.response.code.code();
                        let message = out.response.text().to_string();
                        let err = SmtpAuthLoginError::Rejected { code, message };
                        return SmtpCoroutineState::Complete(Err(err));
                    }

                    // NOTE: the final reply ends the exchange, and the
                    // mechanism is told so rather than dropped, so that a
                    // mechanism with something left to verify can refuse.
                    if let Err(err) = self.resume_sasl(SaslArg::Done) {
                        return SmtpCoroutineState::Complete(Err(err));
                    }

                    match self.advance_after_auth() {
                        Some(next) => {
                            self.state = next;
                            debug!("{}", self.state);
                        }
                        None => return SmtpCoroutineState::Complete(Ok(())),
                    }
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
    Command(SmtpCommandSend<SmtpAuthCommand<'static>>),
    Username(SmtpCommandSend<SmtpAuthData>),
    Password(SmtpCommandSend<SmtpAuthData>),
    Ehlo(SmtpEhlo),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => f.write_str("start mechanism"),
            Self::Command(_) => f.write_str("send auth login"),
            Self::Username(_) => f.write_str("send username"),
            Self::Password(_) => f.write_str("send password"),
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
        sasl::auth_login::*,
        send::SmtpCommandSendError,
    };

    fn domain() -> SmtpEhloDomain<'static> {
        SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com")))
    }

    fn password() -> SecretString {
        SecretString::from("secret".to_string())
    }

    #[test]
    fn success_does_not_send_ehlo_by_default() {
        let opts = SmtpAuthLoginOptions::default();
        let mut auth = SmtpAuthLogin::new("alice", &password(), domain(), opts);

        let bytes = expect_wants_write(&mut auth, None);
        assert_eq!(bytes, b"AUTH LOGIN\r\n");

        expect_wants_read(&mut auth);
        let username = expect_wants_write(&mut auth, Some(b"334 VXNlcm5hbWU6\r\n"));
        assert_eq!(username, b"YWxpY2U=\r\n");

        expect_wants_read(&mut auth);
        let password = expect_wants_write(&mut auth, Some(b"334 UGFzc3dvcmQ6\r\n"));
        assert_eq!(password, b"c2VjcmV0\r\n");

        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn success_with_ehlo_returns_ok() {
        let opts = SmtpAuthLoginOptions {
            initial_request: false,
            ensure_capabilities: true,
        };
        let mut auth = SmtpAuthLogin::new("alice", &password(), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ = expect_wants_write(&mut auth, Some(b"334 VXNlcm5hbWU6\r\n"));
        expect_wants_read(&mut auth);
        let _ = expect_wants_write(&mut auth, Some(b"334 UGFzc3dvcmQ6\r\n"));
        expect_wants_read(&mut auth);
        let _ehlo = expect_wants_write(&mut auth, Some(b"235 OK\r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"250 server.example.com\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let opts = SmtpAuthLoginOptions::default();
        let mut auth = SmtpAuthLogin::new("alice", &password(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ = expect_wants_write(&mut auth, Some(b"334 VXNlcm5hbWU6\r\n"));
        expect_wants_read(&mut auth);
        let _ = expect_wants_write(&mut auth, Some(b"334 UGFzc3dvcmQ6\r\n"));
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"535 bad credentials\r\n");
        let SmtpAuthLoginError::Rejected { code, message } = err else {
            panic!("expected SmtpAuthLoginError::Rejected, got {err:?}");
        };
        assert_eq!(code, 535);
        assert_eq!(message, "bad credentials");
    }

    #[test]
    fn missing_first_challenge_returns_rejected_error() {
        let opts = SmtpAuthLoginOptions::default();
        let mut auth = SmtpAuthLogin::new("alice", &password(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"504 AUTH LOGIN not enabled\r\n");
        let SmtpAuthLoginError::Rejected { code, .. } = err else {
            panic!("expected SmtpAuthLoginError::Rejected, got {err:?}");
        };
        assert_eq!(code, 504);
    }

    #[test]
    fn success_before_password_returns_expected_continuation_error() {
        let opts = SmtpAuthLoginOptions::default();
        let mut auth = SmtpAuthLogin::new("alice", &password(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ = expect_wants_write(&mut auth, Some(b"334 VXNlcm5hbWU6\r\n"));
        expect_wants_read(&mut auth);

        // NOTE: the password was never asked for, so the server authenticated
        // on a username alone.
        let err = expect_complete_err(&mut auth, b"235 OK\r\n");
        let SmtpAuthLoginError::ExpectedContinuationRequest = err else {
            panic!("expected SmtpAuthLoginError::ExpectedContinuationRequest, got {err:?}");
        };
    }

    #[test]
    fn invalid_challenge_returns_challenge_error() {
        let opts = SmtpAuthLoginOptions::default();
        let mut auth = SmtpAuthLogin::new("alice", &password(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ = expect_wants_write(&mut auth, Some(b"334 VXNlcm5hbWU6\r\n"));
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"334 not base64 at all\r\n");
        let SmtpAuthLoginError::Challenge(SmtpAuthChallengeError::Base64(_)) = err else {
            panic!("expected SmtpAuthLoginError::Challenge, got {err:?}");
        };
    }

    #[test]
    fn eof_returns_eof_error() {
        let opts = SmtpAuthLoginOptions::default();
        let mut auth = SmtpAuthLogin::new("alice", &password(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"");
        assert!(matches!(
            err,
            SmtpAuthLoginError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpAuthLogin, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpAuthLogin) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpAuthLogin, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpAuthLogin, reply: &[u8]) -> SmtpAuthLoginError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
