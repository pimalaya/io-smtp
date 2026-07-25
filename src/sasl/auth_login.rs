//! SMTP SASL LOGIN coroutine (legacy two-prompt mechanism,
//! pre-IETF). Prefer [`auth_plain`] or [`auth_scram_sha_256`] when
//! the server supports them.
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
    string::{String, ToString},
    vec::Vec,
};

use bounded_static::IntoBoundedStatic;
use log::debug;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc4954::auth_data::SmtpAuthData,
    rfc5321::{
        SmtpEhloDomain, SmtpReplyCode, SmtpText,
        ehlo::{SmtpEhlo, SmtpEhloError},
    },
    send::*,
    smtp_try,
};

/// The SASL mechanism name as it appears on the wire.
pub const LOGIN: &str = "LOGIN";

/// The AUTH LOGIN command (no formal RFC).
pub struct SmtpAuthLoginCommand;

impl From<SmtpAuthLoginCommand> for Vec<u8> {
    fn from(_: SmtpAuthLoginCommand) -> Vec<u8> {
        b"AUTH LOGIN\r\n".to_vec()
    }
}

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
    username: Option<Vec<u8>>,
    password: Option<Vec<u8>>,
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
        Self {
            state: State::Command(SmtpCommandSend::new(SmtpAuthLoginCommand)),
            username: Some(login.as_bytes().to_vec()),
            password: Some(password.expose_secret().as_bytes().to_vec()),
            domain: Some(domain.into_static()),
            opts,
        }
    }
}

impl SmtpCoroutine for SmtpAuthLogin {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthLoginError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Command(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != SmtpReplyCode::AUTH_CONTINUE {
                        return SmtpCoroutineState::Complete(Err(self
                            .rejected_or_missing_challenge(
                                out.response.code,
                                out.response.text(),
                            )));
                    }

                    let username = self.username.take().expect("username taken twice");
                    let data = SmtpAuthData::r#continue(username.into_boxed_slice());
                    self.state = State::Username(SmtpCommandSend::new(data));
                    debug!("challenge received, sending username");
                }
                State::Username(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != SmtpReplyCode::AUTH_CONTINUE {
                        return SmtpCoroutineState::Complete(Err(self
                            .rejected_or_missing_challenge(
                                out.response.code,
                                out.response.text(),
                            )));
                    }

                    let password = self.password.take().expect("password taken twice");
                    let data = SmtpAuthData::r#continue(password.into_boxed_slice());
                    self.state = State::Password(SmtpCommandSend::new(data));
                    debug!("challenge received, sending password");
                }
                State::Password(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code == SmtpReplyCode::AUTH_SUCCESSFUL {
                        self.advance_after_auth();
                        continue;
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpAuthLoginError::Rejected {
                        code,
                        message,
                    }));
                }
                State::Ehlo(ehlo) => {
                    let _ = smtp_try!(ehlo, arg);
                    debug!("capabilities refreshed");
                    return SmtpCoroutineState::Complete(Ok(()));
                }
                State::Done => return SmtpCoroutineState::Complete(Ok(())),
            }
        }
    }
}

impl SmtpAuthLogin {
    fn advance_after_auth(&mut self) {
        let _ = self.password.take();
        debug!("authenticated");
        if self.opts.ensure_capabilities {
            let domain = self.domain.take().expect("domain taken twice");
            self.state = State::Ehlo(SmtpEhlo::new(domain));
        } else {
            self.state = State::Done;
        }
    }

    fn rejected_or_missing_challenge(
        &self,
        code: SmtpReplyCode,
        text: &SmtpText<'_>,
    ) -> SmtpAuthLoginError {
        if code.is_success() {
            // NOTE: 2xx where we expected 334 (would mean the server
            // accepted before the challenge).
            SmtpAuthLoginError::ExpectedContinuationRequest
        } else {
            SmtpAuthLoginError::Rejected {
                code: code.code(),
                message: text.to_string(),
            }
        }
    }
}

enum State {
    Command(SmtpCommandSend<SmtpAuthLoginCommand>),
    Username(SmtpCommandSend<SmtpAuthData>),
    Password(SmtpCommandSend<SmtpAuthData>),
    Ehlo(SmtpEhlo),
    Done,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(_) => f.write_str("send auth login"),
            Self::Username(_) => f.write_str("send username"),
            Self::Password(_) => f.write_str("send password"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
            Self::Done => f.write_str("done"),
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
        let _username = expect_wants_write(&mut auth, Some(b"334 VXNlcm5hbWU6\r\n"));

        expect_wants_read(&mut auth);
        let _password = expect_wants_write(&mut auth, Some(b"334 UGFzc3dvcmQ6\r\n"));

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
    fn success_without_ehlo_returns_ok() {
        let opts = SmtpAuthLoginOptions {
            initial_request: false,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthLogin::new("alice", &password(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ = expect_wants_write(&mut auth, Some(b"334 VXNlcm5hbWU6\r\n"));
        expect_wants_read(&mut auth);
        let _ = expect_wants_write(&mut auth, Some(b"334 UGFzc3dvcmQ6\r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
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
