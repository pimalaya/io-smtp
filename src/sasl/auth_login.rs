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
//!     rfc5321::types::{domain::Domain, ehlo_domain::EhloDomain},
//!     sasl::auth_login::{SmtpAuthLogin, SmtpAuthLoginOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let password = SecretString::from("secret".to_string());
//! let domain = EhloDomain::Domain(Domain(Cow::Borrowed("client.example.org")));
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
use log::trace;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc4954::auth_data::SmtpAuthData,
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError},
        types::{ehlo_domain::EhloDomain, reply_code::ReplyCode, text::Text},
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpAuthLoginOptions {
    /// Ignored (LOGIN has no SASL-IR variant); kept for option
    /// surface parity with the other SASL coroutines.
    pub initial_request: bool,
    /// Refresh capabilities with an `EHLO` after a successful auth.
    pub ensure_capabilities: bool,
}

impl Default for SmtpAuthLoginOptions {
    fn default() -> Self {
        Self {
            initial_request: false,
            ensure_capabilities: true,
        }
    }
}

/// Failure causes during the SMTP AUTH LOGIN exchange.
#[derive(Debug, Error)]
pub enum SmtpAuthLoginError {
    #[error("SMTP AUTH LOGIN failed: rejected {code} {message}")]
    Rejected { code: u16, message: String },
    #[error("SMTP AUTH LOGIN failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
    #[error("SMTP AUTH LOGIN failed: {0}")]
    Send(#[from] SendSmtpCommandError),
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH LOGIN coroutine.
pub struct SmtpAuthLogin {
    state: State,
    username: Option<Vec<u8>>,
    password: Option<Vec<u8>>,
    domain: Option<EhloDomain<'static>>,
    opts: SmtpAuthLoginOptions,
}

impl SmtpAuthLogin {
    pub fn new(
        login: &str,
        password: &SecretString,
        domain: EhloDomain<'_>,
        opts: SmtpAuthLoginOptions,
    ) -> Self {
        Self {
            state: State::Command(SendSmtpCommand::new(SmtpAuthLoginCommand)),
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
            trace!("auth login: {}", self.state);

            match &mut self.state {
                State::Command(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != ReplyCode::AUTH_CONTINUE {
                        return SmtpCoroutineState::Complete(Err(self
                            .rejected_or_missing_challenge(
                                out.response.code,
                                out.response.text(),
                            )));
                    }

                    let username = self.username.take().expect("username taken twice");
                    let data = SmtpAuthData::r#continue(username.into_boxed_slice());
                    self.state = State::Username(SendSmtpCommand::new(data));
                }
                State::Username(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code != ReplyCode::AUTH_CONTINUE {
                        return SmtpCoroutineState::Complete(Err(self
                            .rejected_or_missing_challenge(
                                out.response.code,
                                out.response.text(),
                            )));
                    }

                    let password = self.password.take().expect("password taken twice");
                    let data = SmtpAuthData::r#continue(password.into_boxed_slice());
                    self.state = State::Password(SendSmtpCommand::new(data));
                }
                State::Password(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code == ReplyCode::AUTH_SUCCESSFUL {
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
        if self.opts.ensure_capabilities {
            let domain = self.domain.take().expect("domain taken twice");
            self.state = State::Ehlo(SmtpEhlo::new(domain));
        } else {
            self.state = State::Done;
        }
    }

    fn rejected_or_missing_challenge(
        &self,
        code: ReplyCode,
        text: &Text<'_>,
    ) -> SmtpAuthLoginError {
        if code.is_success() {
            // 2xx where we expected 334 (would mean the server
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
    Command(SendSmtpCommand<SmtpAuthLoginCommand>),
    Username(SendSmtpCommand<SmtpAuthData>),
    Password(SendSmtpCommand<SmtpAuthData>),
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
    use alloc::borrow::Cow;

    use crate::rfc5321::types::domain::Domain;

    use super::*;

    fn domain() -> EhloDomain<'static> {
        EhloDomain::Domain(Domain(Cow::Borrowed("example.com")))
    }

    fn password() -> SecretString {
        SecretString::from("secret".to_string())
    }

    #[test]
    fn success_then_ehlo_returns_ok() {
        let opts = SmtpAuthLoginOptions::default();
        let mut auth = SmtpAuthLogin::new("alice", &password(), domain(), opts);

        let bytes = expect_wants_write(&mut auth, None);
        assert_eq!(bytes, b"AUTH LOGIN\r\n");

        expect_wants_read(&mut auth);
        let _username = expect_wants_write(&mut auth, Some(b"334 VXNlcm5hbWU6\r\n"));

        expect_wants_read(&mut auth);
        let _password = expect_wants_write(&mut auth, Some(b"334 UGFzc3dvcmQ6\r\n"));

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
            SmtpAuthLoginError::Send(SendSmtpCommandError::Eof)
        ));
    }

    // --- utils

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
