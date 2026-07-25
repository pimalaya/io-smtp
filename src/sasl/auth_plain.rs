//! SMTP SASL PLAIN coroutine; supports both the non-IR and SASL-IR
//! (RFC 4954 §4) flows.
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
//! let password = SecretString::from("secret".to_string());
//! let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com")));
//! let opts = SmtpAuthPlainOptions::default();
//! let mut coroutine = SmtpAuthPlain::new("alice", &password, domain, opts);
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
use log::debug;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc4954::{auth::SmtpAuthCommand, auth_data::SmtpAuthData},
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
    /// The server challenged despite the inline initial response.
    #[error("SMTP AUTH PLAIN failed: server sent an unexpected continuation request")]
    UnexpectedContinuationRequest,
    /// The server accepted before the expected challenge.
    #[error("SMTP AUTH PLAIN failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
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
    domain: Option<SmtpEhloDomain<'static>>,
    payload: Option<Vec<u8>>,
    opts: SmtpAuthPlainOptions,
}

impl SmtpAuthPlain {
    /// Creates the coroutine from the credentials and the client
    /// identity used by the capability refresh.
    pub fn new(
        login: &str,
        password: &SecretString,
        domain: SmtpEhloDomain<'_>,
        opts: SmtpAuthPlainOptions,
    ) -> Self {
        let mut payload = Vec::new();
        payload.push(0);
        payload.extend_from_slice(login.as_bytes());
        payload.push(0);
        payload.extend_from_slice(password.expose_secret().as_bytes());

        let state = if opts.initial_request {
            let cmd = SmtpAuthCommand {
                mechanism: Cow::Borrowed(PLAIN),
                initial_response: Some(SecretBox::new(payload.clone().into_boxed_slice())),
            };
            State::Send(SmtpCommandSend::new(cmd))
        } else {
            let cmd = SmtpAuthCommand {
                mechanism: Cow::Borrowed(PLAIN),
                initial_response: None,
            };
            State::Send(SmtpCommandSend::new(cmd))
        };

        Self {
            state,
            domain: Some(domain.into_static()),
            payload: Some(payload),
            opts,
        }
    }
}

impl SmtpCoroutine for SmtpAuthPlain {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthPlainError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Send(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code == SmtpReplyCode::AUTH_SUCCESSFUL {
                        if self.opts.initial_request {
                            // NOTE: IR flow: success on first reply.
                            self.advance_after_auth();
                            continue;
                        }
                        // NOTE: non-IR flow: success before the
                        // challenge, technically RFC 4954 §4 forbids
                        // this.
                        return SmtpCoroutineState::Complete(Err(
                            SmtpAuthPlainError::ExpectedContinuationRequest,
                        ));
                    }

                    if out.response.code == SmtpReplyCode::AUTH_CONTINUE {
                        if self.opts.initial_request {
                            // NOTE: IR flow: server should never
                            // challenge.
                            return SmtpCoroutineState::Complete(Err(
                                SmtpAuthPlainError::UnexpectedContinuationRequest,
                            ));
                        }
                        // NOTE: non-IR flow: send credentials now.
                        let payload = self.payload.take().expect("payload taken twice");
                        let data = SmtpAuthData::r#continue(payload.into_boxed_slice());
                        self.state = State::Continue(SmtpCommandSend::new(data));
                        debug!("challenge received, sending credentials");
                        continue;
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpAuthPlainError::Rejected {
                        code,
                        message,
                    }));
                }
                State::Continue(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code == SmtpReplyCode::AUTH_SUCCESSFUL {
                        self.advance_after_auth();
                        continue;
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpAuthPlainError::Rejected {
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

impl SmtpAuthPlain {
    fn advance_after_auth(&mut self) {
        let _ = self.payload.take();
        debug!("authenticated");
        if self.opts.ensure_capabilities {
            let domain = self.domain.take().expect("domain taken twice");
            self.state = State::Ehlo(SmtpEhlo::new(domain));
        } else {
            self.state = State::Done;
        }
    }
}

enum State {
    Send(SmtpCommandSend<SmtpAuthCommand<'static>>),
    Continue(SmtpCommandSend<SmtpAuthData>),
    Ehlo(SmtpEhlo),
    Done,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send auth plain"),
            Self::Continue(_) => f.write_str("send credentials"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
            Self::Done => f.write_str("done"),
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
        let mut auth = SmtpAuthPlain::new("alice", &password(), domain(), opts);

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
        let mut auth = SmtpAuthPlain::new("alice", &password(), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ehlo = expect_wants_write(&mut auth, Some(b"235 OK\r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"250-server.example.com\r\n250 AUTH PLAIN\r\n");
    }

    #[test]
    fn ir_success_without_ehlo_returns_ok() {
        let opts = SmtpAuthPlainOptions {
            initial_request: true,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthPlain::new("alice", &password(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn ir_invalid_credentials_returns_rejected_error() {
        let opts = SmtpAuthPlainOptions::default();
        let mut auth = SmtpAuthPlain::new("alice", &password(), domain(), opts);
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
    fn non_ir_success_returns_ok() {
        let opts = SmtpAuthPlainOptions {
            initial_request: false,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthPlain::new("alice", &password(), domain(), opts);

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
    fn eof_returns_eof_error() {
        let opts = SmtpAuthPlainOptions::default();
        let mut auth = SmtpAuthPlain::new("alice", &password(), domain(), opts);
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
