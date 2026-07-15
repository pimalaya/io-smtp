//! SMTP SASL XOAUTH2 coroutine (Google's pre-standard OAuth 2.0
//! mechanism, also accepted by Microsoft Exchange Online); supports
//! both the non-IR and SASL-IR (RFC 4954 §4) flows. Prefer
//! OAUTHBEARER (RFC 7628) on servers that support both.
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
//!     rfc5321::types::{domain::SmtpDomain, ehlo_domain::SmtpEhloDomain},
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
    vec,
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as base64};
use bounded_static::IntoBoundedStatic;
use log::debug;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc4954::{auth::SmtpAuthCommand, auth_data::SmtpAuthData},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloError},
        types::{ehlo_domain::SmtpEhloDomain, reply_code::SmtpReplyCode},
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
    /// Refresh capabilities with an `EHLO` after a successful auth.
    pub ensure_capabilities: bool,
}

impl Default for SmtpAuthXoauth2Options {
    fn default() -> Self {
        Self {
            initial_request: true,
            ensure_capabilities: true,
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
        /// The reply text, or the decoded error detail.
        message: String,
    },
    /// The server accepted before the expected challenge.
    #[error("SMTP AUTH XOAUTH2 failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
    /// The underlying command exchange failed.
    #[error("SMTP AUTH XOAUTH2 failed: {0}")]
    Send(#[from] SmtpCommandSendError),
    /// The post-authentication capability refresh failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH XOAUTH2 coroutine. The connection MUST be
/// TLS-protected before calling this.
pub struct SmtpAuthXoauth2 {
    state: State,
    domain: Option<SmtpEhloDomain<'static>>,
    payload: Option<Vec<u8>>,
    error_detail: Option<String>,
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
        let payload = build_payload(username, token);

        let state = if opts.initial_request {
            let cmd = SmtpAuthCommand {
                mechanism: Cow::Borrowed(XOAUTH2),
                initial_response: Some(SecretBox::new(payload.clone().into_boxed_slice())),
            };
            State::Send(SmtpCommandSend::new(cmd))
        } else {
            let cmd = SmtpAuthCommand {
                mechanism: Cow::Borrowed(XOAUTH2),
                initial_response: None,
            };
            State::Send(SmtpCommandSend::new(cmd))
        };

        Self {
            state,
            domain: Some(domain.into_static()),
            payload: Some(payload),
            error_detail: None,
            opts,
        }
    }
}

impl SmtpCoroutine for SmtpAuthXoauth2 {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthXoauth2Error>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Send(send) => {
                    let out = smtp_try!(send, arg);

                    if out.response.code == SmtpReplyCode::AUTH_SUCCESSFUL {
                        if self.opts.initial_request {
                            self.advance_after_auth();
                            continue;
                        }
                        return SmtpCoroutineState::Complete(Err(
                            SmtpAuthXoauth2Error::ExpectedContinuationRequest,
                        ));
                    }

                    if out.response.code == SmtpReplyCode::AUTH_CONTINUE {
                        if self.opts.initial_request {
                            // NOTE: the server is asking us to ack
                            // the JSON error detail (XOAUTH2 failure
                            // flow).
                            let text = out.response.text().0.trim_start();
                            if let Ok(detail_bytes) = base64.decode(text.as_bytes()) {
                                self.error_detail = String::from_utf8(detail_bytes).ok();
                            }

                            let ack = SmtpAuthData::r#continue(vec![0x01u8]);
                            self.state = State::AckError(SmtpCommandSend::new(ack));
                            debug!("error detail received, acknowledging");
                            continue;
                        }

                        // NOTE: non-IR: send the credentials now.
                        let payload = self.payload.take().expect("payload taken twice");
                        let data = SmtpAuthData::r#continue(payload.into_boxed_slice());
                        self.state = State::Continue(SmtpCommandSend::new(data));
                        debug!("challenge received, sending credentials");
                        continue;
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpAuthXoauth2Error::Rejected {
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

                    if out.response.code == SmtpReplyCode::AUTH_CONTINUE {
                        let text = out.response.text().0.trim_start();
                        if let Ok(detail_bytes) = base64.decode(text.as_bytes()) {
                            self.error_detail = String::from_utf8(detail_bytes).ok();
                        }

                        let ack = SmtpAuthData::r#continue(vec![0x01u8]);
                        self.state = State::AckError(SmtpCommandSend::new(ack));
                        debug!("error detail received, acknowledging");
                        continue;
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpAuthXoauth2Error::Rejected {
                        code,
                        message,
                    }));
                }
                State::AckError(send) => {
                    let _ = smtp_try!(send, arg);

                    let message = self
                        .error_detail
                        .take()
                        .unwrap_or_else(|| "authentication failed".into());

                    return SmtpCoroutineState::Complete(Err(SmtpAuthXoauth2Error::Rejected {
                        code: 535,
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

impl SmtpAuthXoauth2 {
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
    AckError(SmtpCommandSend<SmtpAuthData>),
    Ehlo(SmtpEhlo),
    Done,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send auth xoauth2"),
            Self::Continue(_) => f.write_str("send credentials"),
            Self::AckError(_) => f.write_str("ack error detail"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
            Self::Done => f.write_str("done"),
        }
    }
}

/// Build the XOAUTH2 wire payload:
/// `user=<u>\x01auth=Bearer <t>\x01\x01`.
fn build_payload(username: &str, token: &SecretString) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"user=");
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x01);
    payload.extend_from_slice(b"auth=Bearer ");
    payload.extend_from_slice(token.expose_secret().as_bytes());
    payload.push(0x01);
    payload.push(0x01);
    payload
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, string::ToString, vec::Vec};

    use secrecy::SecretString;

    use crate::{
        coroutine::*,
        rfc5321::types::{domain::SmtpDomain, ehlo_domain::SmtpEhloDomain},
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
    fn ir_success_then_ehlo_returns_ok() {
        let opts = SmtpAuthXoauth2Options::default();
        let mut auth = SmtpAuthXoauth2::new("alice@example.com", &token(), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ehlo = expect_wants_write(&mut auth, Some(b"235 OK\r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"250 server.example.com\r\n");
    }

    #[test]
    fn ir_success_without_ehlo_returns_ok() {
        let opts = SmtpAuthXoauth2Options {
            initial_request: true,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthXoauth2::new("alice@example.com", &token(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn error_detail_returns_rejected() {
        let opts = SmtpAuthXoauth2Options {
            initial_request: true,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthXoauth2::new("alice@example.com", &token(), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let challenge = b"334 eyJzdGF0dXMiOiI0MDEifQ==\r\n";
        let _ack = expect_wants_write(&mut auth, Some(challenge));
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"535 authentication failed\r\n");
        let SmtpAuthXoauth2Error::Rejected { code, message } = err else {
            panic!("expected SmtpAuthXoauth2Error::Rejected, got {err:?}");
        };
        assert_eq!(code, 535);
        assert!(message.contains("status") || message.contains("401"));
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
