//! SMTP SASL OAUTHBEARER coroutine; supports both the non-IR and
//! SASL-IR (RFC 4954 §4) flows.
//!
//! OAUTHBEARER: <https://www.rfc-editor.org/rfc/rfc7628>
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
//!     rfc7628::auth_oauthbearer::{SmtpAuthOauthbearer, SmtpAuthOauthbearerOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let token = SecretString::from("ya29.tokenvalue".to_string());
//! let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("client.example.org")));
//! let opts = SmtpAuthOauthbearerOptions::default();
//! let mut coroutine = SmtpAuthOauthbearer::new(&token, Some("alice@example.org"), domain, opts);
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
        /// The reply text, or the decoded error detail.
        message: String,
    },
    /// The server accepted before the expected challenge.
    #[error("SMTP AUTH OAUTHBEARER failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
    /// The underlying command exchange failed.
    #[error("SMTP AUTH OAUTHBEARER failed: {0}")]
    Send(#[from] SmtpCommandSendError),
    /// The post-authentication capability refresh failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH OAUTHBEARER coroutine. The connection MUST be
/// TLS-protected before calling this. The optional `username` is
/// embedded in the GS2 header; most servers ignore it.
pub struct SmtpAuthOauthbearer {
    state: State,
    domain: Option<SmtpEhloDomain<'static>>,
    payload: Option<Vec<u8>>,
    error_detail: Option<String>,
    opts: SmtpAuthOauthbearerOptions,
}

impl SmtpAuthOauthbearer {
    /// Creates the coroutine from the bearer token, an optional
    /// authorization identity and the client identity used by the
    /// capability refresh.
    pub fn new(
        token: &SecretString,
        username: Option<&str>,
        domain: SmtpEhloDomain<'_>,
        opts: SmtpAuthOauthbearerOptions,
    ) -> Self {
        let payload = build_payload(token, username);

        let state = if opts.initial_request {
            let cmd = SmtpAuthCommand {
                mechanism: Cow::Borrowed(OAUTHBEARER),
                initial_response: Some(SecretBox::new(payload.clone().into_boxed_slice())),
            };
            State::Send(SmtpCommandSend::new(cmd))
        } else {
            let cmd = SmtpAuthCommand {
                mechanism: Cow::Borrowed(OAUTHBEARER),
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

impl SmtpCoroutine for SmtpAuthOauthbearer {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthOauthbearerError>;

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
                            SmtpAuthOauthbearerError::ExpectedContinuationRequest,
                        ));
                    }

                    if out.response.code == SmtpReplyCode::AUTH_CONTINUE {
                        if self.opts.initial_request {
                            let text = out.response.text().0.trim_start();
                            if let Ok(detail_bytes) = base64.decode(text.as_bytes()) {
                                self.error_detail = String::from_utf8(detail_bytes).ok();
                            }

                            let ack = SmtpAuthData::r#continue(vec![0x01u8]);
                            self.state = State::AckError(SmtpCommandSend::new(ack));
                            debug!("error detail received, acknowledging");
                            continue;
                        }

                        let payload = self.payload.take().expect("payload taken twice");
                        let data = SmtpAuthData::r#continue(payload.into_boxed_slice());
                        self.state = State::Continue(SmtpCommandSend::new(data));
                        debug!("challenge received, sending credentials");
                        continue;
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpAuthOauthbearerError::Rejected {
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
                    return SmtpCoroutineState::Complete(Err(SmtpAuthOauthbearerError::Rejected {
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

                    return SmtpCoroutineState::Complete(Err(SmtpAuthOauthbearerError::Rejected {
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

impl SmtpAuthOauthbearer {
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
            Self::Send(_) => f.write_str("send auth oauthbearer"),
            Self::Continue(_) => f.write_str("send credentials"),
            Self::AckError(_) => f.write_str("ack error detail"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
            Self::Done => f.write_str("done"),
        }
    }
}

/// Build the OAUTHBEARER wire payload:
/// `n,` [`a=<u>`] `,\x01auth=Bearer <t>\x01\x01`.
fn build_payload(token: &SecretString, username: Option<&str>) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"n,");
    if let Some(user) = username {
        payload.extend_from_slice(b"a=");
        payload.extend_from_slice(user.as_bytes());
    }
    payload.push(b',');
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
        rfc5321::{SmtpDomain, SmtpEhloDomain},
        rfc7628::auth_oauthbearer::*,
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
        let opts = SmtpAuthOauthbearerOptions::default();
        let mut auth =
            SmtpAuthOauthbearer::new(&token(), Some("alice@example.com"), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn ir_success_with_ehlo_returns_ok() {
        let opts = SmtpAuthOauthbearerOptions {
            initial_request: true,
            ensure_capabilities: true,
        };
        let mut auth =
            SmtpAuthOauthbearer::new(&token(), Some("alice@example.com"), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ehlo = expect_wants_write(&mut auth, Some(b"235 OK\r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"250 server.example.com\r\n");
    }

    #[test]
    fn ir_success_without_ehlo_returns_ok() {
        let opts = SmtpAuthOauthbearerOptions {
            initial_request: true,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthOauthbearer::new(&token(), None, domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn error_detail_returns_rejected() {
        let opts = SmtpAuthOauthbearerOptions {
            initial_request: true,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthOauthbearer::new(&token(), None, domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let challenge = b"334 eyJzdGF0dXMiOiI0MDEifQ==\r\n";
        let _ack = expect_wants_write(&mut auth, Some(challenge));
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"535 authentication failed\r\n");
        let SmtpAuthOauthbearerError::Rejected { code, message } = err else {
            panic!("expected SmtpAuthOauthbearerError::Rejected, got {err:?}");
        };
        assert_eq!(code, 535);
        assert!(message.contains("status") || message.contains("401"));
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let opts = SmtpAuthOauthbearerOptions::default();
        let mut auth = SmtpAuthOauthbearer::new(&token(), None, domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"504 mechanism disabled\r\n");
        let SmtpAuthOauthbearerError::Rejected { code, .. } = err else {
            panic!("expected SmtpAuthOauthbearerError::Rejected, got {err:?}");
        };
        assert_eq!(code, 504);
    }

    #[test]
    fn eof_returns_eof_error() {
        let opts = SmtpAuthOauthbearerOptions::default();
        let mut auth = SmtpAuthOauthbearer::new(&token(), None, domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"");
        assert!(matches!(
            err,
            SmtpAuthOauthbearerError::Send(SmtpCommandSendError::Eof)
        ));
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
