//! SMTP SASL ANONYMOUS coroutine; supports both the non-IR and
//! SASL-IR (RFC 4954 §4) flows.
//!
//! ANONYMOUS: <https://www.rfc-editor.org/rfc/rfc4505>
//! AUTH:      <https://www.rfc-editor.org/rfc/rfc4954>
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
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
//!     rfc5321::{SmtpDomain, SmtpEhloDomain},
//!     sasl::auth_anonymous::{SmtpAuthAnonymous, SmtpAuthAnonymousOptions},
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, EHLO consumed)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("client.example.org")));
//! let opts = SmtpAuthAnonymousOptions::default();
//! let mut coroutine = SmtpAuthAnonymous::new(Some("trace@example.org"), domain, opts);
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
use secrecy::SecretBox;
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
pub const ANONYMOUS: &str = "ANONYMOUS";

/// Options for [`SmtpAuthAnonymous::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpAuthAnonymousOptions {
    /// `true` selects SASL-IR (inline trace); `false` selects the
    /// non-IR challenge-response flow.
    pub initial_request: bool,
    /// Refresh capabilities with an `EHLO` after a successful auth.
    pub ensure_capabilities: bool,
}

impl Default for SmtpAuthAnonymousOptions {
    fn default() -> Self {
        Self {
            initial_request: true,
            ensure_capabilities: true,
        }
    }
}

/// Failure causes during the SMTP AUTH ANONYMOUS exchange.
#[derive(Debug, Error)]
pub enum SmtpAuthAnonymousError {
    /// The server rejected the authentication.
    #[error("SMTP AUTH ANONYMOUS failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The server challenged despite the inline initial response.
    #[error("SMTP AUTH ANONYMOUS failed: server sent an unexpected continuation request")]
    UnexpectedContinuationRequest,
    /// The server accepted before the expected challenge.
    #[error("SMTP AUTH ANONYMOUS failed: server did not send the expected continuation request")]
    ExpectedContinuationRequest,
    /// The underlying command exchange failed.
    #[error("SMTP AUTH ANONYMOUS failed: {0}")]
    Send(#[from] SmtpCommandSendError),
    /// The post-authentication capability refresh failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
}

/// I/O-free SMTP AUTH ANONYMOUS coroutine.
pub struct SmtpAuthAnonymous {
    state: State,
    domain: Option<SmtpEhloDomain<'static>>,
    payload: Option<Vec<u8>>,
    opts: SmtpAuthAnonymousOptions,
}

impl SmtpAuthAnonymous {
    /// Pass [`None`] for an empty trace.
    pub fn new(
        trace: Option<&str>,
        domain: SmtpEhloDomain<'_>,
        opts: SmtpAuthAnonymousOptions,
    ) -> Self {
        let payload = trace.unwrap_or("").as_bytes().to_vec();

        let state = if opts.initial_request {
            let cmd = SmtpAuthCommand {
                mechanism: Cow::Borrowed(ANONYMOUS),
                initial_response: Some(SecretBox::new(payload.clone().into_boxed_slice())),
            };
            State::Send(SmtpCommandSend::new(cmd))
        } else {
            let cmd = SmtpAuthCommand {
                mechanism: Cow::Borrowed(ANONYMOUS),
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

impl SmtpCoroutine for SmtpAuthAnonymous {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpAuthAnonymousError>;

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
                            SmtpAuthAnonymousError::ExpectedContinuationRequest,
                        ));
                    }

                    if out.response.code == SmtpReplyCode::AUTH_CONTINUE {
                        if self.opts.initial_request {
                            return SmtpCoroutineState::Complete(Err(
                                SmtpAuthAnonymousError::UnexpectedContinuationRequest,
                            ));
                        }
                        let payload = self.payload.take().expect("payload taken twice");
                        let data = SmtpAuthData::r#continue(payload.into_boxed_slice());
                        self.state = State::Continue(SmtpCommandSend::new(data));
                        debug!("challenge received, sending trace");
                        continue;
                    }

                    let code = out.response.code.code();
                    let message = out.response.text().to_string();
                    return SmtpCoroutineState::Complete(Err(SmtpAuthAnonymousError::Rejected {
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
                    return SmtpCoroutineState::Complete(Err(SmtpAuthAnonymousError::Rejected {
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

impl SmtpAuthAnonymous {
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
            Self::Send(_) => f.write_str("send auth anonymous"),
            Self::Continue(_) => f.write_str("send trace"),
            Self::Ehlo(_) => f.write_str("refresh capabilities"),
            Self::Done => f.write_str("done"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::from_utf8;

    use alloc::{borrow::Cow, vec::Vec};

    use crate::{
        coroutine::*,
        rfc5321::{SmtpDomain, SmtpEhloDomain},
        sasl::auth_anonymous::*,
        send::SmtpCommandSendError,
    };

    fn domain() -> SmtpEhloDomain<'static> {
        SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com")))
    }

    #[test]
    fn ir_success_then_ehlo_returns_ok() {
        let opts = SmtpAuthAnonymousOptions::default();
        let mut auth = SmtpAuthAnonymous::new(Some("trace@example.com"), domain(), opts);

        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ehlo = expect_wants_write(&mut auth, Some(b"235 OK\r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"250 server.example.com\r\n");
    }

    #[test]
    fn ir_empty_trace_returns_ok() {
        let opts = SmtpAuthAnonymousOptions {
            initial_request: true,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthAnonymous::new(None, domain(), opts);

        let bytes = expect_wants_write(&mut auth, None);
        let line = from_utf8(&bytes).expect("utf8 command");
        assert!(line.contains("AUTH ANONYMOUS"));

        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn non_ir_success_returns_ok() {
        let opts = SmtpAuthAnonymousOptions {
            initial_request: false,
            ensure_capabilities: false,
        };
        let mut auth = SmtpAuthAnonymous::new(Some("trace@example.com"), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);
        let _ = expect_wants_write(&mut auth, Some(b"334 \r\n"));
        expect_wants_read(&mut auth);
        expect_complete_ok(&mut auth, b"235 OK\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let opts = SmtpAuthAnonymousOptions::default();
        let mut auth = SmtpAuthAnonymous::new(Some("trace@example.com"), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"535 anonymous disallowed\r\n");
        let SmtpAuthAnonymousError::Rejected { code, message } = err else {
            panic!("expected SmtpAuthAnonymousError::Rejected, got {err:?}");
        };
        assert_eq!(code, 535);
        assert_eq!(message, "anonymous disallowed");
    }

    #[test]
    fn eof_returns_eof_error() {
        let opts = SmtpAuthAnonymousOptions::default();
        let mut auth = SmtpAuthAnonymous::new(Some("trace@example.com"), domain(), opts);
        let _ = expect_wants_write(&mut auth, None);
        expect_wants_read(&mut auth);

        let err = expect_complete_err(&mut auth, b"");
        assert!(matches!(
            err,
            SmtpAuthAnonymousError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpAuthAnonymous, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpAuthAnonymous) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpAuthAnonymous, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpAuthAnonymous, reply: &[u8]) -> SmtpAuthAnonymousError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
