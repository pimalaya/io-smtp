//! SMTP RCPT TO coroutine; declares one recipient.
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
//!     rfc5321::{
//!         rcpt::SmtpRcpt,
//!         types::{
//!             domain::SmtpDomain, ehlo_domain::SmtpEhloDomain, forward_path::SmtpForwardPath,
//!             local_part::SmtpLocalPart, mailbox::SmtpMailbox,
//!         },
//!     },
//! };
//!
//! // Ready stream needed (TCP-connected, TLS-negociated, MAIL FROM accepted)
//! let mut stream = TcpStream::connect("localhost:25").unwrap();
//!
//! let mut buf = [0u8; 4096];
//!
//! let forward_path = SmtpForwardPath(SmtpMailbox {
//!     local_part: SmtpLocalPart(Cow::Borrowed("alice")),
//!     domain: SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com"))),
//! });
//! let mut coroutine = SmtpRcpt::new(forward_path, Vec::new());
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
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::types::{
        forward_path::SmtpForwardPath, parameter::SmtpParameter, reply_code::SmtpReplyCode,
    },
    send::*,
    smtp_try,
};

/// The RCPT TO command (RFC 5321 §4.1.1.3).
pub struct SmtpRcptCommand<'a> {
    /// The recipient's forward path.
    pub forward_path: SmtpForwardPath<'a>,
    /// Optional ESMTP parameters (e.g. DSN `NOTIFY=`, `ORCPT=`).
    pub parameters: Vec<SmtpParameter<'a>>,
}

impl<'a> From<SmtpRcptCommand<'a>> for Vec<u8> {
    fn from(cmd: SmtpRcptCommand<'a>) -> Vec<u8> {
        let mut buf = String::from("RCPT TO:");
        buf.push_str(&cmd.forward_path.to_string());
        for p in cmd.parameters {
            buf.push(' ');
            buf.push_str(&p.to_string());
        }
        buf.push_str("\r\n");
        buf.into_bytes()
    }
}

/// Failure causes during the SMTP RCPT TO exchange.
#[derive(Clone, Debug, Error)]
pub enum SmtpRcptError {
    /// The server rejected the RCPT TO command.
    #[error("SMTP RCPT TO failed: rejected {code} {message}")]
    Rejected {
        /// The reply code.
        code: u16,
        /// The reply text.
        message: String,
    },
    /// The underlying command exchange failed.
    #[error("SMTP RCPT TO failed: {0}")]
    Send(#[from] SmtpCommandSendError),
}

/// I/O-free SMTP RCPT TO coroutine.
pub struct SmtpRcpt {
    state: State,
}

impl SmtpRcpt {
    /// Pass an empty `parameters` vector for the bare `RCPT TO`
    /// form; non-empty entries are appended after the forward path
    /// (e.g. DSN `NOTIFY=`, `ORCPT=`).
    pub fn new(forward_path: SmtpForwardPath<'_>, parameters: Vec<SmtpParameter<'_>>) -> Self {
        let cmd = SmtpRcptCommand {
            forward_path: forward_path.into_static(),
            parameters: parameters.into_iter().map(|p| p.into_static()).collect(),
        };

        Self {
            state: State::Send(SmtpCommandSend::new(cmd)),
        }
    }
}

impl SmtpCoroutine for SmtpRcpt {
    type Yield = SmtpYield;
    type Return = Result<(), SmtpRcptError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        match &mut self.state {
            State::Send(send) => {
                let out = smtp_try!(send, arg);

                if out.response.code == SmtpReplyCode::OK
                    || out.response.code == SmtpReplyCode::USER_NOT_LOCAL_WILL_FORWARD
                {
                    debug!("rcpt to accepted");
                    return SmtpCoroutineState::Complete(Ok(()));
                }

                let code = out.response.code.code();
                let message = out.response.text().to_string();
                SmtpCoroutineState::Complete(Err(SmtpRcptError::Rejected { code, message }))
            }
        }
    }
}

enum State {
    Send(SmtpCommandSend<SmtpRcptCommand<'static>>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => f.write_str("send rcpt to"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, vec::Vec};

    use crate::{
        coroutine::*,
        rfc5321::{
            rcpt::*,
            types::{
                domain::SmtpDomain, ehlo_domain::SmtpEhloDomain, forward_path::SmtpForwardPath,
                local_part::SmtpLocalPart, mailbox::SmtpMailbox,
            },
        },
        send::SmtpCommandSendError,
    };

    fn forward_path() -> SmtpForwardPath<'static> {
        SmtpForwardPath(SmtpMailbox {
            local_part: SmtpLocalPart(Cow::Borrowed("alice")),
            domain: SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("example.com"))),
        })
    }

    #[test]
    fn success_returns_ok() {
        let mut rcpt = SmtpRcpt::new(forward_path(), Vec::new());

        let bytes = expect_wants_write(&mut rcpt, None);
        assert!(bytes.starts_with(b"RCPT TO:"));

        expect_wants_read(&mut rcpt);
        expect_complete_ok(&mut rcpt, b"250 recipient ok\r\n");
    }

    #[test]
    fn forwarded_returns_ok() {
        let mut rcpt = SmtpRcpt::new(forward_path(), Vec::new());
        let _ = expect_wants_write(&mut rcpt, None);
        expect_wants_read(&mut rcpt);

        expect_complete_ok(&mut rcpt, b"251 user not local, forwarding\r\n");
    }

    #[test]
    fn rejected_returns_rejected_error() {
        let mut rcpt = SmtpRcpt::new(forward_path(), Vec::new());
        let _ = expect_wants_write(&mut rcpt, None);
        expect_wants_read(&mut rcpt);

        let err = expect_complete_err(&mut rcpt, b"550 no such user\r\n");
        let SmtpRcptError::Rejected { code, message } = err else {
            panic!("expected SmtpRcptError::Rejected, got {err:?}");
        };
        assert_eq!(code, 550);
        assert_eq!(message, "no such user");
    }

    #[test]
    fn eof_returns_eof_error() {
        let mut rcpt = SmtpRcpt::new(forward_path(), Vec::new());
        let _ = expect_wants_write(&mut rcpt, None);
        expect_wants_read(&mut rcpt);

        let err = expect_complete_err(&mut rcpt, b"");
        assert!(matches!(
            err,
            SmtpRcptError::Send(SmtpCommandSendError::Eof)
        ));
    }

    fn expect_wants_write(cor: &mut SmtpRcpt, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn expect_wants_read(cor: &mut SmtpRcpt) {
        match cor.resume(None) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn expect_complete_ok(cor: &mut SmtpRcpt, reply: &[u8]) {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn expect_complete_err(cor: &mut SmtpRcpt, reply: &[u8]) -> SmtpRcptError {
        match cor.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }
}
