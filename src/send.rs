//! Base coroutine that every higher-level SMTP coroutine delegates
//! to: serialises a command, runs the read/write exchange, and feeds
//! the reply through [`SmtpResponse::is_complete`] / [`SmtpResponse::parse`].

use core::{fmt, marker::PhantomData, mem};

use alloc::{string::String, vec::Vec};

use bounded_static::IntoBoundedStatic;
use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::SmtpResponse,
    utils::{escape_byte_string, parsers::format_rich_errors},
};

/// Failure causes raised by [`SmtpCommandSend`].
#[derive(Clone, Debug, Error)]
pub enum SmtpCommandSendError {
    /// The stream reached EOF before a complete reply arrived.
    #[error("Reached unexpected EOF on SMTP stream")]
    Eof,
    /// The reply could not be parsed as an SMTP response.
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Successful step output emitted on [`SmtpCommandSend`] completion.
pub struct SmtpCommandSendOk {
    /// The parsed reply (possibly multi-line).
    pub response: SmtpResponse<'static>,
}

enum State {
    Write,
    Read,
    Parse,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write => f.write_str("write command"),
            Self::Read => f.write_str("read response"),
            Self::Parse => f.write_str("parse response"),
        }
    }
}

/// I/O-free coroutine sending one SMTP command and parsing its
/// reply. `Cmd: Into<Vec<u8>>` is satisfied by every `Smtp*Command`
/// struct in this crate.
pub struct SmtpCommandSend<Cmd> {
    bytes: Option<Vec<u8>>,
    state: State,
    wants_read: bool,
    buf: Vec<u8>,
    _cmd: PhantomData<Cmd>,
}

impl<Cmd: Into<Vec<u8>>> SmtpCommandSend<Cmd> {
    /// Creates the coroutine, serialising `cmd` upfront.
    pub fn new(cmd: Cmd) -> Self {
        Self {
            bytes: Some(cmd.into()),
            state: State::Write,
            wants_read: false,
            buf: Vec::new(),
            _cmd: PhantomData,
        }
    }
}

impl<Cmd> SmtpCoroutine for SmtpCommandSend<Cmd> {
    type Yield = SmtpYield;
    type Return = Result<SmtpCommandSendOk, SmtpCommandSendError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::Yielded(SmtpYield::WantsRead);
            }

            match &mut self.state {
                State::Write => {
                    let bytes = self.bytes.take().expect("command bytes taken twice");
                    self.state = State::Read;
                    debug!("command sent, awaiting response");
                    return SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes));
                }
                State::Read => match arg.take() {
                    Some(&[]) => {
                        return SmtpCoroutineState::Complete(Err(SmtpCommandSendError::Eof));
                    }
                    Some(data) => {
                        trace!("read bytes: {}", escape_byte_string(data));
                        self.buf.extend_from_slice(data);

                        if !SmtpResponse::is_complete(&self.buf) {
                            self.wants_read = true;
                            continue;
                        }

                        self.state = State::Parse;
                        debug!("response complete, parsing");
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::Parse => {
                    return match SmtpResponse::parse(&self.buf) {
                        Ok(response) => {
                            let response = response.into_static();
                            let _ = mem::take(&mut self.buf);
                            debug!("response parsed");
                            trace!("{response:?}");
                            SmtpCoroutineState::Complete(Ok(SmtpCommandSendOk { response }))
                        }
                        Err(errors) => {
                            let reason = format_rich_errors(errors);
                            let err = SmtpCommandSendError::ParseResponse(reason);
                            SmtpCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}
