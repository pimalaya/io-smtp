//! Base coroutine that every higher-level SMTP coroutine delegates
//! to: serialises a command, drives read/write, and feeds the reply
//! back through [`Response::is_complete`] / [`Response::parse`].

use core::{fmt, marker::PhantomData, mem};

use alloc::{string::String, vec::Vec};

use bounded_static::IntoBoundedStatic;
use log::trace;
use thiserror::Error;

use crate::{
    coroutine::*,
    rfc5321::types::response::Response,
    utils::{escape_byte_string, parsers::format_rich_errors},
};

/// Failure causes raised by [`SendSmtpCommand`].
#[derive(Clone, Debug, Error)]
pub enum SendSmtpCommandError {
    #[error("Reached unexpected EOF on SMTP stream")]
    Eof,
    #[error("Parse SMTP response error: {0}")]
    ParseResponse(String),
}

/// Successful step output emitted on [`SendSmtpCommand`] completion.
pub struct SendSmtpCommandOk {
    /// The parsed reply (possibly multi-line).
    pub response: Response<'static>,
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
pub struct SendSmtpCommand<Cmd> {
    bytes: Option<Vec<u8>>,
    state: State,
    wants_read: bool,
    buf: Vec<u8>,
    _cmd: PhantomData<Cmd>,
}

impl<Cmd: Into<Vec<u8>>> SendSmtpCommand<Cmd> {
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

impl<Cmd> SmtpCoroutine for SendSmtpCommand<Cmd> {
    type Yield = SmtpYield;
    type Return = Result<SendSmtpCommandOk, SendSmtpCommandError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            trace!("send: {}", self.state);

            if mem::take(&mut self.wants_read) {
                return SmtpCoroutineState::Yielded(SmtpYield::WantsRead);
            }

            match &mut self.state {
                State::Write => {
                    let bytes = self.bytes.take().expect("command bytes taken twice");
                    self.state = State::Read;
                    return SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes));
                }
                State::Read => match arg.take() {
                    Some(&[]) => {
                        return SmtpCoroutineState::Complete(Err(SendSmtpCommandError::Eof));
                    }
                    Some(data) => {
                        trace!("read SMTP bytes: {}", escape_byte_string(data));
                        self.buf.extend_from_slice(data);

                        if !Response::is_complete(&self.buf) {
                            self.wants_read = true;
                            continue;
                        }

                        self.state = State::Parse;
                    }
                    None => {
                        self.wants_read = true;
                    }
                },
                State::Parse => {
                    return match Response::parse(&self.buf) {
                        Ok(response) => {
                            let response = response.into_static();
                            let _ = mem::take(&mut self.buf);
                            SmtpCoroutineState::Complete(Ok(SendSmtpCommandOk { response }))
                        }
                        Err(errors) => {
                            let reason = format_rich_errors(errors);
                            let err = SendSmtpCommandError::ParseResponse(reason);
                            SmtpCoroutineState::Complete(Err(err))
                        }
                    };
                }
            }
        }
    }
}
