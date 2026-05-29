//! # Generic coroutine driver
//!
//! Every standard-shape coroutine in this crate exposes the same loop
//! contract: produce some bytes to write, ask for some bytes to read,
//! or terminate with success or failure. The [`SmtpCoroutine`] trait
//! unifies that contract behind a single method so a generic driver
//! ([`SmtpClientStd::run`]) can advance any coroutine without macros.
//!
//! Coroutines whose progression yields a TLS-upgrade intermediate
//! variant ([`SmtpStartTls`](crate::rfc3207::starttls::SmtpStartTls))
//! stay outside this trait and keep their own per-coroutine `Result`
//! enum.
//!
//! [`SmtpClientStd::run`]: crate::client::SmtpClientStd::run

use alloc::vec::Vec;

/// State yielded by an [`SmtpCoroutine`] resume.
///
/// Single generic enum so a generic driver can pattern match on
/// progression without naming a per-coroutine `Result` type.
#[derive(Debug)]
pub enum SmtpCoroutineState<T, E> {
    /// Coroutine terminated successfully with this payload.
    Done(T),
    /// Caller should read more bytes from the socket and feed them back
    /// on the next resume.
    WantsRead,
    /// Caller should write these bytes to the socket; the next resume
    /// typically takes `None`.
    WantsWrite(Vec<u8>),
    /// Coroutine terminated with this error.
    Err(E),
}

/// Standard-shape SMTP coroutine: anything whose progression maps onto
/// [`SmtpCoroutineState`].
///
/// `resume` is the single source of truth: each implementor's body
/// returns [`SmtpCoroutineState::Done`] / [`WantsRead`] / [`WantsWrite`]
/// / [`Err`] directly. [`SmtpClientStd::run`] drives any
/// [`SmtpCoroutine`] to completion against a blocking stream; downstream
/// code can write its own driver against the same trait.
///
/// [`SmtpClientStd::run`]: crate::client::SmtpClientStd::run
/// [`WantsRead`]: SmtpCoroutineState::WantsRead
/// [`WantsWrite`]: SmtpCoroutineState::WantsWrite
/// [`Err`]: SmtpCoroutineState::Err
pub trait SmtpCoroutine {
    /// Payload yielded on terminal success.
    type Output;
    /// Error yielded on terminal failure.
    type Error;

    /// Advances the coroutine one step.
    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Output, Self::Error>;
}
