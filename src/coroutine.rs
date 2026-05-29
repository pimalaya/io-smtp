//! # Generator-shape coroutine driver
//!
//! Mirrors the shape of `core::ops::Coroutine`: a `Yield` associated
//! type for intermediate progress, a `Return` associated type for
//! terminal output, and a two-variant [`SmtpCoroutineState`]
//! (`Yielded` / `Complete`).
//!
//! Each coroutine declares its own `Yield` enum mixing socket I/O step
//! requests with any extra intermediate variants (e.g.
//! [`SmtpStartTlsYield::WantsStartTls`]). Most request/response
//! coroutines pick the standard [`SmtpYield`] directly; only coroutines
//! that need extra variants declare their own.
//!
//! [`SmtpClientStd::run`] drives any standard-Yield coroutine to
//! completion against a blocking stream; coroutines that need extra
//! Yield variants get their own per-method client loops.
//!
//! [`SmtpClientStd::run`]: crate::client::SmtpClientStd::run
//! [`SmtpStartTlsYield::WantsStartTls`]: crate::rfc3207::starttls::SmtpStartTlsYield::WantsStartTls

use alloc::vec::Vec;

/// State yielded by an [`SmtpCoroutine::resume`] step.
///
/// Two-variant by design (matches std's `core::ops::CoroutineState`):
/// any further variation lives inside the per-coroutine `Yield` type.
#[derive(Debug)]
pub enum SmtpCoroutineState<Y, R> {
    /// Intermediate yield. The driver reacts to `Y` (do I/O, perform a
    /// TLS upgrade, etc.) and resumes the coroutine again.
    Yielded(Y),
    /// Terminal yield. By convention `R = Result<Output, Error>`.
    Complete(R),
}

/// Standard-shape SMTP coroutine.
///
/// Implementors own their internal state machine and declare their
/// per-step `Yield` plus a terminal `Return`. The driver pumps I/O
/// based on the `Yield` variant and resumes until `Complete`.
pub trait SmtpCoroutine {
    /// Intermediate value handed back on every step. Per-coroutine:
    /// each implementor picks exactly the variants it needs (socket
    /// I/O, TLS upgrade signals, ...).
    type Yield;
    /// Terminal value. By convention `Result<Output, Error>`; the "ok"
    /// arm carries the operation's final output, the "error" arm
    /// carries the cause.
    type Return;

    /// Advances the coroutine one step.
    ///
    /// Pass [`None`] when there is no data to provide (initial call or
    /// after the previous yield was [`SmtpYield::WantsWrite`]). Pass
    /// `Some(data)` with bytes read from the socket after a
    /// [`SmtpYield::WantsRead`]. Pass `Some(&[])` to signal EOF.
    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return>;
}

/// Standard I/O-only Yield. Pick `type Yield = SmtpYield` for any
/// coroutine that only needs to read or write socket bytes.
#[derive(Debug)]
pub enum SmtpYield {
    /// Driver should read more bytes from the socket and feed them
    /// back on the next resume.
    WantsRead,
    /// Driver should write these bytes to the socket; the next resume
    /// typically takes `None`.
    WantsWrite(Vec<u8>),
}
