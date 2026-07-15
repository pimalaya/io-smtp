//! Generator-shape coroutine contract. Mirrors `core::ops::Coroutine`:
//! `Yield` for intermediate progress, `Return` for terminal output,
//! [`SmtpCoroutineState`] for both.

use alloc::vec::Vec;

/// State yielded by an [`SmtpCoroutine::resume`] step.
#[derive(Debug)]
pub enum SmtpCoroutineState<Y, R> {
    /// Intermediate yield; the caller reacts and resumes.
    Yielded(Y),
    /// Terminal yield; by convention `R = Result<Output, Error>`.
    Complete(R),
}

/// Standard-shape SMTP coroutine.
pub trait SmtpCoroutine {
    /// Per-step value.
    type Yield;
    /// Terminal value; by convention `Result<Output, Error>`.
    type Return;

    /// Advances the coroutine one step. Pass `None` for the initial
    /// call or after a [`SmtpYield::WantsWrite`]; `Some(data)` after
    /// a [`SmtpYield::WantsRead`]; `Some(&[])` to signal EOF.
    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return>;
}

/// Standard I/O-only Yield; every coroutine in this crate picks it.
#[derive(Debug)]
pub enum SmtpYield {
    /// The caller should read more bytes and feed them back on
    /// resume.
    WantsRead,
    /// The caller should write these bytes; the next resume takes
    /// `None`.
    WantsWrite(Vec<u8>),
}

/// Coroutine `?`: forwards `Yielded` (via `Into`), short-circuits
/// on `Err`, evaluates to the inner `Ok` value.
#[macro_export]
macro_rules! smtp_try {
    ($coroutine:expr, $arg:expr $(,)?) => {
        match $crate::coroutine::SmtpCoroutine::resume($coroutine, $arg) {
            $crate::coroutine::SmtpCoroutineState::Yielded(y) => {
                return $crate::coroutine::SmtpCoroutineState::Yielded(y.into());
            }
            $crate::coroutine::SmtpCoroutineState::Complete(Err(err)) => {
                return $crate::coroutine::SmtpCoroutineState::Complete(Err(err.into()));
            }
            $crate::coroutine::SmtpCoroutineState::Complete(Ok(value)) => value,
        }
    };
}
