//! Non-empty vector.
//!
//! Backs the response lines, which the grammar guarantees to carry
//! at least one entry.

use core::fmt::{self, Debug, Formatter};

use alloc::{
    vec,
    vec::{IntoIter, Vec},
};

use bounded_static_derive::ToStatic;

/// A [`Vec`] containing >= 1 elements, i.e., a non-empty vector.
#[derive(Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpVec1<T>(pub(crate) Vec<T>);

impl<T: Debug> Debug for SmtpVec1<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.0.fmt(f)?;
        write!(f, "+")
    }
}

impl<T> SmtpVec1<T> {
    /// Constructs a non-empty vector without validation.
    pub(crate) fn unvalidated(inner: Vec<T>) -> Self {
        Self(inner)
    }

    /// Unwraps the inner vector.
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T> From<T> for SmtpVec1<T> {
    fn from(value: T) -> Self {
        SmtpVec1(vec![value])
    }
}

impl<T> IntoIterator for SmtpVec1<T> {
    type Item = T;
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> AsRef<[T]> for SmtpVec1<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}
