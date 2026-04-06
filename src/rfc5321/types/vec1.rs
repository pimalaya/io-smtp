//! Module dedicated to the non-empty vector.

use alloc::{vec::IntoIter, vec::Vec};
use core::fmt::{Debug, Formatter};

use bounded_static_derive::ToStatic;

/// A [`Vec`] containing >= 1 elements, i.e., a non-empty vector.
#[derive(Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Vec1<T>(pub(crate) Vec<T>);

impl<T: Debug> Debug for Vec1<T> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        self.0.fmt(f)?;
        write!(f, "+")
    }
}

impl<T> Vec1<T> {
    /// Constructs a non-empty vector without validation.
    pub(crate) fn unvalidated(inner: Vec<T>) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T> From<T> for Vec1<T> {
    fn from(value: T) -> Self {
        Vec1(vec![value])
    }
}

impl<T> IntoIterator for Vec1<T> {
    type Item = T;
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> AsRef<[T]> for Vec1<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}
