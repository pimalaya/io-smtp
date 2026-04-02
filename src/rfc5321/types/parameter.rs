//! Module dedicated to the SMTP parameter.

use std::{borrow::Cow, fmt};

use bounded_static_derive::ToStatic;

use super::atom::Atom;

/// An ESMTP parameter (keyword[=value]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Parameter<'a> {
    /// The parameter keyword
    pub keyword: Atom<'a>,
    /// The optional parameter value
    pub value: Option<Cow<'a, str>>,
}

impl fmt::Display for Parameter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{}={}", self.keyword, value),
            None => write!(f, "{}", self.keyword),
        }
    }
}
