//! SMTP session context.

use std::collections::HashSet;

use smtp_codec::smtp_types::{response::Capability, state::State};

/// SMTP session context.
///
/// Maintains the state of an SMTP session, including capabilities
/// advertised by the server and authentication status.
#[derive(Debug)]
pub struct SmtpContext {
    /// Current session state.
    pub state: State,
    /// Server capabilities from EHLO response.
    pub capability: HashSet<Capability<'static>>,
    /// Whether the session is authenticated.
    pub authenticated: bool,
}

impl SmtpContext {
    /// Creates a new SMTP context in the initial Connect state.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for SmtpContext {
    fn default() -> Self {
        Self {
            state: State::Connect,
            capability: HashSet::new(),
            authenticated: false,
        }
    }
}
