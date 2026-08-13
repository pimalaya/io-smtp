//! Composite session-opening coroutine: everything between a bare
//! address and an authenticated SMTP session.
//!
//! The handshake is where the protocol knowledge accumulates: which
//! transport a scheme implies, that the greeting precedes the first
//! EHLO, that STARTTLS is only offered on a cleartext transport, that
//! EHLO must be re-issued once the connection is encrypted, and that
//! every authentication exchange carries the EHLO domain along. Holding
//! all of that in a std client would put it out of reach of every other
//! runtime, so it lives here as a coroutine instead.
//!
//! Unlike a command coroutine, [`SmtpSessionOpen`] yields transport
//! requests as well as reads and writes: connect this socket, upgrade
//! that one to TLS. The caller answers them with whatever sockets its
//! runtime has, and inherits the ordering for free. A caller that skips
//! a step cannot advance, because the state machine never asks for the
//! next one.
//!
//! SMTP has no PREAUTH greeting, so authentication is skipped only when
//! no SASL mechanism is given, which is what a pre-authenticated socket
//! proxy wants.
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
//! use io_sasl::rfc4616::plain::SaslPlainCreds;
//! use io_smtp::{
//!     coroutine::{SmtpCoroutine, SmtpCoroutineState},
//!     rfc5321::{SmtpDomain, SmtpEhloDomain},
//!     session::{SmtpSessionOpen, SmtpSessionOpenOptions, SmtpSessionOpenYield, SmtpSessionTransport},
//! };
//!
//! let transport = SmtpSessionTransport::Tcp {
//!     host: String::from("localhost"),
//!     port: 25,
//! };
//!
//! let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("localhost")));
//!
//! let sasl = SaslPlainCreds {
//!     authzid: None,
//!     authcid: String::from("alice"),
//!     passwd: String::from("secret").into(),
//! };
//!
//! let mut coroutine = SmtpSessionOpen::new(
//!     transport,
//!     domain,
//!     Some(sasl),
//!     SmtpSessionOpenOptions::default(),
//! );
//!
//! let mut stream: Option<TcpStream> = None;
//! let mut buf = [0u8; 4096];
//! let mut arg = None;
//!
//! let session = loop {
//!     match coroutine.resume(arg.take()) {
//!         SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTcpConnect { host, port }) => {
//!             stream = Some(TcpStream::connect((host.as_str(), port)).unwrap());
//!         }
//!         SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsWrite(bytes)) => {
//!             stream.as_mut().unwrap().write_all(&bytes).unwrap();
//!         }
//!         SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead) => {
//!             let n = stream.as_mut().unwrap().read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         SmtpCoroutineState::Yielded(yielded) => panic!("unexpected {yielded:?} over plain TCP"),
//!         SmtpCoroutineState::Complete(Ok(session)) => break session,
//!         SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
//!     }
//! };
//!
//! println!("{:?}", session.capabilities);
//! ```

use core::fmt;

use alloc::{borrow::Cow, boxed::Box, string::String, vec, vec::Vec};

use bounded_static::IntoBoundedStatic;
use io_sasl::{
    login::SaslLoginCreds,
    mechanism::{Sasl, SaslMechanism},
    rfc4505::anonymous::SaslAnonymousCreds,
    rfc4616::plain::SaslPlainCreds,
    rfc7628::oauthbearer::SaslOauthbearerCreds,
    xoauth2::SaslXoauth2Creds,
};
use log::debug;
use thiserror::Error;
#[cfg(feature = "url")]
use url::Url;

#[cfg(feature = "scram")]
use crate::rfc7677::auth_scram_sha_256::*;
use crate::{
    coroutine::*,
    rfc3207::starttls::*,
    rfc5321::{SmtpEhloDomain, ehlo::*, greeting::*},
    rfc7628::auth_oauthbearer::*,
    sasl::{auth_anonymous::*, auth_login::*, auth_plain::*, auth_xoauth2::*},
    smtp_try,
};

/// Failure causes while opening an SMTP session.
#[derive(Debug, Error)]
pub enum SmtpSessionOpenError {
    /// STARTTLS was requested on a transport that is already TLS.
    #[error("STARTTLS requested on an already-encrypted transport: TLS is active")]
    StartTlsOverTls,
    /// The server sent bytes past the STARTTLS 220 reply.
    ///
    /// RFC 3207 §4 forbids them, so their presence means an attacker
    /// injected plaintext commands the server will replay inside the TLS
    /// session. The upgrade is refused rather than performed.
    #[error("SMTP STARTTLS reply carried trailing bytes: refusing the TLS upgrade")]
    StartTlsInjection,
    /// Credentials were given for a mechanism this crate does not
    /// frame.
    ///
    /// io-sasl computes more mechanisms than SMTP wires up here; the
    /// ones left out are named rather than silently skipped, so a
    /// caller learns which of its credentials this crate cannot use.
    #[error("{} SASL mechanism is not supported by this crate", .0.as_str())]
    UnsupportedMechanism(SaslMechanism),
    /// The URL carries no host to connect to.
    #[cfg(feature = "url")]
    #[error("SMTP URL `{0}` has no host")]
    UrlMissingHost(String),
    /// The URL scheme is none of smtp, smtps and unix.
    #[cfg(feature = "url")]
    #[error("SMTP URL `{0}` has unsupported scheme `{1}` (expected `smtp`, `smtps` or `unix`)")]
    UrlUnsupportedScheme(String, String),
    /// The greeting coroutine failed.
    #[error(transparent)]
    Greeting(#[from] SmtpGreetingGetError),
    /// The EHLO coroutine failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
    /// The STARTTLS coroutine failed.
    #[error(transparent)]
    StartTls(#[from] SmtpStartTlsError),
    /// The AUTH ANONYMOUS coroutine failed.
    #[error(transparent)]
    AuthAnonymous(#[from] SmtpAuthAnonymousError),
    /// The AUTH LOGIN coroutine failed.
    #[error(transparent)]
    AuthLogin(#[from] SmtpAuthLoginError),
    /// The AUTH PLAIN coroutine failed.
    #[error(transparent)]
    AuthPlain(#[from] SmtpAuthPlainError),
    /// The AUTH OAUTHBEARER coroutine failed.
    #[error(transparent)]
    AuthOauthbearer(#[from] SmtpAuthOauthbearerError),
    /// The AUTH XOAUTH2 coroutine failed.
    #[error(transparent)]
    AuthXoauth2(#[from] SmtpAuthXoauth2Error),
    /// The AUTH SCRAM-SHA-256 coroutine failed.
    #[cfg(feature = "scram")]
    #[error(transparent)]
    AuthScramSha256(#[from] SmtpAuthScramSha256Error),
}

/// Where and how the connection is opened.
///
/// The scheme table that maps an SMTP URL onto one of these variants is
/// protocol knowledge, so it lives here rather than in the transport
/// layer; see [`SmtpSessionTransport::from_url`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SmtpSessionTransport {
    /// Plain TCP, the `smtp://` scheme. Pair it with
    /// [`SmtpSessionOpenOptions::starttls`] to reach a TLS session.
    Tcp {
        /// The server host name.
        host: String,
        /// The server port, conventionally 25.
        port: u16,
    },
    /// Implicit TLS, the `smtps://` scheme.
    Tls {
        /// The server host name.
        host: String,
        /// The server port, conventionally 465.
        port: u16,
    },
    /// A local unix domain socket, the `unix://` scheme, typically a
    /// pre-authenticated socket proxy such as sirup.
    Unix(String),
}

#[cfg(feature = "url")]
impl SmtpSessionTransport {
    /// Reads the transport out of an SMTP URL.
    ///
    /// `smtp://` is plain TCP on port 25, `smtps://` is implicit TLS on
    /// port 465 and `unix://` is a local socket path; an explicit port
    /// in the URL wins over the default.
    pub fn from_url(url: &Url) -> Result<Self, SmtpSessionOpenError> {
        let scheme = url.scheme();

        if scheme.eq_ignore_ascii_case("unix") {
            return Ok(Self::Unix(String::from(url.path())));
        }

        let Some(host) = url.host_str() else {
            let url = String::from(url.as_str());
            return Err(SmtpSessionOpenError::UrlMissingHost(url));
        };

        let host = String::from(host);
        let port = url.port().unwrap_or_else(|| default_port(scheme));

        if scheme.eq_ignore_ascii_case("smtp") {
            Ok(Self::Tcp { host, port })
        } else if scheme.eq_ignore_ascii_case("smtps") {
            Ok(Self::Tls { host, port })
        } else {
            let scheme = String::from(scheme);
            let url = String::from(url.as_str());
            Err(SmtpSessionOpenError::UrlUnsupportedScheme(url, scheme))
        }
    }
}

/// Policy options for [`SmtpSessionOpen::new`].
///
/// The default upgrades nothing, which is what an `smtps://` transport
/// and a local socket proxy both want.
#[derive(Clone, Debug, Default)]
pub struct SmtpSessionOpenOptions {
    /// Whether to upgrade the connection with `STARTTLS` after the
    /// first EHLO. Only valid on a cleartext transport, since
    /// [`SmtpSessionTransport::Tls`] is already encrypted.
    pub starttls: bool,
}

/// An opened SMTP session.
#[derive(Clone, Debug)]
pub struct SmtpSessionOpenData {
    /// The capability lines reported by the last EHLO, the one sent
    /// over the final transport: after the STARTTLS upgrade when there
    /// was one, before authentication in every case.
    pub capabilities: Vec<Cow<'static, str>>,
}

/// Requests emitted while opening a session.
///
/// The three connect variants and the upgrade are what set this
/// coroutine apart from a command coroutine: the caller answers them
/// with its own sockets, whatever the runtime.
#[derive(Debug)]
pub enum SmtpSessionOpenYield {
    /// The caller opens a plain TCP connection and resumes.
    WantsTcpConnect {
        /// The server host name.
        host: String,
        /// The server port.
        port: u16,
    },
    /// The caller opens a TLS connection and resumes.
    WantsTlsConnect {
        /// The server host name, also the certificate name to verify.
        host: String,
        /// The server port.
        port: u16,
    },
    /// The caller connects to the unix socket at this path and resumes.
    WantsUnixConnect(String),
    /// The caller upgrades the open connection to TLS and resumes.
    ///
    /// Emitted only once the STARTTLS exchange completed cleanly; the
    /// coroutine refuses the upgrade itself when the server appended
    /// bytes to its 220 reply.
    WantsTlsUpgrade,
    /// The caller reads from its stream and resumes with the bytes.
    WantsRead,
    /// The caller writes the given bytes to its stream and resumes.
    WantsWrite(Vec<u8>),
}

impl From<SmtpYield> for SmtpSessionOpenYield {
    fn from(y: SmtpYield) -> Self {
        match y {
            SmtpYield::WantsRead => Self::WantsRead,
            SmtpYield::WantsWrite(bytes) => Self::WantsWrite(bytes),
        }
    }
}

/// I/O-free SMTP session-opening coroutine.
pub struct SmtpSessionOpen {
    state: State,
    transport: SmtpSessionTransport,
    domain: SmtpEhloDomain<'static>,
    sasl: Option<Sasl>,
    capabilities: Vec<Cow<'static, str>>,
    opts: SmtpSessionOpenOptions,
}

impl SmtpSessionOpen {
    /// Builds a session-opening coroutine reaching `transport`,
    /// identifying itself with `domain` and authenticating with `sasl`.
    ///
    /// `sasl` of `None` stops after the EHLO exchange, which is what a
    /// pre-authenticated socket proxy wants. A SCRAM exchange draws
    /// nothing here: its client nonce travels with the credentials, so
    /// this coroutine stays free of both I/O and randomness.
    pub fn new(
        transport: SmtpSessionTransport,
        domain: SmtpEhloDomain<'_>,
        sasl: Option<impl Into<Sasl>>,
        opts: SmtpSessionOpenOptions,
    ) -> Self {
        Self {
            state: State::Connect,
            transport,
            domain: domain.into_static(),
            sasl: sasl.map(Into::into),
            capabilities: Vec::new(),
            opts,
        }
    }

    /// Picks the SASL mechanism and hands it the EHLO domain, which
    /// every SMTP authentication exchange carries for its optional
    /// post-auth capability refresh.
    ///
    /// Returns `None` when there is nothing to authenticate, meaning no
    /// mechanism was given.
    fn wants_auth(&mut self) -> Result<Option<State>, SmtpSessionOpenError> {
        let Some(sasl) = self.sasl.take() else {
            return Ok(None);
        };

        let domain = self.domain.clone();

        let auth = match sasl {
            Sasl::Anonymous(SaslAnonymousCreds { message }) => {
                let opts = SmtpAuthAnonymousOptions::default();
                let trace = message.as_deref();

                Auth::Anonymous(SmtpAuthAnonymous::new(trace, domain, opts))
            }
            Sasl::Login(SaslLoginCreds { username, password }) => {
                let opts = SmtpAuthLoginOptions::default();

                Auth::Login(SmtpAuthLogin::new(&username, &password, domain, opts))
            }
            Sasl::Plain(SaslPlainCreds {
                authzid,
                authcid,
                passwd,
            }) => {
                let opts = SmtpAuthPlainOptions::default();

                Auth::Plain(SmtpAuthPlain::new(authzid, &authcid, &passwd, domain, opts))
            }
            Sasl::Oauthbearer(SaslOauthbearerCreds {
                username,
                host,
                port,
                token,
            }) => {
                let opts = SmtpAuthOauthbearerOptions::default();

                Auth::Oauthbearer(SmtpAuthOauthbearer::new(
                    &username, &host, port, &token, domain, opts,
                ))
            }
            Sasl::Xoauth2(SaslXoauth2Creds { username, token }) => {
                let opts = SmtpAuthXoauth2Options::default();

                Auth::Xoauth2(SmtpAuthXoauth2::new(&username, &token, domain, opts))
            }
            #[cfg(feature = "scram")]
            Sasl::ScramSha256(creds) => {
                let opts = SmtpAuthScramSha256Options::default();

                Auth::ScramSha256(SmtpAuthScramSha256::new(creds, domain, opts))
            }
            // NOTE: RFC 4954 frames any mechanism, but each one still
            // needs its own coroutine here, and these have none. The arm
            // also catches whatever io-sasl gains under a feature this
            // crate does not enable but another crate in the build does.
            sasl => {
                let mechanism = sasl.mechanism();
                return Err(SmtpSessionOpenError::UnsupportedMechanism(mechanism));
            }
        };

        Ok(Some(State::Auth(Box::new(auth))))
    }

    /// Terminal value, taking the capabilities observed along the way.
    fn complete(
        &mut self,
    ) -> SmtpCoroutineState<SmtpSessionOpenYield, <Self as SmtpCoroutine>::Return> {
        let data = SmtpSessionOpenData {
            capabilities: core::mem::take(&mut self.capabilities),
        };

        SmtpCoroutineState::Complete(Ok(data))
    }
}

impl SmtpCoroutine for SmtpSessionOpen {
    type Yield = SmtpSessionOpenYield;
    type Return = Result<SmtpSessionOpenData, SmtpSessionOpenError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> SmtpCoroutineState<Self::Yield, Self::Return> {
        loop {
            match &mut self.state {
                State::Connect => {
                    let is_tls = matches!(self.transport, SmtpSessionTransport::Tls { .. });

                    if self.opts.starttls && is_tls {
                        let err = SmtpSessionOpenError::StartTlsOverTls;
                        return SmtpCoroutineState::Complete(Err(err));
                    }

                    // NOTE: the transport is small and read once per
                    // session, so cloning it out beats threading an
                    // Option through the whole state machine.
                    let yielded = match &self.transport {
                        SmtpSessionTransport::Tcp { host, port } => {
                            SmtpSessionOpenYield::WantsTcpConnect {
                                host: host.clone(),
                                port: *port,
                            }
                        }
                        SmtpSessionTransport::Tls { host, port } => {
                            SmtpSessionOpenYield::WantsTlsConnect {
                                host: host.clone(),
                                port: *port,
                            }
                        }
                        SmtpSessionTransport::Unix(path) => {
                            SmtpSessionOpenYield::WantsUnixConnect(path.clone())
                        }
                    };

                    self.state = State::Greeting(SmtpGreetingGet::new());
                    debug!("{}", self.state);

                    return SmtpCoroutineState::Yielded(yielded);
                }
                State::Greeting(greeting) => {
                    // NOTE: the banner identifies the server and adds
                    // nothing to the session, unlike its IMAP
                    // counterpart which carries the capabilities and the
                    // PREAUTH signal.
                    let _ = smtp_try!(greeting, arg);

                    self.state = State::Ehlo(SmtpEhlo::new(self.domain.clone()));
                    debug!("{}", self.state);
                }
                State::Ehlo(ehlo) => {
                    self.capabilities = smtp_try!(ehlo, arg);

                    if self.opts.starttls {
                        self.state = State::StartTls(SmtpStartTls::new());
                        debug!("{}", self.state);
                        continue;
                    }

                    match self.wants_auth() {
                        Err(err) => return SmtpCoroutineState::Complete(Err(err)),
                        Ok(None) => return self.complete(),
                        Ok(Some(next)) => {
                            self.state = next;
                            debug!("{}", self.state);
                        }
                    }
                }
                State::StartTls(starttls) => {
                    let trailing = smtp_try!(starttls, arg);

                    if !trailing.is_empty() {
                        let err = SmtpSessionOpenError::StartTlsInjection;
                        return SmtpCoroutineState::Complete(Err(err));
                    }

                    self.state = State::Upgraded;
                    debug!("{}", self.state);

                    return SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTlsUpgrade);
                }
                State::Upgraded => {
                    // NOTE: RFC 3207 §4.2 invalidates the pre-upgrade
                    // capability list, so EHLO is re-issued over TLS
                    // rather than the list carried across. The greeting
                    // is not repeated: the server answers the upgrade
                    // with the TLS handshake, not a new banner.
                    self.state = State::EhloTls(SmtpEhlo::new(self.domain.clone()));
                    debug!("{}", self.state);
                }
                State::EhloTls(ehlo) => {
                    self.capabilities = smtp_try!(ehlo, arg);

                    match self.wants_auth() {
                        Err(err) => return SmtpCoroutineState::Complete(Err(err)),
                        Ok(None) => return self.complete(),
                        Ok(Some(next)) => {
                            self.state = next;
                            debug!("{}", self.state);
                        }
                    }
                }
                State::Auth(auth) => {
                    match auth.as_mut() {
                        Auth::Anonymous(auth) => smtp_try!(auth, arg),
                        Auth::Login(auth) => smtp_try!(auth, arg),
                        Auth::Plain(auth) => smtp_try!(auth, arg),
                        Auth::Oauthbearer(auth) => smtp_try!(auth, arg),
                        Auth::Xoauth2(auth) => smtp_try!(auth, arg),
                        #[cfg(feature = "scram")]
                        Auth::ScramSha256(auth) => smtp_try!(auth, arg),
                    }

                    return self.complete();
                }
            }
        }
    }
}

/// Default ALPN identifier for SMTP submission over TLS ([RFC 7595]).
///
/// [RFC 7595]: https://www.rfc-editor.org/rfc/rfc7595
pub fn default_alpn() -> Vec<String> {
    vec![String::from("smtp")]
}

/// Default SMTP port for `scheme`: 465 for `smtps`, 25 otherwise.
pub fn default_port(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("smtps") {
        465
    } else {
        25
    }
}

enum State {
    Connect,
    Greeting(SmtpGreetingGet),
    Ehlo(SmtpEhlo),
    StartTls(SmtpStartTls),
    Upgraded,
    EhloTls(SmtpEhlo),
    // NOTE: boxed because a mechanism holding its own credentials
    // dwarfs every other state, and the enum is as large as its largest
    // variant for the whole session.
    Auth(Box<Auth>),
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("open connection"),
            Self::Greeting(_) => f.write_str("read greeting"),
            Self::Ehlo(_) => f.write_str("send ehlo"),
            Self::StartTls(_) => f.write_str("send starttls"),
            Self::Upgraded => f.write_str("connection upgraded to tls"),
            Self::EhloTls(_) => f.write_str("send ehlo over tls"),
            Self::Auth(auth) => write!(f, "authenticate with {auth}"),
        }
    }
}

enum Auth {
    Anonymous(SmtpAuthAnonymous),
    Login(SmtpAuthLogin),
    Plain(SmtpAuthPlain),
    Oauthbearer(SmtpAuthOauthbearer),
    Xoauth2(SmtpAuthXoauth2),
    #[cfg(feature = "scram")]
    ScramSha256(SmtpAuthScramSha256),
}

impl fmt::Display for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous(_) => f.write_str("anonymous"),
            Self::Login(_) => f.write_str("login"),
            Self::Plain(_) => f.write_str("plain"),
            Self::Oauthbearer(_) => f.write_str("oauthbearer"),
            Self::Xoauth2(_) => f.write_str("xoauth2"),
            #[cfg(feature = "scram")]
            Self::ScramSha256(_) => f.write_str("scram-sha-256"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::{rfc5321::SmtpDomain, session::*};

    fn domain() -> SmtpEhloDomain<'static> {
        SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Borrowed("client.example.org")))
    }

    #[test]
    fn tcp_transport_yields_tcp_connect_then_greeting_and_ehlo() {
        let transport = SmtpSessionTransport::Tcp {
            host: "localhost".to_string(),
            port: 25,
        };

        let mut session =
            SmtpSessionOpen::new(transport, domain(), None::<Sasl>, Default::default());

        match session.resume(None) {
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTcpConnect { host, port }) => {
                assert_eq!(host, "localhost");
                assert_eq!(port, 25);
            }
            state => panic!("expected WantsTcpConnect, got {state:?}"),
        }

        match session.resume(None) {
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }

        let greeting = b"220 server.example.org ready\r\n";
        let command = match session.resume(Some(greeting)) {
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        assert_eq!(command, b"EHLO client.example.org\r\n");

        match session.resume(None) {
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead) => {}
            state => panic!("expected WantsRead, got {state:?}"),
        }

        let reply = b"250-server.example.org\r\n250 STARTTLS\r\n";
        match session.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(data)) => {
                assert_eq!(data.capabilities, vec![Cow::Borrowed("STARTTLS")]);
            }
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    #[test]
    fn unix_transport_yields_unix_connect() {
        let transport = SmtpSessionTransport::Unix("/run/sirup.sock".to_string());

        let mut session =
            SmtpSessionOpen::new(transport, domain(), None::<Sasl>, Default::default());

        match session.resume(None) {
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsUnixConnect(path)) => {
                assert_eq!(path, "/run/sirup.sock");
            }
            state => panic!("expected WantsUnixConnect, got {state:?}"),
        }
    }

    #[test]
    fn starttls_over_tls_fails_before_opening_a_socket() {
        let transport = SmtpSessionTransport::Tls {
            host: "localhost".to_string(),
            port: 465,
        };

        let opts = SmtpSessionOpenOptions { starttls: true };

        let mut session = SmtpSessionOpen::new(transport, domain(), None::<Sasl>, opts);

        match session.resume(None) {
            SmtpCoroutineState::Complete(Err(SmtpSessionOpenError::StartTlsOverTls)) => {}
            state => panic!("expected StartTlsOverTls, got {state:?}"),
        }
    }

    #[test]
    fn starttls_reaches_the_upgrade_then_reissues_ehlo() {
        let mut session = starttls_session();

        assert!(matches!(
            session.resume(None),
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTcpConnect { .. })
        ));
        assert!(matches!(
            session.resume(None),
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead)
        ));

        let greeting = b"220 server.example.org ready\r\n";
        assert!(matches!(
            session.resume(Some(greeting)),
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsWrite(_))
        ));
        assert!(matches!(
            session.resume(None),
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead)
        ));

        let reply = b"250-server.example.org\r\n250 STARTTLS\r\n";
        let command = match session.resume(Some(reply)) {
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        assert_eq!(command, b"STARTTLS\r\n");

        assert!(matches!(
            session.resume(None),
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead)
        ));

        let reply = b"220 go ahead\r\n";
        assert!(matches!(
            session.resume(Some(reply)),
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTlsUpgrade)
        ));

        // NOTE: the caller has swapped in the TLS stream; the coroutine
        // must now re-issue EHLO rather than trust the cleartext
        // capability list.
        let command = match session.resume(None) {
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        };

        assert_eq!(command, b"EHLO client.example.org\r\n");

        assert!(matches!(
            session.resume(None),
            SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead)
        ));

        let reply = b"250-server.example.org\r\n250 AUTH PLAIN\r\n";
        match session.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Ok(data)) => {
                assert_eq!(data.capabilities, vec![Cow::Borrowed("AUTH PLAIN")]);
            }
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    #[test]
    fn starttls_trailing_bytes_refuse_the_upgrade() {
        let mut session = starttls_session();

        session.resume(None);
        session.resume(None);
        session.resume(Some(b"220 server.example.org ready\r\n"));
        session.resume(None);
        session.resume(Some(b"250 STARTTLS\r\n"));
        session.resume(None);

        // NOTE: the injected NOOP rides in the same TCP segment as the
        // 220 reply, so the server would replay it inside the TLS
        // session.
        let reply = b"220 go ahead\r\nNOOP\r\n";
        match session.resume(Some(reply)) {
            SmtpCoroutineState::Complete(Err(SmtpSessionOpenError::StartTlsInjection)) => {}
            state => panic!("expected StartTlsInjection, got {state:?}"),
        }
    }

    #[cfg(feature = "url")]
    #[test]
    fn urls_map_onto_transports() {
        let url = Url::parse("smtp://example.org").unwrap();
        let expected = SmtpSessionTransport::Tcp {
            host: "example.org".to_string(),
            port: 25,
        };
        assert_eq!(SmtpSessionTransport::from_url(&url).unwrap(), expected);

        let url = Url::parse("smtps://example.org:1465").unwrap();
        let expected = SmtpSessionTransport::Tls {
            host: "example.org".to_string(),
            port: 1465,
        };
        assert_eq!(SmtpSessionTransport::from_url(&url).unwrap(), expected);

        let url = Url::parse("unix:///run/sirup.sock").unwrap();
        let expected = SmtpSessionTransport::Unix("/run/sirup.sock".to_string());
        assert_eq!(SmtpSessionTransport::from_url(&url).unwrap(), expected);

        let url = Url::parse("http://example.org").unwrap();
        let err = SmtpSessionTransport::from_url(&url).unwrap_err();
        assert!(matches!(
            err,
            SmtpSessionOpenError::UrlUnsupportedScheme(_, _)
        ));
    }

    fn starttls_session() -> SmtpSessionOpen {
        let transport = SmtpSessionTransport::Tcp {
            host: "localhost".to_string(),
            port: 587,
        };

        let opts = SmtpSessionOpenOptions { starttls: true };

        SmtpSessionOpen::new(transport, domain(), None::<Sasl>, opts)
    }
}
