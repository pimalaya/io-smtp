//! # SMTP client surfaces
//!
//! Two traits and one implementation of them. [`SmtpClient`] and
//! [`SmtpClientAsync`] carry the command surface: implement one `run`
//! method that pumps a coroutine against your transport, and inherit
//! every command. [`SmtpClientStd`] is the opinionated blocking
//! implementation, holding a single stream (any blocking `Read + Write`
//! impl).
//!
//! SMTP has no long-lived session context like IMAP: capabilities are
//! returned by [`greeting`] / [`ehlo`] and consumed by the caller, and
//! each coroutine is otherwise stateless.
//!
//! The bare [`new`] constructor takes a pre-connected stream; callers
//! handle TCP and TLS themselves. With one of the TLS feature flags
//! enabled (`rustls-ring`, `rustls-aws`, `native-tls`), [`connect`] is
//! also available and produces a ready-to-use authenticated client
//! end-to-end. It owns no protocol logic of its own: the ordering, the
//! scheme table and the SASL dispatch all live in [`SmtpSessionOpen`],
//! and [`connect`] only answers its transport, read and write requests
//! with a [`Stream`].
//!
//! [`SmtpSessionOpen`]: crate::session::SmtpSessionOpen
//! [`Stream`]: pimalaya_stream::stream::Stream
//! [`new`]: SmtpClientStd::new
//! [`connect`]: SmtpClientStd::connect
//! [`greeting`]: SmtpClient::greeting
//! [`ehlo`]: SmtpClient::ehlo

use core::{any::Any, fmt, future::Future};

use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};

use std::io::{self, Read, Write};

#[cfg(feature = "scram")]
use io_sasl::rfc5802::SaslScramCreds;
use secrecy::SecretString;
use thiserror::Error;

#[cfg(feature = "scram")]
use crate::rfc7677::auth_scram_sha_256::*;
use crate::{
    coroutine::*,
    message::*,
    rfc3207::starttls::*,
    rfc5321::{
        SmtpDomain, SmtpEhloDomain, SmtpForwardPath, SmtpGreeting, SmtpParameter, SmtpReversePath,
        data::*, ehlo::*, greeting::*, helo::*, mail::*, noop::*, quit::*, raw::*, rcpt::*,
        rset::*,
    },
    rfc7628::auth_oauthbearer::*,
    sasl::{auth_anonymous::*, auth_login::*, auth_plain::*, auth_xoauth2::*},
    session::*,
};

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
mod connect;

/// Errors returned by the client surfaces.
#[derive(Debug, Error)]
pub enum SmtpClientError {
    /// The greeting coroutine failed.
    #[error(transparent)]
    SmtpGreeting(#[from] SmtpGreetingGetError),
    /// The EHLO coroutine failed.
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
    /// The HELO coroutine failed.
    #[error(transparent)]
    Helo(#[from] SmtpHeloError),
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
    AuthOAuthBearer(#[from] SmtpAuthOauthbearerError),
    /// The AUTH XOAUTH2 coroutine failed.
    #[error(transparent)]
    AuthXOAuth2(#[from] SmtpAuthXoauth2Error),
    /// The AUTH SCRAM-SHA-256 coroutine failed.
    #[cfg(feature = "scram")]
    #[error(transparent)]
    AuthScramSha256(#[from] SmtpAuthScramSha256Error),
    /// The session-opening coroutine failed.
    #[error(transparent)]
    SessionOpen(#[from] SmtpSessionOpenError),
    /// The MAIL FROM coroutine failed.
    #[error(transparent)]
    Mail(#[from] SmtpMailError),
    /// The RCPT TO coroutine failed.
    #[error(transparent)]
    Rcpt(#[from] SmtpRcptError),
    /// The DATA coroutine failed.
    #[error(transparent)]
    Data(#[from] SmtpDataError),
    /// The NOOP coroutine failed.
    #[error(transparent)]
    Noop(#[from] SmtpNoopError),
    /// The raw passthrough coroutine failed.
    #[error(transparent)]
    Raw(#[from] SmtpRawError),
    /// The RSET coroutine failed.
    #[error(transparent)]
    Rset(#[from] SmtpRsetError),
    /// The QUIT coroutine failed.
    #[error(transparent)]
    Quit(#[from] SmtpQuitError),
    /// The composite message send coroutine failed.
    #[error(transparent)]
    MessageSend(#[from] SmtpMessageSendError),
    /// Reading from or writing to the stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Opening the TCP connection or negotiating TLS failed.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error(transparent)]
    Tls(#[from] anyhow::Error),
    /// The implementor's own transport failed.
    ///
    /// [`SmtpClientStd`] reports I/O through [`Self::Io`]; this variant
    /// exists for implementors whose failures are something else, such
    /// as a JNI upcall or a runtime-specific socket error.
    #[error(transparent)]
    Transport(Box<dyn core::error::Error + Send + Sync>),
}

/// Emits the [`SmtpClient`] and [`SmtpClientAsync`] command surfaces
/// from a single list of delegations.
///
/// Both traits carry the same one-line bodies, differing only in
/// whether they hand back a value or a future. Writing them twice is how
/// two implementations of one thing drift apart, so the list is written
/// once and expanded twice.
macro_rules! smtp_client_commands {
    (
        $(
            $(#[$meta:meta])*
            fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $out:ty {
                $coroutine:expr
            }
        )*
    ) => {
        /// Blocking SMTP command surface: implement [`run`] and inherit
        /// every command.
        ///
        /// [`SmtpClientStd`] implements it over a `Read + Write` stream;
        /// a caller whose transport is its own (a JNI upcall bridge, a
        /// pre-authenticated proxy socket, an in-memory test double)
        /// implements the same one method and gets the rest.
        ///
        /// The `Yield = SmtpYield` bound on [`run`] is deliberate: it
        /// admits exactly the coroutines every client wraps identically.
        /// A coroutine declaring its own yield vocabulary is one
        /// implementations are expected to wire differently, so it
        /// cannot be defaulted here and is not meant to be.
        ///
        /// The trait is not dyn-compatible, because [`run`] is generic.
        /// The dynamism this crate needs lives one layer down, at
        /// [`SmtpStream`], which already spans TCP, TLS, unix sockets
        /// and foreign bridges behind a single concrete client type.
        ///
        /// [`run`]: Self::run
        pub trait SmtpClient {
            /// Runs a standard-shape coroutine to completion, fulfilling
            /// its read and write requests against the transport.
            fn run<C, T, E>(&mut self, coroutine: C) -> Result<T, SmtpClientError>
            where
                C: SmtpCoroutine<Yield = SmtpYield, Return = Result<T, E>>,
                SmtpClientError: From<E>;

            $(
                $(#[$meta])*
                fn $name(&mut self, $($arg: $ty),*) -> Result<$out, SmtpClientError> {
                    self.run($coroutine)
                }
            )*
        }

        /// Async SMTP command surface, the [`SmtpClient`] twin for
        /// callers whose transport is a future.
        ///
        /// Everything [`SmtpClient`] documents applies here, plus the
        /// `Send` bounds. They are load-bearing rather than defensive: a
        /// plain `async fn` in a trait cannot promise that the future it
        /// returns is `Send`, so anything built from the default bodies
        /// would fail to compile under `tokio::spawn`, which is the first
        /// thing a worker-spawning consumer reaches for. Declaring the
        /// return type explicitly as `impl Future<..> + Send`, with
        /// `Send` as a supertrait so `&mut Self` carries through, keeps
        /// the defaults spawnable.
        ///
        /// [`SmtpClient`] deliberately carries no such bound. A blocking
        /// call returns a value, so there is no future whose auto-traits
        /// need pinning down, and requiring `Send` there would exclude a
        /// perfectly good client built on a thread-affine handle.
        pub trait SmtpClientAsync: Send {
            /// Runs a standard-shape coroutine to completion, fulfilling
            /// its read and write requests against the transport.
            fn run<C, T, E>(
                &mut self,
                coroutine: C,
            ) -> impl Future<Output = Result<T, SmtpClientError>> + Send
            where
                C: SmtpCoroutine<Yield = SmtpYield, Return = Result<T, E>> + Send,
                T: Send,
                E: Send,
                SmtpClientError: From<E>;

            $(
                $(#[$meta])*
                fn $name(
                    &mut self,
                    $($arg: $ty),*
                ) -> impl Future<Output = Result<$out, SmtpClientError>> + Send {
                    self.run($coroutine)
                }
            )*
        }
    };
}

smtp_client_commands! {
    /// Reads the initial server greeting. Call it once on a freshly
    /// opened connection.
    fn greeting() -> SmtpGreeting<'static> {
        SmtpGreetingGet::new()
    }

    /// `EHLO <domain>` (RFC 5321 §4.1.1.1), returning the raw
    /// capability lines the server reports.
    fn ehlo(domain: SmtpEhloDomain<'static>) -> Vec<Cow<'static, str>> {
        SmtpEhlo::new(domain)
    }

    /// `HELO <domain>` (RFC 5321 §4.1.1.1).
    ///
    /// Use [`ehlo`](Self::ehlo) on any modern server; fall back to HELO
    /// only when the server rejects EHLO with 500/502.
    fn helo(domain: SmtpDomain<'static>) -> () {
        SmtpHelo::new(domain)
    }

    /// `STARTTLS` (RFC 3207).
    ///
    /// On success the caller upgrades the underlying socket to TLS,
    /// builds a new client around the upgraded stream and re-issues
    /// [`ehlo`](Self::ehlo). The returned bytes are anything the
    /// coroutine pre-read past the 220 reply: a non-empty return is a
    /// STARTTLS-injection signal, refuse the upgrade.
    fn starttls() -> Vec<u8> {
        SmtpStartTls::new()
    }

    /// `QUIT` (RFC 5321 §4.1.1.10).
    fn quit() -> () {
        SmtpQuit::new()
    }

    /// SASL `AUTH ANONYMOUS` (RFC 4505).
    ///
    /// The optional trace token is sent in cleartext for server-side
    /// logging; do not put credentials in it.
    fn auth_anonymous(trace: Option<&str>, domain: SmtpEhloDomain<'static>) -> () {
        SmtpAuthAnonymous::new(trace, domain, SmtpAuthAnonymousOptions::default())
    }

    /// SASL `AUTH LOGIN` (legacy mechanism).
    ///
    /// Prefer [`auth_plain`](Self::auth_plain) or
    /// [`auth_scram_sha256`](Self::auth_scram_sha256) when the server
    /// supports them.
    fn auth_login(
        login: &str,
        password: &SecretString,
        domain: SmtpEhloDomain<'static>,
    ) -> () {
        SmtpAuthLogin::new(login, password, domain, SmtpAuthLoginOptions::default())
    }

    /// SASL `AUTH PLAIN` (RFC 4616).
    fn auth_plain(
        authzid: Option<&str>,
        authcid: &str,
        password: &SecretString,
        domain: SmtpEhloDomain<'static>,
    ) -> () {
        SmtpAuthPlain::new(authzid, authcid, password, domain, SmtpAuthPlainOptions::default())
    }

    /// SASL `AUTH OAUTHBEARER` (RFC 7628). Channel must be
    /// TLS-protected.
    ///
    /// `host` and `port` travel verbatim in the GS2 header and should
    /// match the server the stream is connected to.
    fn auth_oauthbearer(
        username: &str,
        host: &str,
        port: u16,
        token: &SecretString,
        domain: SmtpEhloDomain<'static>,
    ) -> () {
        SmtpAuthOauthbearer::new(
            username,
            host,
            port,
            token,
            domain,
            SmtpAuthOauthbearerOptions::default(),
        )
    }

    /// SASL `AUTH XOAUTH2` (Google's pre-standard OAuth 2.0 mechanism).
    /// Channel must be TLS-protected.
    ///
    /// Prefer [`auth_oauthbearer`](Self::auth_oauthbearer) on servers
    /// supporting both.
    fn auth_xoauth2(
        username: &str,
        token: &SecretString,
        domain: SmtpEhloDomain<'static>,
    ) -> () {
        SmtpAuthXoauth2::new(username, token, domain, SmtpAuthXoauth2Options::default())
    }

    /// SASL `AUTH SCRAM-SHA-256` (RFC 7677).
    ///
    /// The credentials carry the client nonce, which RFC 5802 wants
    /// drawn from at least 18 bytes of cryptographic randomness, and the
    /// channel binding deciding whether the exchange announces
    /// `SCRAM-SHA-256` or `SCRAM-SHA-256-PLUS`.
    #[cfg(feature = "scram")]
    fn auth_scram_sha256(creds: SaslScramCreds, domain: SmtpEhloDomain<'static>) -> () {
        SmtpAuthScramSha256::new(creds, domain, SmtpAuthScramSha256Options::default())
    }

    /// `MAIL FROM:<reverse-path>` (RFC 5321 §4.1.1.2).
    ///
    /// Pass an empty `parameters` vector for the bare form, non-empty
    /// entries for ESMTP parameters (`SIZE=`, `BODY=`, DSN).
    fn mail(
        reverse_path: SmtpReversePath<'static>,
        parameters: Vec<SmtpParameter<'static>>,
    ) -> () {
        SmtpMail::new(reverse_path, parameters)
    }

    /// `RCPT TO:<forward-path>` (RFC 5321 §4.1.1.3).
    ///
    /// Pass an empty `parameters` vector for the bare form, non-empty
    /// entries for ESMTP parameters (DSN `NOTIFY=`, `ORCPT=`).
    fn rcpt(
        forward_path: SmtpForwardPath<'static>,
        parameters: Vec<SmtpParameter<'static>>,
    ) -> () {
        SmtpRcpt::new(forward_path, parameters)
    }

    /// `DATA` followed by the body terminator (RFC 5321 §4.1.1.4). The
    /// coroutine dot-stuffs the message.
    fn data(message: Vec<u8>) -> () {
        SmtpData::new(message)
    }

    /// `RSET` (RFC 5321 §4.1.1.5), aborting the current mail
    /// transaction.
    fn rset() -> () {
        SmtpRset::new()
    }

    /// `NOOP` (RFC 5321 §4.1.1.9).
    fn noop() -> () {
        SmtpNoop::new()
    }

    /// Sends an arbitrary command line (without the trailing CRLF) and
    /// returns the server reply verbatim.
    ///
    /// Reserved for simple request/reply commands: DATA and STARTTLS
    /// switch the stream into a different mode and have their own
    /// methods.
    fn raw(command: Cow<'static, str>) -> String {
        SmtpRaw::new(command)
    }

    /// A complete `MAIL FROM` / `RCPT TO` (one per recipient) / `DATA`
    /// exchange in one call.
    fn send(
        reverse_path: SmtpReversePath<'static>,
        forward_paths: Vec<SmtpForwardPath<'static>>,
        message: Vec<u8>,
    ) -> () {
        SmtpMessageSend::new(reverse_path, forward_paths, message)
    }
}

const READ_BUFFER_SIZE: usize = 16 * 1024;

// NOTE: both are protocol constants rather than client state, so they
// live next to the scheme table in the session module and stay reachable
// without the client feature. Re-exported here because config layers
// already reach for them through this path.
pub use crate::session::{default_alpn, default_port};

/// Std-blocking SMTP client wrapping a single boxed stream.
pub struct SmtpClientStd {
    /// The wrapped stream every coroutine is pumped against.
    pub stream: Box<dyn SmtpStream>,
}

impl SmtpClient for SmtpClientStd {
    fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, SmtpClientError>
    where
        C: SmtpCoroutine<Yield = SmtpYield, Return = Result<T, E>>,
        SmtpClientError: From<E>,
    {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                SmtpCoroutineState::Complete(Ok(out)) => return Ok(out),
                SmtpCoroutineState::Complete(Err(err)) => return Err(err.into()),
                SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
            }
        }
    }
}

impl SmtpClientStd {
    /// Builds a client around `stream`. The caller is responsible for opening
    /// the connection (TCP, TLS handshake if needed, STARTTLS upgrade if
    /// needed).
    pub fn new<S: Read + Write + Send + 'static>(stream: S) -> Self {
        Self {
            stream: Box::new(stream),
        }
    }

    /// Default ALPN protocol identifier offered during the TLS handshake for
    /// SMTP submission connections (RFC 7595 registers the `smtp` token).
    /// Exposed so config-based callers can use it as a serde default and so
    /// wizard/discovery code shares a single source of truth.
    ///
    /// Delegates to [`session::default_alpn`], where the protocol
    /// constants live; a caller without the client feature reaches them
    /// there.
    ///
    /// [`session::default_alpn`]: crate::session::default_alpn
    pub fn default_alpn() -> Vec<String> {
        default_alpn()
    }

    /// Default SMTP port for `scheme`: 465 for `smtps`, 25 otherwise.
    ///
    /// Delegates to [`session::default_port`], where the scheme table
    /// lives.
    ///
    /// [`session::default_port`]: crate::session::default_port
    pub fn default_port(scheme: &str) -> u16 {
        default_port(scheme)
    }

    /// Replaces the underlying stream; useful after a caller-managed TLS
    /// upgrade or reconnection.
    pub fn set_stream<S: Read + Write + Send + 'static>(&mut self, stream: S) {
        self.stream = Box::new(stream);
    }
}

impl fmt::Debug for SmtpClientStd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpClientStd").finish_non_exhaustive()
    }
}

/// Marker for everything the client can run against; auto-implemented for any
/// blocking `Read + Write + Send + 'static` impl. The `Send` supertrait flows
/// the auto-trait through the `Box<dyn SmtpStream>` type erasure so
/// `SmtpClientStd` can travel between threads.  [`as_any_mut`] lets specialized
/// callers (e.g. byte-level proxies that need [`Stream::set_read_timeout`])
/// downcast the boxed stream back to its concrete type.
///
/// [`as_any_mut`]: SmtpStream::as_any_mut
/// [`Stream::set_read_timeout`]: pimalaya_stream::stream::Stream::set_read_timeout
pub trait SmtpStream: Read + Write + Send + Any {
    /// Downcasts the boxed stream back to its concrete type.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: Read + Write + Send + Any> SmtpStream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
