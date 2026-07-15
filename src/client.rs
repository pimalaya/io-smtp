//! # Standard, blocking SMTP client
//!
//! Holds a single stream (any blocking `Read + Write` impl) and exposes one
//! method per common coroutine. SMTP has no long-lived session context like
//! IMAP: capabilities are returned by [`greeting`] / [`ehlo`] and consumed by
//! the caller, and each coroutine is otherwise stateless.
//!
//! The bare [`new`] constructor takes a pre-connected stream; callers handle
//! TCP and TLS themselves. With one of the TLS feature flags enabled
//! (`rustls-ring`, `rustls-aws`, `native-tls`), [`connect`] is also available
//! and produces a ready-to-use authenticated client end-to-end: it opens the
//! transport (plain TCP for `smtp://`, implicit TLS for `smtps://`), reads the
//! greeting, sends the initial EHLO, optionally performs the STARTTLS upgrade
//! and a fresh EHLO over TLS, then runs the chosen SASL mechanism if one was
//! provided.
//!
//! [`new`]: SmtpClientStd::new
//! [`connect`]: SmtpClientStd::connect
//! [`greeting`]: SmtpClientStd::greeting
//! [`ehlo`]: SmtpClientStd::ehlo

use core::{any::Any, fmt};

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use alloc::string::ToString;
use alloc::{borrow::Cow, boxed::Box, string::String, vec, vec::Vec};

use std::io::{self, Read, Write};

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use bounded_static::IntoBoundedStatic;
#[cfg(feature = "scram")]
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use pimalaya_stream::sasl::SaslScramSha256;
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use pimalaya_stream::{
    sasl::{Sasl, SaslAnonymous, SaslLogin, SaslOauthbearer, SaslPlain, SaslXoauth2},
    std::stream::StreamStd,
    tls::Tls,
};
#[cfg(feature = "scram")]
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use rand::{RngExt, distr::Alphanumeric, rng};
use secrecy::SecretString;
use thiserror::Error;
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use url::Url;

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
};

/// Errors returned by [`SmtpClientStd`].
#[derive(Debug, Error)]
pub enum SmtpClientStdError {
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
    /// SCRAM-SHA-256 was requested but its cargo feature is off.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[cfg(not(feature = "scram"))]
    #[error("SCRAM-SHA-256 SASL mechanism requires the `scram` cargo feature")]
    ScramSha256NotEnabled,
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
    /// The connection URL carries no host part.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error("SMTP URL `{0}` has no host")]
    UrlMissingHost(String),
    /// The connection URL scheme is neither smtp nor smtps.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error("SMTP URL `{0}` has unsupported scheme `{1}` (expected `smtp` or `smtps`)")]
    UrlUnsupportedScheme(String, String),
    /// STARTTLS was requested on an already-TLS connection.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error("STARTTLS requested on an `smtps://` URL: TLS is already active")]
    StartTlsOverTls,
}

const READ_BUFFER_SIZE: usize = 16 * 1024;

/// Std-blocking SMTP client wrapping a single boxed stream.
pub struct SmtpClientStd {
    /// The wrapped stream every coroutine is pumped against.
    pub stream: Box<dyn SmtpStream>,
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
    pub fn default_alpn() -> Vec<String> {
        vec![String::from("smtp")]
    }

    /// Replaces the underlying stream; useful after a caller-managed TLS
    /// upgrade or reconnection.
    pub fn set_stream<S: Read + Write + Send + 'static>(&mut self, stream: S) {
        self.stream = Box::new(stream);
    }

    /// Pumps any standard-shape coroutine (`Yield = SmtpYield`, `Return =
    /// Result<Output, Error>`) against the wrapped stream until it
    /// terminates. Every coroutine in this crate (including [`SmtpStartTls`])
    /// fits this signature.
    pub fn run<C, T, E>(&mut self, mut coroutine: C) -> Result<T, SmtpClientStdError>
    where
        C: SmtpCoroutine<Yield = SmtpYield, Return = Result<T, E>>,
        SmtpClientStdError: From<E>,
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

    // NOTE: Session lifecycle methods below.

    /// Runs [`SmtpGreetingGet`]: reads the initial server greeting.  Call this
    /// once after [`new`] / [`connect`].
    ///
    /// [`new`]: SmtpClientStd::new
    /// [`connect`]: SmtpClientStd::connect
    pub fn greeting(&mut self) -> Result<SmtpGreeting<'static>, SmtpClientStdError> {
        self.run(SmtpGreetingGet::new())
    }

    /// Runs [`SmtpEhlo`] (`EHLO <domain>`, RFC 5321 §4.1.1.1). Returns the raw
    /// capability lines reported by the server.
    pub fn ehlo(
        &mut self,
        domain: SmtpEhloDomain<'_>,
    ) -> Result<Vec<Cow<'static, str>>, SmtpClientStdError> {
        self.run(SmtpEhlo::new(domain))
    }

    /// Runs [`SmtpHelo`] (`HELO <domain>`, RFC 5321 §4.1.1.1). Use [`ehlo`] on
    /// any modern server; fall back to HELO only if the server rejects EHLO
    /// with 500/502.
    ///
    /// [`ehlo`]: SmtpClientStd::ehlo
    pub fn helo(&mut self, domain: SmtpDomain<'_>) -> Result<(), SmtpClientStdError> {
        self.run(SmtpHelo::new(domain))
    }

    /// Runs [`SmtpStartTls`] (`STARTTLS`, RFC 3207). On success the caller must
    /// upgrade the underlying socket to TLS (via [`StreamStd::upgrade_tls`]),
    /// then build a new client around the upgraded stream and re-issue
    /// [`ehlo`]. The returned bytes are anything the coroutine pre-read past
    /// the `220` reply (normally empty; any pre-handshake bytes are a classic
    /// STARTTLS-injection signal).
    ///
    /// [`StreamStd::upgrade_tls`]: pimalaya_stream::std::stream::StreamStd::upgrade_tls
    /// [`ehlo`]: SmtpClientStd::ehlo
    pub fn starttls(&mut self) -> Result<Vec<u8>, SmtpClientStdError> {
        self.run(SmtpStartTls::new())
    }

    /// Runs [`SmtpQuit`] (`QUIT`, RFC 5321 §4.1.1.10).
    pub fn quit(&mut self) -> Result<(), SmtpClientStdError> {
        self.run(SmtpQuit::new())
    }

    // NOTE: Authentication methods below.

    /// Runs [`SmtpAuthAnonymous`] (`AUTH ANONYMOUS`, RFC 4505).  Refreshes the
    /// capability list with an `EHLO` after a successful authentication. The
    /// optional `trace` token is sent in cleartext for server-side logging; do
    /// not put credentials in it.
    pub fn auth_anonymous(
        &mut self,
        trace: Option<&str>,
        domain: SmtpEhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        self.run(SmtpAuthAnonymous::new(
            trace,
            domain,
            SmtpAuthAnonymousOptions::default(),
        ))
    }

    /// Runs [`SmtpAuthLogin`] (`AUTH LOGIN`, legacy SASL mechanism).  Refreshes
    /// the capability list with an `EHLO` after a successful
    /// authentication. Prefer [`auth_plain`] or [`auth_scram_sha256`] when the
    /// server supports them.
    ///
    /// [`auth_plain`]: SmtpClientStd::auth_plain
    /// [`auth_scram_sha256`]: SmtpClientStd::auth_scram_sha256
    pub fn auth_login(
        &mut self,
        login: &str,
        password: &SecretString,
        domain: SmtpEhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        self.run(SmtpAuthLogin::new(
            login,
            password,
            domain,
            SmtpAuthLoginOptions::default(),
        ))
    }

    /// Runs [`SmtpAuthPlain`] (`AUTH PLAIN`, RFC 4616). Refreshes the
    /// capability list with an `EHLO` after a successful authentication.
    pub fn auth_plain(
        &mut self,
        login: &str,
        password: &SecretString,
        domain: SmtpEhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        self.run(SmtpAuthPlain::new(
            login,
            password,
            domain,
            SmtpAuthPlainOptions::default(),
        ))
    }

    /// Runs [`SmtpAuthOauthbearer`] (`AUTH OAUTHBEARER`, RFC 7628).  Refreshes
    /// the capability list with an `EHLO` after a successful
    /// authentication. The `token` is an OAuth 2.0 bearer access token: the
    /// connection **must** be TLS-protected before calling this method.
    pub fn auth_oauthbearer(
        &mut self,
        token: &SecretString,
        username: Option<&str>,
        domain: SmtpEhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        self.run(SmtpAuthOauthbearer::new(
            token,
            username,
            domain,
            SmtpAuthOauthbearerOptions::default(),
        ))
    }

    /// Runs [`SmtpAuthXoauth2`] (`AUTH XOAUTH2`, Google's pre-standard OAuth
    /// 2.0 SASL mechanism). Refreshes the capability list with an `EHLO` after
    /// a successful authentication. The `token` is an OAuth 2.0 bearer access
    /// token: the connection **must** be TLS-protected before calling this
    /// method. Prefer [`auth_oauthbearer`] on servers that support both.
    ///
    /// [`auth_oauthbearer`]: SmtpClientStd::auth_oauthbearer
    pub fn auth_xoauth2(
        &mut self,
        username: &str,
        token: &SecretString,
        domain: SmtpEhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        self.run(SmtpAuthXoauth2::new(
            username,
            token,
            domain,
            SmtpAuthXoauth2Options::default(),
        ))
    }

    /// Runs [`SmtpAuthScramSha256`] (`AUTH SCRAM-SHA-256`, RFC 7677).
    /// Refreshes the capability list with an `EHLO` after a successful
    /// authentication. `nonce` must be printable ASCII (no commas); the
    /// standard recommends at least 18 bytes of cryptographic randomness.
    #[cfg(feature = "scram")]
    pub fn auth_scram_sha256(
        &mut self,
        username: &str,
        password: &SecretString,
        nonce: &[u8],
        domain: SmtpEhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        self.run(SmtpAuthScramSha256::new(
            username,
            password,
            nonce,
            domain,
            SmtpAuthScramSha256Options::default(),
        ))
    }

    // NOTE: Mail transaction methods below.

    /// Runs [`SmtpMail`] (`MAIL FROM:<reverse-path>`, RFC 5321
    /// §4.1.1.2). Pass an empty `parameters` vector for the bare
    /// form, non-empty entries for ESMTP parameters (e.g. `SIZE=`,
    /// `BODY=`, DSN).
    pub fn mail(
        &mut self,
        reverse_path: SmtpReversePath<'_>,
        parameters: Vec<SmtpParameter<'_>>,
    ) -> Result<(), SmtpClientStdError> {
        self.run(SmtpMail::new(reverse_path, parameters))
    }

    /// Runs [`SmtpRcpt`] (`RCPT TO:<forward-path>`, RFC 5321
    /// §4.1.1.3). Pass an empty `parameters` vector for the bare
    /// form, non-empty entries for ESMTP parameters (e.g. DSN
    /// `NOTIFY=`, `ORCPT=`).
    pub fn rcpt(
        &mut self,
        forward_path: SmtpForwardPath<'_>,
        parameters: Vec<SmtpParameter<'_>>,
    ) -> Result<(), SmtpClientStdError> {
        self.run(SmtpRcpt::new(forward_path, parameters))
    }

    /// Runs [`SmtpData`] (`DATA` + body terminator, RFC 5321
    /// §4.1.1.4). The coroutine handles dot-stuffing automatically.
    pub fn data(&mut self, message: Vec<u8>) -> Result<(), SmtpClientStdError> {
        self.run(SmtpData::new(message))
    }

    /// Runs [`SmtpRset`] (`RSET`, RFC 5321 §4.1.1.5). Aborts the
    /// current mail transaction.
    pub fn rset(&mut self) -> Result<(), SmtpClientStdError> {
        self.run(SmtpRset::new())
    }

    /// Runs [`SmtpNoop`] (`NOOP`, RFC 5321 §4.1.1.9).
    pub fn noop(&mut self) -> Result<(), SmtpClientStdError> {
        self.run(SmtpNoop::new())
    }

    /// Runs [`SmtpRaw`]: sends an arbitrary command line (without the
    /// trailing CRLF) and returns the server reply verbatim. Reserved
    /// for simple request/reply commands; do not use for DATA or
    /// STARTTLS, which switch the stream into a different mode.
    pub fn raw(
        &mut self,
        command: impl Into<Cow<'static, str>>,
    ) -> Result<String, SmtpClientStdError> {
        self.run(SmtpRaw::new(command))
    }

    // NOTE: High-level helpers below.

    /// Runs [`SmtpMessageSend`]: a complete `MAIL FROM` / `RCPT TO`
    /// (one per recipient) / `DATA` exchange in one call.
    pub fn send<'a>(
        &mut self,
        reverse_path: SmtpReversePath<'_>,
        forward_paths: impl IntoIterator<Item = SmtpForwardPath<'a>>,
        message: Vec<u8>,
    ) -> Result<(), SmtpClientStdError> {
        self.run(SmtpMessageSend::new(reverse_path, forward_paths, message))
    }
}

impl fmt::Debug for SmtpClientStd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpClientStd").finish_non_exhaustive()
    }
}

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
impl SmtpClientStd {
    /// Connects to `url`, reads the greeting, sends an initial EHLO,
    /// optionally performs the STARTTLS upgrade (then re-sends EHLO),
    /// and finally runs the chosen SASL mechanism.
    ///
    /// - `smtp://`  goes through plain TCP (port defaults to 25).
    /// - `smtps://` goes through implicit TLS (port defaults to 465).
    /// - `tls` carries the rustls/native-tls knobs *and* the ALPN list
    ///   (see [`Self::default_alpn`] for the SMTP-conformant `["smtp"]`).
    ///   Set `tls.rustls.alpn` to an empty vec to skip ALPN.
    /// - `starttls = true` (only valid on `smtp://`) performs the SMTP
    ///   `STARTTLS` upgrade and runs a fresh EHLO over TLS.
    /// - `domain` is the client identifier sent in EHLO (typically
    ///   the sending host's name or an address literal).
    /// - `sasl` is the optional SASL mechanism. Accepts anything that
    ///   converts into a [`Sasl`], so callers can pass the
    ///   per-mechanism struct directly (e.g. `Some(SaslPlain { .. })`)
    ///   without wrapping it in a [`Sasl`] variant. Supported
    ///   mechanisms: [`SaslAnonymous`] (RFC 4505), [`SaslLogin`]
    ///   (legacy two-prompt LOGIN), [`SaslPlain`] (RFC 4616),
    ///   [`SaslOauthbearer`] (RFC 7628), [`SaslXoauth2`] (Google),
    ///   and [`SaslScramSha256`] (RFC 7677, behind the `scram` cargo
    ///   feature). Pass [`None`] to skip authentication.
    ///
    /// Returns a fully authenticated client ready to issue further
    /// commands.
    pub fn connect(
        url: &Url,
        tls: &Tls,
        starttls: bool,
        domain: SmtpEhloDomain<'_>,
        sasl: Option<impl Into<Sasl>>,
    ) -> Result<Self, SmtpClientStdError> {
        let Some(host) = url.host_str() else {
            return Err(SmtpClientStdError::UrlMissingHost(url.to_string()));
        };

        let (stream, is_tls) = match url.scheme() {
            scheme if scheme.eq_ignore_ascii_case("smtp") => (
                StreamStd::connect_tcp(host, url.port().unwrap_or(25))?,
                false,
            ),
            scheme if scheme.eq_ignore_ascii_case("smtps") => (
                StreamStd::connect_tls(host, url.port().unwrap_or(465), tls)?,
                true,
            ),
            scheme => {
                let url = url.to_string();
                let scheme = scheme.to_string();
                return Err(SmtpClientStdError::UrlUnsupportedScheme(url, scheme));
            }
        };

        if starttls && is_tls {
            return Err(SmtpClientStdError::StartTlsOverTls);
        }

        let domain = domain.into_static();

        // NOTE: STARTTLS needs the concrete StreamStd to call
        // upgrade_tls after the SMTP-layer handshake; once boxed
        // there is no way back to the concrete type. Run greeting +
        // the initial EHLO (and optionally STARTTLS) inline against
        // the raw stream, upgrade if requested, then build the boxed
        // client.
        let stream = {
            let mut stream = stream;
            run_smtp_inline(&mut stream, SmtpGreetingGet::new())?;
            run_smtp_inline(&mut stream, SmtpEhlo::new(domain.clone()))?;
            if starttls {
                run_smtp_inline(&mut stream, SmtpStartTls::new())?;
                stream.upgrade_tls(tls)?
            } else {
                stream
            }
        };

        let mut client = Self::new(stream);

        if starttls {
            client.ehlo(domain.clone())?;
        }

        if let Some(sasl) = sasl.map(Into::into) {
            match sasl {
                Sasl::Anonymous(SaslAnonymous { message }) => {
                    client.auth_anonymous(message.as_deref(), domain.clone())?;
                }
                Sasl::Login(SaslLogin { username, password }) => {
                    client.auth_login(&username, &password, domain.clone())?;
                }
                Sasl::Plain(SaslPlain {
                    authzid: _,
                    authcid,
                    passwd,
                }) => {
                    client.auth_plain(&authcid, &passwd, domain.clone())?;
                }
                Sasl::Oauthbearer(SaslOauthbearer {
                    username,
                    host: _,
                    port: _,
                    token,
                }) => {
                    client.auth_oauthbearer(&token, Some(&username), domain.clone())?;
                }
                Sasl::Xoauth2(SaslXoauth2 { username, token }) => {
                    client.auth_xoauth2(&username, &token, domain.clone())?;
                }
                #[cfg(feature = "scram")]
                Sasl::ScramSha256(SaslScramSha256 { username, password }) => {
                    let nonce = rng()
                        .sample_iter(Alphanumeric)
                        .take(24)
                        .collect::<Vec<u8>>();
                    client.auth_scram_sha256(&username, &password, &nonce, domain.clone())?;
                }
                #[cfg(not(feature = "scram"))]
                Sasl::ScramSha256(_) => {
                    return Err(SmtpClientStdError::ScramSha256NotEnabled);
                }
            }
        }

        Ok(client)
    }
}

/// Pumps any standard-shape SMTP coroutine inline against a concrete
/// [`StreamStd`]. Used by [`SmtpClientStd::connect`] to run greeting +
/// the pre-STARTTLS EHLO before boxing the stream; the boxed
/// [`SmtpClientStd::stream`] hides the concrete type that
/// [`StreamStd::upgrade_tls`] needs.
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
fn run_smtp_inline<C, T, E>(
    stream: &mut StreamStd,
    mut coroutine: C,
) -> Result<T, SmtpClientStdError>
where
    C: SmtpCoroutine<Yield = SmtpYield, Return = Result<T, E>>,
    SmtpClientStdError: From<E>,
{
    let mut buf = [0u8; READ_BUFFER_SIZE];
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(out)) => return Ok(out),
            SmtpCoroutineState::Complete(Err(err)) => return Err(err.into()),
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes)?;
            }
        }
    }
}

/// Marker for everything the client can run against; auto-implemented for any
/// blocking `Read + Write + Send + 'static` impl. The `Send` supertrait flows
/// the auto-trait through the `Box<dyn SmtpStream>` type erasure so
/// `SmtpClientStd` can travel between threads.  [`as_any_mut`] lets specialized
/// callers (e.g. byte-level proxies that need [`StreamStd::set_read_timeout`])
/// downcast the boxed stream back to its concrete type.
///
/// [`as_any_mut`]: SmtpStream::as_any_mut
/// [`StreamStd::set_read_timeout`]: pimalaya_stream::std::stream::StreamStd::set_read_timeout
pub trait SmtpStream: Read + Write + Send + Any {
    /// Downcasts the boxed stream back to its concrete type.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: Read + Write + Send + Any> SmtpStream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
