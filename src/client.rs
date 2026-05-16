//! # Standard, blocking SMTP client
//!
//! Holds a single stream (any blocking `Read + Write` impl) and
//! exposes one method per common coroutine. SMTP has no long-lived
//! session context like IMAP: capabilities are returned by
//! [`greeting`] / [`ehlo`] and consumed by the caller, and each
//! coroutine is otherwise stateless.
//!
//! The bare [`new`] constructor takes a pre-connected stream; callers
//! handle TCP and TLS themselves. With one of the TLS feature flags
//! enabled (`rustls-ring`, `rustls-aws`, `native-tls`), [`connect`] is
//! also available and produces a ready-to-use authenticated client
//! end-to-end: it opens the transport (plain TCP for `smtp://`,
//! implicit TLS for `smtps://`), reads the greeting, sends the
//! initial EHLO, optionally performs the STARTTLS upgrade and a fresh
//! EHLO over TLS, then runs the chosen SASL mechanism if one was
//! provided.
//!
//! [`new`]: SmtpClientStd::new
//! [`connect`]: SmtpClientStd::connect
//! [`greeting`]: SmtpClientStd::greeting
//! [`ehlo`]: SmtpClientStd::ehlo

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use std::string::{String, ToString};
use std::{
    io::{self, Read, Write},
    vec::Vec,
};

use alloc::borrow::Cow;
use secrecy::SecretString;
use thiserror::Error;

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
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use url::Url;

#[cfg(feature = "scram")]
use crate::rfc7677::scram_sha256::*;
use crate::{
    login::*,
    rfc3207::starttls::*,
    rfc4505::anonymous::*,
    rfc4616::plain::*,
    rfc5321::{
        data::*,
        ehlo::*,
        greeting::*,
        helo::*,
        mail::*,
        noop::*,
        quit::*,
        rcpt::*,
        rset::*,
        types::{
            domain::Domain, ehlo_domain::EhloDomain, forward_path::ForwardPath, greeting::Greeting,
            parameter::Parameter, reverse_path::ReversePath,
        },
    },
    rfc7628::{oauthbearer::*, xoauth2::*},
    send::*,
};

const READ_BUFFER_SIZE: usize = 16 * 1024;

/// Errors returned by [`SmtpClientStd`].
#[derive(Debug, Error)]
pub enum SmtpClientStdError {
    #[error(transparent)]
    Greeting(#[from] GetSmtpGreetingError),
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
    #[error(transparent)]
    Helo(#[from] SmtpHeloError),
    #[error(transparent)]
    StartTls(#[from] SmtpStartTlsError),

    #[error(transparent)]
    AuthAnonymous(#[from] SmtpAnonymousError),
    #[error(transparent)]
    AuthLogin(#[from] SmtpLoginError),
    #[error(transparent)]
    AuthPlain(#[from] SmtpPlainError),
    #[error(transparent)]
    AuthOAuthBearer(#[from] SmtpOauthbearerError),
    #[error(transparent)]
    AuthXOAuth2(#[from] SmtpXoauth2Error),
    #[cfg(feature = "scram")]
    #[error(transparent)]
    AuthScramSha256(#[from] SmtpScramSha256Error),
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[cfg(not(feature = "scram"))]
    #[error("SCRAM-SHA-256 SASL mechanism requires the `scram` cargo feature")]
    ScramSha256NotEnabled,

    #[error(transparent)]
    Mail(#[from] SmtpMailError),
    #[error(transparent)]
    Rcpt(#[from] SmtpRcptError),
    #[error(transparent)]
    Data(#[from] SmtpDataError),
    #[error(transparent)]
    Noop(#[from] SmtpNoopError),
    #[error(transparent)]
    Rset(#[from] SmtpRsetError),
    #[error(transparent)]
    Quit(#[from] SmtpQuitError),
    #[error(transparent)]
    MessageSend(#[from] SmtpMessageSendError),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error(transparent)]
    Tls(#[from] anyhow::Error),
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error("SMTP URL `{0}` has no host")]
    UrlMissingHost(String),
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error("SMTP URL `{0}` has unsupported scheme `{1}` (expected `smtp` or `smtps`)")]
    UrlUnsupportedScheme(String, String),
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error("STARTTLS requested on an `smtps://` URL: TLS is already active")]
    StartTlsOverTls,
}

/// Output of [`SmtpClientStd::greeting`]: the parsed greeting line
/// plus any bytes read past it that the caller may need to re-feed.
pub type SmtpGreetingOutput = (Greeting<'static>, Vec<u8>);

/// Output of [`SmtpClientStd::ehlo`]: the raw capability strings (one
/// entry per EHLO continuation line) plus any bytes read past the
/// final reply line.
pub type SmtpEhloOutput = (Vec<Cow<'static, str>>, Vec<u8>);

/// Std-blocking SMTP client wrapping a single `Read + Write` stream.
pub struct SmtpClientStd<S: Read + Write> {
    stream: S,
}

/// Drive a coroutine whose `Result` enum is unit-shaped on success
/// (`Ok`, `WantsRead`, `WantsWrite(Vec<u8>)`, `Err(<error>)`).
macro_rules! coroutine {
    ($self:ident, $coroutine:expr, $Result:ident) => {{
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;
        let mut coroutine = $coroutine;

        loop {
            match coroutine.resume(arg) {
                $Result::Ok => return Ok(()),
                $Result::WantsRead => {
                    let n = $self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                $Result::WantsWrite(bytes) => {
                    $self.stream.write_all(&bytes)?;
                    arg = None;
                }
                $Result::Err(err) => return Err(err.into()),
            }
        }
    }};
}

impl<S: Read + Write> SmtpClientStd<S> {
    /// Builds a client around `stream`. The caller is responsible for
    /// opening the connection (TCP, TLS handshake if needed, STARTTLS
    /// upgrade if needed).
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Returns a shared reference to the underlying stream.
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Returns an exclusive reference to the underlying stream.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the client and returns its underlying stream. Useful
    /// after [`starttls`] to perform a TLS upgrade on the raw stream
    /// before rebuilding a fresh client around it.
    ///
    /// [`starttls`]: SmtpClientStd::starttls
    pub fn into_stream(self) -> S {
        self.stream
    }

    // ---- Session lifecycle -----------------------------------------------

    /// Runs [`GetSmtpGreeting`]: reads the initial server greeting.
    /// Call this once after [`new`] / [`connect`].
    ///
    /// [`new`]: SmtpClientStd::new
    /// [`connect`]: SmtpClientStd::connect
    pub fn greeting(&mut self) -> Result<SmtpGreetingOutput, SmtpClientStdError> {
        let mut coroutine = GetSmtpGreeting::new();
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg) {
                GetSmtpGreetingResult::Ok {
                    greeting,
                    remaining,
                } => return Ok((greeting, remaining)),
                GetSmtpGreetingResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                GetSmtpGreetingResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Runs [`SmtpEhlo`] (`EHLO <domain>`, RFC 5321 §4.1.1.1). Returns
    /// the raw capability lines reported by the server.
    pub fn ehlo(&mut self, domain: EhloDomain<'_>) -> Result<SmtpEhloOutput, SmtpClientStdError> {
        let mut coroutine = SmtpEhlo::new(domain);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg) {
                SmtpEhloResult::Ok {
                    capabilities,
                    remaining,
                } => return Ok((capabilities, remaining)),
                SmtpEhloResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                SmtpEhloResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
                SmtpEhloResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Runs [`SmtpHelo`] (`HELO <domain>`, RFC 5321 §4.1.1.1). Use
    /// [`ehlo`] on any modern server; fall back to HELO only if the
    /// server rejects EHLO with 500/502.
    ///
    /// [`ehlo`]: SmtpClientStd::ehlo
    pub fn helo(&mut self, domain: Domain<'_>) -> Result<(), SmtpClientStdError> {
        coroutine!(self, SmtpHelo::new(domain), SmtpHeloResult);
    }

    /// Runs [`SmtpStartTls`] (`STARTTLS`, RFC 3207). On success the
    /// caller must upgrade the underlying socket to TLS (via
    /// [`into_stream`]), then build a new client around the upgraded
    /// stream and re-issue [`ehlo`]. The returned bytes are anything
    /// the coroutine pre-read past the `220` reply (normally empty;
    /// any pre-handshake bytes are a classic STARTTLS-injection
    /// signal).
    ///
    /// [`into_stream`]: SmtpClientStd::into_stream
    /// [`ehlo`]: SmtpClientStd::ehlo
    pub fn starttls(&mut self) -> Result<Vec<u8>, SmtpClientStdError> {
        let mut coroutine = SmtpStartTls::new();
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg) {
                SmtpStartTlsResult::WantsStartTls(remaining) => return Ok(remaining),
                SmtpStartTlsResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                SmtpStartTlsResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                    arg = None;
                }
                SmtpStartTlsResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Runs [`SmtpQuit`] (`QUIT`, RFC 5321 §4.1.1.10).
    pub fn quit(&mut self) -> Result<(), SmtpClientStdError> {
        coroutine!(self, SmtpQuit::new(), SmtpQuitResult);
    }

    // ---- Authentication --------------------------------------------------

    /// Runs [`SmtpAnonymous`] (`AUTH ANONYMOUS`, RFC 4505).
    /// Refreshes the capability list with an `EHLO` after a successful
    /// authentication. The optional `trace` token is sent in
    /// cleartext for server-side logging; do not put credentials in
    /// it.
    pub fn auth_anonymous(
        &mut self,
        trace: Option<&str>,
        domain: EhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        coroutine!(self, SmtpAnonymous::new(trace, domain), SmtpAnonymousResult);
    }

    /// Runs [`SmtpLogin`] (`AUTH LOGIN`, legacy SASL mechanism).
    /// Refreshes the capability list with an `EHLO` after a successful
    /// authentication. Prefer [`auth_plain`] or [`auth_scram_sha256`]
    /// when the server supports them.
    ///
    /// [`auth_plain`]: SmtpClientStd::auth_plain
    /// [`auth_scram_sha256`]: SmtpClientStd::auth_scram_sha256
    pub fn auth_login(
        &mut self,
        login: &str,
        password: &SecretString,
        domain: EhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        coroutine!(
            self,
            SmtpLogin::new(login, password, domain),
            SmtpLoginResult
        );
    }

    /// Runs [`SmtpPlain`] (`AUTH PLAIN`, RFC 4616). Refreshes the
    /// capability list with an `EHLO` after a successful
    /// authentication.
    pub fn auth_plain(
        &mut self,
        login: &str,
        password: &SecretString,
        domain: EhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        coroutine!(
            self,
            SmtpPlain::new(login, password, domain),
            SmtpPlainResult
        );
    }

    /// Runs [`SmtpOAuthBearer`] (`AUTH OAUTHBEARER`, RFC 7628).
    /// Refreshes the capability list with an `EHLO` after a successful
    /// authentication. The `token` is an OAuth 2.0 bearer access
    /// token: the connection **must** be TLS-protected before calling
    /// this method.
    pub fn auth_oauthbearer(
        &mut self,
        token: &SecretString,
        username: Option<&str>,
        domain: EhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        coroutine!(
            self,
            SmtpOauthbearer::new(token, username, domain),
            SmtpOauthbearerResult
        );
    }

    /// Runs [`SmtpXOAuth2`] (`AUTH XOAUTH2`, Google's pre-standard
    /// OAuth 2.0 SASL mechanism). Refreshes the capability list with
    /// an `EHLO` after a successful authentication. The `token` is an
    /// OAuth 2.0 bearer access token: the connection **must** be
    /// TLS-protected before calling this method. Prefer
    /// [`auth_oauthbearer`] on servers that support both.
    ///
    /// [`auth_oauthbearer`]: SmtpClientStd::auth_oauthbearer
    pub fn auth_xoauth2(
        &mut self,
        username: &str,
        token: &SecretString,
        domain: EhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        coroutine!(
            self,
            SmtpXoauth2::new(username, token, domain),
            SmtpXoauth2Result
        );
    }

    /// Runs [`SmtpScramSha256`] (`AUTH SCRAM-SHA-256`, RFC 7677).
    /// Refreshes the capability list with an `EHLO` after a successful
    /// authentication. `nonce` must be printable ASCII (no commas);
    /// the standard recommends at least 18 bytes of cryptographic
    /// randomness.
    #[cfg(feature = "scram")]
    pub fn auth_scram_sha256(
        &mut self,
        username: &str,
        password: &SecretString,
        nonce: &[u8],
        domain: EhloDomain<'_>,
    ) -> Result<(), SmtpClientStdError> {
        coroutine!(
            self,
            SmtpScramSha256::new(username, password, nonce, domain),
            SmtpScramSha256Result
        );
    }

    // ---- Mail transaction ------------------------------------------------

    /// Runs [`SmtpMail`] (`MAIL FROM:<reverse-path>`, RFC 5321
    /// §4.1.1.2).
    pub fn mail(&mut self, reverse_path: ReversePath<'_>) -> Result<(), SmtpClientStdError> {
        coroutine!(self, SmtpMail::new(reverse_path), SmtpMailResult);
    }

    /// Runs [`SmtpMail::with_params`]: same as [`mail`] but appends
    /// ESMTP parameters (e.g. `SIZE=`, `BODY=`, DSN).
    ///
    /// [`mail`]: SmtpClientStd::mail
    pub fn mail_with_params(
        &mut self,
        reverse_path: ReversePath<'_>,
        parameters: Vec<Parameter<'_>>,
    ) -> Result<(), SmtpClientStdError> {
        coroutine!(
            self,
            SmtpMail::with_params(reverse_path, parameters),
            SmtpMailResult
        );
    }

    /// Runs [`SmtpRcpt`] (`RCPT TO:<forward-path>`, RFC 5321
    /// §4.1.1.3).
    pub fn rcpt(&mut self, forward_path: ForwardPath<'_>) -> Result<(), SmtpClientStdError> {
        coroutine!(self, SmtpRcpt::new(forward_path), SmtpRcptResult);
    }

    /// Runs [`SmtpRcpt::with_params`]: same as [`rcpt`] but appends
    /// ESMTP parameters (e.g. DSN `NOTIFY=`, `ORCPT=`).
    ///
    /// [`rcpt`]: SmtpClientStd::rcpt
    pub fn rcpt_with_params(
        &mut self,
        forward_path: ForwardPath<'_>,
        parameters: Vec<Parameter<'_>>,
    ) -> Result<(), SmtpClientStdError> {
        coroutine!(
            self,
            SmtpRcpt::with_params(forward_path, parameters),
            SmtpRcptResult
        );
    }

    /// Runs [`SmtpData`] (`DATA` + body terminator, RFC 5321
    /// §4.1.1.4). The coroutine handles dot-stuffing automatically.
    pub fn data(&mut self, message: Vec<u8>) -> Result<(), SmtpClientStdError> {
        coroutine!(self, SmtpData::new(message), SmtpDataResult);
    }

    /// Runs [`SmtpRset`] (`RSET`, RFC 5321 §4.1.1.5). Aborts the
    /// current mail transaction.
    pub fn rset(&mut self) -> Result<(), SmtpClientStdError> {
        coroutine!(self, SmtpRset::new(), SmtpRsetResult);
    }

    /// Runs [`SmtpNoop`] (`NOOP`, RFC 5321 §4.1.1.9).
    pub fn noop(&mut self) -> Result<(), SmtpClientStdError> {
        coroutine!(self, SmtpNoop::new(), SmtpNoopResult);
    }

    // ---- High-level helpers ----------------------------------------------

    /// Runs [`SmtpMessageSend`]: a complete `MAIL FROM` / `RCPT TO`
    /// (one per recipient) / `DATA` exchange in one call.
    pub fn send<'a>(
        &mut self,
        reverse_path: ReversePath<'_>,
        forward_paths: impl IntoIterator<Item = ForwardPath<'a>>,
        message: Vec<u8>,
    ) -> Result<(), SmtpClientStdError> {
        coroutine!(
            self,
            SmtpMessageSend::new(reverse_path, forward_paths, message),
            SmtpMessageSendResult
        );
    }
}

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
impl SmtpClientStd<StreamStd> {
    /// Connects to `url`, reads the greeting, sends an initial EHLO,
    /// optionally performs the STARTTLS upgrade (then re-sends EHLO),
    /// and finally runs the chosen SASL mechanism.
    ///
    /// - `smtp://`  goes through plain TCP (port defaults to 25).
    /// - `smtps://` goes through implicit TLS (port defaults to 465).
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
        domain: EhloDomain<'_>,
        sasl: Option<impl Into<Sasl>>,
    ) -> Result<Self, SmtpClientStdError> {
        use bounded_static::IntoBoundedStatic;

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
        let mut client = Self::new(stream);

        client.greeting()?;
        client.ehlo(domain.clone())?;

        if starttls {
            client.starttls()?;
            let upgraded = client.into_stream().upgrade_tls(tls)?;
            client = Self::new(upgraded);
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
                    use rand::{Rng, distributions::Alphanumeric, thread_rng};

                    let nonce = thread_rng()
                        .sample_iter(&Alphanumeric)
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
