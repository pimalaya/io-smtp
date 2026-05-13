//! # Standard, blocking SMTP client
//!
//! Holds a single boxed [`SmtpStream`] (any blocking `Read + Write`
//! impl) and exposes one method per common coroutine. SMTP has no
//! long-lived session context like IMAP — capabilities are returned
//! by [`greeting`] / [`ehlo`] and consumed by the caller, and each
//! coroutine is otherwise stateless.
//!
//! The bare [`new`] constructor takes a pre-connected stream —
//! callers handle TCP and TLS themselves. With one of the TLS
//! feature flags enabled (`rustls-ring`, `rustls-aws`, `native-tls`),
//! [`connect`] is also available and handles `smtp://` / `smtps://`
//! URLs end-to-end via [`pimalaya_stream::tls::upgrade_tls`].
//!
//! STARTTLS is *not* handled in [`connect`] — drive
//! [`crate::rfc3207::starttls::SmtpStartTls`] yourself, then build a
//! new client around the upgraded stream.
//!
//! [`new`]: SmtpClient::new
//! [`connect`]: SmtpClient::connect
//! [`greeting`]: SmtpClient::greeting
//! [`ehlo`]: SmtpClient::ehlo

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use alloc::string::{String, ToString};
use alloc::{borrow::Cow, boxed::Box, vec::Vec};
use std::io::{self, Read, Write};

use secrecy::SecretString;
use thiserror::Error;

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use pimalaya_stream::tls::{Tls, upgrade_tls};
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use std::net::TcpStream;
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use url::Url;

use crate::{
    login::*,
    rfc3207::starttls::*,
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
    rfc7628::oauthbearer::*,
    send::*,
};

#[cfg(feature = "scram")]
use crate::rfc7677::scram_sha256::*;

const READ_BUFFER_SIZE: usize = 16 * 1024;

/// Open marker for everything the client can drive — auto-implemented
/// for any blocking `Read + Write`.
pub trait SmtpStream: Read + Write {}
impl<T: Read + Write + ?Sized> SmtpStream for T {}

/// Errors returned by [`SmtpClient`].
#[derive(Debug, Error)]
pub enum SmtpClientError {
    #[error(transparent)]
    Greeting(#[from] GetSmtpGreetingError),
    #[error(transparent)]
    Ehlo(#[from] SmtpEhloError),
    #[error(transparent)]
    Helo(#[from] SmtpHeloError),
    #[error(transparent)]
    StartTls(#[from] SmtpStartTlsError),

    #[error(transparent)]
    Login(#[from] SmtpLoginError),
    #[error(transparent)]
    Plain(#[from] SmtpPlainError),
    #[error(transparent)]
    OAuthBearer(#[from] SmtpOAuthBearerError),
    #[cfg(feature = "scram")]
    #[error(transparent)]
    ScramSha256(#[from] SmtpScramSha256Error),

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
}

/// Output of [`SmtpClient::greeting`] — the parsed greeting line plus
/// any bytes read past the greeting that the caller should re-feed to
/// the next coroutine.
pub type SmtpGreetingOutput = (Greeting<'static>, Vec<u8>);

/// Output of [`SmtpClient::ehlo`] — the raw capability strings (one
/// entry per EHLO continuation line) plus any bytes read past the
/// final reply line that the caller should re-feed to the next
/// coroutine.
pub type SmtpEhloOutput = (Vec<Cow<'static, str>>, Vec<u8>);

/// Std-blocking SMTP client wrapping a single [`SmtpStream`].
pub struct SmtpClient {
    stream: Box<dyn SmtpStream>,
}

/// Drive a coroutine whose `Result` enum has the four variants
/// `Ok`, `WantsRead`, `WantsWrite(Vec<u8>)`, `Err(<error>)` and whose
/// `Ok` carries no payload. Returns `Ok(())` on success, propagates
/// the error otherwise.
macro_rules! drive_unit {
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

impl SmtpClient {
    /// Builds a client around `stream`. The caller is responsible
    /// for opening the connection (TCP, TLS handshake if needed,
    /// STARTTLS upgrade if needed).
    pub fn new<S: Read + Write + 'static>(stream: S) -> Self {
        Self {
            stream: Box::new(stream),
        }
    }

    /// Connects to `url` and runs the TLS handshake when the scheme
    /// is `smtps`. `smtp` URLs go through plain TCP. ALPN is set to
    /// `smtp`. STARTTLS is *not* handled here — drive
    /// [`crate::rfc3207::starttls::SmtpStartTls`] yourself, then
    /// hand the upgraded stream to [`new`].
    ///
    /// [`new`]: SmtpClient::new
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    pub fn connect(url: &Url, tls: &Tls) -> Result<Self, SmtpClientError> {
        let host = url
            .host_str()
            .ok_or_else(|| SmtpClientError::UrlMissingHost(url.to_string()))?;

        let stream: Box<dyn SmtpStream> = match url.scheme() {
            scheme if scheme.eq_ignore_ascii_case("smtp") => {
                let port = url.port().unwrap_or(25);
                Box::new(TcpStream::connect((host, port))?)
            }
            scheme if scheme.eq_ignore_ascii_case("smtps") => {
                let port = url.port().unwrap_or(465);
                let tcp = TcpStream::connect((host, port))?;
                Box::new(upgrade_tls(host, tcp, tls, &[b"smtp"])?)
            }
            scheme => {
                return Err(SmtpClientError::UrlUnsupportedScheme(
                    url.to_string(),
                    scheme.to_string(),
                ));
            }
        };

        Ok(Self { stream })
    }

    // ---- Session lifecycle ------------------------------------------------

    /// Drives [`GetSmtpGreeting`]: reads the initial server greeting.
    /// Call this once after [`new`] / [`connect`].
    ///
    /// [`new`]: SmtpClient::new
    /// [`connect`]: SmtpClient::connect
    pub fn greeting(&mut self) -> Result<SmtpGreetingOutput, SmtpClientError> {
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

    /// Drives [`SmtpEhlo`] (`EHLO <domain>`, RFC 5321 §4.1.1.1).
    /// Returns the raw capability lines reported by the server.
    pub fn ehlo(&mut self, domain: EhloDomain<'_>) -> Result<SmtpEhloOutput, SmtpClientError> {
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

    /// Drives [`SmtpHelo`] (`HELO <domain>`, RFC 5321 §4.1.1.1). Use
    /// [`ehlo`] on any modern server; fall back to HELO only if the
    /// server rejects EHLO with 500/502.
    ///
    /// [`ehlo`]: SmtpClient::ehlo
    pub fn helo(&mut self, domain: Domain<'_>) -> Result<(), SmtpClientError> {
        drive_unit!(self, SmtpHelo::new(domain), SmtpHeloResult);
    }

    /// Drives [`SmtpStartTls`] (`STARTTLS`, RFC 3207). On success the
    /// caller must upgrade the underlying socket to TLS, then build a
    /// new client around the upgraded stream and re-issue [`ehlo`].
    /// The returned bytes are anything the coroutine pre-read past the
    /// `220` reply (normally empty — any pre-handshake bytes are a
    /// classic STARTTLS-injection signal).
    ///
    /// [`ehlo`]: SmtpClient::ehlo
    pub fn starttls(&mut self) -> Result<Vec<u8>, SmtpClientError> {
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

    /// Drives [`SmtpQuit`] (`QUIT`, RFC 5321 §4.1.1.10).
    pub fn quit(&mut self) -> Result<(), SmtpClientError> {
        drive_unit!(self, SmtpQuit::new(), SmtpQuitResult);
    }

    // ---- Authentication --------------------------------------------------

    /// Drives [`SmtpLogin`] (`AUTH LOGIN`, legacy SASL mechanism).
    /// Refreshes the capability list with an `EHLO` after a successful
    /// authentication. Prefer [`auth_plain`] or [`auth_scram_sha256`]
    /// when the server supports them.
    ///
    /// [`auth_plain`]: SmtpClient::auth_plain
    /// [`auth_scram_sha256`]: SmtpClient::auth_scram_sha256
    pub fn auth_login(
        &mut self,
        login: &str,
        password: &SecretString,
        domain: EhloDomain<'_>,
    ) -> Result<(), SmtpClientError> {
        drive_unit!(
            self,
            SmtpLogin::new(login, password, domain),
            SmtpLoginResult
        );
    }

    /// Drives [`SmtpPlain`] (`AUTH PLAIN`, RFC 4616). Refreshes the
    /// capability list with an `EHLO` after a successful
    /// authentication.
    pub fn auth_plain(
        &mut self,
        login: &str,
        password: &SecretString,
        domain: EhloDomain<'_>,
    ) -> Result<(), SmtpClientError> {
        drive_unit!(
            self,
            SmtpPlain::new(login, password, domain),
            SmtpPlainResult
        );
    }

    /// Drives [`SmtpOAuthBearer`] (`AUTH OAUTHBEARER`, RFC 7628).
    /// Refreshes the capability list with an `EHLO` after a successful
    /// authentication. The `token` is an OAuth 2.0 bearer access
    /// token — the connection **must** be TLS-protected before
    /// calling this method.
    pub fn auth_oauthbearer(
        &mut self,
        token: &SecretString,
        username: Option<&str>,
        domain: EhloDomain<'_>,
    ) -> Result<(), SmtpClientError> {
        drive_unit!(
            self,
            SmtpOAuthBearer::new(token, username, domain),
            SmtpOAuthBearerResult
        );
    }

    /// Drives [`SmtpScramSha256`] (`AUTH SCRAM-SHA-256`, RFC 7677).
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
    ) -> Result<(), SmtpClientError> {
        drive_unit!(
            self,
            SmtpScramSha256::new(username, password, nonce, domain),
            SmtpScramSha256Result
        );
    }

    // ---- Mail transaction ------------------------------------------------

    /// Drives [`SmtpMail`] (`MAIL FROM:<reverse-path>`, RFC 5321
    /// §4.1.1.2).
    pub fn mail(&mut self, reverse_path: ReversePath<'_>) -> Result<(), SmtpClientError> {
        drive_unit!(self, SmtpMail::new(reverse_path), SmtpMailResult);
    }

    /// Drives [`SmtpMail::with_params`]: same as [`mail`] but appends
    /// ESMTP parameters (e.g. `SIZE=`, `BODY=`, DSN).
    ///
    /// [`mail`]: SmtpClient::mail
    pub fn mail_with_params(
        &mut self,
        reverse_path: ReversePath<'_>,
        parameters: Vec<Parameter<'_>>,
    ) -> Result<(), SmtpClientError> {
        drive_unit!(
            self,
            SmtpMail::with_params(reverse_path, parameters),
            SmtpMailResult
        );
    }

    /// Drives [`SmtpRcpt`] (`RCPT TO:<forward-path>`, RFC 5321
    /// §4.1.1.3).
    pub fn rcpt(&mut self, forward_path: ForwardPath<'_>) -> Result<(), SmtpClientError> {
        drive_unit!(self, SmtpRcpt::new(forward_path), SmtpRcptResult);
    }

    /// Drives [`SmtpRcpt::with_params`]: same as [`rcpt`] but appends
    /// ESMTP parameters (e.g. DSN `NOTIFY=`, `ORCPT=`).
    ///
    /// [`rcpt`]: SmtpClient::rcpt
    pub fn rcpt_with_params(
        &mut self,
        forward_path: ForwardPath<'_>,
        parameters: Vec<Parameter<'_>>,
    ) -> Result<(), SmtpClientError> {
        drive_unit!(
            self,
            SmtpRcpt::with_params(forward_path, parameters),
            SmtpRcptResult
        );
    }

    /// Drives [`SmtpData`] (`DATA` + body terminator, RFC 5321
    /// §4.1.1.4). The coroutine handles dot-stuffing automatically.
    pub fn data(&mut self, message: Vec<u8>) -> Result<(), SmtpClientError> {
        drive_unit!(self, SmtpData::new(message), SmtpDataResult);
    }

    /// Drives [`SmtpRset`] (`RSET`, RFC 5321 §4.1.1.5). Aborts the
    /// current mail transaction.
    pub fn rset(&mut self) -> Result<(), SmtpClientError> {
        drive_unit!(self, SmtpRset::new(), SmtpRsetResult);
    }

    /// Drives [`SmtpNoop`] (`NOOP`, RFC 5321 §4.1.1.9).
    pub fn noop(&mut self) -> Result<(), SmtpClientError> {
        drive_unit!(self, SmtpNoop::new(), SmtpNoopResult);
    }

    // ---- High-level helpers ----------------------------------------------

    /// Drives [`SmtpMessageSend`]: a complete `MAIL FROM` /
    /// `RCPT TO` (one per recipient) / `DATA` exchange in one call.
    pub fn send<'a>(
        &mut self,
        reverse_path: ReversePath<'_>,
        forward_paths: impl IntoIterator<Item = ForwardPath<'a>>,
        message: Vec<u8>,
    ) -> Result<(), SmtpClientError> {
        drive_unit!(
            self,
            SmtpMessageSend::new(reverse_path, forward_paths, message),
            SmtpMessageSendResult
        );
    }
}
