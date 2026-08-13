//! End-to-end connect for the std client, the half that needs a TLS
//! provider.
//!
//! The module is gated once where it is declared, so nothing inside
//! repeats the feature list. It holds [`SmtpClientStd::connect`] and the
//! one decision the coroutines cannot make for themselves: drawing a
//! SCRAM client nonce when the caller supplied none.

use alloc::{borrow::Cow, vec::Vec};

use std::io::{self, Read, Write};

use io_sasl::mechanism::Sasl;
#[cfg(feature = "scram")]
use io_sasl::rfc5802::SaslScramCreds;
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};
#[cfg(feature = "scram")]
use rand::{RngExt, distr::Alphanumeric, rng};
use url::Url;

use crate::{
    client::{READ_BUFFER_SIZE, SmtpClientError, SmtpClientStd},
    coroutine::*,
    rfc5321::SmtpEhloDomain,
    session::*,
};

impl SmtpClientStd {
    /// End-to-end connect: TCP/TLS, greeting, EHLO, optional STARTTLS
    /// with a second EHLO, optional SASL.
    ///
    /// `smtp://` is plain TCP (25), `smtps://` is implicit TLS (465),
    /// `unix://` is a local socket reaching a proxy such as sirup.
    /// `opts.starttls = true` is only valid on a cleartext transport.
    /// `domain` is the client identifier sent in EHLO, typically the
    /// sending host name or an address literal. `tls` carries the
    /// rustls/native-tls options and the ALPN list (see
    /// [`Self::default_alpn`] for the SMTP-conformant `["smtp"]`; set
    /// `tls.rustls.alpn` to an empty vec to skip ALPN).
    ///
    /// `sasl` accepts anything converting into a [`Sasl`], so a caller
    /// passes the per-mechanism credentials directly; [`None`] skips
    /// authentication, since SMTP has no PREAUTH greeting to skip it
    /// for you. SCRAM credentials carrying an empty nonce are given one
    /// drawn here, an empty nonce being no nonce at all as far as RFC
    /// 5802 is concerned; a caller wanting its own passes it in the
    /// credentials.
    ///
    /// Every protocol decision belongs to [`SmtpSessionOpen`]; this
    /// method only answers its transport requests with [`StreamStd`].
    /// A caller on another runtime pumps the same coroutine with its
    /// own sockets.
    ///
    /// Returns the authenticated client and the capability lines
    /// reported by the last EHLO.
    pub fn connect(
        url: &Url,
        tls: &Tls,
        domain: SmtpEhloDomain<'_>,
        sasl: Option<impl Into<Sasl>>,
        opts: SmtpSessionOpenOptions,
    ) -> Result<(Self, Vec<Cow<'static, str>>), SmtpClientError> {
        let transport = SmtpSessionTransport::from_url(url)?;
        let sasl = sasl.map(Into::into).map(with_client_nonce);
        let mut session = SmtpSessionOpen::new(transport, domain, sasl, opts);
        let mut stream: Option<StreamStd> = None;
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        // NOTE: the state machine always asks for a connect before any
        // read, write or upgrade, so the stream is open by the time
        // those arrive.
        let missing = || io::Error::other("SMTP session yielded I/O before connecting");

        loop {
            match session.resume(arg.take()) {
                SmtpCoroutineState::Complete(Err(err)) => return Err(err.into()),
                SmtpCoroutineState::Complete(Ok(data)) => {
                    let stream = stream.ok_or_else(missing)?;
                    return Ok((Self::new(stream), data.capabilities));
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTcpConnect {
                    host,
                    port,
                }) => {
                    stream = Some(StreamStd::connect_tcp(host, port)?);
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTlsConnect {
                    host,
                    port,
                }) => {
                    stream = Some(StreamStd::connect_tls(host, port, tls)?);
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsUnixConnect(path)) => {
                    stream = Some(StreamStd::connect_unix(path)?);
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTlsUpgrade) => {
                    let plain = stream.take().ok_or_else(missing)?;
                    stream = Some(plain.upgrade_tls(tls)?);
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead) => {
                    let n = stream.as_mut().ok_or_else(missing)?.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsWrite(bytes)) => {
                    stream.as_mut().ok_or_else(missing)?.write_all(&bytes)?;
                }
            }
        }
    }
}

/// Draws the SCRAM-SHA-256 client nonce a caller left empty.
///
/// RFC 5802 asks for printable ASCII without commas, hence the
/// alphanumeric sample, and at least 18 bytes of randomness. The
/// coroutines take the nonce as an input so they stay free of
/// randomness; this is where the std client makes that decision.
#[cfg(feature = "scram")]
fn with_client_nonce(sasl: Sasl) -> Sasl {
    match sasl {
        Sasl::ScramSha256(creds) if creds.nonce.is_empty() => {
            let nonce = rng().sample_iter(Alphanumeric).take(24).collect();
            Sasl::ScramSha256(SaslScramCreds { nonce, ..creds })
        }
        sasl => sasl,
    }
}

/// Stands in when the scram feature is off: no mechanism reads a nonce.
#[cfg(not(feature = "scram"))]
fn with_client_nonce(sasl: Sasl) -> Sasl {
    sasl
}
