//! Full tokio session: answer every [`SmtpSessionOpen`] transport
//! request with tokio sockets and tokio-rustls, then implement
//! [`SmtpClientAsync`] over the same socket so every command comes with
//! it.
//!
//! This is the "any other runtime" case. No io-smtp TLS feature is
//! involved: the runtime, the sockets and the TLS stack belong to the
//! consumer. What stays in io-smtp is the protocol thinking, and the
//! coroutine hands it over as a checklist: which socket the URL scheme
//! implies, that the greeting precedes the first EHLO, that STARTTLS is
//! only offered on a cleartext transport, that EHLO is re-issued once
//! the connection is encrypted, and which SASL exchange the credentials
//! call for. The loop below answers requests, it decides nothing.
//!
//! Run with: `URL=smtps://smtp.example.org DOMAIN=client.example.org LOGIN=alice PASSWORD=secret cargo run --example tokio_session`
//!
//! `smtp://` opens plain TCP, `smtps://` implicit TLS and `unix://` a
//! local socket. Setting `STARTTLS=1` on an `smtp://` URL takes the
//! upgrade path. Omitting the credentials stops after the EHLO
//! exchange, which is what a pre-authenticated socket proxy wants.

use std::{borrow::Cow, env, error::Error, io, sync::Arc};

use io_sasl::{mechanism::Sasl, rfc4616::plain::SaslPlainCreds};
use io_smtp::{
    client::{SmtpClientAsync, SmtpClientError},
    coroutine::*,
    rfc5321::{SmtpDomain, SmtpEhloDomain},
    session::*,
};
use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use url::Url;

/// Read buffer, sized for line-oriented protocol traffic.
const READ_BUFFER_SIZE: usize = 16 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let url = Url::parse(&env::var("URL")?)?;
    let starttls = env::var("STARTTLS").is_ok();

    let domain = env::var("DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Owned(domain)));

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let config = ClientConfig::with_platform_verifier()?;
    let connector = TlsConnector::from(Arc::new(config));

    let sasl = env::var("LOGIN")
        .ok()
        .zip(env::var("PASSWORD").ok())
        .map(|(authcid, passwd)| SaslPlainCreds {
            authzid: None,
            authcid,
            passwd: passwd.into(),
        });

    let opts = SmtpSessionOpenOptions { starttls };

    let (mut client, capabilities) =
        SmtpClientTokio::connect(&url, &connector, domain, sasl, opts).await?;

    for capability in &capabilities {
        println!("{capability}");
    }

    // NOTE: `noop` is one of the trait's default bodies, and the future
    // it returns is Send, so a command can move onto another task. That
    // is why `run` is declared as `impl Future<..> + Send` rather than
    // written as an `async fn`: an `async fn` in a trait cannot promise
    // Send, and this spawn would stop compiling.
    tokio::spawn(async move { client.noop().await }).await??;

    Ok(())
}

/// A tokio SMTP client: a socket, and nothing else. Every command comes
/// from [`SmtpClientAsync`].
struct SmtpClientTokio {
    stream: TokioStream,
}

impl SmtpClientTokio {
    /// Opens an authenticated session at `url` by answering the
    /// coroutine's transport requests with tokio sockets.
    ///
    /// The four transport requests are the whole difference between
    /// this and a command pump: connect a TCP socket, connect a TLS
    /// one, connect a unix socket, upgrade the open one. Ordering is
    /// the coroutine's business, so a caller that gets it wrong is
    /// never asked for the next step.
    async fn connect(
        url: &Url,
        connector: &TlsConnector,
        domain: SmtpEhloDomain<'_>,
        sasl: Option<impl Into<Sasl>>,
        opts: SmtpSessionOpenOptions,
    ) -> Result<(Self, Vec<Cow<'static, str>>), Box<dyn Error>> {
        let transport = SmtpSessionTransport::from_url(url)?;
        let mut session = SmtpSessionOpen::new(transport, domain, sasl, opts);
        let mut stream: Option<TokioStream> = None;
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        // NOTE: WantsTlsUpgrade carries no payload, so the host name of
        // the plaintext connect is kept for the certificate check the
        // upgrade performs later.
        let mut tls_host = String::new();

        // NOTE: the state machine always asks for a connect before any
        // read, write or upgrade, so the socket is open by the time
        // those arrive.
        let missing = || String::from("SMTP session yielded I/O before connecting");

        loop {
            match session.resume(arg.take()) {
                SmtpCoroutineState::Complete(Err(err)) => return Err(err.into()),
                SmtpCoroutineState::Complete(Ok(data)) => {
                    let client = Self {
                        stream: stream.ok_or_else(missing)?,
                    };

                    return Ok((client, data.capabilities));
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTcpConnect {
                    host,
                    port,
                }) => {
                    let sock = TcpStream::connect((host.as_str(), port)).await?;

                    tls_host = host;
                    stream = Some(TokioStream::Tcp(sock));
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTlsConnect {
                    host,
                    port,
                }) => {
                    let name = ServerName::try_from(host.as_str())?.to_owned();
                    let sock = TcpStream::connect((host.as_str(), port)).await?;

                    stream = Some(TokioStream::Tls(Box::new(
                        connector.connect(name, sock).await?,
                    )));
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsUnixConnect(path)) => {
                    let sock = UnixStream::connect(path).await?;

                    stream = Some(TokioStream::Unix(sock));
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTlsUpgrade) => {
                    // NOTE: the STARTTLS exchange already happened and
                    // came back clean; the coroutine refuses the upgrade
                    // itself when the server appended bytes to its 220
                    // reply, so injected commands cannot ride into the
                    // TLS session.
                    let plain = stream.take().ok_or_else(missing)?;

                    stream = Some(plain.upgrade_tls(connector, &tls_host).await?);
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead) => {
                    let n = stream.as_mut().ok_or_else(missing)?.read(&mut buf).await?;

                    arg = Some(&buf[..n]);
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsWrite(bytes)) => {
                    stream
                        .as_mut()
                        .ok_or_else(missing)?
                        .write_all(&bytes)
                        .await?;
                }
            }
        }
    }
}

impl SmtpClientAsync for SmtpClientTokio {
    // NOTE: clippy asks to collapse this into an `async fn`. Refuse: an
    // `async fn` in a trait cannot state that its future is Send, and
    // that Send bound is what lets any command built on this method
    // move onto a spawned task.
    #[allow(clippy::manual_async_fn)]
    fn run<C, T, E>(
        &mut self,
        mut coroutine: C,
    ) -> impl Future<Output = Result<T, SmtpClientError>> + Send
    where
        C: SmtpCoroutine<Yield = SmtpYield, Return = Result<T, E>> + Send,
        T: Send,
        E: Send,
        SmtpClientError: From<E>,
    {
        async move {
            let mut buf = [0u8; READ_BUFFER_SIZE];
            let mut arg: Option<&[u8]> = None;

            loop {
                match coroutine.resume(arg.take()) {
                    SmtpCoroutineState::Complete(Ok(out)) => return Ok(out),
                    SmtpCoroutineState::Complete(Err(err)) => return Err(err.into()),
                    SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                        let n = self.stream.read(&mut buf).await?;

                        // NOTE: the coroutines read a zero-length chunk
                        // as the end of the connection and report it as
                        // their own EOF error, so it travels on rather
                        // than being turned into an io error here.
                        arg = Some(&buf[..n]);
                    }
                    SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                        self.stream.write_all(&bytes).await?;
                        arg = None;
                    }
                }
            }
        }
    }
}

/// The sockets [`SmtpSessionOpen`] can ask for, plus the TLS session a
/// STARTTLS upgrade swaps in.
enum TokioStream {
    /// Plain TCP, from an `smtp://` URL.
    Tcp(TcpStream),
    /// TLS, either from an `smtps://` URL or from a STARTTLS upgrade.
    ///
    /// Boxed because a rustls session is far bigger than a bare socket,
    /// and an enum is as wide as its widest variant.
    Tls(Box<TlsStream<TcpStream>>),
    /// A local unix socket, from a `unix://` URL.
    Unix(UnixStream),
}

impl TokioStream {
    /// Reads whatever the socket has, as the coroutine feeds partial
    /// reads back through its own buffer.
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf).await,
            Self::Tls(stream) => stream.read(buf).await,
            Self::Unix(stream) => stream.read(buf).await,
        }
    }

    /// Writes a whole command; a short write would desynchronise the
    /// exchange.
    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(bytes).await,
            Self::Tls(stream) => stream.write_all(bytes).await,
            Self::Unix(stream) => stream.write_all(bytes).await,
        }
    }

    /// Consumes the plaintext socket and hands it to rustls, the
    /// STARTTLS half the coroutine cannot perform itself.
    async fn upgrade_tls(
        self,
        connector: &TlsConnector,
        host: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let Self::Tcp(sock) = self else {
            let err = String::from("SMTP STARTTLS upgrade on an already-encrypted transport");
            return Err(err.into());
        };

        let name = ServerName::try_from(host)?.to_owned();
        let tls = connector.connect(name, sock).await?;

        Ok(Self::Tls(Box::new(tls)))
    }
}
