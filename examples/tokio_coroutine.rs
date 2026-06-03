//! Async, tokio-rustls example: same shape as `std_coroutine` but on
//! top of `tokio::net::TcpStream` + `tokio_rustls::TlsConnector`. The
//! coroutine itself is identical; only the I/O glue changes.
//!
//! Run with: `HOST=smtp.example.org cargo run --example tokio_coroutine`

use std::{env, error::Error, sync::Arc};

use io_smtp::{
    coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
    rfc5321::greeting::SmtpGreetingGet,
};
use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let host = env::var("HOST").unwrap();
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(465);

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let config = Arc::new(ClientConfig::with_platform_verifier()?);
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(host.as_str())?.to_owned();
    let sock = TcpStream::connect((host.as_str(), port)).await?;
    let mut stream = connector.connect(server_name, sock).await?;

    let mut buf = [0u8; 4096];

    let mut coroutine = SmtpGreetingGet::new();
    let mut arg = None;

    let greeting = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).await?;
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                let n = stream.read(&mut buf).await?;
                arg = Some(&buf[..n]);
            }
            SmtpCoroutineState::Complete(Ok(greeting)) => break greeting,
            SmtpCoroutineState::Complete(Err(err)) => return Err(err.into()),
        }
    };

    println!("{greeting:?}");

    Ok(())
}
