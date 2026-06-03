//! Blocking, rustls-only example: open a TCP+TLS connection by hand,
//! drive [`SmtpGreetingGet`] manually, print the server's greeting.
//! No io-smtp features required.
//!
//! Run with: `HOST=smtp.example.org cargo run --example std_coroutine`

use std::{
    env,
    error::Error,
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use io_smtp::{
    coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
    rfc5321::greeting::SmtpGreetingGet,
};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;

fn main() -> Result<(), Box<dyn Error>> {
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
    let server_name = rustls::pki_types::ServerName::try_from(host.as_str())?.to_owned();
    let tls = ClientConnection::new(config, server_name)?;
    let sock = TcpStream::connect((host.as_str(), port))?;
    let mut stream = StreamOwned::new(tls, sock);

    let mut buf = [0u8; 4096];

    let mut coroutine = SmtpGreetingGet::new();
    let mut arg = None;

    let greeting = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes)?;
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            SmtpCoroutineState::Complete(Ok(greeting)) => break greeting,
            SmtpCoroutineState::Complete(Err(err)) => return Err(err.into()),
        }
    };

    println!("{greeting:?}");

    Ok(())
}
