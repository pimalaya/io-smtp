use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use io_smtp::{
    rfc3207::starttls::{SmtpStartTls, SmtpStartTlsResult},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloResult},
        greeting::{GetSmtpGreeting, GetSmtpGreetingResult},
        types::{domain::Domain, ehlo_domain::EhloDomain},
    },
};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;

fn read_chunk<S: Read>(stream: &mut S, buf: &mut [u8]) -> Vec<u8> {
    let n = stream.read(buf).unwrap();
    buf[..n].to_vec()
}

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port: u16 = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let mut stream = TcpStream::connect((host.as_str(), port)).unwrap();
    let mut buf = [0u8; 4096];

    // Read greeting.
    let mut coroutine = GetSmtpGreeting::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    let greeting = loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::Ok { greeting, .. } => break greeting,
            GetSmtpGreetingResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            GetSmtpGreetingResult::Err(err) => panic!("{err}"),
        }
    };

    println!("greeting: {greeting:#?}");

    // Send EHLO to get capabilities (including STARTTLS).
    let domain: EhloDomain<'_> = Domain::parse(b"localhost").unwrap().into();
    let mut coroutine = SmtpEhlo::new(domain);
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    let capabilities = loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { capabilities, .. } => break capabilities,
            SmtpEhloResult::WantsWrite(bytes) => stream.write_all(&bytes).unwrap(),
            SmtpEhloResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpEhloResult::Err(err) => panic!("{err}"),
        }
    };

    println!("capabilities: {capabilities:#?}");

    // Send STARTTLS.
    let mut coroutine = SmtpStartTls::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    let preread = loop {
        match coroutine.resume(arg.take()) {
            SmtpStartTlsResult::WantsStartTls(remaining) => break remaining,
            SmtpStartTlsResult::WantsWrite(bytes) => stream.write_all(&bytes).unwrap(),
            SmtpStartTlsResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpStartTlsResult::Err(err) => panic!("{err}"),
        }
    };

    println!("STARTTLS successful, upgrading to TLS...");
    if !preread.is_empty() {
        eprintln!(
            "warning: {} bytes pre-read before TLS upgrade are unused",
            preread.len()
        );
    }

    // Upgrade the plain TCP stream to TLS.
    let server_name = rustls::pki_types::ServerName::try_from(host.clone()).unwrap();
    let config = ClientConfig::with_platform_verifier().unwrap();
    let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls_stream = StreamOwned::new(conn, stream);

    // Send EHLO again after TLS upgrade.
    let domain: EhloDomain<'_> = Domain::parse(b"localhost").unwrap().into();
    let mut coroutine = SmtpEhlo::new(domain);
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    let capabilities = loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { capabilities, .. } => break capabilities,
            SmtpEhloResult::WantsWrite(bytes) => tls_stream.write_all(&bytes).unwrap(),
            SmtpEhloResult::WantsRead => {
                chunk = read_chunk(&mut tls_stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpEhloResult::Err(err) => panic!("{err}"),
        }
    };

    println!("capabilities after TLS: {capabilities:#?}");
}
