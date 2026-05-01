use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use io_smtp::{
    rfc4616::plain::{SmtpPlain, SmtpPlainResult},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloResult},
        greeting::{GetSmtpGreeting, GetSmtpGreetingResult},
        types::{domain::Domain, ehlo_domain::EhloDomain},
    },
};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;
use secrecy::SecretString;

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
    let user = env::var("USER").expect("USER env var");
    let pass = env::var("PASS").expect("PASS env var");

    let tcp = TcpStream::connect((host.as_str(), port)).unwrap();
    let server_name = rustls::pki_types::ServerName::try_from(host.clone()).unwrap();
    let config = ClientConfig::with_platform_verifier().unwrap();
    let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut stream = StreamOwned::new(conn, tcp);

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

    // Send EHLO.
    let domain: EhloDomain<'static> = Domain::parse(b"localhost").unwrap().into();
    let mut coroutine = SmtpEhlo::new(domain.clone());
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

    // AUTH PLAIN.
    let password = SecretString::from(pass);
    let mut coroutine = SmtpPlain::new(&user, &password, domain);
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpPlainResult::Ok => break,
            SmtpPlainResult::WantsWrite(bytes) => stream.write_all(&bytes).unwrap(),
            SmtpPlainResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpPlainResult::Err(err) => panic!("{err}"),
        }
    }

    println!("AUTH PLAIN successful!");
}
