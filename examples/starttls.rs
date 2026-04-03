use std::{env, net::TcpStream, sync::Arc};

use io_smtp::{
    rfc3207::starttls::{SmtpStartTls, SmtpStartTlsResult},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloResult},
        greeting::{GetSmtpGreeting, GetSmtpGreetingResult},
        types::{domain::Domain, ehlo_domain::EhloDomain},
    },
};
use io_socket::runtimes::std_stream::handle;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port: u16 = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let mut stream = TcpStream::connect((host.as_str(), port)).unwrap();

    // Read greeting.
    let mut coroutine = GetSmtpGreeting::new();
    let mut arg = None;

    let greeting = loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::Ok { greeting } => break greeting,
            GetSmtpGreetingResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            GetSmtpGreetingResult::Err { err } => panic!("{err}"),
        }
    };

    println!("greeting: {greeting:#?}");

    // Send EHLO to get capabilities (including STARTTLS).
    let domain: EhloDomain<'_> = Domain::parse(b"localhost").unwrap().into();
    let mut coroutine = SmtpEhlo::new(domain);
    let mut arg = None;

    let capabilities = loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { capabilities } => break capabilities,
            SmtpEhloResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            SmtpEhloResult::Err { err } => panic!("{err}"),
        }
    };

    println!("capabilities: {capabilities:#?}");

    // Send STARTTLS.
    let mut coroutine = SmtpStartTls::new();
    let mut arg = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpStartTlsResult::Ok => break,
            SmtpStartTlsResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            SmtpStartTlsResult::Err { err } => panic!("{err}"),
        }
    }

    println!("STARTTLS successful, upgrading to TLS...");

    // Upgrade the plain TCP stream to TLS.
    let server_name = rustls::pki_types::ServerName::try_from(host.clone()).unwrap();
    let config = ClientConfig::with_platform_verifier().unwrap();
    let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls_stream = StreamOwned::new(conn, stream);

    // Send EHLO again after TLS upgrade.
    let domain: EhloDomain<'_> = Domain::parse(b"localhost").unwrap().into();
    let mut coroutine = SmtpEhlo::new(domain);
    let mut arg = None;

    let capabilities = loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { capabilities } => break capabilities,
            SmtpEhloResult::Io { input } => {
                arg = Some(handle(&mut tls_stream, input).unwrap());
            }
            SmtpEhloResult::Err { err } => panic!("{err}"),
        }
    };

    println!("capabilities after TLS: {capabilities:#?}");
}
