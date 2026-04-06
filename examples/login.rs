use std::{env, net::TcpStream, sync::Arc};

use io_smtp::{
    rfc4616::plain::{SmtpPlain, SmtpPlainResult},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloResult},
        greeting::{GetSmtpGreeting, GetSmtpGreetingResult},
        types::{domain::Domain, ehlo_domain::EhloDomain},
    },
};
use io_socket::runtimes::std_stream::handle;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;
use secrecy::SecretString;

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

    // Send EHLO.
    let domain: EhloDomain<'static> = Domain::parse(b"localhost").unwrap().into();
    let mut coroutine = SmtpEhlo::new(domain.clone());
    let mut arg = None;

    let capabilities = loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { capabilities } => break capabilities,
            SmtpEhloResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            SmtpEhloResult::Err { err } => panic!("{err}"),
        }
    };

    println!("capabilities: {capabilities:#?}");

    // AUTH PLAIN.
    let password = SecretString::from(pass);
    let mut coroutine = SmtpPlain::new(&user, &password, domain);
    let mut arg = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpPlainResult::Ok => break,
            SmtpPlainResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            SmtpPlainResult::Err { err } => panic!("{err}"),
        }
    }

    println!("AUTH PLAIN successful!");
}
