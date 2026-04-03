use std::{env, net::TcpStream, sync::Arc};

use io_smtp::rfc5321::greeting::{GetSmtpGreeting, GetSmtpGreetingResult};
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

    let tcp = TcpStream::connect((host.as_str(), port)).unwrap();
    let server_name = rustls::pki_types::ServerName::try_from(host.clone()).unwrap();
    let config = ClientConfig::with_platform_verifier().unwrap();
    let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut stream = StreamOwned::new(conn, tcp);

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
}
