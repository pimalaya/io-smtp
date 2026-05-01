use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use io_smtp::rfc5321::greeting::{GetSmtpGreeting, GetSmtpGreetingResult};
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
    let mut buf = [0u8; 4096];
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    let greeting = loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::Ok { greeting, .. } => break greeting,
            GetSmtpGreetingResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                chunk = buf[..n].to_vec();
                arg = Some(&chunk);
            }
            GetSmtpGreetingResult::Err(err) => panic!("{err}"),
        }
    };

    let _ = stream.flush();
    println!("greeting: {greeting:#?}");
}
