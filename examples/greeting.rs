use std::{env, net::TcpStream, sync::Arc};

use io_smtp::{context::SmtpContext, coroutines::greeting_with_capability::*};
use io_stream::runtimes::std::handle;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let context = SmtpContext::new();

    let stream = TcpStream::connect((host.as_str(), port)).unwrap();
    let server_name = host.try_into().unwrap();
    let config = ClientConfig::with_platform_verifier().unwrap();
    let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut stream = StreamOwned::new(conn, stream);

    let mut coroutine = GetSmtpGreetingWithCapability::new(context);
    let mut arg = None;

    let context = loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingWithCapabilityResult::Ok { context } => break context,
            GetSmtpGreetingWithCapabilityResult::Io { io } => {
                arg = Some(handle(&mut stream, io).unwrap())
            }
            GetSmtpGreetingWithCapabilityResult::Err { err, .. } => panic!("{err}"),
        }
    };

    println!("context: {context:#?}");
}
