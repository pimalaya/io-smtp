use std::{env, net::TcpStream, sync::Arc};

use io_smtp::{
    context::SmtpContext,
    coroutines::{authenticate_plain::*, ehlo::*, greeting::*},
    types::core::Domain,
};
use io_stream::runtimes::std::handle;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;
use secrecy::SecretString;

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let user = env::var("USER").expect("USER env var");
    let pass = env::var("PASS").expect("PASS env var");

    let context = SmtpContext::new();

    let stream = TcpStream::connect((host.as_str(), port)).unwrap();
    let server_name = host.try_into().unwrap();
    let config = ClientConfig::with_platform_verifier().unwrap();
    let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut stream = StreamOwned::new(conn, stream);

    // Read greeting
    let mut coroutine = GetSmtpGreeting::new(context);
    let mut arg = None;

    let (context, greeting) = loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::Ok { context, greeting } => break (context, greeting),
            GetSmtpGreetingResult::Io { io } => arg = Some(handle(&mut stream, io).unwrap()),
            GetSmtpGreetingResult::Err { err, .. } => panic!("{err}"),
        }
    };

    println!("greeting: {greeting:#?}");

    // Send EHLO
    let client_domain = Domain::try_from("localhost").unwrap();
    let mut coroutine = SmtpEhlo::new(context, client_domain.into());
    let mut arg = None;

    let context = loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Io { io } => arg = Some(handle(&mut stream, io).unwrap()),
            SmtpEhloResult::Ok { context } => break context,
            SmtpEhloResult::Err { err, .. } => panic!("{err}"),
        }
    };

    // AUTH PLAIN
    let password = SecretString::from(pass);
    let mut coroutine = SmtpAuthenticatePlain::new(context, &user, &password);
    let mut arg = None;

    let context = loop {
        match coroutine.resume(arg.take()) {
            SmtpAuthenticatePlainResult::Ok { context } => break context,
            SmtpAuthenticatePlainResult::Io { io } => arg = Some(handle(&mut stream, io).unwrap()),
            SmtpAuthenticatePlainResult::Err { err, .. } => panic!("{err}"),
        }
    };

    println!("AUTH PLAIN successful!");
    println!("context: {context:#?}");
}
