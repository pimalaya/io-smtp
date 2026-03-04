use std::{env, net::TcpStream, sync::Arc};

use io_smtp::{
    context::SmtpContext,
    coroutines::{ehlo::*, greeting::*, starttls::*},
    types::core::Domain,
};
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
    let mut stream = TcpStream::connect((host.as_str(), port)).unwrap();

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

    // Send EHLO to get capabilities (including STARTTLS)
    let client_domain = Domain::try_from("localhost").unwrap();
    let mut coroutine = SmtpEhlo::new(context, client_domain.into());
    let mut arg = None;

    let (context, ehlo_response) = loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { context, response } => break (context, response),
            SmtpEhloResult::Io { io } => arg = Some(handle(&mut stream, io).unwrap()),
            SmtpEhloResult::Err { err, .. } => panic!("{err}"),
        }
    };

    println!("EHLO response: {ehlo_response:#?}");

    // Send STARTTLS
    let mut coroutine = SmtpStartTls::new(context);
    let mut arg = None;

    let context = loop {
        match coroutine.resume(arg.take()) {
            SmtpStartTlsResult::Ok { context } => break context,
            SmtpStartTlsResult::Io { io } => arg = Some(handle(&mut stream, io).unwrap()),
            SmtpStartTlsResult::Err { err, .. } => panic!("{err}"),
        }
    };

    println!("STARTTLS successful, upgrading to TLS...");

    // Upgrade to TLS
    let server_name = host.try_into().unwrap();
    let config = ClientConfig::with_platform_verifier().unwrap();
    let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut stream = StreamOwned::new(conn, stream);

    // Send EHLO again after TLS upgrade
    let client_domain = Domain::try_from("localhost").unwrap();
    let mut coroutine = SmtpEhlo::new(context, client_domain.into());
    let mut arg = None;

    let (context, ehlo_response) = loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { context, response } => break (context, response),
            SmtpEhloResult::Io { io } => arg = Some(handle(&mut stream, io).unwrap()),
            SmtpEhloResult::Err { err, .. } => panic!("{err}"),
        }
    };

    println!("EHLO after TLS: {ehlo_response:#?}");
    println!("context: {context:#?}");
}
