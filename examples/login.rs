use std::{
    env,
    io::{Read, Write},
};

use io_smtp::{
    login::*,
    rfc5321::{
        ehlo::*,
        greeting::*,
        types::{domain::Domain, ehlo_domain::EhloDomain},
    },
};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};
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

    let tls = Tls::default();
    let mut stream = StreamStd::connect_tls(&host, port, &tls).unwrap();
    let mut buf = [0u8; 16 * 1024];

    // Read greeting.
    let mut coroutine = GetSmtpGreeting::new();
    let mut arg: Option<&[u8]> = None;

    let greeting = loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::Ok { greeting, .. } => break greeting,
            GetSmtpGreetingResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            GetSmtpGreetingResult::Err(err) => panic!("{err}"),
        }
    };

    println!("greeting: {greeting:#?}");

    // Initial EHLO.
    let domain: EhloDomain<'_> = Domain::parse(b"localhost").unwrap().into();
    let mut coroutine = SmtpEhlo::new(domain.clone());
    let mut arg: Option<&[u8]> = None;

    let capabilities = loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { capabilities, .. } => break capabilities,
            SmtpEhloResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            SmtpEhloResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            SmtpEhloResult::Err(err) => panic!("{err}"),
        }
    };

    println!("capabilities pre auth: {capabilities:#?}");

    // AUTH LOGIN.
    let password = SecretString::from(pass);
    let mut coroutine = SmtpLogin::new(&user, &password, domain);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpLoginResult::Ok => break,
            SmtpLoginResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            SmtpLoginResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            SmtpLoginResult::Err(err) => panic!("{err}"),
        }
    }

    println!("AUTH LOGIN succeeded");
}
