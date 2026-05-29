use std::{
    env,
    io::{Read, Write},
};

use io_smtp::{
    coroutine::*,
    rfc3207::starttls::*,
    rfc5321::{
        ehlo::*,
        greeting::*,
        types::{domain::Domain, ehlo_domain::EhloDomain},
    },
};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let mut stream = StreamStd::connect_tcp(&host, port).unwrap();
    let mut buf = [0u8; 16 * 1024];

    // Read greeting.
    let mut coroutine = GetSmtpGreeting::new();
    let mut arg: Option<&[u8]> = None;

    let greeting = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done((greeting, _)) => break greeting,
            SmtpCoroutineState::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            SmtpCoroutineState::WantsWrite(_) => arg = None,
            SmtpCoroutineState::Err(err) => panic!("{err}"),
        }
    };

    println!("greeting: {greeting:#?}");

    // Initial EHLO over plain TCP.
    let domain: EhloDomain<'_> = Domain::parse(b"localhost").unwrap().into();
    let mut coroutine = SmtpEhlo::new(domain.clone());
    let mut arg: Option<&[u8]> = None;

    let capabilities = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done((capabilities, _)) => break capabilities,
            SmtpCoroutineState::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            SmtpCoroutineState::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            SmtpCoroutineState::Err(err) => panic!("{err}"),
        }
    };

    println!("capabilities pre STARTTLS: {capabilities:#?}");

    // STARTTLS handshake (exempt coroutine: keeps its own result enum).
    let mut coroutine = SmtpStartTls::new();
    let mut arg: Option<&[u8]> = None;

    let preread = loop {
        match coroutine.resume(arg.take()) {
            SmtpStartTlsResult::WantsStartTls(remaining) => break remaining,
            SmtpStartTlsResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            SmtpStartTlsResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            SmtpStartTlsResult::Err(err) => panic!("{err}"),
        }
    };

    if !preread.is_empty() {
        eprintln!(
            "warning: {} bytes pre-read before TLS upgrade (possible injection)",
            preread.len()
        );
    }

    // Upgrade to TLS.
    let tls = Tls::default();
    let mut stream = stream.upgrade_tls(&tls).unwrap();

    // EHLO again over TLS.
    let mut coroutine = SmtpEhlo::new(domain);
    let mut arg: Option<&[u8]> = None;

    let capabilities = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done((capabilities, _)) => break capabilities,
            SmtpCoroutineState::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            SmtpCoroutineState::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
                arg = None;
            }
            SmtpCoroutineState::Err(err) => panic!("{err}"),
        }
    };

    println!("capabilities post STARTTLS: {capabilities:#?}");
}
