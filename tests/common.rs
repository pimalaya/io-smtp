//! Shared helpers for provider integration tests.
//!
//! Each test pumps the raw coroutine loop against a live SMTP
//! server using blocking std I/O.

#![allow(dead_code)]

use std::io::{Read, Write};

use io_smtp::{
    coroutine::*,
    message::SmtpMessageSend,
    rfc5321::{
        SmtpDomain, SmtpEhloDomain, SmtpForwardPath, SmtpLocalPart, SmtpMailbox, SmtpReversePath,
        ehlo::SmtpEhlo, greeting::SmtpGreetingGet, helo::SmtpHelo, mail::SmtpMail, noop::SmtpNoop,
        quit::SmtpQuit, rcpt::SmtpRcpt, rset::SmtpRset,
    },
    sasl::{
        auth_login::{SmtpAuthLogin, SmtpAuthLoginOptions},
        auth_plain::{SmtpAuthPlain, SmtpAuthPlainOptions},
    },
};
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};
use secrecy::SecretString;

/// Auth mechanism to use for a test run.
pub enum Auth {
    None,
    Plain { username: String, password: String },
    Login { username: String, password: String },
}

/// A shared end-to-end SMTP test flow.
///
/// Connects via SMTP (TCP) and exercises the following sequence:
///
/// ```text
/// GREETING -> HELO -> EHLO -> AUTH -> NOOP
///   -> MAIL FROM -> RCPT TO -> RSET   (aborted transaction)
///   -> MAIL FROM -> RCPT TO -> DATA   (actual send)
///   -> QUIT
/// ```
pub fn run_smtp(host: &str, auth: Auth, email: &str) {
    let _ = env_logger::try_init();
    let stream = StreamStd::connect_tcp(host, 25).expect("TCP connect");
    run(stream, auth, email)
}

/// A shared end-to-end SMTP test flow.
///
/// Connects via SMTPS (direct TLS) and exercises the following sequence:
///
/// ```text
/// GREETING -> HELO -> EHLO -> AUTH -> NOOP
///   -> MAIL FROM -> RCPT TO -> RSET   (aborted transaction)
///   -> MAIL FROM -> RCPT TO -> DATA   (actual send)
///   -> QUIT
/// ```
pub fn run_smtps(host: &str, port: u16, auth: Auth, email: &str) {
    let _ = env_logger::try_init();
    let stream = StreamStd::connect_tls(host, port, &Tls::default()).expect("TLS connect");
    run(stream, auth, email)
}

fn read_chunk<S: Read>(stream: &mut S, buf: &mut [u8]) -> Vec<u8> {
    let n = stream.read(buf).expect("read");
    buf[..n].to_vec()
}

fn run(mut stream: impl Read + Write, auth: Auth, email: &str) {
    let domain = SmtpDomain::parse(b"pimalaya.org").unwrap();
    let ehlo_domain: SmtpEhloDomain<'static> = domain.clone().into();

    let mut buf = [0u8; 4096];

    // NOTE: GREETING step.

    let mut coroutine = SmtpGreetingGet::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(_)) => break,
            SmtpCoroutineState::Complete(Err(err)) => panic!("GREETING: {err}"),
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(_)) => arg = None,
        }
    }

    // NOTE: HELO step.

    let mut coroutine = SmtpHelo::new(domain);
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(())) => break,
            SmtpCoroutineState::Complete(Err(err)) => panic!("HELO: {err}"),
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("write")
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
        }
    }

    // NOTE: EHLO step.

    let mut coroutine = SmtpEhlo::new(ehlo_domain.clone());
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(_)) => break,
            SmtpCoroutineState::Complete(Err(err)) => panic!("EHLO: {err}"),
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("write")
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
        }
    }

    // NOTE: AUTH step.

    match auth {
        Auth::None => {}
        Auth::Plain { username, password } => {
            let password = SecretString::from(password);
            let mut coroutine = SmtpAuthPlain::new(
                &username,
                &password,
                ehlo_domain.clone(),
                SmtpAuthPlainOptions::default(),
            );
            let mut chunk: Vec<u8>;
            let mut arg: Option<&[u8]> = None;

            loop {
                match coroutine.resume(arg.take()) {
                    SmtpCoroutineState::Complete(Ok(())) => break,
                    SmtpCoroutineState::Complete(Err(err)) => panic!("AUTH PLAIN: {err}"),
                    SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                        stream.write_all(&bytes).expect("write")
                    }
                    SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                        chunk = read_chunk(&mut stream, &mut buf);
                        arg = Some(&chunk);
                    }
                }
            }
        }
        Auth::Login { username, password } => {
            let password = SecretString::from(password);
            let mut coroutine = SmtpAuthLogin::new(
                &username,
                &password,
                ehlo_domain.clone(),
                SmtpAuthLoginOptions::default(),
            );
            let mut chunk: Vec<u8>;
            let mut arg: Option<&[u8]> = None;

            loop {
                match coroutine.resume(arg.take()) {
                    SmtpCoroutineState::Complete(Ok(())) => break,
                    SmtpCoroutineState::Complete(Err(err)) => panic!("AUTH LOGIN: {err}"),
                    SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                        stream.write_all(&bytes).expect("write")
                    }
                    SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                        chunk = read_chunk(&mut stream, &mut buf);
                        arg = Some(&chunk);
                    }
                }
            }
        }
    }

    // NOTE: NOOP step.

    let mut coroutine = SmtpNoop::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(())) => break,
            SmtpCoroutineState::Complete(Err(err)) => panic!("NOOP: {err}"),
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("write")
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
        }
    }

    // NOTE: Build paths (shared across the aborted and real transactions) step.

    let (local, domain_part) = email.split_once('@').unwrap();
    let mailbox = SmtpMailbox {
        local_part: SmtpLocalPart(local.to_owned().into()),
        domain: SmtpDomain::parse(domain_part.as_bytes()).unwrap().into(),
    };

    let reverse_path = SmtpReversePath::SmtpMailbox(mailbox.clone());
    let forward_path = SmtpForwardPath(mailbox);

    // NOTE: MAIL FROM -> RCPT TO -> RSET (aborted transaction) step.

    let mut coroutine = SmtpMail::new(reverse_path.clone(), Vec::new());
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(())) => break,
            SmtpCoroutineState::Complete(Err(err)) => panic!("MAIL FROM (aborted): {err}"),
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("write")
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
        }
    }

    let mut coroutine = SmtpRcpt::new(forward_path.clone(), Vec::new());
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(())) => break,
            SmtpCoroutineState::Complete(Err(err)) => panic!("RCPT TO (aborted): {err}"),
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("write")
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
        }
    }

    let mut coroutine = SmtpRset::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(())) => break,
            SmtpCoroutineState::Complete(Err(err)) => panic!("RSET: {err}"),
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("write")
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
        }
    }

    // NOTE: MAIL FROM -> RCPT TO -> DATA (actual send) step.

    let eml = [
        &format!("From: io-smtp test <{email}>"),
        &format!("To: io-smtp test <{email}>"),
        "Subject: io-smtp integration test",
        "Date: Thu, 01 Jan 2026 00:00:00 +0000",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "This is an automated test email from io-smtp integration tests.",
    ]
    .join("\r\n");

    let mut coroutine = SmtpMessageSend::new(reverse_path, [forward_path], eml.into_bytes());
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(())) => break,
            SmtpCoroutineState::Complete(Err(err)) => panic!("send message: {err}"),
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("write")
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
        }
    }

    // NOTE: QUIT step.

    let mut coroutine = SmtpQuit::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Complete(Ok(())) => break,
            SmtpCoroutineState::Complete(Err(err)) => panic!("QUIT: {err}"),
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes).expect("write")
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
        }
    }
}
