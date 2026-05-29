//! Shared helpers for provider integration tests.
//!
//! Each test drives the raw coroutine loop against a live SMTP
//! server using blocking [`std::net`] I/O.

#![allow(dead_code)]

use std::io::{Read, Write};

use io_smtp::{
    coroutine::*,
    login::SmtpLogin,
    rfc4616::plain::SmtpPlain,
    rfc5321::{
        ehlo::SmtpEhlo,
        greeting::GetSmtpGreeting,
        helo::SmtpHelo,
        mail::SmtpMail,
        noop::SmtpNoop,
        quit::SmtpQuit,
        rcpt::SmtpRcpt,
        rset::SmtpRset,
        types::{
            domain::Domain, ehlo_domain::EhloDomain, forward_path::ForwardPath,
            local_part::LocalPart, mailbox::Mailbox, reverse_path::ReversePath,
        },
    },
    send::SmtpMessageSend,
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
/// GREETING → HELO → EHLO → AUTH → NOOP
///   → MAIL FROM → RCPT TO → RSET   (aborted transaction)
///   → MAIL FROM → RCPT TO → DATA   (actual send)
///   → QUIT
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
/// GREETING → HELO → EHLO → AUTH → NOOP
///   → MAIL FROM → RCPT TO → RSET   (aborted transaction)
///   → MAIL FROM → RCPT TO → DATA   (actual send)
///   → QUIT
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
    let domain = Domain::parse(b"pimalaya.org").unwrap();
    let ehlo_domain: EhloDomain<'static> = domain.clone().into();

    let mut buf = [0u8; 4096];

    // ── GREETING ─────────────────────────────────────────────────────────────

    let mut coroutine = GetSmtpGreeting::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done(_) => break,
            SmtpCoroutineState::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::WantsWrite(_) => arg = None,
            SmtpCoroutineState::Err(err) => panic!("GREETING: {err}"),
        }
    }

    // ── HELO ─────────────────────────────────────────────────────────────────

    let mut coroutine = SmtpHelo::new(domain);
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done(()) => break,
            SmtpCoroutineState::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpCoroutineState::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::Err(err) => panic!("HELO: {err}"),
        }
    }

    // ── EHLO ─────────────────────────────────────────────────────────────────

    let mut coroutine = SmtpEhlo::new(ehlo_domain.clone());
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done(_) => break,
            SmtpCoroutineState::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpCoroutineState::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::Err(err) => panic!("EHLO: {err}"),
        }
    }

    // ── AUTH ──────────────────────────────────────────────────────────────────

    match auth {
        Auth::None => {}
        Auth::Plain { username, password } => {
            let password = SecretString::from(password);
            let mut coroutine = SmtpPlain::new(&username, &password, ehlo_domain.clone());
            let mut chunk: Vec<u8>;
            let mut arg: Option<&[u8]> = None;

            loop {
                match coroutine.resume(arg.take()) {
                    SmtpCoroutineState::Done(()) => break,
                    SmtpCoroutineState::WantsWrite(bytes) => {
                        stream.write_all(&bytes).expect("write")
                    }
                    SmtpCoroutineState::WantsRead => {
                        chunk = read_chunk(&mut stream, &mut buf);
                        arg = Some(&chunk);
                    }
                    SmtpCoroutineState::Err(err) => panic!("AUTH PLAIN: {err}"),
                }
            }
        }
        Auth::Login { username, password } => {
            let password = SecretString::from(password);
            let mut coroutine = SmtpLogin::new(&username, &password, ehlo_domain.clone());
            let mut chunk: Vec<u8>;
            let mut arg: Option<&[u8]> = None;

            loop {
                match coroutine.resume(arg.take()) {
                    SmtpCoroutineState::Done(()) => break,
                    SmtpCoroutineState::WantsWrite(bytes) => {
                        stream.write_all(&bytes).expect("write")
                    }
                    SmtpCoroutineState::WantsRead => {
                        chunk = read_chunk(&mut stream, &mut buf);
                        arg = Some(&chunk);
                    }
                    SmtpCoroutineState::Err(err) => panic!("AUTH LOGIN: {err}"),
                }
            }
        }
    }

    // ── NOOP ─────────────────────────────────────────────────────────────────

    let mut coroutine = SmtpNoop::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done(()) => break,
            SmtpCoroutineState::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpCoroutineState::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::Err(err) => panic!("NOOP: {err}"),
        }
    }

    // ── Build paths (shared across the aborted and real transactions) ─────────

    let (local, domain_part) = email.split_once('@').unwrap();
    let mailbox = Mailbox {
        local_part: LocalPart(local.to_owned().into()),
        domain: Domain::parse(domain_part.as_bytes()).unwrap().into(),
    };

    let reverse_path = ReversePath::Mailbox(mailbox.clone());
    let forward_path = ForwardPath(mailbox);

    // ── MAIL FROM → RCPT TO → RSET (aborted transaction) ────────────────────

    let mut coroutine = SmtpMail::new(reverse_path.clone());
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done(()) => break,
            SmtpCoroutineState::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpCoroutineState::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::Err(err) => panic!("MAIL FROM (aborted): {err}"),
        }
    }

    let mut coroutine = SmtpRcpt::new(forward_path.clone());
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done(()) => break,
            SmtpCoroutineState::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpCoroutineState::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::Err(err) => panic!("RCPT TO (aborted): {err}"),
        }
    }

    let mut coroutine = SmtpRset::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done(()) => break,
            SmtpCoroutineState::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpCoroutineState::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::Err(err) => panic!("RSET: {err}"),
        }
    }

    // ── MAIL FROM → RCPT TO → DATA (actual send) ─────────────────────────────

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
            SmtpCoroutineState::Done(()) => break,
            SmtpCoroutineState::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpCoroutineState::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::Err(err) => panic!("send message: {err}"),
        }
    }

    // ── QUIT ──────────────────────────────────────────────────────────────────

    let mut coroutine = SmtpQuit::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Done(()) => break,
            SmtpCoroutineState::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpCoroutineState::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpCoroutineState::Err(err) => panic!("QUIT: {err}"),
        }
    }
}
