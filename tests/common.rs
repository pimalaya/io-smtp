//! Shared helpers for provider integration tests.
//!
//! Each test drives the raw coroutine loop against a live SMTP
//! server using blocking [`std::net`] I/O.

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use io_smtp::{
    login::{SmtpLogin, SmtpLoginResult},
    rfc4616::plain::{SmtpPlain, SmtpPlainResult},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloResult},
        greeting::{GetSmtpGreeting, GetSmtpGreetingResult},
        helo::{SmtpHelo, SmtpHeloResult},
        mail::{SmtpMail, SmtpMailResult},
        noop::{SmtpNoop, SmtpNoopResult},
        quit::{SmtpQuit, SmtpQuitResult},
        rcpt::{SmtpRcpt, SmtpRcptResult},
        rset::{SmtpRset, SmtpRsetResult},
        types::{
            domain::Domain, ehlo_domain::EhloDomain, forward_path::ForwardPath,
            local_part::LocalPart, mailbox::Mailbox, reverse_path::ReversePath,
        },
    },
    send::{SmtpMessageSend, SmtpMessageSendResult},
};
use rustls::{ClientConfig, ClientConnection, StreamOwned, pki_types::ServerName};
use rustls_platform_verifier::ConfigVerifierExt;
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
    let stream = TcpStream::connect((host, 25)).expect("TCP connect");
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
    let tcp = TcpStream::connect((host, port)).expect("TCP connect");
    let server_name = ServerName::try_from(host.to_owned()).expect("valid server name");
    let config = ClientConfig::with_platform_verifier().expect("TLS config");
    let conn = ClientConnection::new(Arc::new(config), server_name).expect("TLS handshake");
    let stream = StreamOwned::new(conn, tcp);

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
            GetSmtpGreetingResult::Ok { .. } => break,
            GetSmtpGreetingResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            GetSmtpGreetingResult::Err(err) => panic!("GREETING: {err}"),
        }
    }

    // ── HELO ─────────────────────────────────────────────────────────────────

    let mut coroutine = SmtpHelo::new(domain);
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpHeloResult::Ok => break,
            SmtpHeloResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpHeloResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpHeloResult::Err(err) => panic!("HELO: {err}"),
        }
    }

    // ── EHLO ─────────────────────────────────────────────────────────────────

    let mut coroutine = SmtpEhlo::new(ehlo_domain.clone());
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { .. } => break,
            SmtpEhloResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpEhloResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpEhloResult::Err(err) => panic!("EHLO: {err}"),
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
                    SmtpPlainResult::Ok => break,
                    SmtpPlainResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
                    SmtpPlainResult::WantsRead => {
                        chunk = read_chunk(&mut stream, &mut buf);
                        arg = Some(&chunk);
                    }
                    SmtpPlainResult::Err(err) => panic!("AUTH PLAIN: {err}"),
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
                    SmtpLoginResult::Ok => break,
                    SmtpLoginResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
                    SmtpLoginResult::WantsRead => {
                        chunk = read_chunk(&mut stream, &mut buf);
                        arg = Some(&chunk);
                    }
                    SmtpLoginResult::Err(err) => panic!("AUTH LOGIN: {err}"),
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
            SmtpNoopResult::Ok => break,
            SmtpNoopResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpNoopResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpNoopResult::Err(err) => panic!("NOOP: {err}"),
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
            SmtpMailResult::Ok => break,
            SmtpMailResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpMailResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpMailResult::Err(err) => panic!("MAIL FROM (aborted): {err}"),
        }
    }

    let mut coroutine = SmtpRcpt::new(forward_path.clone());
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpRcptResult::Ok => break,
            SmtpRcptResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpRcptResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpRcptResult::Err(err) => panic!("RCPT TO (aborted): {err}"),
        }
    }

    let mut coroutine = SmtpRset::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpRsetResult::Ok => break,
            SmtpRsetResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpRsetResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpRsetResult::Err(err) => panic!("RSET: {err}"),
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
            SmtpMessageSendResult::Ok => break,
            SmtpMessageSendResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpMessageSendResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpMessageSendResult::Err(err) => panic!("send message: {err}"),
        }
    }

    // ── QUIT ──────────────────────────────────────────────────────────────────

    let mut coroutine = SmtpQuit::new();
    let mut chunk: Vec<u8>;
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpQuitResult::Ok => break,
            SmtpQuitResult::WantsWrite(bytes) => stream.write_all(&bytes).expect("write"),
            SmtpQuitResult::WantsRead => {
                chunk = read_chunk(&mut stream, &mut buf);
                arg = Some(&chunk);
            }
            SmtpQuitResult::Err(err) => panic!("QUIT: {err}"),
        }
    }
}
