//! Shared helpers for provider integration tests.
//!
//! Each test drives the raw coroutine loop against a live SMTP
//! server.

use std::{net::TcpStream, sync::Arc};

use io_smtp::{
    login::{SmtpLogin, SmtpLoginResult},
    rfc4616::plain::{SmtpPlain, SmtpPlainResult},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloResult},
        greeting::{GetSmtpGreeting, GetSmtpGreetingResult},
        quit::{SmtpQuit, SmtpQuitResult},
        types::{
            domain::Domain, ehlo_domain::EhloDomain, forward_path::ForwardPath,
            local_part::LocalPart, mailbox::Mailbox, reverse_path::ReversePath,
        },
    },
    send::{SmtpMessageSend, SmtpMessageSendResult},
};
use io_socket::runtimes::std_stream::handle;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;
use secrecy::SecretString;

/// Auth mechanism to use for a test run.
pub enum Auth {
    Plain { username: String, password: String },
    Login { username: String, password: String },
}

/// A shared end-to-end SMTP test flow.
///
/// Connects via SMTPS (direct TLS), authenticates with the given credentials,
/// sends a single test message to `email` (from and to the same address),
/// then quits.
pub fn run_smtps(host: &str, port: u16, auth: Auth, email: &str) {
    let client_domain: EhloDomain<'static> = Domain::parse(b"localhost").unwrap().into();

    // ── TCP + TLS connection ─────────────────────────────────────────────────

    let tcp = TcpStream::connect((host, port)).expect("TCP connect");
    let server_name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).expect("valid server name");
    let config = ClientConfig::with_platform_verifier().expect("TLS config");
    let conn = ClientConnection::new(Arc::new(config), server_name).expect("TLS handshake");
    let mut stream = StreamOwned::new(conn, tcp);

    // ── GREETING ─────────────────────────────────────────────────────────────

    let mut coroutine = GetSmtpGreeting::new();
    let mut arg = None;
    loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::Ok { .. } => break,
            GetSmtpGreetingResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            GetSmtpGreetingResult::Err { err } => panic!("greeting: {err}"),
        }
    }

    // ── EHLO ─────────────────────────────────────────────────────────────────

    let mut coroutine = SmtpEhlo::new(client_domain.clone());
    let mut arg = None;
    loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { .. } => break,
            SmtpEhloResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            SmtpEhloResult::Err { err } => panic!("EHLO: {err}"),
        }
    }

    // ── AUTH ──────────────────────────────────────────────────────────────────

    match auth {
        Auth::Plain { username, password } => {
            let password = SecretString::from(password);
            let mut coroutine = SmtpPlain::new(&username, &password, client_domain.clone());
            let mut arg = None;
            loop {
                match coroutine.resume(arg.take()) {
                    SmtpPlainResult::Ok => break,
                    SmtpPlainResult::Io { input } => {
                        arg = Some(handle(&mut stream, input).unwrap())
                    }
                    SmtpPlainResult::Err { err } => panic!("AUTH PLAIN: {err}"),
                }
            }
        }
        Auth::Login { username, password } => {
            let password = SecretString::from(password);
            let mut coroutine = SmtpLogin::new(&username, &password, client_domain.clone());
            let mut arg = None;
            loop {
                match coroutine.resume(arg.take()) {
                    SmtpLoginResult::Ok => break,
                    SmtpLoginResult::Io { input } => {
                        arg = Some(handle(&mut stream, input).unwrap())
                    }
                    SmtpLoginResult::Err { err } => panic!("AUTH LOGIN: {err}"),
                }
            }
        }
    }

    // ── SEND MESSAGE ──────────────────────────────────────────────────────────

    send_test_message(&mut stream, email);

    // ── QUIT ──────────────────────────────────────────────────────────────────

    let mut coroutine = SmtpQuit::new();
    let mut arg = None;
    loop {
        match coroutine.resume(arg.take()) {
            SmtpQuitResult::Ok => break,
            SmtpQuitResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            SmtpQuitResult::Err { err } => panic!("QUIT: {err}"),
        }
    }
}

/// Send a minimal test email from and to `email`.
fn send_test_message(stream: &mut (impl std::io::Read + std::io::Write), email: &str) {
    let (local, domain) = email.split_once('@').unwrap();

    let mailbox = Mailbox {
        local_part: LocalPart(local.to_owned().into()),
        domain: Domain::parse(domain.as_bytes()).unwrap().into(),
    };

    let reverse_path = ReversePath::Mailbox(mailbox.clone());
    let forward_path = ForwardPath(mailbox);

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
    let mut arg = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpMessageSendResult::Ok => break,
            SmtpMessageSendResult::Io { input } => arg = Some(handle(&mut *stream, input).unwrap()),
            SmtpMessageSendResult::Err { err } => panic!("send message: {err}"),
        }
    }
}
