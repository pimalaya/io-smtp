//! Shared helpers for provider integration tests.
//!
//! Each test pumps the raw coroutine loop against a live SMTP
//! server using blocking std I/O.

#![allow(dead_code)]
// NOTE: the helpers open sockets through pimalaya-stream, which only
// exists once a TLS provider feature is on.
#![cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]

use std::io::{Read, Write};

use bounded_static::IntoBoundedStatic;
use io_sasl::mechanism::Sasl;
use io_smtp::{
    client::{SmtpClient, SmtpClientStd, SmtpClientStdConnectOptions},
    coroutine::*,
    message::{SmtpMessageSend, SmtpMessageSendOptions},
    rfc1870::size::SmtpSizeCapability,
    rfc3461::parameter::{SmtpDsnNotify, SmtpDsnRet},
    rfc4954::capability::SmtpAuthCapability,
    rfc5321::{
        SmtpAtom, SmtpDomain, SmtpEhloDomain, SmtpForwardPath, SmtpLocalPart, SmtpMailbox,
        SmtpParameter, SmtpReversePath, ehlo::SmtpEhlo, greeting::SmtpGreetingGet, helo::SmtpHelo,
        mail::SmtpMail, noop::SmtpNoop, quit::SmtpQuit, rcpt::SmtpRcpt, rset::SmtpRset,
    },
    sasl::{
        auth_login::{SmtpAuthLogin, SmtpAuthLoginOptions},
        auth_plain::{SmtpAuthPlain, SmtpAuthPlainOptions},
    },
    session::SmtpSessionOpenOptions,
};
use pimalaya_stream::{
    stream::{Stream, TcpConnectOptions, TlsConnectOptions},
    tls::Tls,
};
use secrecy::SecretString;
use url::Url;

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
///   -> MAIL FROM -> RCPT TO -> DATA   (actual send, with the SIZE and
///                                      DSN parameters when advertised)
///   -> QUIT
/// ```
pub fn run_smtp(host: &str, auth: Auth, email: &str) {
    let _ = env_logger::try_init();
    let opts = TcpConnectOptions::default();
    let stream = Stream::connect_tcp(host, 25, opts).expect("TCP connect");
    run(stream, auth, email)
}

/// A shared end-to-end SMTP test flow.
///
/// Connects via SMTPS (direct TLS) and exercises the following sequence:
///
/// ```text
/// GREETING -> HELO -> EHLO -> AUTH -> NOOP
///   -> MAIL FROM -> RCPT TO -> RSET   (aborted transaction)
///   -> MAIL FROM -> RCPT TO -> DATA   (actual send, with the SIZE and
///                                      DSN parameters when advertised)
///   -> QUIT
/// ```
pub fn run_smtps(host: &str, port: u16, auth: Auth, email: &str) {
    let _ = env_logger::try_init();
    let opts = TlsConnectOptions {
        tls: Tls::default(),
        ..Default::default()
    };
    let stream = Stream::connect_tls(host, port, opts).expect("TLS connect");
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
                None::<&str>,
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

    let mut coroutine = SmtpMessageSend::new(
        reverse_path,
        [forward_path],
        eml.into_bytes(),
        SmtpMessageSendOptions::default(),
    );
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

/// A shared end-to-end flow over [`SmtpClientStd`], the client layer
/// consumers use.
///
/// [`SmtpClientStd::connect`] opens the session (implicit TLS or
/// STARTTLS, greeting, EHLO, SASL when given), then:
///
/// ```text
/// NOOP -> RAW (NOOP)
///   -> MAIL FROM -> RCPT TO -> RSET   (aborted transaction)
///   -> MAIL FROM -> RCPT TO -> DATA   (actual send, with the SIZE and
///                                      DSN parameters when advertised)
///   -> QUIT
/// ```
pub fn run_client(url: &str, sasl: Option<Sasl>, email: &str, starttls: bool) {
    let _ = env_logger::try_init();
    let url = Url::parse(url).expect("parse SMTP URL");
    let domain = SmtpDomain::parse(b"pimalaya.org").unwrap();

    let opts = SmtpClientStdConnectOptions {
        sasl,
        session: SmtpSessionOpenOptions { starttls },
        ..Default::default()
    };
    let (mut client, capabilities) =
        SmtpClientStd::connect(&url, domain.into(), opts).expect("connect");
    assert!(!capabilities.is_empty(), "no capability after connect");

    client.noop().expect("NOOP");
    let reply = client.raw("NOOP".into()).expect("RAW");
    assert!(reply.starts_with("250"), "RAW NOOP answered {reply}");

    let (local, domain_part) = email.split_once('@').unwrap();
    let mailbox = SmtpMailbox {
        local_part: SmtpLocalPart(local.to_owned().into()),
        domain: SmtpDomain::parse(domain_part.as_bytes()).unwrap().into(),
    };
    let mailbox = mailbox.into_static();
    let reverse_path = SmtpReversePath::SmtpMailbox(mailbox.clone());
    let forward_path = SmtpForwardPath(mailbox);

    // NOTE: MAIL FROM -> RCPT TO -> RSET (aborted transaction) step.

    client
        .mail(reverse_path.clone(), Vec::new())
        .expect("MAIL FROM (aborted)");
    client
        .rcpt(forward_path.clone(), Vec::new())
        .expect("RCPT TO (aborted)");
    client.rset().expect("RSET");

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

    // NOTE: the ESMTP parameters go out only where the server
    // advertises their extension: SIZE (RFC 1870) and DSN (RFC 3461).
    let advertised = |keyword: &str| {
        capabilities.iter().find(|line| {
            line.split_ascii_whitespace()
                .next()
                .is_some_and(|key| key.eq_ignore_ascii_case(keyword))
        })
    };

    let mut mail_parameters = Vec::new();
    let mut rcpt_parameters = Vec::new();

    if let Some(line) = advertised("SIZE") {
        let max = SmtpSizeCapability::parse(line).expect("parse SIZE capability");
        assert!(max.0 == 0 || max.0 >= eml.len() as u64, "message over SIZE");

        mail_parameters.push(SmtpParameter {
            keyword: SmtpAtom::parse(b"SIZE").unwrap(),
            value: Some(eml.len().to_string().into()),
        });
    }

    if advertised("DSN").is_some() {
        mail_parameters.push(SmtpDsnRet::Hdrs.into_parameter());
        mail_parameters.push(SmtpParameter::envid("io-smtp-test"));
        rcpt_parameters.push(SmtpDsnNotify::NEVER.into_parameter());
        rcpt_parameters.push(SmtpParameter::orcpt_rfc822(email));
    }

    if let Some(line) = advertised("AUTH") {
        let auth = SmtpAuthCapability::parse(line).expect("parse AUTH capability");
        assert!(auth.mechanisms().next().is_some(), "empty AUTH line");
    }

    client
        .mail(reverse_path, mail_parameters)
        .expect("MAIL FROM");
    client.rcpt(forward_path, rcpt_parameters).expect("RCPT TO");
    client.data(eml.into_bytes()).expect("DATA");

    client.quit().expect("QUIT");
}
