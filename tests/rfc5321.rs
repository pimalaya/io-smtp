//! Tests for RFC 5321 — Simple Mail Transfer Protocol.
//!
//! All tests drive SMTP coroutines against pre-crafted in-memory
//! buffers via [`stub::StubStream`]. No network connection is made.

mod stub;

use io_smtp::rfc5321::{
    ehlo::*,
    greeting::*,
    noop::*,
    quit::*,
    rset::*,
    types::{domain::Domain, ehlo_domain::EhloDomain},
};
use io_socket::runtimes::std_stream::handle;
use stub::StubStream;

fn run_greeting(response: &[u8]) -> GetSmtpGreetingResult {
    let mut stream = StubStream::new(response);
    let mut coroutine = GetSmtpGreeting::new();
    let mut arg = None;

    loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            any => return any,
        }
    }
}

fn run_ehlo(response: &[u8], domain: EhloDomain<'_>) -> SmtpEhloResult {
    let mut stream = StubStream::new(response);
    let mut coroutine = SmtpEhlo::new(domain);
    let mut arg = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            any => return any,
        }
    }
}

#[test]
fn greeting_220() {
    let response = b"220 smtp.example.com ESMTP ready\r\n";

    match run_greeting(response) {
        GetSmtpGreetingResult::Ok { greeting } => {
            assert_eq!(greeting.domain.0.as_ref(), "smtp.example.com");
        }
        _ => panic!("unexpected result"),
    }
}

#[test]
fn greeting_incomplete_rejected() {
    // No CRLF — not a complete greeting
    let response = b"220 smtp.example.com";

    match run_greeting(response) {
        GetSmtpGreetingResult::Err { .. } => {}
        _ => panic!("expected error for incomplete greeting"),
    }
}

#[test]
fn ehlo_single_line() {
    let response = b"250 smtp.example.com\r\n";
    let domain = EhloDomain::Domain(Domain("localhost".into()));

    match run_ehlo(response, domain) {
        SmtpEhloResult::Ok { capabilities } => {
            assert!(capabilities.is_empty());
        }
        _ => panic!("unexpected result"),
    }
}

#[test]
fn ehlo_with_capabilities() {
    let response = b"250-smtp.example.com Hello\r\n\
                     250-SIZE 10240000\r\n\
                     250-STARTTLS\r\n\
                     250 ENHANCEDSTATUSCODES\r\n";
    let domain = EhloDomain::Domain(Domain("localhost".into()));

    match run_ehlo(response, domain) {
        SmtpEhloResult::Ok { capabilities } => {
            assert_eq!(capabilities.len(), 3);
        }
        _ => panic!("unexpected result"),
    }
}

#[test]
fn noop_ok() {
    let response = b"250 OK\r\n";
    let mut stream = StubStream::new(response);
    let mut coroutine = SmtpNoop::new();
    let mut arg = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpNoopResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            any => break any,
        }
    };

    assert!(matches!(result, SmtpNoopResult::Ok));
}

#[test]
fn quit_ok() {
    let response = b"221 Bye\r\n";
    let mut stream = StubStream::new(response);
    let mut coroutine = SmtpQuit::new();
    let mut arg = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpQuitResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            any => break any,
        }
    };

    assert!(matches!(result, SmtpQuitResult::Ok));
}

#[test]
fn rset_ok() {
    let response = b"250 OK\r\n";
    let mut stream = StubStream::new(response);
    let mut coroutine = SmtpRset::new();
    let mut arg = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpRsetResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            any => break any,
        }
    };

    assert!(matches!(result, SmtpRsetResult::Ok));
}
