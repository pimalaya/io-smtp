//! Tests for RFC 5321 — Simple Mail Transfer Protocol.
//!
//! All tests drive SMTP coroutines against pre-crafted in-memory
//! response buffers. No network connection is made.

use io_smtp::rfc5321::{
    ehlo::{SmtpEhlo, SmtpEhloResult},
    greeting::{GetSmtpGreeting, GetSmtpGreetingResult},
    noop::{SmtpNoop, SmtpNoopResult},
    quit::{SmtpQuit, SmtpQuitResult},
    rset::{SmtpRset, SmtpRsetResult},
    types::{domain::Domain, ehlo_domain::EhloDomain},
};

fn run_greeting(response: &[u8]) -> GetSmtpGreetingResult {
    let mut coroutine = GetSmtpGreeting::new();
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::WantsRead => arg = Some(response),
            any => return any,
        }
    }
}

fn run_ehlo(response: &[u8], domain: EhloDomain<'_>) -> SmtpEhloResult {
    let mut coroutine = SmtpEhlo::new(domain);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::WantsWrite(_) => arg = None,
            SmtpEhloResult::WantsRead => arg = Some(response),
            any => return any,
        }
    }
}

#[test]
fn greeting_220() {
    let response = b"220 smtp.example.com ESMTP ready\r\n";

    match run_greeting(response) {
        GetSmtpGreetingResult::Ok { greeting, .. } => {
            assert_eq!(greeting.domain.0.as_ref(), "smtp.example.com");
        }
        any => panic!("unexpected result: {any:?}"),
    }
}

#[test]
fn greeting_incomplete_rejected() {
    // No CRLF — drive the coroutine until it asks for more bytes, then
    // signal EOF to force an error terminal.
    let mut coroutine = GetSmtpGreeting::new();
    let mut arg: Option<&[u8]> = None;
    let mut sent = false;

    let result = loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::WantsRead if !sent => {
                sent = true;
                arg = Some(b"220 smtp.example.com");
            }
            GetSmtpGreetingResult::WantsRead => arg = Some(b""),
            any => break any,
        }
    };

    match result {
        GetSmtpGreetingResult::Err(_) => {}
        any => panic!("expected error for incomplete greeting, got: {any:?}"),
    }
}

#[test]
fn ehlo_single_line() {
    let response = b"250 smtp.example.com\r\n";
    let domain = EhloDomain::Domain(Domain("localhost".into()));

    match run_ehlo(response, domain) {
        SmtpEhloResult::Ok { capabilities, .. } => assert!(capabilities.is_empty()),
        any => panic!("unexpected result: {any:?}"),
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
        SmtpEhloResult::Ok { capabilities, .. } => assert_eq!(capabilities.len(), 3),
        any => panic!("unexpected result: {any:?}"),
    }
}

#[test]
fn noop_ok() {
    let response = b"250 OK\r\n";
    let mut coroutine = SmtpNoop::new();
    let mut arg: Option<&[u8]> = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpNoopResult::WantsWrite(_) => arg = None,
            SmtpNoopResult::WantsRead => arg = Some(response),
            any => break any,
        }
    };

    assert!(matches!(result, SmtpNoopResult::Ok));
}

#[test]
fn quit_ok() {
    let response = b"221 Bye\r\n";
    let mut coroutine = SmtpQuit::new();
    let mut arg: Option<&[u8]> = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpQuitResult::WantsWrite(_) => arg = None,
            SmtpQuitResult::WantsRead => arg = Some(response),
            any => break any,
        }
    };

    assert!(matches!(result, SmtpQuitResult::Ok));
}

#[test]
fn rset_ok() {
    let response = b"250 OK\r\n";
    let mut coroutine = SmtpRset::new();
    let mut arg: Option<&[u8]> = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpRsetResult::WantsWrite(_) => arg = None,
            SmtpRsetResult::WantsRead => arg = Some(response),
            any => break any,
        }
    };

    assert!(matches!(result, SmtpRsetResult::Ok));
}
