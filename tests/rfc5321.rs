//! Tests for RFC 5321 — Simple Mail Transfer Protocol.
//!
//! All tests drive SMTP coroutines against pre-crafted in-memory
//! response buffers. No network connection is made.

use io_smtp::{
    coroutine::*,
    rfc5321::{
        ehlo::*,
        greeting::*,
        noop::*,
        quit::*,
        rset::*,
        types::{domain::Domain, ehlo_domain::EhloDomain},
    },
};

fn run_greeting(response: &[u8]) -> SmtpCoroutineState<SmtpGreetingOutput, GetSmtpGreetingError> {
    let mut coroutine = GetSmtpGreeting::new();
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::WantsRead => arg = Some(response),
            any => return any,
        }
    }
}

fn run_ehlo(
    response: &[u8],
    domain: EhloDomain<'_>,
) -> SmtpCoroutineState<SmtpEhloOutput, SmtpEhloError> {
    let mut coroutine = SmtpEhlo::new(domain);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::WantsWrite(_) => arg = None,
            SmtpCoroutineState::WantsRead => arg = Some(response),
            any => return any,
        }
    }
}

#[test]
fn greeting_220() {
    let response = b"220 smtp.example.com ESMTP ready\r\n";

    match run_greeting(response) {
        SmtpCoroutineState::Done((greeting, _)) => {
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
            SmtpCoroutineState::WantsRead if !sent => {
                sent = true;
                arg = Some(b"220 smtp.example.com");
            }
            SmtpCoroutineState::WantsRead => arg = Some(b""),
            any => break any,
        }
    };

    match result {
        SmtpCoroutineState::Err(_) => {}
        any => panic!("expected error for incomplete greeting, got: {any:?}"),
    }
}

#[test]
fn ehlo_single_line() {
    let response = b"250 smtp.example.com\r\n";
    let domain = EhloDomain::Domain(Domain("localhost".into()));

    match run_ehlo(response, domain) {
        SmtpCoroutineState::Done((capabilities, _)) => assert!(capabilities.is_empty()),
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
        SmtpCoroutineState::Done((capabilities, _)) => assert_eq!(capabilities.len(), 3),
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
            SmtpCoroutineState::WantsWrite(_) => arg = None,
            SmtpCoroutineState::WantsRead => arg = Some(response),
            any => break any,
        }
    };

    assert!(matches!(
        result,
        SmtpCoroutineState::<(), SmtpNoopError>::Done(())
    ));
}

#[test]
fn quit_ok() {
    let response = b"221 Bye\r\n";
    let mut coroutine = SmtpQuit::new();
    let mut arg: Option<&[u8]> = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::WantsWrite(_) => arg = None,
            SmtpCoroutineState::WantsRead => arg = Some(response),
            any => break any,
        }
    };

    assert!(matches!(
        result,
        SmtpCoroutineState::<(), SmtpQuitError>::Done(())
    ));
}

#[test]
fn rset_ok() {
    let response = b"250 OK\r\n";
    let mut coroutine = SmtpRset::new();
    let mut arg: Option<&[u8]> = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::WantsWrite(_) => arg = None,
            SmtpCoroutineState::WantsRead => arg = Some(response),
            any => break any,
        }
    };

    assert!(matches!(
        result,
        SmtpCoroutineState::<(), SmtpRsetError>::Done(())
    ));
}
