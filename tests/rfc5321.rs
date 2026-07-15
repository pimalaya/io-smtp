//! Tests for RFC 5321: Simple Mail Transfer Protocol.
//!
//! All tests pump SMTP coroutines against pre-crafted in-memory
//! response buffers. No network connection is made.

use std::borrow::Cow;

use io_smtp::{
    coroutine::*,
    rfc5321::{
        ehlo::*,
        greeting::*,
        noop::*,
        quit::*,
        rset::*,
        types::{domain::SmtpDomain, ehlo_domain::SmtpEhloDomain, greeting::SmtpGreeting},
    },
};

fn run_greeting(
    response: &[u8],
) -> SmtpCoroutineState<SmtpYield, Result<SmtpGreeting<'static>, SmtpGreetingGetError>> {
    let mut coroutine = SmtpGreetingGet::new();
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => arg = Some(response),
            any => return any,
        }
    }
}

fn run_ehlo(
    response: &[u8],
    domain: SmtpEhloDomain<'_>,
) -> SmtpCoroutineState<SmtpYield, Result<Vec<Cow<'static, str>>, SmtpEhloError>> {
    let mut coroutine = SmtpEhlo::new(domain);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(_)) => arg = None,
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => arg = Some(response),
            any => return any,
        }
    }
}

#[test]
fn greeting_220() {
    let response = b"220 smtp.example.com ESMTP ready\r\n";

    match run_greeting(response) {
        SmtpCoroutineState::Complete(Ok(greeting)) => {
            assert_eq!(greeting.domain.0.as_ref(), "smtp.example.com");
        }
        any => panic!("unexpected result: {any:?}"),
    }
}

#[test]
fn greeting_incomplete_rejected() {
    // NOTE: no CRLF: resume the coroutine until it asks for more
    // bytes, then signal EOF to force an error terminal.
    let mut coroutine = SmtpGreetingGet::new();
    let mut arg: Option<&[u8]> = None;
    let mut sent = false;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) if !sent => {
                sent = true;
                arg = Some(b"220 smtp.example.com");
            }
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => arg = Some(b""),
            any => break any,
        }
    };

    match result {
        SmtpCoroutineState::Complete(Err(_)) => {}
        any => panic!("expected error for incomplete greeting, got: {any:?}"),
    }
}

#[test]
fn ehlo_single_line() {
    let response = b"250 smtp.example.com\r\n";
    let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain("localhost".into()));

    match run_ehlo(response, domain) {
        SmtpCoroutineState::Complete(Ok(capabilities)) => assert!(capabilities.is_empty()),
        any => panic!("unexpected result: {any:?}"),
    }
}

#[test]
fn ehlo_with_capabilities() {
    let response = b"250-smtp.example.com Hello\r\n\
                     250-SIZE 10240000\r\n\
                     250-STARTTLS\r\n\
                     250 ENHANCEDSTATUSCODES\r\n";
    let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain("localhost".into()));

    match run_ehlo(response, domain) {
        SmtpCoroutineState::Complete(Ok(capabilities)) => assert_eq!(capabilities.len(), 3),
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
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(_)) => arg = None,
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => arg = Some(response),
            any => break any,
        }
    };

    assert!(matches!(
        result,
        SmtpCoroutineState::<SmtpYield, Result<(), SmtpNoopError>>::Complete(Ok(()))
    ));
}

#[test]
fn quit_ok() {
    let response = b"221 Bye\r\n";
    let mut coroutine = SmtpQuit::new();
    let mut arg: Option<&[u8]> = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(_)) => arg = None,
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => arg = Some(response),
            any => break any,
        }
    };

    assert!(matches!(
        result,
        SmtpCoroutineState::<SmtpYield, Result<(), SmtpQuitError>>::Complete(Ok(()))
    ));
}

#[test]
fn rset_ok() {
    let response = b"250 OK\r\n";
    let mut coroutine = SmtpRset::new();
    let mut arg: Option<&[u8]> = None;

    let result = loop {
        match coroutine.resume(arg.take()) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(_)) => arg = None,
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => arg = Some(response),
            any => break any,
        }
    };

    assert!(matches!(
        result,
        SmtpCoroutineState::<SmtpYield, Result<(), SmtpRsetError>>::Complete(Ok(()))
    ));
}
