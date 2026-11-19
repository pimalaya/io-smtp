#![no_main]

//! Coverage-guided fuzz target for the server session. The oracle:
//! whatever a client sends, split however the transport splits it, and
//! whatever the caller decides, the session never panics, every line it
//! writes is a reply line (three digits, then a space or a dash) or an
//! AUTH challenge, a message only ever comes with at least one
//! recipient, and once the session completes it stays complete.

use arbitrary::Arbitrary;
use io_smtp::{
    coroutine::SmtpCoroutineState,
    server::{
        reply::SmtpServerReply,
        session::{
            SmtpServerArg, SmtpServerConfig, SmtpServerExtensions, SmtpServerMode,
            SmtpServerSession, SmtpServerYield,
        },
    },
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    lmtp: bool,
    starttls: bool,
    auth_required: bool,
    tls_active: bool,
    max_message_size: u16,
    reads: Vec<Vec<u8>>,
    verdicts: Vec<u16>,
}

fuzz_target!(|input: Input| {
    let mode = if input.lmtp {
        SmtpServerMode::Lmtp
    } else {
        SmtpServerMode::Smtp
    };

    let config = SmtpServerConfig {
        hostname: "fuzz.example".into(),
        max_message_size: u64::from(input.max_message_size),
        max_recipients: 8,
        auth_required: input.auth_required,
        auth_requires_tls: !input.tls_active,
        tls_active: input.tls_active,
        extensions: SmtpServerExtensions {
            starttls: input.starttls,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut session = SmtpServerSession::new(mode, config);
    let mut verdicts = input.verdicts.iter().copied().cycle();
    let mut output = Vec::new();
    let mut done = false;

    let mut decide = |yielded: &SmtpServerYield| {
        if let SmtpServerYield::WantsMessage { envelope, .. } = yielded {
            assert!(!envelope.recipients.is_empty(), "message without recipient");
        }

        match verdicts.next().unwrap_or(250) % 600 {
            code if code < 200 => SmtpServerArg::Accept,
            code => match SmtpServerReply::from_codes(code, None, "fuzz") {
                Some(reply) if code % 7 == 0 => SmtpServerArg::Replies(vec![reply]),
                Some(reply) => SmtpServerArg::Reply(reply),
                None => SmtpServerArg::Accept,
            },
        }
    };

    let reads = input.reads.iter().map(Vec::as_slice).chain([&[][..]]);
    let mut state = session.resume(SmtpServerArg::None);

    for read in reads {
        loop {
            let arg = match state {
                SmtpCoroutineState::Complete(_) => {
                    done = true;
                    break;
                }
                SmtpCoroutineState::Yielded(SmtpServerYield::WantsRead) => break,
                SmtpCoroutineState::Yielded(SmtpServerYield::WantsWrite(bytes)) => {
                    output.extend(bytes);
                    SmtpServerArg::None
                }
                SmtpCoroutineState::Yielded(SmtpServerYield::WantsTlsUpgrade) => SmtpServerArg::None,
                SmtpCoroutineState::Yielded(yielded) => decide(&yielded),
            };

            state = session.resume(arg);
        }

        if done {
            break;
        }

        state = session.resume(SmtpServerArg::Read(read));
    }

    if done {
        assert!(matches!(
            session.resume(SmtpServerArg::None),
            SmtpCoroutineState::Complete(Err(_))
        ));
    }

    assert!(output.is_empty() || output.ends_with(b"\r\n"));

    for line in output.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let well_formed = line.len() >= 4
            && line[..3].iter().all(u8::is_ascii_digit)
            && matches!(line[3], b' ' | b'-' | b'\r');
        assert!(well_formed, "malformed reply line {line:?}");
        assert!(!line[..line.len() - 1].contains(&b'\r'), "CR inside a reply line");
    }
});
