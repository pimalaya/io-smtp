#![no_main]

//! Coverage-guided fuzz target for the reply parsers. The oracle:
//! whatever a server sends, split however the transport splits it, the
//! coroutines answer or fail, never panic, never spin on EOF, and never
//! refuse a reply as too large before it outgrew the limit. A reply reads
//! as a greeting when its code is 220, as an EHLO response when it is 250,
//! and neither is ever reported as refused.

use arbitrary::Arbitrary;
use io_sasl::{rfc5801::SaslGs2ChannelBinding, rfc5802::SaslScramCreds};
use io_smtp::{
    coroutine::*,
    rfc3207::starttls::SmtpStartTls,
    rfc4954::auth_data::{SmtpAuthData, parse_challenge},
    rfc5321::{
        SmtpEhloDomain, SmtpEhloResponse, SmtpGreeting, SmtpResponse,
        ehlo::{SmtpEhlo, SmtpEhloError},
        greeting::{SmtpGreetingGet, SmtpGreetingGetError},
    },
    rfc7677::auth_scram_sha_256::{SmtpAuthScramSha256, SmtpAuthScramSha256Options},
    sasl::auth_login::{SmtpAuthLogin, SmtpAuthLoginOptions},
    send::{SMTP_MAX_REPLY_LEN, SmtpCommandSend, SmtpCommandSendError},
};
use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

/// How many reads a coroutine may still ask for once EOF was reported.
const MAX_READS_AFTER_EOF: usize = 2;

#[derive(Arbitrary, Debug)]
struct Input {
    initial_request: bool,
    ensure_capabilities: bool,
    reads: Vec<Vec<u8>>,
}

fuzz_target!(|input: Input| {
    if let Some(first) = input.reads.first() {
        let code = SmtpResponse::parse(first).ok().map(|r| r.code.code());
        assert_eq!(SmtpGreeting::parse(first).is_ok(), code == Some(220));
        assert_eq!(SmtpEhloResponse::parse(first).is_ok(), code == Some(250));

        let _ = SmtpAuthData::parse(first);
        let _ = parse_challenge(&String::from_utf8_lossy(first));
    }

    let domain = || SmtpEhloDomain::try_from("example.com").unwrap();

    let (_, result) = check(SmtpGreetingGet::new(), &input.reads);

    if let Err(SmtpGreetingGetError::Rejected { code, .. }) = result {
        assert_ne!(code, 220, "refused a greeting");
    }

    let (_, result) = check(SmtpEhlo::new(domain()), &input.reads);

    if let Err(SmtpEhloError::Rejected { code, .. }) = result {
        assert_ne!(code, 250, "refused an EHLO response");
    }

    let _ = check(SmtpStartTls::new(), &input.reads);

    let send = SmtpCommandSend::new(b"NOOP\r\n".to_vec());
    let (fed, result) = check(send, &input.reads);

    if let Err(SmtpCommandSendError::TooLarge(limit)) = result {
        assert_eq!(limit, SMTP_MAX_REPLY_LEN);
        assert!(fed > SMTP_MAX_REPLY_LEN, "refused {fed} bytes as too large");
    }

    let password = SecretString::from("secret");

    let opts = SmtpAuthLoginOptions {
        initial_request: input.initial_request,
        ensure_capabilities: input.ensure_capabilities,
    };
    let _ = check(
        SmtpAuthLogin::new("alice", &password, domain(), opts),
        &input.reads,
    );

    let creds = SaslScramCreds {
        username: "user".into(),
        password,
        nonce: b"fyko+d2lbbFgONRv9qkxdawL".to_vec(),
        channel_binding: SaslGs2ChannelBinding::Unsupported,
    };
    let opts = SmtpAuthScramSha256Options {
        initial_request: input.initial_request,
        ensure_capabilities: input.ensure_capabilities,
    };
    let _ = check(
        SmtpAuthScramSha256::new(creds, domain(), opts),
        &input.reads,
    );
});

/// Runs `cor` against the reads then EOF, returning how many bytes it was
/// fed and how it completed.
fn check<C>(mut cor: C, reads: &[Vec<u8>]) -> (usize, C::Return)
where
    C: SmtpCoroutine<Yield = SmtpYield>,
{
    let mut reads = reads.iter().filter(|r| !r.is_empty());
    let mut reads_after_eof = 0;
    let mut fed = 0;
    let mut arg: Option<&[u8]> = None;

    loop {
        match cor.resume(arg.take()) {
            SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(_)) => {}
            SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => match reads.next() {
                Some(read) => {
                    fed += read.len();
                    arg = Some(read);
                }
                None => {
                    reads_after_eof += 1;
                    assert!(reads_after_eof <= MAX_READS_AFTER_EOF, "spins on EOF");
                    arg = Some(b"");
                }
            },
            SmtpCoroutineState::Complete(result) => return (fed, result),
        }
    }
}
