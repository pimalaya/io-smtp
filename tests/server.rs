//! Tests for the server side: transcripts from RFC 5321 appendix D,
//! RFC 2033 and RFC 3461 replayed against the session, the edges of
//! the DATA reader and of pipelining, and the crate's own client
//! coroutines pumped against the session in memory.

#![cfg(feature = "server")]

use io_sasl::server::SaslServerMechanism;
use io_smtp::{
    coroutine::SmtpCoroutineState,
    rfc3461::parameter::{SmtpDsnNotify, SmtpDsnRet},
    server::{reply::SmtpServerReply, session::*},
};
use secrecy::ExposeSecret;

/// What the caller saw while driving a session.
#[derive(Debug, Default)]
struct Seen {
    output: Vec<u8>,
    messages: Vec<(SmtpServerEnvelope, Vec<u8>)>,
    closed: Option<Result<(), SmtpServerError>>,
    upgrades: usize,
}

/// The caller decisions, all accepting unless a test overrides one.
type Decide = dyn FnMut(&SmtpServerYield) -> SmtpServerArg<'static>;

fn accept_all(_: &SmtpServerYield) -> SmtpServerArg<'static> {
    SmtpServerArg::Accept
}

struct Harness {
    session: SmtpServerSession,
    seen: Seen,
    decide: Box<Decide>,
}

impl Harness {
    fn new(mode: SmtpServerMode, config: SmtpServerConfig) -> Self {
        let mut harness = Self {
            session: SmtpServerSession::new(mode, config),
            seen: Seen::default(),
            decide: Box::new(accept_all),
        };

        harness.drive(SmtpServerArg::None);
        harness
    }

    fn with(
        mut self,
        decide: impl FnMut(&SmtpServerYield) -> SmtpServerArg<'static> + 'static,
    ) -> Self {
        self.decide = Box::new(decide);
        self
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.drive(SmtpServerArg::Read(bytes));
    }

    fn drive(&mut self, first: SmtpServerArg<'_>) {
        let mut state = self.session.resume(first);

        loop {
            let arg = match state {
                SmtpCoroutineState::Complete(result) => {
                    self.seen.closed = Some(result);
                    return;
                }
                SmtpCoroutineState::Yielded(SmtpServerYield::WantsRead) => return,
                SmtpCoroutineState::Yielded(SmtpServerYield::WantsWrite(bytes)) => {
                    self.seen.output.extend(bytes);
                    SmtpServerArg::None
                }
                SmtpCoroutineState::Yielded(SmtpServerYield::WantsTlsUpgrade) => {
                    self.seen.upgrades += 1;
                    SmtpServerArg::None
                }
                SmtpCoroutineState::Yielded(yielded) => {
                    let arg = (self.decide)(&yielded);

                    if let SmtpServerYield::WantsMessage { envelope, data } = yielded {
                        self.seen.messages.push((envelope, data));
                    }

                    arg
                }
            };

            state = self.session.resume(arg);
        }
    }

    fn take_output(&mut self) -> String {
        String::from_utf8(std::mem::take(&mut self.seen.output)).unwrap()
    }

    /// The codes of the final line of every reply written so far.
    fn codes(&mut self) -> Vec<u16> {
        self.take_output()
            .split("\r\n")
            .filter(|line| line.len() >= 4 && line.as_bytes()[3] == b' ' || line.len() == 3)
            .map(|line| line[..3].parse().unwrap())
            .collect()
    }
}

fn config() -> SmtpServerConfig {
    SmtpServerConfig {
        hostname: "foo.com".into(),
        auth_requires_tls: false,
        ..Default::default()
    }
}

fn reply(code: u16, enhanced: Option<(u8, u16, u16)>, text: &str) -> SmtpServerReply {
    SmtpServerReply::from_codes(code, enhanced, text).unwrap()
}

#[test]
fn rfc5321_d1_a_typical_transaction() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config()).with(|y| match y {
        SmtpServerYield::WantsRcptTo { forward_path, .. }
            if forward_path.to_string() == "<Green@foo.com>" =>
        {
            SmtpServerArg::Reply(reply(550, Some((5, 1, 1)), "No such user here"))
        }
        _ => SmtpServerArg::Accept,
    });

    assert_eq!(smtp.take_output(), "220 foo.com ESMTP ready\r\n");

    smtp.feed(b"EHLO bar.com\r\n");
    let ehlo = smtp.take_output();
    assert!(ehlo.starts_with("250-foo.com\r\n"), "{ehlo}");
    for capability in [
        "PIPELINING",
        "SIZE 26214400",
        "8BITMIME",
        "SMTPUTF8",
        "ENHANCEDSTATUSCODES",
        "DSN",
        "AUTH PLAIN LOGIN",
    ] {
        assert!(
            ehlo.contains(capability),
            "{capability} missing from {ehlo}"
        );
    }
    assert!(!ehlo.contains("STARTTLS"));

    for line in [
        "MAIL FROM:<Smith@bar.com>\r\n",
        "RCPT TO:<Jones@foo.com>\r\n",
        "RCPT TO:<Green@foo.com>\r\n",
        "RCPT TO:<Brown@foo.com>\r\n",
        "DATA\r\n",
        "Blah blah blah...\r\n",
        "...etc. etc. etc.\r\n",
        ".\r\n",
        "QUIT\r\n",
    ] {
        smtp.feed(line.as_bytes());
    }

    assert_eq!(smtp.codes(), [250, 250, 550, 250, 354, 250, 221]);
    assert_eq!(smtp.seen.closed, Some(Ok(())));

    let (envelope, data) = &smtp.seen.messages[0];
    assert_eq!(envelope.helo, "bar.com");
    assert_eq!(envelope.reverse_path.to_string(), "<Smith@bar.com>");
    let recipients: Vec<_> = envelope
        .recipients
        .iter()
        .map(|r| r.forward_path.to_string())
        .collect();
    assert_eq!(recipients, ["<Jones@foo.com>", "<Brown@foo.com>"]);
    assert_eq!(data, b"Blah blah blah...\r\n..etc. etc. etc.\r\n");
}

#[test]
fn rfc5321_d2_aborted_transaction_and_d4_verify() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config()).with(|y| match y {
        SmtpServerYield::WantsRcptTo { .. } => {
            SmtpServerArg::Reply(reply(550, Some((5, 1, 1)), "No such user here"))
        }
        _ => SmtpServerArg::Accept,
    });

    smtp.feed(b"EHLO bar.com\r\n");
    smtp.take_output();
    smtp.feed(b"MAIL FROM:<Smith@bar.com>\r\nRCPT TO:<Jones@foo.com>\r\nDATA\r\nRSET\r\nVRFY Crispin\r\nQUIT\r\n");

    assert_eq!(smtp.codes(), [250, 550, 554, 250, 252, 221]);
    assert!(smtp.seen.messages.is_empty());
}

#[test]
fn rfc2033_lmtp_replies_once_per_recipient() {
    let config = SmtpServerConfig {
        hostname: "foo.edu".into(),
        ..config()
    };
    let mut lmtp = Harness::new(SmtpServerMode::Lmtp, config).with(|y| match y {
        SmtpServerYield::WantsRcptTo { forward_path, .. }
            if forward_path.to_string() == "<jones@foo.edu>" =>
        {
            SmtpServerArg::Reply(reply(550, Some((5, 1, 1)), "No such user here"))
        }
        SmtpServerYield::WantsMessage { .. } => SmtpServerArg::Replies(vec![
            reply(250, Some((2, 1, 5)), "OK"),
            reply(
                452,
                Some((4, 2, 2)),
                "<green@foo.edu> is temporarily over quota",
            ),
        ]),
        _ => SmtpServerArg::Accept,
    });

    assert_eq!(lmtp.take_output(), "220 foo.edu LMTP ready\r\n");

    lmtp.feed(b"EHLO foo.edu\r\n");
    assert_eq!(lmtp.codes(), [500]);

    lmtp.feed(b"LHLO foo.edu\r\n");
    assert!(lmtp.take_output().starts_with("250-foo.edu\r\n"));

    lmtp.feed(b"MAIL FROM:<chris@bar.com>\r\nRCPT TO:<pat@foo.edu>\r\nRCPT TO:<jones@foo.edu>\r\nRCPT TO:<green@foo.edu>\r\nDATA\r\n");
    assert_eq!(lmtp.codes(), [250, 250, 550, 250, 354]);

    lmtp.feed(b"Blah blah blah...\r\n.\r\n");
    assert_eq!(
        lmtp.take_output(),
        "250 2.1.5 OK\r\n452 4.2.2 <green@foo.edu> is temporarily over quota\r\n"
    );

    lmtp.feed(b"QUIT\r\n");
    assert_eq!(lmtp.codes(), [221]);
}

#[test]
fn lmtp_missing_replies_default_to_451() {
    let mut lmtp = Harness::new(SmtpServerMode::Lmtp, config()).with(|y| match y {
        SmtpServerYield::WantsMessage { .. } => SmtpServerArg::Replies(vec![]),
        _ => SmtpServerArg::Accept,
    });
    lmtp.feed(b"LHLO a\r\nMAIL FROM:<>\r\nRCPT TO:<a@foo.com>\r\nRCPT TO:<b@foo.com>\r\nDATA\r\nx\r\n.\r\n");
    assert_eq!(lmtp.codes(), [220, 250, 250, 250, 250, 354, 451, 451]);
}

#[test]
fn rfc3461_dsn_parameters_reach_the_envelope() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    smtp.feed(
        b"EHLO Example.ORG\r\n\
          MAIL FROM:<Alice@Example.ORG> RET=HDRS ENVID=QQ314159\r\n\
          RCPT TO:<Bob@Example.COM> NOTIFY=SUCCESS ORCPT=rfc822;Bob@Example.COM\r\n\
          RCPT TO:<Carol@Ivory.EDU> NOTIFY=FAILURE ORCPT=rfc822;Carol@Ivory.EDU\r\n\
          RCPT TO:<Dana@Ivory.EDU> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;Dana@Ivory.EDU\r\n\
          RCPT TO:<Fred@Bombs.AF.MIL> NOTIFY=NEVER\r\n\
          DATA\r\nhi\r\n.\r\n",
    );

    let (envelope, _) = &smtp.seen.messages[0];
    assert_eq!(envelope.params.ret, Some(SmtpDsnRet::Hdrs));
    assert_eq!(envelope.params.envid.as_deref(), Some("QQ314159"));

    let notify: Vec<_> = envelope
        .recipients
        .iter()
        .map(|r| r.params.notify.unwrap())
        .collect();
    assert_eq!(
        notify,
        [
            SmtpDsnNotify::SUCCESS,
            SmtpDsnNotify::FAILURE,
            SmtpDsnNotify::SUCCESS | SmtpDsnNotify::FAILURE,
            SmtpDsnNotify::NEVER,
        ]
    );

    let orcpt = envelope.recipients[0].params.orcpt.as_ref().unwrap();
    assert_eq!(
        (orcpt.addr_type.as_str(), orcpt.addr.as_str()),
        ("rfc822", "Bob@Example.COM")
    );

    let config = SmtpServerConfig {
        extensions: SmtpServerExtensions {
            dsn: false,
            ..Default::default()
        },
        ..config()
    };
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config);
    smtp.feed(b"EHLO a\r\nMAIL FROM:<a@b.c> RET=FULL\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f> NOTIFY=NEVER\r\n");
    assert_eq!(smtp.codes(), [220, 250, 555, 250, 555]);
}

#[test]
fn pipelined_commands_get_their_replies_in_order_in_one_write() {
    let mut session = SmtpServerSession::new(SmtpServerMode::Smtp, config());

    let SmtpCoroutineState::Yielded(SmtpServerYield::WantsWrite(_)) =
        session.resume(SmtpServerArg::None)
    else {
        panic!("expected the greeting");
    };
    let SmtpCoroutineState::Yielded(SmtpServerYield::WantsRead) =
        session.resume(SmtpServerArg::None)
    else {
        panic!("expected a read");
    };

    let batch = b"EHLO a\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f>\r\nRCPT TO:<g@h.i>\r\nDATA\r\n";
    let mut state = session.resume(SmtpServerArg::Read(batch));
    let mut events = 0;

    let output = loop {
        state = match state {
            SmtpCoroutineState::Yielded(SmtpServerYield::WantsWrite(bytes)) => break bytes,
            SmtpCoroutineState::Yielded(_) => {
                events += 1;
                session.resume(SmtpServerArg::Accept)
            }
            state => panic!("unexpected {state:?}"),
        };
    };

    assert_eq!(events, 3);
    let output = String::from_utf8(output).unwrap();
    let codes: Vec<_> = output
        .split("\r\n")
        .filter(|l| l.len() > 3 && l.as_bytes()[3] == b' ')
        .map(|l| &l[..3])
        .collect();
    assert_eq!(codes, ["250", "250", "250", "250", "354"]);
}

#[test]
fn dot_unstuffing_and_terminator_survive_any_chunking() {
    let body = b"line one\r\n..leading dot\r\n.\r\n";
    let stream = [
        b"EHLO a\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f>\r\nDATA\r\n".as_slice(),
        body,
        b"QUIT\r\n",
    ]
    .concat();

    for chunk in [1, 2, 3, 5, 7, 64] {
        let mut smtp = Harness::new(SmtpServerMode::Smtp, config());

        for bytes in stream.chunks(chunk) {
            smtp.feed(bytes);
        }

        assert_eq!(smtp.seen.messages.len(), 1, "chunk {chunk}");
        assert_eq!(
            smtp.seen.messages[0].1, b"line one\r\n.leading dot\r\n",
            "chunk {chunk}"
        );
        assert_eq!(smtp.seen.closed, Some(Ok(())), "chunk {chunk}");
    }
}

#[test]
fn bare_line_feeds_never_end_the_data() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    smtp.feed(b"EHLO a\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f>\r\nDATA\r\n");
    smtp.feed(b"a\n.\nMAIL FROM:<evil@x.y>\r\nb\r\n.\r\n");

    assert_eq!(smtp.seen.messages.len(), 1);
    assert_eq!(
        smtp.seen.messages[0].1,
        b"a\n.\nMAIL FROM:<evil@x.y>\r\nb\r\n"
    );
}

#[test]
fn an_empty_message_is_received() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    smtp.feed(b"EHLO a\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f>\r\nDATA\r\n.\r\n");
    assert_eq!(smtp.seen.messages[0].1, b"");
}

#[test]
fn an_oversized_message_is_read_to_its_end_then_refused() {
    let config = SmtpServerConfig {
        max_message_size: 10,
        ..config()
    };
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config);
    smtp.feed(
        b"EHLO a\r\nMAIL FROM:<a@b.c> SIZE=11\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f>\r\nDATA\r\n",
    );
    smtp.feed(b"0123456789\r\nmore\r\n.\r\nNOOP\r\n");

    assert_eq!(smtp.codes(), [220, 250, 552, 250, 250, 354, 552, 250]);
    assert!(smtp.seen.messages.is_empty());
}

#[test]
fn sequence_syntax_and_unknown_commands_are_refused() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    smtp.feed(b"MAIL FROM:<a@b.c>\r\nFOO\r\nEXPN list\r\nEHLO\r\nEHLO a\r\nRCPT TO:<d@e.f>\r\nDATA\r\nMAIL FROM:a@b.c\r\nMAIL FROM:<a@b.c> FOO=1\r\nMAIL FROM:<a@b.c>\r\nMAIL FROM:<a@b.c>\r\n");
    assert_eq!(
        smtp.codes(),
        [220, 503, 500, 502, 501, 250, 503, 503, 501, 555, 250, 503]
    );
}

#[test]
fn too_many_errors_close_with_421() {
    let config = SmtpServerConfig {
        max_errors: 3,
        ..config()
    };
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config);
    smtp.feed(b"FOO\r\nBAR\r\nBAZ\r\nNOOP\r\n");

    assert_eq!(smtp.codes(), [220, 500, 500, 500, 421]);
    assert_eq!(smtp.seen.closed, Some(Err(SmtpServerError::TooManyErrors)));
}

#[test]
fn an_overlong_line_is_refused_and_the_next_one_read() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    let long = format!("NOOP {}\r\n", "x".repeat(600));
    smtp.feed(&long.as_bytes()[..300]);
    smtp.feed(&long.as_bytes()[300..]);
    smtp.feed(b"NOOP\r\n");

    assert_eq!(smtp.codes(), [220, 500, 250]);
}

#[test]
fn auth_plain_then_mail_when_auth_is_required() {
    let config = SmtpServerConfig {
        auth_required: true,
        ..config()
    };
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config).with(|y| match y {
        SmtpServerYield::WantsAuth(creds) if creds.password.expose_secret() == "pencil" => {
            SmtpServerArg::Accept
        }
        SmtpServerYield::WantsAuth(_) => SmtpServerArg::Reply(reply(535, Some((5, 7, 8)), "No")),
        _ => SmtpServerArg::Accept,
    });

    smtp.feed(b"HELO a\r\nAUTH PLAIN AGFsaWNlAHBlbmNpbA==\r\nEHLO a\r\nMAIL FROM:<a@b.c>\r\n");
    smtp.feed(b"AUTH PLAIN AGFsaWNlAHdyb25n\r\nAUTH PLAIN AGFsaWNlAHBlbmNpbA==\r\nAUTH PLAIN AGFsaWNlAHBlbmNpbA==\r\nMAIL FROM:<a@b.c>\r\n");

    assert_eq!(smtp.codes(), [220, 250, 503, 250, 530, 535, 235, 503, 250]);
    assert_eq!(smtp.session.identity().unwrap().authcid, "alice");
}

#[test]
fn auth_login_runs_through_334_challenges_and_can_be_cancelled() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    smtp.feed(b"EHLO a\r\nAUTH LOGIN\r\n");
    assert!(smtp.take_output().ends_with("334 VXNlcm5hbWU6\r\n"));

    smtp.feed(b"*\r\n");
    assert_eq!(smtp.take_output(), "501 5.0.0 Authentication cancelled\r\n");

    smtp.feed(b"AUTH LOGIN YWxpY2U=\r\n");
    assert_eq!(smtp.take_output(), "334 UGFzc3dvcmQ6\r\n");
    smtp.feed(b"cGVuY2ls\r\n");
    assert_eq!(
        smtp.take_output(),
        "235 2.7.0 Authentication successful\r\n"
    );

    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    smtp.feed(b"EHLO a\r\nAUTH PLAIN\r\n");
    assert!(smtp.take_output().ends_with("334 \r\n"));
    smtp.feed(b"!!!\r\nAUTH CRAM-MD5\r\nAUTH PLAIN =\r\n");
    assert_eq!(smtp.codes(), [501, 504, 501]);
}

#[test]
fn starttls_upgrades_then_auth_is_offered() {
    let config = SmtpServerConfig {
        auth_requires_tls: true,
        extensions: SmtpServerExtensions {
            starttls: true,
            ..Default::default()
        },
        ..config()
    };
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config);

    smtp.feed(b"EHLO a\r\n");
    let ehlo = smtp.take_output();
    assert!(ehlo.contains("STARTTLS") && !ehlo.contains("AUTH"));

    smtp.feed(b"AUTH PLAIN AGFsaWNlAHBlbmNpbA==\r\nSTARTTLS\r\nMAIL FROM:<injected@x.y>\r\n");
    assert_eq!(smtp.codes(), [530, 220]);
    assert_eq!(smtp.seen.upgrades, 1);
    assert!(smtp.session.is_tls());
    assert_eq!(smtp.session.helo(), None);

    smtp.feed(b"MAIL FROM:<a@b.c>\r\nEHLO a\r\n");
    let output = smtp.take_output();
    assert!(output.starts_with("503 "), "{output}");
    assert!(output.contains("AUTH PLAIN LOGIN") && !output.contains("STARTTLS"));

    smtp.feed(b"STARTTLS\r\nAUTH PLAIN AGFsaWNlAHBlbmNpbA==\r\n");
    assert_eq!(smtp.codes(), [503, 235]);
}

#[test]
fn utf8_addresses_need_smtputf8() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    smtp.feed("EHLO a\r\nMAIL FROM:<jörg@bücher.example>\r\nMAIL FROM:<jörg@bücher.example> SMTPUTF8\r\nRCPT TO:<δοκιμή@παράδειγμα.δοκιμή>\r\n".as_bytes());
    assert_eq!(smtp.codes(), [220, 250, 553, 250, 250]);
}

#[test]
fn postmaster_resolves_to_the_server_host() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    smtp.feed(b"EHLO a\r\nMAIL FROM:<>\r\nRCPT TO:<Postmaster>\r\nDATA\r\nx\r\n.\r\n");
    let (envelope, _) = &smtp.seen.messages[0];
    assert_eq!(
        envelope.recipients[0].forward_path.to_string(),
        "<postmaster@foo.com>"
    );
}

#[test]
fn too_many_recipients_get_452() {
    let config = SmtpServerConfig {
        max_recipients: 1,
        ..config()
    };
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config);
    smtp.feed(b"EHLO a\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f>\r\nRCPT TO:<g@h.i>\r\n");
    assert_eq!(smtp.codes(), [220, 250, 250, 250, 452]);
}

#[test]
fn eof_and_misuse_end_the_session() {
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config());
    smtp.feed(b"");
    assert_eq!(smtp.seen.closed, Some(Err(SmtpServerError::Eof)));

    let mut session = SmtpServerSession::new(SmtpServerMode::Smtp, config());
    let _ = session.resume(SmtpServerArg::None);
    assert!(matches!(
        session.resume(SmtpServerArg::Accept),
        SmtpCoroutineState::Complete(Err(SmtpServerError::UnexpectedArg))
    ));
}

#[test]
fn enhanced_codes_follow_the_extension() {
    let config = SmtpServerConfig {
        extensions: SmtpServerExtensions {
            enhanced_status_codes: false,
            ..Default::default()
        },
        ..config()
    };
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config);
    smtp.feed(b"EHLO a\r\n");
    assert!(!smtp.take_output().contains("ENHANCEDSTATUSCODES"));
    smtp.feed(b"NOOP\r\n");
    assert_eq!(smtp.take_output(), "250 OK\r\n");
}

#[test]
fn auth_can_be_disabled() {
    let config = SmtpServerConfig {
        auth_mechanisms: vec![],
        ..config()
    };
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config);
    smtp.feed(b"EHLO a\r\n");
    assert!(!smtp.take_output().contains("AUTH"));
    smtp.feed(b"AUTH PLAIN\r\n");
    assert_eq!(smtp.codes(), [502]);

    let config = SmtpServerConfig {
        auth_mechanisms: vec![SaslServerMechanism::Plain],
        ..self::config()
    };
    let mut smtp = Harness::new(SmtpServerMode::Smtp, config);
    smtp.feed(b"EHLO a\r\nAUTH LOGIN\r\n");
    assert_eq!(smtp.codes(), [220, 250, 504]);
}

#[cfg(feature = "client")]
mod client {
    use io_sasl::rfc4616::plain::SaslPlainCreds;
    use io_smtp::{
        coroutine::{SmtpCoroutine, SmtpCoroutineState, SmtpYield},
        message::{SmtpMessageSend, SmtpMessageSendOptions},
        rfc5321::{SmtpEhloDomain, SmtpForwardPath, SmtpMailbox, SmtpReversePath},
        session::{
            SmtpSessionOpen, SmtpSessionOpenOptions, SmtpSessionOpenYield, SmtpSessionTransport,
        },
    };
    use secrecy::ExposeSecret;

    use super::*;

    /// Feeds the client bytes to the server, returning nothing: the
    /// server output piles up in the harness for the client to read.
    fn to_server(server: &mut Harness, bytes: &[u8]) {
        server.feed(bytes);
    }

    fn to_client(server: &mut Harness) -> Vec<u8> {
        let bytes = std::mem::take(&mut server.seen.output);
        assert!(
            !bytes.is_empty(),
            "the client waits for a reply the server never wrote"
        );
        bytes
    }

    #[test]
    fn the_crate_client_sends_a_message_with_auth_plain() {
        let config = SmtpServerConfig {
            auth_required: true,
            ..config()
        };
        let mut server = Harness::new(SmtpServerMode::Smtp, config).with(|y| match y {
            SmtpServerYield::WantsAuth(creds)
                if creds.authcid == "alice" && creds.password.expose_secret() == "pencil" =>
            {
                SmtpServerArg::Accept
            }
            SmtpServerYield::WantsAuth(_) => {
                SmtpServerArg::Reply(reply(535, Some((5, 7, 8)), "No"))
            }
            _ => SmtpServerArg::Accept,
        });

        let creds = SaslPlainCreds {
            authzid: None,
            authcid: "alice".into(),
            passwd: "pencil".into(),
        };
        let transport = SmtpSessionTransport::Tcp {
            host: "foo.com".into(),
            port: 25,
        };
        let domain = SmtpEhloDomain::try_from("bar.com").unwrap();
        let mut open = SmtpSessionOpen::new(
            transport,
            domain,
            Some(creds),
            SmtpSessionOpenOptions::default(),
        );

        let mut arg: Option<&[u8]> = None;

        let session = loop {
            match open.resume(arg.take()) {
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsTcpConnect { .. }) => (),
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsWrite(bytes)) => {
                    to_server(&mut server, &bytes);
                }
                SmtpCoroutineState::Yielded(SmtpSessionOpenYield::WantsRead) => {
                    arg = Some(leak(to_client(&mut server)));
                }
                SmtpCoroutineState::Yielded(y) => panic!("unexpected {y:?}"),
                SmtpCoroutineState::Complete(result) => break result.unwrap(),
            }
        };

        assert!(session.capabilities.iter().any(|c| c == "PIPELINING"));
        assert_eq!(server.session.identity().unwrap().authcid, "alice");

        let message = b"From: alice@bar.com\r\nTo: bob@foo.com\r\nSubject: hi\r\n\r\n.hidden\r\n..twice\r\nend\r\n".to_vec();
        let from = SmtpReversePath::from(SmtpMailbox::try_from("alice@bar.com").unwrap());
        let to = [
            SmtpForwardPath::from(SmtpMailbox::try_from("bob@foo.com").unwrap()),
            SmtpForwardPath::from(SmtpMailbox::try_from("carol@foo.com").unwrap()),
        ];
        let mut send =
            SmtpMessageSend::new(from, to, message.clone(), SmtpMessageSendOptions::default());

        let mut arg: Option<&[u8]> = None;

        let refusals = loop {
            match send.resume(arg.take()) {
                SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
                    to_server(&mut server, &bytes)
                }
                SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
                    arg = Some(leak(to_client(&mut server)));
                }
                SmtpCoroutineState::Complete(result) => break result.unwrap(),
            }
        };

        assert!(refusals.is_empty());
        let (envelope, data) = &server.seen.messages[0];
        assert_eq!(envelope.identity.as_ref().unwrap().authcid, "alice");
        assert_eq!(envelope.reverse_path.to_string(), "<alice@bar.com>");
        assert_eq!(envelope.recipients.len(), 2);
        assert_eq!(data, &message);
    }

    /// Leaks a read buffer so it outlives the loop-carried argument.
    fn leak(bytes: Vec<u8>) -> &'static [u8] {
        Box::leak(bytes.into_boxed_slice())
    }
}
