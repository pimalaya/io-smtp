//! Parser regression and correctness tests.
//!
//! Each test feeds raw server bytes into a `::parse()` or `::is_complete()`
//! method and asserts the result. When a user reports a parsing failure,
//! add a test case here so the behaviour is preserved forever.

use io_smtp::rfc5321::{SmtpDomain, SmtpEhloResponse, SmtpGreeting, SmtpReplyCode, SmtpResponse};

// NOTE: ReplyCode tests below.

#[test]
fn reply_code_250() {
    let code = SmtpReplyCode::parse(b"250").unwrap();
    assert_eq!(code, SmtpReplyCode::OK);
    assert!(code.is_positive_completion());
    assert!(!code.is_error());
}

#[test]
fn reply_code_354() {
    let code = SmtpReplyCode::parse(b"354").unwrap();
    assert_eq!(code, SmtpReplyCode::START_MAIL_INPUT);
    assert!(code.is_positive_intermediate());
}

#[test]
fn reply_code_421() {
    let code = SmtpReplyCode::parse(b"421").unwrap();
    assert_eq!(code, SmtpReplyCode::SERVICE_NOT_AVAILABLE);
    assert!(code.is_transient_negative());
}

#[test]
fn reply_code_535() {
    let code = SmtpReplyCode::parse(b"535").unwrap();
    assert_eq!(code, SmtpReplyCode::AUTH_INVALID);
    assert!(code.is_permanent_negative());
}

#[test]
fn reply_code_235() {
    let code = SmtpReplyCode::parse(b"235").unwrap();
    assert_eq!(code, SmtpReplyCode::AUTH_SUCCESSFUL);
    assert_eq!(code.code(), 235);
}

#[test]
fn reply_code_invalid_class() {
    assert!(SmtpReplyCode::parse(b"150").is_err());
    assert!(SmtpReplyCode::parse(b"650").is_err());
}

// NOTE: Response tests below.

#[test]
fn response_is_complete_single_line() {
    assert!(SmtpResponse::is_complete(b"250 Ok\r\n"));
    assert!(!SmtpResponse::is_complete(b"250 Ok"));
    assert!(!SmtpResponse::is_complete(b"250 Ok\n"));
}

#[test]
fn response_is_complete_multiline() {
    // NOTE: a continuation line alone is not complete
    assert!(!SmtpResponse::is_complete(b"250-Ok\r\n"));
    // NOTE: continuation + final line is complete
    assert!(SmtpResponse::is_complete(b"250-Ok\r\n250 Done\r\n"));
}

#[test]
fn response_parse_single_line() {
    let r = SmtpResponse::parse(b"250 Ok\r\n").unwrap();
    assert_eq!(r.code, SmtpReplyCode::OK);
    assert_eq!(r.text().as_ref(), "Ok");
}

#[test]
fn response_parse_single_line_no_text() {
    let r = SmtpResponse::parse(b"250 \r\n").unwrap();
    assert_eq!(r.code, SmtpReplyCode::OK);
}

#[test]
fn response_parse_multiline() {
    let buf = b"250-First line\r\n250-Second line\r\n250 Final line\r\n";
    let r = SmtpResponse::parse(buf).unwrap();
    assert_eq!(r.code, SmtpReplyCode::OK);
    assert_eq!(r.text().as_ref(), "First line");
    assert_eq!(r.lines.as_ref().len(), 3);
}

#[test]
fn response_parse_auth_continue() {
    let r = SmtpResponse::parse(b"334 dXNlcm5hbWU6\r\n").unwrap();
    assert_eq!(r.code, SmtpReplyCode::AUTH_CONTINUE);
    assert_eq!(r.text().as_ref(), "dXNlcm5hbWU6");
}

#[test]
fn response_parse_enhanced_status_code() {
    // NOTE: some servers prefix text with an enhanced status code (RFC 2034)
    let r = SmtpResponse::parse(b"250 2.0.0 Ok: queued\r\n").unwrap();
    assert_eq!(r.code, SmtpReplyCode::OK);
    assert_eq!(r.text().as_ref(), "2.0.0 Ok: queued");
}

#[test]
fn response_parse_auth_rejected() {
    let r = SmtpResponse::parse(b"535 5.7.8 Authentication credentials invalid\r\n").unwrap();
    assert!(r.code.is_permanent_negative());
    assert_eq!(r.code.code(), 535);
}

// NOTE: Greeting tests below.

#[test]
fn greeting_is_complete_single() {
    assert!(SmtpGreeting::is_complete(b"220 smtp.example.com ESMTP\r\n"));
    assert!(!SmtpGreeting::is_complete(b"220 smtp.example.com ESMTP"));
    assert!(!SmtpGreeting::is_complete(b"220-smtp.example.com\r\n")); // NOTE: continuation, not done
}

#[test]
fn greeting_is_complete_multiline() {
    let buf = b"220-smtp.example.com Hello\r\n220 Ready\r\n";
    assert!(SmtpGreeting::is_complete(buf));
}

#[test]
fn greeting_parse_single_line() {
    let g = SmtpGreeting::parse(b"220 smtp.example.com ESMTP Postfix\r\n").unwrap();
    assert_eq!(g.domain.as_ref(), "smtp.example.com");
    assert!(g.text.is_some());
    assert_eq!(g.text.as_ref().unwrap().as_ref(), "ESMTP Postfix");
}

#[test]
fn greeting_parse_single_line_no_text() {
    let g = SmtpGreeting::parse(b"220 mail.example.org\r\n").unwrap();
    assert_eq!(g.domain.as_ref(), "mail.example.org");
    assert!(g.text.is_none());
}

#[test]
fn greeting_parse_multiline() {
    let buf = b"220-smtp.example.com ESMTP Sendmail\r\n\
                220-We do not relay\r\n\
                220 smtp.example.com\r\n";
    let g = SmtpGreeting::parse(buf).unwrap();
    assert_eq!(g.domain.as_ref(), "smtp.example.com");
    // NOTE: text from the first line is retained
    assert!(g.text.is_some());
    assert_eq!(g.text.as_ref().unwrap().as_ref(), "ESMTP Sendmail");
}

#[test]
fn greeting_parse_multiline_no_continuation_text() {
    let buf = b"220-smtp.example.com\r\n220 smtp.example.com\r\n";
    let g = SmtpGreeting::parse(buf).unwrap();
    assert_eq!(g.domain.as_ref(), "smtp.example.com");
    assert!(g.text.is_none());
}

// NOTE: Domain tests below.

#[test]
fn domain_parse_simple() {
    let d = SmtpDomain::parse(b"example.com").unwrap();
    assert_eq!(d.as_ref(), "example.com");
}

#[test]
fn domain_parse_subdomain() {
    let d = SmtpDomain::parse(b"smtp.mail.example.com").unwrap();
    assert_eq!(d.as_ref(), "smtp.mail.example.com");
}

#[test]
fn domain_parse_with_hyphen() {
    let d = SmtpDomain::parse(b"smtp-relay.example.com").unwrap();
    assert_eq!(d.as_ref(), "smtp-relay.example.com");
}

#[test]
fn domain_parse_reject_empty() {
    assert!(SmtpDomain::parse(b"").is_err());
}

// NOTE: EhloResponse tests below.

#[test]
fn ehlo_response_single_line() {
    let r = SmtpEhloResponse::parse(b"250 smtp.example.com\r\n").unwrap();
    assert_eq!(r.domain.as_ref(), "smtp.example.com");
    assert!(r.capabilities.is_empty());
}

#[test]
fn ehlo_response_with_greet() {
    let r = SmtpEhloResponse::parse(b"250 smtp.example.com Hello\r\n").unwrap();
    assert_eq!(r.domain.as_ref(), "smtp.example.com");
    assert!(r.greet.is_some());
    assert!(r.capabilities.is_empty());
}

#[test]
fn ehlo_response_multiline_capabilities() {
    let buf = b"250-smtp.example.com\r\n\
                250-SIZE 52428800\r\n\
                250-8BITMIME\r\n\
                250-PIPELINING\r\n\
                250-STARTTLS\r\n\
                250-AUTH PLAIN LOGIN\r\n\
                250 ENHANCEDSTATUSCODES\r\n";
    let r = SmtpEhloResponse::parse(buf).unwrap();
    assert_eq!(r.domain.as_ref(), "smtp.example.com");
    assert!(r.has_capability("SIZE"));
    assert!(r.has_capability("8BITMIME"));
    assert!(r.has_capability("PIPELINING"));
    assert!(r.has_capability("STARTTLS"));
    assert!(r.has_capability("AUTH"));
    assert!(r.has_capability("ENHANCEDSTATUSCODES"));
    let max_size: Option<u64> = r
        .capabilities
        .iter()
        .find(|c| {
            c.split_ascii_whitespace()
                .next()
                .is_some_and(|k| k.eq_ignore_ascii_case("SIZE"))
        })
        .and_then(|c| c.split_ascii_whitespace().nth(1))
        .and_then(|v| v.parse().ok());
    assert_eq!(max_size, Some(52428800));
}

#[test]
fn ehlo_response_size_without_value() {
    let buf = b"250-smtp.example.com\r\n250 SIZE\r\n";
    let r = SmtpEhloResponse::parse(buf).unwrap();
    assert!(r.has_capability("SIZE"));
    let max_size: Option<u64> = r
        .capabilities
        .iter()
        .find(|c| {
            c.split_ascii_whitespace()
                .next()
                .is_some_and(|k| k.eq_ignore_ascii_case("SIZE"))
        })
        .and_then(|c| c.split_ascii_whitespace().nth(1))
        .and_then(|v| v.parse().ok());
    assert_eq!(max_size, None);
}

#[test]
fn ehlo_response_auth_mechanisms() {
    let buf = b"250-smtp.example.com\r\n\
                250 AUTH PLAIN LOGIN SCRAM-SHA-256\r\n";
    let r = SmtpEhloResponse::parse(buf).unwrap();
    let mechs: Vec<&str> = r
        .capabilities
        .iter()
        .find(|c| {
            c.split_ascii_whitespace()
                .next()
                .is_some_and(|k| k.eq_ignore_ascii_case("AUTH"))
        })
        .map_or(vec![], |c| c.split_ascii_whitespace().skip(1).collect());
    assert!(mechs.contains(&"PLAIN"));
    assert!(mechs.contains(&"LOGIN"));
    assert!(mechs.contains(&"SCRAM-SHA-256"));
}

#[test]
fn ehlo_response_unknown_capability() {
    let buf = b"250-smtp.example.com\r\n250 CHUNKING\r\n";
    let r = SmtpEhloResponse::parse(buf).unwrap();
    assert!(r.has_capability("CHUNKING"));
}

#[test]
fn ehlo_response_smtputf8() {
    let buf = b"250-smtp.example.com\r\n250 SMTPUTF8\r\n";
    let r = SmtpEhloResponse::parse(buf).unwrap();
    assert_eq!(r.capabilities[0].as_ref(), "SMTPUTF8");
}

#[test]
fn ehlo_response_is_complete() {
    // NOTE: incomplete: still a continuation line
    assert!(!SmtpEhloResponse::is_complete(b"250-smtp.example.com\r\n"));
    // NOTE: complete: final line has space not dash
    assert!(SmtpEhloResponse::is_complete(
        b"250-smtp.example.com\r\n250 OK\r\n"
    ));
    // NOTE: single-line with space is complete
    assert!(SmtpEhloResponse::is_complete(b"250 smtp.example.com\r\n"));
}

// NOTE: Real-world server response samples below.

/// Gmail EHLO response (real-world sample).
#[test]
fn real_world_gmail_ehlo() {
    let buf = b"250-smtp.gmail.com at your service, [1.2.3.4]\r\n\
                250-SIZE 35882577\r\n\
                250-8BITMIME\r\n\
                250-STARTTLS\r\n\
                250-ENHANCEDSTATUSCODES\r\n\
                250-PIPELINING\r\n\
                250-CHUNKING\r\n\
                250 SMTPUTF8\r\n";
    let r = SmtpEhloResponse::parse(buf).unwrap();
    assert_eq!(r.domain.as_ref(), "smtp.gmail.com");
    assert!(r.has_capability("STARTTLS"));
    assert!(r.has_capability("SMTPUTF8"));
    let max_size: Option<u64> = r
        .capabilities
        .iter()
        .find(|c| {
            c.split_ascii_whitespace()
                .next()
                .is_some_and(|k| k.eq_ignore_ascii_case("SIZE"))
        })
        .and_then(|c| c.split_ascii_whitespace().nth(1))
        .and_then(|v| v.parse().ok());
    assert_eq!(max_size, Some(35882577));
}

/// Fastmail EHLO response (real-world sample).
#[test]
fn real_world_fastmail_ehlo() {
    let buf = b"250-smtp.fastmail.com\r\n\
                250-SIZE 52428800\r\n\
                250-8BITMIME\r\n\
                250-PIPELINING\r\n\
                250-STARTTLS\r\n\
                250-ENHANCEDSTATUSCODES\r\n\
                250 AUTH PLAIN\r\n";
    let r = SmtpEhloResponse::parse(buf).unwrap();
    assert!(r.has_capability("AUTH"));
    let mechs: Vec<&str> = r
        .capabilities
        .iter()
        .find(|c| {
            c.split_ascii_whitespace()
                .next()
                .is_some_and(|k| k.eq_ignore_ascii_case("AUTH"))
        })
        .map_or(vec![], |c| c.split_ascii_whitespace().skip(1).collect());
    assert!(mechs.contains(&"PLAIN"));
}

/// Multi-line 220 greeting as sent by some Sendmail/Postfix configurations.
#[test]
fn real_world_multiline_greeting() {
    let buf = b"220-mail.example.org ESMTP Sendmail 8.17/8.17\r\n\
                220-Ready to receive messages\r\n\
                220 mail.example.org\r\n";
    assert!(SmtpGreeting::is_complete(buf));
    let g = SmtpGreeting::parse(buf).unwrap();
    assert_eq!(g.domain.as_ref(), "mail.example.org");
}

/// Stalwart SMTP greeting (real-world sample).
#[test]
fn real_world_stalwart_greeting() {
    let g = SmtpGreeting::parse(b"220 localhost ESMTP Stalwart Mail Server\r\n").unwrap();
    assert_eq!(g.domain.as_ref(), "localhost");
    assert_eq!(
        g.text.as_ref().unwrap().as_ref(),
        "ESMTP Stalwart Mail Server"
    );
}
