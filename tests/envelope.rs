//! Tests for the command arguments the caller gives: whatever the
//! string, a command stays one line. No network connection is made.

use io_smtp::rfc5321::{
    SmtpAddressLiteral, SmtpDomain, SmtpEhloDomain, SmtpForwardPath, SmtpGeneralAddressLiteral,
    SmtpLocalPart, SmtpMailbox, SmtpParameter, SmtpReversePath, SmtpSyntaxError,
    ehlo::SmtpEhloCommand, helo::SmtpHeloCommand, mail::SmtpMailCommand, rcpt::SmtpRcptCommand,
};

fn mail(reverse_path: SmtpReversePath<'_>, parameters: Vec<SmtpParameter<'_>>) -> Vec<u8> {
    let command = SmtpMailCommand {
        reverse_path,
        parameters,
    };

    command.into()
}

fn rcpt(mailbox: SmtpMailbox<'_>, parameters: Vec<SmtpParameter<'_>>) -> Vec<u8> {
    let command = SmtpRcptCommand {
        forward_path: SmtpForwardPath(mailbox),
        parameters,
    };

    command.into()
}

#[test]
fn mail_from_local_part_crlf() {
    let local_part = "a@x>\r\nRCPT TO:<eve@evil.example>\r\nNOOP <a";
    let err = SmtpLocalPart::try_from(local_part).unwrap_err();
    assert_eq!(err, SmtpSyntaxError::LocalPart);

    let mailbox = "a@x>\r\nRCPT TO:<eve@evil.example>\r\nNOOP <a@example.com";
    assert!(SmtpMailbox::try_from(mailbox).is_err());
}

#[test]
fn rcpt_to_domain_crlf() {
    let err = SmtpDomain::try_from("x>\r\nRCPT TO:<eve@evil.example").unwrap_err();
    assert_eq!(err, SmtpSyntaxError::Domain);
}

#[test]
fn mail_from_parameter_value_crlf() {
    let value = "1\r\nRCPT TO:<eve@evil.example>";
    let err = SmtpParameter::new("SIZE", Some(value)).unwrap_err();
    assert_eq!(err, SmtpSyntaxError::ParameterValue);
}

#[test]
fn mail_from_envid_space() {
    let envid = SmtpParameter::envid("a SMTPUTF8").unwrap();
    let wire = mail(SmtpReversePath::Null, vec![envid]);

    assert_eq!(wire, b"MAIL FROM:<> ENVID=a+20SMTPUTF8\r\n");
}

#[test]
fn rcpt_to_orcpt_plus() {
    let mailbox = SmtpMailbox::try_from("a@x").unwrap();
    let orcpt = SmtpParameter::orcpt_rfc822("a+b@x").unwrap();
    let wire = rcpt(mailbox, vec![orcpt]);

    assert_eq!(wire, b"RCPT TO:<a@x> ORCPT=rfc822;a+2Bb@x\r\n");
}

#[test]
fn ehlo_address_literal_crlf() {
    let err = SmtpGeneralAddressLiteral::new("tag", "x]\r\nMAIL FROM:<>").unwrap_err();
    assert_eq!(err, SmtpSyntaxError::AddressLiteral);

    let err = SmtpEhloDomain::try_from("[tag:x]\r\nMAIL FROM:<>]").unwrap_err();
    assert_eq!(err, SmtpSyntaxError::AddressLiteral);
}

#[test]
fn helo_domain_crlf() {
    let err = SmtpDomain::try_from("x\r\nMAIL FROM:<>").unwrap_err();
    assert_eq!(err, SmtpSyntaxError::Domain);
}

#[test]
fn rcpt_to_local_part_space() {
    let err = SmtpMailbox::try_from("john doe@x").unwrap_err();
    assert_eq!(err, SmtpSyntaxError::LocalPart);

    let mailbox = SmtpMailbox {
        local_part: SmtpLocalPart::quote("john doe").unwrap(),
        domain: SmtpEhloDomain::try_from("x").unwrap(),
    };

    assert_eq!(rcpt(mailbox, Vec::new()), b"RCPT TO:<\"john doe\"@x>\r\n");
}

/// Every ASCII character, put inside every argument: the constructor
/// refuses it or the command it serialises to is one line.
#[test]
fn accepted_arguments_serialise_to_one_line() {
    let one_line = |wire: Vec<u8>| {
        let (line, crlf) = wire.split_at(wire.len() - 2);
        crlf == b"\r\n" && !line.iter().any(|b| matches!(b, b'\r' | b'\n' | 0))
    };

    let x = || SmtpEhloDomain::try_from("x").unwrap();

    for c in (0..=0x7fu8).map(char::from) {
        let s = format!("a{c}b");
        let quoted = format!("\"a{c}b\"");
        let literal = format!("[tag:a{c}b]");

        let local_parts = [
            SmtpLocalPart::try_from(s.as_str()),
            SmtpLocalPart::try_from(quoted.as_str()),
            SmtpLocalPart::quote(&s),
        ];

        for local_part in local_parts.into_iter().flatten() {
            let domain = x();
            let wire = rcpt(SmtpMailbox { local_part, domain }, Vec::new());
            assert!(one_line(wire), "local part with {c:?}");
        }

        for address in [format!("{s}@x"), format!("x@{s}"), format!("x@{literal}")] {
            if let Ok(mailbox) = SmtpMailbox::try_from(address.as_str()) {
                let wire = mail(SmtpReversePath::SmtpMailbox(mailbox), Vec::new());
                assert!(one_line(wire), "mailbox with {c:?}");
            }
        }

        if let Ok(domain) = SmtpDomain::try_from(s.as_str()) {
            let wire: Vec<u8> = SmtpHeloCommand { domain }.into();
            assert!(one_line(wire), "domain with {c:?}");
        }

        if let Ok(literal) = SmtpAddressLiteral::try_from(literal.as_str()) {
            let domain = SmtpEhloDomain::SmtpAddressLiteral(literal);
            let wire: Vec<u8> = SmtpEhloCommand { domain }.into();
            assert!(one_line(wire), "address literal with {c:?}");
        }

        let parameters = [
            SmtpParameter::new(&s, None),
            SmtpParameter::new("K", Some(&s)),
            SmtpParameter::envid(&s),
            SmtpParameter::orcpt_rfc822(&s),
        ];

        for parameter in parameters.into_iter().flatten() {
            let wire = mail(SmtpReversePath::Null, vec![parameter]);
            assert!(one_line(wire.clone()), "parameter with {c:?}");

            let spaces = wire.iter().filter(|b| **b == b' ').count();
            assert_eq!(spaces, 2, "parameter with {c:?}");
        }
    }
}
