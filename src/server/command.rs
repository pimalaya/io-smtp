//! Server-side command parser (RFC 5321 section 4.1, RFC 2033, RFC 1870,
//! RFC 3461, RFC 4954, RFC 6152, RFC 6531).
//!
//! [`SmtpServerCommand::parse`] reads one command line, CRLF excluded.
//! Verbs and parameter keywords are case-insensitive, `<>` is the null
//! reverse path, a source route is accepted and ignored, and addresses
//! may hold UTF-8 (RFC 6531).

use alloc::string::{String, ToString};
use core::str;

use bounded_static::IntoBoundedStatic;
use thiserror::Error;

use crate::{
    rfc3461::parameter::{SmtpDsnNotify, SmtpDsnRet, xtext_decode},
    rfc5321::{SmtpForwardPath, SmtpMailbox, SmtpReversePath},
};

/// A command a client sent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SmtpServerCommand {
    /// `EHLO <domain>`.
    Ehlo(String),
    /// `HELO <domain>`.
    Helo(String),
    /// `LHLO <domain>` (RFC 2033).
    Lhlo(String),
    /// `MAIL FROM:<reverse-path> [params]`.
    Mail {
        /// The sender, possibly null.
        reverse_path: SmtpReversePath<'static>,
        /// The ESMTP parameters.
        params: SmtpServerMailParams,
    },
    /// `RCPT TO:<forward-path> [params]`.
    Rcpt {
        /// The recipient, `None` for the bare `<Postmaster>` of RFC 5321
        /// section 4.5.1.
        forward_path: Option<SmtpForwardPath<'static>>,
        /// The ESMTP parameters.
        params: SmtpServerRcptParams,
    },
    /// `DATA`.
    Data,
    /// `RSET`.
    Rset,
    /// `NOOP [string]`.
    Noop,
    /// `QUIT`.
    Quit,
    /// `VRFY <string>`.
    Vrfy(String),
    /// `HELP [string]`.
    Help(Option<String>),
    /// `STARTTLS` (RFC 3207).
    StartTls,
    /// `AUTH <mechanism> [initial-response]` (RFC 4954).
    Auth {
        /// The mechanism name, as sent.
        mechanism: String,
        /// The initial response, still base64-encoded, `=` for an empty
        /// one.
        initial_response: Option<String>,
    },
}

/// The body type of `MAIL FROM` (RFC 6152, RFC 3030).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmtpServerBody {
    /// `BODY=7BIT`.
    SevenBit,
    /// `BODY=8BITMIME`.
    EightBitMime,
    /// `BODY=BINARYMIME`.
    BinaryMime,
}

/// The parameters of `MAIL FROM`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SmtpServerMailParams {
    /// `SIZE=` (RFC 1870).
    pub size: Option<u64>,
    /// `BODY=` (RFC 6152).
    pub body: Option<SmtpServerBody>,
    /// `SMTPUTF8` (RFC 6531).
    pub smtputf8: bool,
    /// `RET=` (RFC 3461).
    pub ret: Option<SmtpDsnRet>,
    /// `ENVID=`, xtext-decoded (RFC 3461).
    pub envid: Option<String>,
    /// `AUTH=`, xtext-decoded, `<>` included (RFC 4954).
    pub auth: Option<String>,
}

/// The `ORCPT=` parameter of `RCPT TO` (RFC 3461 section 4.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpServerOrcpt {
    /// The address type, such as `rfc822`.
    pub addr_type: String,
    /// The original address, xtext-decoded.
    pub addr: String,
}

/// The parameters of `RCPT TO`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SmtpServerRcptParams {
    /// `NOTIFY=` (RFC 3461).
    pub notify: Option<SmtpDsnNotify>,
    /// `ORCPT=` (RFC 3461).
    pub orcpt: Option<SmtpServerOrcpt>,
}

/// Failure causes of [`SmtpServerCommand::parse`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SmtpServerCommandError {
    /// The verb is unknown (500).
    #[error("Unknown SMTP command")]
    Unknown,
    /// The verb is known but not implemented (502).
    #[error("SMTP command not implemented")]
    NotImplemented,
    /// The arguments do not follow the grammar (501).
    #[error("Invalid SMTP command syntax")]
    Syntax,
    /// The path is not a valid address (501).
    #[error("Invalid SMTP address")]
    Address,
    /// A parameter keyword is unknown (555).
    #[error("Unknown SMTP parameter {0}")]
    UnknownParam(String),
    /// A parameter value is invalid, or the parameter repeated (501).
    #[error("Invalid SMTP parameter {0}")]
    InvalidParam(String),
}

impl SmtpServerCommand {
    /// Parses one command line, CRLF excluded.
    pub fn parse(line: &[u8]) -> Result<Self, SmtpServerCommandError> {
        let line = str::from_utf8(line).map_err(|_| SmtpServerCommandError::Syntax)?;

        let (verb, args) = match line.find(' ') {
            Some(i) => (&line[..i], Some(&line[i + 1..])),
            None => (line, None),
        };

        let verb_is = |name: &str| verb.eq_ignore_ascii_case(name);

        if verb_is("EHLO") || verb_is("HELO") || verb_is("LHLO") {
            let domain = single_arg(args)?.to_string();

            return Ok(if verb_is("EHLO") {
                Self::Ehlo(domain)
            } else if verb_is("HELO") {
                Self::Helo(domain)
            } else {
                Self::Lhlo(domain)
            });
        }

        if verb_is("MAIL") {
            let rest = strip_prefix_no_case(args.unwrap_or_default(), "FROM:")?;
            let (path, params) = split_path(rest)?;

            let reverse_path = if path.is_empty() {
                SmtpReversePath::Null
            } else {
                SmtpReversePath::SmtpMailbox(mailbox(path)?)
            };

            let params = mail_params(params)?;
            return Ok(Self::Mail {
                reverse_path,
                params,
            });
        }

        if verb_is("RCPT") {
            let rest = strip_prefix_no_case(args.unwrap_or_default(), "TO:")?;
            let (path, params) = split_path(rest)?;

            let forward_path = if path.eq_ignore_ascii_case("postmaster") {
                None
            } else if path.is_empty() {
                return Err(SmtpServerCommandError::Address);
            } else {
                Some(SmtpForwardPath(mailbox(path)?))
            };

            let params = rcpt_params(params)?;
            return Ok(Self::Rcpt {
                forward_path,
                params,
            });
        }

        if verb_is("AUTH") {
            let mut words = args.unwrap_or_default().split(' ');

            let (Some(mechanism), initial_response, None) = (
                words.next().filter(|m| !m.is_empty()),
                words.next(),
                words.next(),
            ) else {
                return Err(SmtpServerCommandError::Syntax);
            };

            if initial_response.is_some_and(str::is_empty) {
                return Err(SmtpServerCommandError::Syntax);
            }

            return Ok(Self::Auth {
                mechanism: mechanism.to_string(),
                initial_response: initial_response.map(ToString::to_string),
            });
        }

        if verb_is("VRFY") {
            let arg = args.filter(|a| !a.is_empty());
            let arg = arg.ok_or(SmtpServerCommandError::Syntax)?;
            return Ok(Self::Vrfy(arg.to_string()));
        }

        if verb_is("HELP") {
            let arg = args.filter(|a| !a.is_empty()).map(ToString::to_string);
            return Ok(Self::Help(arg));
        }

        if verb_is("NOOP") {
            return Ok(Self::Noop);
        }

        let bare = |command| match args {
            None => Ok(command),
            Some(_) => Err(SmtpServerCommandError::Syntax),
        };

        if verb_is("DATA") {
            bare(Self::Data)
        } else if verb_is("RSET") {
            bare(Self::Rset)
        } else if verb_is("QUIT") {
            bare(Self::Quit)
        } else if verb_is("STARTTLS") {
            bare(Self::StartTls)
        } else if [
            "EXPN", "BDAT", "TURN", "ETRN", "ATRN", "SEND", "SOML", "SAML",
        ]
        .iter()
        .any(|name| verb_is(name))
        {
            Err(SmtpServerCommandError::NotImplemented)
        } else {
            Err(SmtpServerCommandError::Unknown)
        }
    }
}

/// The one argument of a hello command, extra words being tolerated.
fn single_arg(args: Option<&str>) -> Result<&str, SmtpServerCommandError> {
    let arg = args.and_then(|a| a.split(' ').find(|w| !w.is_empty()));
    let arg = arg.ok_or(SmtpServerCommandError::Syntax)?;

    if arg.bytes().any(|b| b.is_ascii_control()) {
        return Err(SmtpServerCommandError::Syntax);
    }

    Ok(arg)
}

fn strip_prefix_no_case<'a>(s: &'a str, prefix: &str) -> Result<&'a str, SmtpServerCommandError> {
    match s.get(..prefix.len()) {
        Some(head) if head.eq_ignore_ascii_case(prefix) => Ok(&s[prefix.len()..]),
        _ => Err(SmtpServerCommandError::Syntax),
    }
}

/// Splits `<path> params` into the path content and the parameters,
/// a source route being dropped.
fn split_path(s: &str) -> Result<(&str, &str), SmtpServerCommandError> {
    let s = s.trim_start_matches(' ');
    let s = s.strip_prefix('<').ok_or(SmtpServerCommandError::Syntax)?;

    let mut quoted = false;
    let mut escaped = false;
    let mut end = None;

    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '>' if !quoted => {
                end = Some(i);
                break;
            }
            _ => (),
        }
    }

    let end = end.ok_or(SmtpServerCommandError::Syntax)?;
    let mut path = &s[..end];
    let params = &s[end + 1..];

    if !params.is_empty() && !params.starts_with(' ') {
        return Err(SmtpServerCommandError::Syntax);
    }

    if path.starts_with('@') {
        let colon = path.find(':').ok_or(SmtpServerCommandError::Address)?;
        path = &path[colon + 1..];

        if path.is_empty() {
            return Err(SmtpServerCommandError::Address);
        }
    }

    Ok((path, params))
}

fn mailbox(path: &str) -> Result<SmtpMailbox<'static>, SmtpServerCommandError> {
    match SmtpMailbox::try_from(path) {
        Ok(mailbox) => Ok(mailbox.into_static()),
        Err(_) => Err(SmtpServerCommandError::Address),
    }
}

/// Iterates over `keyword[=value]` parameters, keywords uppercased.
fn params(s: &str) -> impl Iterator<Item = (String, Option<&str>)> {
    s.split(' ')
        .filter(|p| !p.is_empty())
        .map(|p| match p.find('=') {
            Some(i) => (p[..i].to_ascii_uppercase(), Some(&p[i + 1..])),
            None => (p.to_ascii_uppercase(), None),
        })
}

fn set<T>(
    slot: &mut Option<T>,
    keyword: &str,
    value: Option<T>,
) -> Result<(), SmtpServerCommandError> {
    let invalid = || SmtpServerCommandError::InvalidParam(keyword.to_string());

    if slot.is_some() {
        return Err(invalid());
    }

    *slot = Some(value.ok_or_else(invalid)?);
    Ok(())
}

fn mail_params(s: &str) -> Result<SmtpServerMailParams, SmtpServerCommandError> {
    let mut out = SmtpServerMailParams::default();

    for (keyword, value) in params(s) {
        let invalid = || SmtpServerCommandError::InvalidParam(keyword.clone());

        match keyword.as_str() {
            "SIZE" => {
                let size = value
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|v| v.parse().ok());
                set(&mut out.size, &keyword, size)?;
            }
            "BODY" => {
                let body = match value.map(str::to_ascii_uppercase).as_deref() {
                    Some("7BIT") => Some(SmtpServerBody::SevenBit),
                    Some("8BITMIME") => Some(SmtpServerBody::EightBitMime),
                    Some("BINARYMIME") => Some(SmtpServerBody::BinaryMime),
                    _ => None,
                };
                set(&mut out.body, &keyword, body)?;
            }
            "SMTPUTF8" => {
                if out.smtputf8 || value.is_some() {
                    return Err(invalid());
                }
                out.smtputf8 = true;
            }
            "RET" => {
                let ret = match value.map(str::to_ascii_uppercase).as_deref() {
                    Some("FULL") => Some(SmtpDsnRet::Full),
                    Some("HDRS") => Some(SmtpDsnRet::Hdrs),
                    _ => None,
                };
                set(&mut out.ret, &keyword, ret)?;
            }
            "ENVID" => {
                let envid = value.filter(|v| !v.is_empty()).and_then(xtext_decode);
                set(&mut out.envid, &keyword, envid)?;
            }
            "AUTH" => {
                let auth = value.filter(|v| !v.is_empty()).and_then(xtext_decode);
                set(&mut out.auth, &keyword, auth)?;
            }
            _ => return Err(SmtpServerCommandError::UnknownParam(keyword)),
        }
    }

    Ok(out)
}

fn rcpt_params(s: &str) -> Result<SmtpServerRcptParams, SmtpServerCommandError> {
    let mut out = SmtpServerRcptParams::default();

    for (keyword, value) in params(s) {
        match keyword.as_str() {
            "NOTIFY" => {
                let notify = value.and_then(notify);
                set(&mut out.notify, &keyword, notify)?;
            }
            "ORCPT" => {
                let orcpt = value.and_then(|v| {
                    let (addr_type, addr) = v.split_once(';')?;
                    let valid_type = !addr_type.is_empty()
                        && addr_type
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-');

                    if !valid_type || addr.is_empty() {
                        return None;
                    }

                    Some(SmtpServerOrcpt {
                        addr_type: addr_type.to_string(),
                        addr: xtext_decode(addr)?,
                    })
                });
                set(&mut out.orcpt, &keyword, orcpt)?;
            }
            _ => return Err(SmtpServerCommandError::UnknownParam(keyword)),
        }
    }

    Ok(out)
}

fn notify(value: &str) -> Option<SmtpDsnNotify> {
    if value.eq_ignore_ascii_case("NEVER") {
        return Some(SmtpDsnNotify::NEVER);
    }

    let mut notify: Option<SmtpDsnNotify> = None;

    for condition in value.split(',') {
        let flag = if condition.eq_ignore_ascii_case("SUCCESS") {
            SmtpDsnNotify::SUCCESS
        } else if condition.eq_ignore_ascii_case("FAILURE") {
            SmtpDsnNotify::FAILURE
        } else if condition.eq_ignore_ascii_case("DELAY") {
            SmtpDsnNotify::DELAY
        } else {
            return None;
        };

        if notify.is_some_and(|n| n.contains(flag)) {
            return None;
        }

        notify = Some(notify.map_or(flag, |n| n | flag));
    }

    notify
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use crate::{
        rfc3461::parameter::{SmtpDsnNotify, SmtpDsnRet},
        server::command::*,
    };

    fn parse(line: &str) -> Result<SmtpServerCommand, SmtpServerCommandError> {
        SmtpServerCommand::parse(line.as_bytes())
    }

    #[test]
    fn verbs_are_case_insensitive() {
        assert_eq!(
            parse("ehlo a.example").unwrap(),
            SmtpServerCommand::Ehlo("a.example".into())
        );
        assert_eq!(
            parse("HeLo a.example").unwrap(),
            SmtpServerCommand::Helo("a.example".into())
        );
        assert_eq!(
            parse("LHLO a.example").unwrap(),
            SmtpServerCommand::Lhlo("a.example".into())
        );
        assert_eq!(parse("data").unwrap(), SmtpServerCommand::Data);
        assert_eq!(parse("Rset").unwrap(), SmtpServerCommand::Rset);
        assert_eq!(parse("NOOP whatever").unwrap(), SmtpServerCommand::Noop);
        assert_eq!(parse("quit").unwrap(), SmtpServerCommand::Quit);
        assert_eq!(parse("StartTLS").unwrap(), SmtpServerCommand::StartTls);
        assert_eq!(parse("HELP").unwrap(), SmtpServerCommand::Help(None));
        assert_eq!(
            parse("VRFY Smith").unwrap(),
            SmtpServerCommand::Vrfy("Smith".into())
        );
    }

    #[test]
    fn unknown_and_unimplemented_verbs_are_told_apart() {
        assert_eq!(parse("FOO").unwrap_err(), SmtpServerCommandError::Unknown);
        assert_eq!(parse("").unwrap_err(), SmtpServerCommandError::Unknown);
        assert_eq!(
            parse("EXPN list").unwrap_err(),
            SmtpServerCommandError::NotImplemented
        );
        assert_eq!(
            parse("BDAT 10 LAST").unwrap_err(),
            SmtpServerCommandError::NotImplemented
        );
    }

    #[test]
    fn bare_commands_refuse_arguments() {
        for line in [
            "DATA x",
            "RSET x",
            "QUIT x",
            "STARTTLS x",
            "EHLO",
            "VRFY",
            "AUTH",
        ] {
            assert_eq!(
                parse(line).unwrap_err(),
                SmtpServerCommandError::Syntax,
                "{line}"
            );
        }
    }

    #[test]
    fn null_reverse_path_and_source_route() {
        let SmtpServerCommand::Mail { reverse_path, .. } = parse("MAIL FROM:<>").unwrap() else {
            panic!();
        };
        assert_eq!(reverse_path, SmtpReversePath::Null);

        let line = "RCPT TO:<@hosta.int,@jkl.org:userc@d.bar.org>";
        let SmtpServerCommand::Rcpt { forward_path, .. } = parse(line).unwrap() else {
            panic!();
        };
        assert_eq!(forward_path.unwrap().to_string(), "<userc@d.bar.org>");
    }

    #[test]
    fn postmaster_and_utf8_addresses() {
        let SmtpServerCommand::Rcpt { forward_path, .. } = parse("RCPT TO:<Postmaster>").unwrap()
        else {
            panic!();
        };
        assert_eq!(forward_path, None);

        let line = "MAIL FROM:<jörg@bücher.example> SMTPUTF8";
        let SmtpServerCommand::Mail {
            reverse_path,
            params,
        } = parse(line).unwrap()
        else {
            panic!();
        };
        assert_eq!(reverse_path.to_string(), "<jörg@bücher.example>");
        assert!(params.smtputf8);
    }

    #[test]
    fn lenient_space_after_colon_and_quoted_local_part() {
        let line = r#"mail from: <"a>b"@example.org> size=100"#;
        let SmtpServerCommand::Mail {
            reverse_path,
            params,
        } = parse(line).unwrap()
        else {
            panic!();
        };
        assert_eq!(reverse_path.to_string(), r#"<"a>b"@example.org>"#);
        assert_eq!(params.size, Some(100));
    }

    #[test]
    fn mail_parameters_are_parsed() {
        let line =
            "MAIL FROM:<a@b.example> SIZE=1234 BODY=8BITMIME RET=HDRS ENVID=QQ+2B314 AUTH=<>";
        let SmtpServerCommand::Mail { params, .. } = parse(line).unwrap() else {
            panic!();
        };
        assert_eq!(
            params,
            SmtpServerMailParams {
                size: Some(1234),
                body: Some(SmtpServerBody::EightBitMime),
                smtputf8: false,
                ret: Some(SmtpDsnRet::Hdrs),
                envid: Some("QQ+314".into()),
                auth: Some("<>".into()),
            }
        );

        let line = "MAIL FROM:<a@b.example> BODY=binarymime";
        let SmtpServerCommand::Mail { params, .. } = parse(line).unwrap() else {
            panic!();
        };
        assert_eq!(params.body, Some(SmtpServerBody::BinaryMime));
    }

    #[test]
    fn rcpt_dsn_parameters_follow_rfc3461() {
        let line =
            "RCPT TO:<Bob@Example.COM> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;Bob+2BBobby@Example.COM";
        let SmtpServerCommand::Rcpt { params, .. } = parse(line).unwrap() else {
            panic!();
        };
        assert_eq!(
            params.notify,
            Some(SmtpDsnNotify::SUCCESS | SmtpDsnNotify::FAILURE)
        );
        assert_eq!(
            params.orcpt,
            Some(SmtpServerOrcpt {
                addr_type: "rfc822".into(),
                addr: "Bob+Bobby@Example.COM".into(),
            })
        );

        let line = "RCPT TO:<a@b.example> NOTIFY=NEVER";
        let SmtpServerCommand::Rcpt { params, .. } = parse(line).unwrap() else {
            panic!();
        };
        assert!(params.notify.unwrap().is_never());
    }

    #[test]
    fn invalid_parameters_are_refused() {
        let cases = vec![
            (
                "MAIL FROM:<a@b.example> SIZE=abc",
                SmtpServerCommandError::InvalidParam("SIZE".into()),
            ),
            (
                "MAIL FROM:<a@b.example> SIZE=1 SIZE=2",
                SmtpServerCommandError::InvalidParam("SIZE".into()),
            ),
            (
                "MAIL FROM:<a@b.example> BODY=9BIT",
                SmtpServerCommandError::InvalidParam("BODY".into()),
            ),
            (
                "MAIL FROM:<a@b.example> ENVID=a+2",
                SmtpServerCommandError::InvalidParam("ENVID".into()),
            ),
            (
                "MAIL FROM:<a@b.example> FOO=bar",
                SmtpServerCommandError::UnknownParam("FOO".into()),
            ),
            (
                "RCPT TO:<a@b.example> NOTIFY=NEVER,SUCCESS",
                SmtpServerCommandError::InvalidParam("NOTIFY".into()),
            ),
            (
                "RCPT TO:<a@b.example> NOTIFY=SUCCESS,SUCCESS",
                SmtpServerCommandError::InvalidParam("NOTIFY".into()),
            ),
            (
                "RCPT TO:<a@b.example> ORCPT=rfc822",
                SmtpServerCommandError::InvalidParam("ORCPT".into()),
            ),
            (
                "RCPT TO:<a@b.example> SIZE=1",
                SmtpServerCommandError::UnknownParam("SIZE".into()),
            ),
            ("RCPT TO:<>", SmtpServerCommandError::Address),
            ("RCPT TO:<a b@c>", SmtpServerCommandError::Address),
            ("MAIL FROM:a@b.example", SmtpServerCommandError::Syntax),
            ("MAIL FROM:<a@b.example", SmtpServerCommandError::Syntax),
            (
                "MAIL FROM:<a@b.example>SIZE=1",
                SmtpServerCommandError::Syntax,
            ),
            ("MAIL TO:<a@b.example>", SmtpServerCommandError::Syntax),
        ];

        for (line, expected) in cases {
            assert_eq!(parse(line).unwrap_err(), expected, "{line}");
        }
    }

    #[test]
    fn auth_takes_a_mechanism_and_an_optional_response() {
        assert_eq!(
            parse("AUTH PLAIN AGFsaWNlAHBlbmNpbA==").unwrap(),
            SmtpServerCommand::Auth {
                mechanism: "PLAIN".into(),
                initial_response: Some("AGFsaWNlAHBlbmNpbA==".into()),
            }
        );
        assert_eq!(
            parse("auth login").unwrap(),
            SmtpServerCommand::Auth {
                mechanism: "login".into(),
                initial_response: None,
            }
        );
        assert_eq!(
            parse("AUTH PLAIN a b").unwrap_err(),
            SmtpServerCommandError::Syntax
        );
    }

    #[test]
    fn invalid_utf8_is_a_syntax_error() {
        let err = SmtpServerCommand::parse(b"MAIL FROM:<\xff@b>").unwrap_err();
        assert_eq!(err, SmtpServerCommandError::Syntax);
    }
}
