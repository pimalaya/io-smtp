---
cairn: log
change: validated-command-arguments
landed: 2026-11-13
---

# Command arguments are valid by construction

The family audit of 2026-11-13 (SMTP-01) found that the `MAIL FROM`, `RCPT TO`, `EHLO` and `HELO` serialisers wrote caller strings as given. Eight tests on the 0.7.1 code, each building one command from a hostile string, all failed: a local part of `a@x>\r\nRCPT TO:<eve@evil.example>\r\nNOOP <a` gave three lines on the wire, a CR LF in a domain, a parameter value, a general address literal or a `HELO` domain gave two, `ENVID=a SMTPUTF8` and `ORCPT=rfc822;a+b@x` went out without their xtext encoding, and `john doe@x` unquoted.

The fix is in the types, not in the serialisers. `SmtpLocalPart` and `SmtpDomain` keep their string private and are built through `TryFrom<&str>`, `SmtpParameter` through `SmtpParameter::new`, and `SmtpAddressLiteral::General` holds the new `SmtpGeneralAddressLiteral`. Each enforces its RFC 5321 4.1.2 or 4.1.3 production and returns `SmtpSyntaxError`, one unit variant per production. `SmtpMailbox`, `SmtpEhloDomain` and `SmtpAddressLiteral` parse from their wire form: the mailbox reads its local part from the left, so a quoted `@` or a general literal holding one splits where it should, which a split at the last at sign does not guarantee. `SmtpMail::new`, `SmtpRcpt::new`, `SmtpEhlo::new`, `SmtpHelo::new`, `SmtpMessageSend::new` and both client traits are untouched, since a value of these types cannot hold a line ending.

Choices worth knowing:

- Non-ASCII characters pass in a local part, a domain and a parameter value, as RFC 6531 3.3 extends those productions. A strict RFC 5321 reading would have refused the internationalised addresses that went through before, and left the `SMTPUTF8` parameter without an address to carry. Nothing checks that a non-ASCII domain is a valid U-label, nor that `EHLO` gets an ASCII identity (RFC 6531 3.7.1): both fail at the server, on one line.
- `TryFrom<&str>` takes the wire form and never quotes, so `"a"` always means the Quoted-string. `SmtpLocalPart::quote` is the separate entry for unquoted content.
- `SmtpParameter::envid` and `SmtpParameter::orcpt_rfc822` now take the value before encoding and return a `Result`. A caller that passed an already encoded value gets its `+` encoded again.
- The length limits of RFC 5321 4.5.3.1 are not enforced: the RFC asks implementations not to impose them.
- `SmtpDomain::parse` and the greeting and `EHLO` parsers are unchanged, so what the server sends is read as before.
- `SmtpAtom` is kept, though nothing in the crate uses it any more: a parameter keyword is an esmtp-keyword and a literal tag an Ldh-str, both narrower than an atom.

**Breaking**: the public field of `SmtpLocalPart` and of `SmtpDomain` is gone; `SmtpParameter` has no public field and its keyword is no `SmtpAtom`; `SmtpAddressLiteral::General` is a tuple variant over `SmtpGeneralAddressLiteral`; `SmtpParameter::envid` and `SmtpParameter::orcpt_rfc822` return `Result<_, SmtpSyntaxError>` and take `impl AsRef<str>`. An application replaces its own split and tuple constructors by `SmtpMailbox::try_from(address)?.into_static()`, and `SmtpDomain(..)` by `SmtpDomain::try_from` or `SmtpEhloDomain::try_from`.

Still sent as given, by design or out of this change: the line of `SmtpRaw`, and the public fields `SmtpNoopCommand::string` and `SmtpAuthCommand::mechanism`, which no coroutine of the crate fills from a caller string.

Capabilities moved: command-arguments (new: "Arguments are valid by construction", "Non-ASCII characters are accepted", "Addresses parse from their wire form", "A local part is quoted when needed", "DSN values are xtext-encoded").

Existing tests changed, all for the removed fields: the greeting tests read `domain.as_ref()` instead of `domain.0`, and every helper building a domain or a mailbox from a tuple struct goes through `try_from`.

Verified: tests/envelope.rs holds the eight reproductions, now asserting the refusal or the encoded line, plus `accepted_arguments_serialise_to_one_line`, which puts every ASCII character in every argument and checks that what is accepted serialises to one line. `cargo test --all-features` 141 unit tests (22 new), 9 + 40 + 7 integration tests and 19 doc tests passed; `cargo clippy --all-features --all-targets -- -D warnings` clean; `cargo build --no-default-features` passes; `cargo check` on the fuzz crate passes once its lockfile, which still pins io-sasl 0.1.0, is refreshed (left as it was).
