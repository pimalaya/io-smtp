---
cairn: change
id: validated-command-arguments
status: landed
created: 2026-11-13
---

# Validate what the caller puts in a command

## Why

The `MAIL FROM`, `RCPT TO`, `EHLO` and `HELO` serialisers wrote the caller's strings to the wire as given. `SmtpLocalPart` and `SmtpDomain` were tuple structs over a public string, `SmtpParameter::value` and the content of `SmtpAddressLiteral::General` public strings, and `SmtpParameter::envid` and `SmtpParameter::orcpt_rfc822` copied their argument. A CR LF in any of them ended the command and started another: a local part of `a@x>\r\nRCPT TO:<eve@evil.example>` added a recipient the user never saw. No constructor checked a local part, a mailbox or a parameter value, and the applications building these types split an address at its last at sign and nothing more. Found by the family audit of 2026-11-13 (SMTP-01).

Two lesser defects shared the cause: a local part needing quotes, such as `john doe`, went out unquoted, and an `ENVID` or `ORCPT` value holding a space, `+` or `=` went out without its xtext encoding (RFC 3461 4).

## What

- The strings become valid by construction. `SmtpLocalPart`, `SmtpDomain` and `SmtpParameter` lose their public fields; `TryFrom<&str>` (and `SmtpParameter::new`) enforce the RFC 5321 4.1.2 productions and return the new `SmtpSyntaxError`. `SmtpAddressLiteral::General` holds a `SmtpGeneralAddressLiteral`, checked the same way (4.1.3).
- `SmtpMailbox`, `SmtpEhloDomain` and `SmtpAddressLiteral` parse from their wire form, so a caller writes `SmtpMailbox::try_from("alice@example.org")` in place of its own split.
- `SmtpLocalPart::quote` builds a local part from unquoted content, quoting it when it is not a Dot-string.
- `SmtpParameter::envid` and `SmtpParameter::orcpt_rfc822` xtext-encode their value and refuse what is not printable US-ASCII.
- Non-ASCII characters are accepted in a local part, a domain and a parameter value (RFC 6531 3.3): an internationalised address passed through before, and the `SMTPUTF8` parameter is the caller's to add.
- The command coroutines and the client traits keep their signatures: with valid types there is nothing left for them to refuse.
- What the server sends is parsed as before.

Left out: `SmtpRaw` sends its line as given, which is its purpose.
