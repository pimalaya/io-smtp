---
cairn: change
id: noop-auth-arguments-and-bcc-lines
status: landed
created: 2026-11-13
---

# Validate the NOOP and AUTH arguments, strip Bcc on the lines DATA sends

## Why

Two defects from the family audit of 2026-11-13.

The change validated-command-arguments left two public fields that reach the wire as given: `SmtpNoopCommand::string` and `SmtpAuthCommand::mechanism`. No coroutine of the crate fills them from a caller string, but both structs are public and `SmtpCommandSend` serialises them, so a CR LF in either adds a command.

The `Bcc` removal of `SmtpMessageSend` and the `DATA` rewrite disagreed on what ends a line (SMTP-04). The removal split at LF only, `DATA` at CRLF, a bare CR or a bare LF. In `To: b@x\rBcc: c@x\r\n` the removal saw one `To` line and kept it, then `DATA` turned the bare CR into CRLF and sent a well-formed `Bcc` field to every recipient. It needs a bare CR line ending in the caller's own message, which classic Mac or mixed line endings give. The `Resent-Bcc` field, which RFC 5322 3.6.6 gives the meaning of `Bcc`, was transmitted as well.

## What

- `SmtpString`, an Atom or a Quoted-string (RFC 5321 4.1.2), is the type of `SmtpNoopCommand::string`. `SmtpAuthMechanism`, a sasl-mech (RFC 4422 3.1), is the type of `SmtpAuthCommand::mechanism`. Both are built through `TryFrom<&str>` and fail with `SmtpSyntaxError`, which gains the `String` and `AuthMechanism` variants.
- `SmtpRaw` stays unchecked, which is its purpose, and its documentation now says so.
- `strip_bcc` reads lines as `DATA` ends them, an empty line under any of the three endings closing the header section. It keeps its single pass and still returns a message without blind field as is.
- When the line before a removed field ends with a bare CR, an LF is added after it. Without it the CR could pair with a bare LF following the field, and the empty line that LF stood for would vanish.
- `Resent-Bcc` is removed like `Bcc`, and kept by `keep_bcc` like `Bcc`.
- An exhaustive test over short messages of field names, blanks and line endings checks the removal against the `DATA` rewrite itself, which becomes visible to the crate for it.
