---
cairn: log
change: noop-auth-arguments-and-bcc-lines
landed: 2026-11-13
---

# NOOP and AUTH arguments are validated, Bcc is stripped on the lines DATA sends

Two follow-ups of the family audit of 2026-11-13.

## The last two unchecked fields

validated-command-arguments left `SmtpNoopCommand::string` and `SmtpAuthCommand::mechanism` as public strings. Two tests building each command with a CR LF in the field counted two lines on the wire. `SmtpString` (Atom or Quoted-string, RFC 5321 4.1.2) and `SmtpAuthMechanism` (1 to 20 characters among upper case letters, digits, hyphen and underscore, RFC 4422 3.1) now type them, built through `TryFrom<&str>`, with the `String` and `AuthMechanism` variants added to `SmtpSyntaxError`. `SmtpString` reuses the local part reader: a String is a local part whose Dot-string holds no dot. The six mechanism coroutines build their name from their own constant inside the crate, and a test checks every constant against the public constructor. A lower case mechanism name is refused, the production being upper case only.

`SmtpRaw` keeps sending its line as given. Its module, its constructor and the `raw` method of the client traits now say that a CR or LF in the line starts another command.

**Breaking**: `SmtpNoopCommand::string` is an `Option<SmtpString>` and `SmtpAuthCommand::mechanism` a `SmtpAuthMechanism`. Neither is built by the applications of the family, which go through `SmtpNoop::new` and the mechanism coroutines.

## Bcc removal and DATA agree on lines (SMTP-04)

`strip_bcc` split at LF only while `SmtpData` ends a line at CRLF, a bare CR or a bare LF. For `To: b@x\rBcc: c@x\r\n\r\nbody\r\n` the composite wrote `To: b@x\r\nBcc: c@x\r\n\r\nbody\r\n.\r\n`: the blind recipient disclosed to every recipient. Only the caller's own message can hold that bare CR, so there is no lever for a third party, but a message with classic Mac or mixed line endings is enough.

`strip_bcc` now finds the next CR or LF, takes a CRLF as one ending, and stops at the first line with no content. It stays a single pass and returns a message without blind field untouched. The alternative, running the `DATA` rewrite before the removal, would have added a pass over every message.

Removing bytes between two line endings has a trap the exhaustive test found during the work: in `To:\rBcc:\n\nbody` the kept `To:\r` would land next to the `\n` of the empty line and read as one CRLF, the empty line gone and the body turned into header lines. An LF is therefore added after a kept bare CR when the field following it is removed, which is what `DATA` sends for that CR anyway.

`Resent-Bcc` is removed too (RFC 5322 3.6.6), and `keep_bcc` keeps both.

Capabilities moved: command-arguments (MODIFIED "Arguments are valid by construction"), submission (MODIFIED "Blind recipients stay blind").

Verified: before the fix `removes_the_bcc_field_after_a_bare_cr`, `keeps_the_empty_line_between_a_bare_cr_and_a_bare_lf`, `removes_the_resent_bcc_field` and `matches_a_line_by_line_removal` failed. The last one builds every message of up to six tokens among `Bcc:`, `Resent-Bcc:`, `To:`, `x`, a space, CR and LF (137,257 messages) and requires the payload `SmtpData::prepare_body` makes of the stripped message to equal the payload of the untouched one less the lines of its blind fields; `prepare_body` became `pub(crate)` for it. With the LF-only split put back it fails on `To:\rBcc:`, and without the added LF on `To:\rBcc:\n\n`. tests/envelope.rs gains `noop_string_crlf` and `auth_mechanism_crlf`, and its every-character test now covers both types. `cargo test --all-features` 149 unit tests, 11 + 40 + 7 integration tests and 19 doc tests passed; `cargo clippy --all-features --all-targets -- -D warnings` clean; `cargo build --no-default-features` passes.
