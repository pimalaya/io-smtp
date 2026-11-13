---
cairn: tasks
change: noop-auth-arguments-and-bcc-lines
---

# Tasks

- [x] Reproduce: a CR LF in the NOOP string and in the AUTH mechanism gives two lines (two failing tests)
- [x] Add `SmtpString` and `SmtpAuthMechanism`, type the two fields with them
- [x] Document that `SmtpRaw` sends its line unchecked
- [x] Reproduce: a `Bcc` field after a bare CR and a `Resent-Bcc` field are transmitted (four failing tests)
- [x] End a line at CRLF, a bare CR or a bare LF in `strip_bcc`, match `Resent-Bcc`
- [x] Keep a bare CR from pairing with an LF across a removed field
- [x] Exhaustive test of the removal against the `DATA` rewrite
- [x] CHANGELOG, spec, log
