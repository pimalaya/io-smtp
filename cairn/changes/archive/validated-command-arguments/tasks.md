---
cairn: tasks
change: validated-command-arguments
---

# Tasks

- [x] Reproduce: one command per hostile string, counted lines on the wire (eight failing tests)
- [x] Add `SmtpSyntaxError`
- [x] Make `SmtpLocalPart` and `SmtpDomain` private, add `TryFrom<&str>` and `SmtpLocalPart::quote`
- [x] Add `SmtpGeneralAddressLiteral`, parse `SmtpAddressLiteral`, `SmtpEhloDomain` and `SmtpMailbox` from their wire form
- [x] Make `SmtpParameter` private, add `SmtpParameter::new` and its readers
- [x] xtext-encode `ENVID` and `ORCPT`
- [x] Move the doc examples, the tests, the examples and the fuzz target to the constructors
- [x] Tests: each production, each refusal, every ASCII character through every argument
- [x] CHANGELOG, spec, log
