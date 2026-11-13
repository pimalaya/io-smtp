---
cairn: tasks
change: reported-refusals-and-server-names
---

# Tasks

- [x] Reproduce: a refused greeting and a refused EHLO as parse errors, a banner with an address literal, a refused recipient without name nor RSET, a bracketed IPv6 host (five failing tests)
- [x] Add `SmtpResponse::message`, use it in every `Rejected`
- [x] Read the greeting and the EHLO response out of the generic reply, add the `Rejected` variants
- [x] Take the server name as given, as a `SmtpText`
- [x] Name the refused recipient, add `skip_refused_recipients`, `SmtpMessageSendRefusal` and `NoRecipient`
- [x] Send RSET before failing on a refused recipient or DATA command
- [x] `arg.take()` in the composites
- [x] Render the URL host from `Url::host`
- [x] Teach the fuzz target the new variants, run it
- [x] CHANGELOG, spec, log
