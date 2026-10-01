---
cairn: change
id: client-live-suite
status: landed
created: 2026-10-01
---

# The client layer verified live

## Why

Measured with tarpaulin on 2026-10-01, the live suites reach 30% of the library and none of `SmtpClientStd::connect`, the session layer or STARTTLS: every live test opens its own socket and pumps raw coroutines. The path consumers use (himalaya, sirup) is the one never tested against a real server.

## What

- tests/common.rs: `run_client(url, sasl, email, starttls)` drives `SmtpClientStd::connect` (TLS or STARTTLS, greeting, EHLO, SASL), then NOOP, a raw command, an aborted transaction (MAIL, RCPT, RSET), a sent one (MAIL, RCPT, DATA) and QUIT.
- tests/gmail.rs: `oauth_xoauth2` runs it over implicit TLS on 465, `oauth_oauthbearer` over STARTTLS on 587. Each still sends one message to the subject.
- The raw flow's OAuth variants, now unused, are removed.

No library change.
