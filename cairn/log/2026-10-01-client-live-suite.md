---
cairn: log
change: client-live-suite
landed: 2026-10-01
---

# The client layer verified live

`run_client` (tests/common.rs) drives `SmtpClientStd::connect`, then NOOP, a raw NOOP, an aborted transaction and a sent one, then QUIT. The sent MAIL FROM carries `SIZE=` when the server advertises SIZE and the DSN parameters when it advertises DSN; an advertised AUTH line is read through `SmtpAuthCapability`.

Gmail runs it twice: `oauth_xoauth2` over implicit TLS on 465, `oauth_oauthbearer` over STARTTLS on 587. Stalwart gains `stalwart_client`, unauthenticated on 25. The raw flow's OAuth variants, unused since, are gone.

Live coverage of the library, measured with tarpaulin over the Gmail OAuth and Stalwart suites: 30.6% before, 43.4% after. Still unreached live: the password and SCRAM mechanisms (neither server offers them to these tests), DSN (neither advertises it), address literals.

Verified: all four tests green live, offline suite green, clippy clean on the test targets.

The [auth](../spec/auth.md) capability moved: "The OAuth mechanisms are verified live" now names the client layer and both transports.
