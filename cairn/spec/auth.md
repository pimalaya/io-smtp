---
cairn: spec
capability: auth
status: current
---

# Authentication

The `AUTH` extension (RFC 4954) and the SASL mechanisms io-smtp frames over it. Two surfaces: the mechanism coroutines a caller drives to authenticate, and the reading of the `AUTH` line a server advertises in its `EHLO` response.

## Requirement: One coroutine per framed mechanism

io-smtp SHALL frame ANONYMOUS (RFC 4505), LOGIN, PLAIN (RFC 4616), OAUTHBEARER (RFC 7628), XOAUTH2 and SCRAM-SHA-256 (RFC 7677), each as its own coroutine under the `sasl` module. SCRAM-SHA-256 SHALL sit behind the `scram` feature, which is what pulls the hash and randomness crates; the rest SHALL be unconditional.

io-sasl computes more mechanisms than this crate frames. A session opened with credentials for one io-smtp has no coroutine for SHALL fail with `SmtpSessionOpenError::UnsupportedMechanism`, naming the mechanism, rather than skipping the exchange silently: a caller learns which of its credentials this crate cannot use. A mechanism io-sasl gains under a feature this crate does not enable falls into that same arm, so a build combining the two cannot authenticate by accident.

## Requirement: A session authenticates at most once, after any upgrade

`SmtpSessionOpen` SHALL take an `Option<Sasl>` and, given `None`, SHALL stop after the `EHLO` exchange, sending no `AUTH` command at all. That is the unauthenticated relay, and it SHALL NOT be reported as an error.

Given credentials, the `AUTH` exchange SHALL follow the STARTTLS upgrade and the second `EHLO` it requires, never precede them, so a mechanism carrying a password or a token is never framed over cleartext on a connection that was going to be upgraded.

## Requirement: The advertised mechanisms are readable from the EHLO response

`SmtpAuthCapability::parse` SHALL read the raw `AUTH` capability line, rejecting a line whose first token is not `AUTH`, and SHALL expose the advertised mechanism names through `has` (case-insensitive) and `mechanisms`. Both SHALL borrow from the capability line rather than allocating names, the response outliving the read.

The names SHALL be exposed as they were advertised, `&str`, and not as `SaslMechanism` values. A caller matching them against the mechanisms it can configure does that mapping itself.

## Requirement: The OAuth mechanisms are verified live

OAUTHBEARER and XOAUTH2 SHALL each be exercised by an ignored live test against Gmail's submission service, authenticating as a Workspace test user with a token the test mints from a service account key, so the suite runs unattended. The tests SHALL go through `SmtpClientStd::connect`, one over implicit TLS and one over STARTTLS, so the session layer and the upgrade are verified against a real server too. The test message SHALL go to that user only.
