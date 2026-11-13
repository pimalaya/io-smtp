---
cairn: change
id: scram-bounds-and-prepared-credentials
status: landed
created: 2026-11-13
---

# Move to io-sasl 0.2: bounded SCRAM iterations, prepared credentials

## Why

io-sasl 0.2.0 was published on 2026-11-13 and io-smtp has to move to it before its own release. Two of its changes reach this crate's behaviour, both left "for the bump" by the family audit of 2026-11-13.

- The SCRAM mechanism takes a `SaslScramOptions` bounding the iteration count a server may announce. Until now the key derivation ran for whatever count arrived, inside one resume: a server, or whoever stands in for it before the signature is verified, decided how long the caller computed. The bounds are of no use unless a caller of this crate can reach them.
- The `saslprep` feature of io-sasl is gone and preparation is unconditional. This crate depended on io-sasl without that feature, so PLAIN and SCRAM-SHA-256 sent, and derived from, the credentials as given.

## What

- The io-sasl requirement moves to 0.2, dependency and dev-dependency, and in the fuzz crate, whose lockfile is refreshed.
- `SmtpAuthScramSha256Options` gains `scram`, a `SaslScramOptions` handed to the mechanism.
- `SmtpSessionOpenOptions` gains `scram_min_iterations` and `scram_max_iterations`, which the session hands to the SCRAM coroutine and which `SmtpClientStd::connect` already carries in its `session` options. They are two plain fields present in every build, not a `SaslScramOptions` behind the `scram` feature: a field that exists under a feature makes a struct literal of the options compile or not depending on what another crate of the build enabled.
- `auth_scram_sha256` of both client traits takes a `SaslScramOptions`.
- A count outside the bounds comes in a 334, so it goes through the cancellation the mechanism coroutines already have.
- Credentials are prepared in every build. Nothing to write here but a test and the record.
