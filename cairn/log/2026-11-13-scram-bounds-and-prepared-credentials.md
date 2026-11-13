---
cairn: log
change: scram-bounds-and-prepared-credentials
landed: 2026-11-13
---

# io-sasl 0.2: the SCRAM iteration count is bounded, credentials are prepared

io-smtp moved from io-sasl 0.1.1 to 0.2.0, published the same day, as a dependency, a dev-dependency and in the fuzz crate. `cargo tree -i io-sasl --all-features` shows one copy, 0.2.0; io-oauth 0.4, a dev-dependency, does not pull it. The lockfile gained unicode-normalization and tinyvec, which io-sasl now always needs. The fuzz lockfile was stale (io-sasl 0.1.0, rand and base64 still listed) and was refreshed with `cargo update -p io-sasl`. **Breaking**, io-sasl types being part of this crate's API.

## Iteration bounds

`SaslScramSha256::new` takes a `SaslScramOptions`, the floor and the ceiling of the iteration count a server may announce. Three places hand it over:

- `SmtpAuthScramSha256Options::scram`, passed to the mechanism as it is.
- `SmtpSessionOpenOptions::scram_min_iterations` and `scram_max_iterations`, from which the session builds the options of the SCRAM coroutine. `SmtpClientStd::connect` needed nothing: its options carry the session ones.
- a third argument of `auth_scram_sha256` on both client traits.

The session fields are two `Option<u32>` present in every build, not a `SaslScramOptions` under the `scram` feature, the type living in a module of io-sasl that only exists with it. A field under a feature was tried first: `SmtpSessionOpenOptions { starttls: true, ..Default::default() }` then fails clippy's `needless_update` in a build without `scram` and `SmtpSessionOpenOptions { starttls: true }` fails to compile in a build with it, so a caller's literal would depend on a feature another crate of the build may enable. The coroutine options keep the io-sasl type, their module being gated as a whole.

All defaults are `None`, which io-sasl reads as 4096 and five million. A server announcing fewer than 4096 iterations is therefore refused where it was accepted: a caller facing such a server lowers the floor.

A refused count arrives in a 334, so it takes the cancellation added the same day: `*`, one reply, then `Mechanism(IterationCountTooHigh { .. })`. `iteration_count_above_the_ceiling_is_cancelled_without_deriving` announces `i=4294967295` under a ceiling of 100000 and expects that error with `max: 100000`: the ceiling is the option's, and a derivation of that length would not return. `scram_iteration_bounds_follow_the_options` does the same through a session with `scram_max_iterations: Some(4096)` and a count of 4097.

The `reply` fuzz target sets the ceiling to 4096, so a run does not spend its time deriving keys for counts the fuzzer invents.

## Preparation

io-sasl 0.2 has no `saslprep` feature: PLAIN and SCRAM prepare their credentials (RFC 4013) in every build. This crate never enabled the feature, and nothing in its manifest or documentation named it, so until now it sent the credentials as given. `ir_sends_the_prepared_password` gives PLAIN the password `pa<U+00AD>ss` and expects the initial response of `pass`; against the previous commit it fails, the command carrying `AGFsaWNlAHBhwq1zcw==` (the soft hyphen kept) instead of `AGFsaWNlAHBhc3M=`. A credential SASLprep prohibits fails the first resume, before the `AUTH` command is written.

Two more changes of io-sasl 0.2 show through without code here: a SCRAM client nonce shorter than 18 bytes fails the first resume with `InvalidNonce` (the nonce `connect` draws has 24), and OAUTHBEARER and XOAUTH2 refuse a credential holding the `%x01` separator.

Capabilities moved: auth (ADDED "The SCRAM iteration count is bounded", "Credentials are prepared").

Existing tests changed: none in behaviour. The struct literals of `SmtpSessionOpenOptions` in src/session.rs, tests/common.rs, tests/outlook.rs and examples/tokio_session.rs gained `..Default::default()`.

Verified: `cargo test --all-features` 171 unit tests (3 new), 11 + 43 + 7 integration tests and 19 doc tests passed; `cargo clippy --all-features --all-targets -- -D warnings` clean, also with no feature, with `url`, with `scram`, with `client,url`, with `rustls-ring` and with `native-tls`; `cargo build --no-default-features` and `--features scram` pass; `cargo publish --dry-run --allow-dirty` packages and builds against the registry. The fuzz crate checks, and the `reply` target ran 46 seconds: 330,207 executions, no finding.
