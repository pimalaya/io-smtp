---
cairn: log
change: cancelled-auth-and-scram-without-rand
landed: 2026-11-13
---

# A given-up AUTH exchange is cancelled, scram pulls no rand

Two findings of the family audit of 2026-11-13 (SMTP-08, SMTP-07), and one example.

## Cancellation

Eight tests, one or two per mechanism, fed a 334 the exchange cannot answer and expected the `*` line of RFC 4954 section 4: all failed with `expected WantsWrite, got Complete(Err(..))`, the coroutine having completed while the server waited for a response. The cases: PLAIN and ANONYMOUS challenged again after their inline response, LOGIN, XOAUTH2 and OAUTHBEARER given `334 not!base64`, SCRAM-SHA-256 given a server-first-message without a nonce and a server-final-message with a forged signature in a challenge, PLAIN without inline response given a bad second challenge.

Each coroutine gained a `Cancel` state holding a `SmtpCommandSend` of `SmtpAuthData::Cancel`, which already serialised to `*`, and the error. The state writes the line, reads one reply, and completes with the error whatever the exchange ended with: the 501 the RFC prescribes, anything else, or an EOF. The places that returned an error after a 334 now enter that state: the two after each challenge in the four inline-capable mechanisms and in SCRAM, and in LOGIN the opening payload, the answer to the second prompt, and a third prompt, which used to complete with `Rejected { code: 334 }` and still does, after the `*`.

Where the server waits for nothing, nothing is sent: a rejection, a transport failure, and a success reply the mechanism refuses. The last one matters for SCRAM: a forged signature in a 235 leaves a session the server holds authenticated and the client must not use, and no `*` can undo it.

The six coroutines were not merged into one. The audit suggested it, as io-managesieve frames every mechanism in one coroutine, but here the spec requires one coroutine per framed mechanism, each has public options and a public error type callers match on, and three exchange shapes differ: LOGIN speaks first whatever the challenge says, SCRAM may find the server-final-message in the success reply, the two OAuth mechanisms carry a JSON error into their rejection. A merge keeping those types would be a generic engine behind six wrappers, which is a design change and not a mechanical one. It stays the maintainer's call.

## rand

Before: `cargo tree --no-default-features --features scram -e features,no-dev` listed `rand feature "default"` with `std`, `std_rng`, `sys_rng`, `thread_rng` and getrandom under it. After: no line mentions rand, and the same command without `no-dev` only finds it under the dev-dependency io-oauth. `scram` is now `["io-sasl/scram"]`, the three TLS features name `dep:rand`, and the dependency reads `default-features = false, features = ["thread_rng"]`, as io-managesieve does since the same day. A TLS build without `scram` compiles rand unused, Cargo having no way to enable a dependency on two features at once. Cargo.lock did not move. The build was not tried on a target without std, none being installed in the dev shell.

AGENTS.md still says the SCRAM randomness sits behind a feature, which stays true (the TLS ones), and was left as it is.

## Example

`tokio_session` requires `client` and `url`; it required `url` alone while importing `io_smtp::client`, so `cargo clippy --no-default-features --features url --all-targets` failed on it.

Capabilities moved: auth (ADDED "An exchange the client gives up is cancelled"; MODIFIED "One coroutine per framed mechanism").

Existing tests changed: `ir_extra_challenge_returns_mechanism_error` (PLAIN, ANONYMOUS), `invalid_challenge_returns_challenge_error` (LOGIN) and `invalid_server_first_returns_mechanism_error` (SCRAM) expected the error on the 334 itself; they are renamed and expect the `*`, a read, then the same error.

Verified: `cargo test --all-features` 168 unit tests (5 new), 11 + 43 + 7 integration tests and 19 doc tests passed; `cargo clippy --all-features --all-targets -- -D warnings` clean, also with no feature and with `url` alone; `cargo build --no-default-features` and `--features scram` pass. The `reply` fuzz target, which runs the LOGIN and SCRAM exchanges, ran 121 seconds: 999,479 executions, no finding (coverage 2202).
