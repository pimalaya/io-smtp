---
cairn: change
id: cancelled-auth-and-scram-without-rand
status: landed
created: 2026-11-13
---

# Cancel an AUTH exchange the client gives up, keep rand out of scram

## Why

Two findings of the family audit of 2026-11-13.

- SMTP-08. When a mechanism refused a challenge, or a challenge was not base64, the mechanism coroutine completed with its error right after the 334. The server was still waiting for a response line: the next command, such as the `AUTH PLAIN` of a caller falling back from SCRAM, was read as a bad SASL response and answered 501, which the second coroutine reported as its own rejection. RFC 4954 section 4 gives the client the `*` line to end the exchange, and `SmtpAuthData::Cancel` serialised it, but nothing sent it.
- SMTP-07. The `scram` feature enabled `rand` with its default features, std included, while the only code drawing randomness is the nonce of the connect module, compiled under the TLS features. `cargo build --no-default-features --features scram`, the "coroutines + SCRAM-SHA-256" line of the contributing guide, therefore pulled a std-only crate the coroutine never calls. The record (spec, contributing guide) stated that `scram` pulls the randomness crate: this change reverses it.

The `tokio_session` example required `url` alone though it uses the `client` module, so `--no-default-features --features url --all-targets` did not build.

## What

- Each of the six mechanism coroutines gains a cancel state: on a 334 it cannot answer it sends `*`, reads one reply through the ordinary command exchange, and completes with the error that made it give up, whatever the reply and even on EOF. LOGIN also cancels on a third prompt.
- Nothing is cancelled where the server is not waiting: a rejection, a transport failure, a success reply the mechanism refuses.
- The six coroutines stay six. One coroutine over every mechanism, as io-managesieve has, was considered and left out: the spec requires one coroutine per framed mechanism, each has its own public options and error type, and three exchange shapes differ (LOGIN speaks first, SCRAM may read the server-final-message in the success reply, the OAuth mechanisms report a JSON error). The cancellation is eight lines a file.
- `scram` no longer names `rand`; the three TLS features do, and the dependency drops its default features for `thread_rng`.
- `tokio_session` requires `client` and `url`.
