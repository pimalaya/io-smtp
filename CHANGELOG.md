# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- New `rfc4505` module exposing the `ANONYMOUS` SASL mechanism via
  `SmtpAnonymous` (single-shot `AUTH ANONYMOUS [<trace>]` + EHLO
  refresh).
- New `rfc7628::xoauth2` module exposing Google's pre-standard
  `XOAUTH2` mechanism via `SmtpXOAuth2` (same `334`-error
  acknowledgement dance as `OAUTHBEARER`).
- New `client` feature gating a standard, blocking std client:
  `SmtpClientStd::new(stream)` wraps any `Read + Write` and exposes
  one method per SMTP coroutine (greeting, ehlo, helo, starttls,
  auth_*, mail, rcpt, data, send, rset, noop, quit).
- New `rustls-ring` (default), `rustls-aws`, `native-tls`, and
  `vendored` features pulling [pimalaya/stream] as the transport.
  Behind these, `SmtpClientStd::connect(url, tls, starttls, domain,
  sasl)` handles `smtp://` / `smtps://` URLs end-to-end: TCP / TLS
  setup, greeting, EHLO, optional STARTTLS upgrade with a fresh EHLO
  over TLS, and the chosen SASL mechanism (`SaslAnonymous`,
  `SaslLogin`, `SaslPlain`, `SaslOauthbearer`, `SaslXoauth2`,
  `SaslScramSha256` behind `scram`).

### Changed

- **Breaking:** `rfc7677` (`SCRAM-SHA-256`) is now gated behind the
  `scram` cargo feature. The feature additionally pulls `rand` for
  client-side nonce generation in `connect`.
- **Breaking:** rewrote every coroutine to drive raw bytes directly
  instead of going through `io-socket`. `resume` now takes
  `Option<&[u8]>` and returns a `*Result` enum with `WantsRead`,
  `WantsWrite(Vec<u8>)`, `Ok`, and `Err(*Error)` variants (no more
  `Io { input }` indirection). Pass `Some(&[])` to signal EOF.
- **Breaking:** `SmtpStartTls` no longer terminates with `Ok`. On
  success it returns `WantsStartTls(Vec<u8>)`, signalling that the
  caller must upgrade the socket to TLS. The payload carries any
  bytes pre-read past the `220` reply (normally empty).
- **Breaking:** `SmtpEhlo` and `GetSmtpGreeting` now return
  `Ok { capabilities, remaining }` / `Ok { greeting, remaining }`.

### Removed

- **Breaking:** dropped the `io-socket` dependency. `src/read.rs`,
  `src/write.rs`, and the `SmtpRead` / `SmtpWrite` primitives are
  gone: every higher-level coroutine now manages its own internal
  buffer.

[pimalaya/stream]: https://github.com/pimalaya/stream

[unreleased]: https://github.com/pimalaya/io-smtp/compare/root..HEAD
