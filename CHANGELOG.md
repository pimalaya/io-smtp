# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Disabled the post-authentication `EHLO` capability refresh by default.

## [0.2.0] - 2026-07-15

### Added

- Added the raw passthrough coroutine and its client method.

  Sends an arbitrary command line (without the trailing CRLF) and returns the server reply verbatim; reserved for simple request/reply commands, not for `DATA` or `STARTTLS`.

### Changed

- Prefixed every RFC 5321 wire type with the strict `Smtp` domain prefix (`SmtpDomain`, `SmtpMailbox`, `SmtpGreeting`, `SmtpResponse`, `SmtpReplyCode`, `SmtpText`, `SmtpVec1`, `SmtpAtom`, `SmtpAddressLiteral`, `SmtpEhloDomain`, `SmtpEhloResponse`, `SmtpForwardPath`, `SmtpReversePath`, `SmtpLocalPart`, `SmtpParameter`), along with `SmtpEnhancedStatusCode`, `SmtpDsnRet` and `SmtpDsnNotify`.
- Renamed the send coroutine family to the target-first naming convention: `SendSmtpCommand` is now `SmtpCommandSend` (`SmtpCommandSendOk`, `SmtpCommandSendError` along).
- Moved the free helpers onto their types: `envid` and `orcpt_rfc822` became `SmtpParameter::envid` and `SmtpParameter::orcpt_rfc822`, `default_alpn` became `SmtpClientStd::default_alpn`; the crate-root utils module is no longer public and dropped its unused helpers (quoted-string escaping, character-class predicates, generic parser combinators).
- Flattened the RFC 5321 wire types into the rfc5321 module path: `rfc5321::types::domain::SmtpDomain` is now `rfc5321::SmtpDomain`, the types submodule becoming an internal detail.
- Bumped pimalaya-stream to 0.1.

## [0.1.0] - 2026-06-03

### Added

- Added the `SmtpCoroutine` trait mirroring `core::ops::Coroutine`.

  The trait is composed of `Yield` and `Return` associated types, plus a two-variant `SmtpCoroutineState<Y, R>` (`Yielded(Y)` and `Complete(R)`). Standard coroutines pick the shared `SmtpYield { WantsRead, WantsWrite(Vec<u8>) }`; the previous `SmtpStartTlsYield` is gone (see Changed below).

- Added the `smtp_try!` macro: coroutine equivalent of `?`.

  Advances one inner resume step, re-yields intermediate `Yielded(y)` (via `Into`), short-circuits on `Complete(Err(_))`, otherwise binds the inner `Ok` value to the caller.

- Added `SendSmtpCommand<Cmd>` in `crate::send`: base coroutine that serialises one SMTP command (any `Cmd: Into<Vec<u8>>`), writes it, drives the read loop, and parses the reply through `Response::is_complete` / `Response::parse`. Every higher-level coroutine delegates to it.

- Added I/O-free SMTP RFC 5321 coroutines.

  greeting (renamed `SmtpGreetingGet`), ehlo, helo, mail, rcpt, data (with dot-stuffing), noop, quit, rset.

- Added I/O-free SMTP STARTTLS coroutine following RFC 3207.

- Added I/O-free SASL coroutines under `crate::sasl`: ANONYMOUS, LOGIN, PLAIN, XOAUTH2.

  Each supports both SASL-IR (RFC 4954 §4 inline credentials) and the non-IR challenge-response flow, behind the new `Smtp*Options::initial_request` option.

- Added I/O-free SASL OAUTHBEARER coroutine following RFC 7628 under `crate::rfc7628::auth_oauthbearer`.

  Surfaces the base64-encoded JSON failure detail (sent by the server on `334`) in the `Rejected` error message after the mandatory `\x01` acknowledgement.

- Added I/O-free SASL SCRAM-SHA-256 coroutine following RFC 7677 under `crate::rfc7677::auth_scram_sha_256`, behind the `scram` cargo feature.

  Verifies the server signature before returning `Ok` (protects against MITM).

- Added `Smtp*Options` structs on every auth coroutine: `{ initial_request, ensure_capabilities }`.

  `initial_request = true` (default) inlines credentials with `AUTH` for a single round-trip; `false` waits for the `334` challenge. `ensure_capabilities = true` (default) chains a fresh `EHLO` after the `235` reply so callers see the post-authentication capability set. AUTH LOGIN ignores `initial_request` (always challenge-response). SCRAM-SHA-256 ignores `initial_request` (always SASL-IR).

- Added the `client` cargo feature enabling `SmtpClientStd::new(stream)`.

  Blocking light client wrapping any `Read + Write` stream and exposing one method per SMTP coroutine.

- Added the `rustls-ring` cargo feature (default) enabling `SmtpClientStd::connect(url, tls, starttls, domain, sasl)`.

  Opens `smtp://` (plain TCP) or `smtps://` (implicit TLS) via [pimalaya/stream](https://github.com/pimalaya/stream) with rustls + ring crypto provider, drives optional STARTTLS upgrade, reads greeting and initial EHLO, runs the chosen SASL mechanism, returns an authenticated client.

- Added the `rustls-aws` cargo feature.

  Same full client as `rustls-ring` but with the aws-lc-rs crypto provider.

- Added the `native-tls` cargo feature.

  Same full client backed by the platform's `native-tls` implementation.

- Added the `vendored` cargo feature.

  Compiles the underlying TLS dependencies in vendored mode (forwarded to `pimalaya-stream/vendored`).

### Changed

- Reshuffled SASL mechanisms under `crate::sasl/`.

  PLAIN, LOGIN, ANONYMOUS and XOAUTH2 (mechanisms with no protocol-specific RFC glue) moved to `crate::sasl::{auth_plain, auth_login, auth_anonymous, auth_xoauth2}`. OAUTHBEARER kept under `crate::rfc7628::auth_oauthbearer` and SCRAM-SHA-256 under `crate::rfc7677::auth_scram_sha_256` (their RFCs specify cryptographic and transport behaviour beyond plain SASL framing).

- Renamed coroutine types for naming consistency.

  `GetSmtpGreeting → SmtpGreetingGet`, `SmtpAnonymous → SmtpAuthAnonymous`, `SmtpLogin → SmtpAuthLogin`, `SmtpPlain → SmtpAuthPlain`, `SmtpXoauth2 → SmtpAuthXoauth2`, `SmtpOauthbearer → SmtpAuthOauthbearer`, `SmtpScramSha256 → SmtpAuthScramSha256`, plus matching `*Error` rename.

- Dropped `SmtpStartTlsYield`.

  `SmtpStartTls` now uses `type Yield = SmtpYield; type Return = Result<Vec<u8>, SmtpStartTlsError>`. The success arm `Complete(Ok(remaining))` is the "go ahead and upgrade" signal; `remaining` carries any bytes pre-read past the `220` reply (a non-empty value is a STARTTLS-injection signal per RFC 3207 §6). `SmtpClientStd::starttls()` collapses to a one-liner over `run()`; `run_starttls_inline` in `connect()` is gone.

- Normalised error messages across every coroutine.

  Every `Smtp*Error` variant now formats as `"SMTP <OP> failed: <reason>"`, with the common `Send(#[from] SendSmtpCommandError)` variant carrying lower-level read/parse failures.

- Renamed `crate::send` to `crate::message`.

  The `SmtpMessageSend` composite coroutine (MAIL FROM → RCPT TO → DATA) moved to `crate::message`. The freed `crate::send` module now hosts `SendSmtpCommand` (the base helper).

- Every coroutine grew a dedicated `enum State` with a `fmt::Display` impl.

  Enables `trace!("<op>: {}", self.state)` for uniform protocol tracing.

[unreleased]: https://github.com/pimalaya/io-smtp/compare/v0.2.0..HEAD
[0.2.0]: https://github.com/pimalaya/io-smtp/compare/v0.1.0..v0.2.0
[0.1.0]: https://github.com/pimalaya/io-smtp/compare/root..v0.1.0
