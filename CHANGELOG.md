# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-15

### Added

- Added the `session` module and its `SmtpSessionOpen` coroutine, the composite covering everything between an address and an authenticated SMTP session: transport selection, the greeting, the EHLO exchange, the optional STARTTLS upgrade with a second EHLO over TLS, and the SASL exchange.

  It yields transport requests (`WantsTcpConnect`, `WantsTlsConnect`, `WantsUnixConnect`, `WantsTlsUpgrade`) alongside the usual reads and writes, so a caller on any runtime answers them with its own sockets and inherits the handshake ordering instead of reimplementing it. The scheme table moved with it as `SmtpSessionTransport::from_url` (`smtp://` on 25, `smtps://` on 465, `unix://` on a socket path, an explicit port winning over the default). The SCRAM-SHA-256 client nonce travels with the credentials rather than being generated, so the coroutine stays free of both I/O and randomness.

- Added the `client::SmtpClient` and `client::SmtpClientAsync` traits. Implement one `run` method, inherit every command.

  The `Yield = SmtpYield` bound on `run` makes the surface self-selecting: coroutines that every client wraps identically are defaulted methods, and one declaring its own yield vocabulary falls outside the trait, which is where implementations are expected to diverge anyway. `SmtpClientAsync` declares `-> impl Future<..> + Send` with `Send` as a supertrait, so anything built from a default body survives `tokio::spawn`; a plain `async fn` in a trait cannot express that. `SmtpClient` carries no `Send` bound on purpose, since a blocking call returns a value rather than a future and the bound would exclude a thread-affine client such as a JNI bridge. Neither trait is dyn-compatible: the dynamism this crate needs lives at `client::SmtpStream`.

- Added `rfc4954::auth_data::parse_challenge` and its `SmtpAuthChallengeError`, decoding the payload a `334` challenge carries. Every SASL coroutine reports a challenge that is not valid base64 through its own `Challenge` variant instead of ignoring it.

- Added the tokio session example, answering the session coroutine's transport requests with tokio sockets and tokio-rustls, then implementing `SmtpClientAsync` over the same socket.

- Added the `url` cargo feature, gating `SmtpSessionTransport::from_url` and the two URL variants of `SmtpSessionOpenError`. The TLS provider features enable it.

- Added `session::default_alpn` and `session::default_port`, the protocol constants formerly reachable only through `SmtpClientStd`. They now live in the coroutine core, so a caller answering `WantsTlsConnect` on another runtime gets the ALPN list without the `client` feature. `SmtpClientStd::default_alpn` and `SmtpClientStd::default_port` remain as delegating shims.

### Changed

- Replaced the trailing `SmtpClientStd::connect` parameters with `SmtpSessionOpenOptions`, and made it return the EHLO capabilities. **Breaking.**

  `connect(url, tls, starttls, domain, sasl)` becomes `connect(url, tls, domain, sasl, opts)` returning `(SmtpClientStd, Vec<Cow<'static, str>>)`, where `opts` carries `starttls` and the capability lines are those of the last EHLO, so reading them no longer costs an extra round trip. The body is now a pump over `SmtpSessionOpen`.

- Removed the `SmtpClientStdError` variants `UrlMissingHost`, `UrlUnsupportedScheme`, `StartTlsOverTls` and `ScramSha256NotEnabled`, replaced by a single `SessionOpen` variant wrapping `SmtpSessionOpenError`. **Breaking.**

- Moved the command methods off `SmtpClientStd` and onto the `SmtpClient` trait. **Breaking.**

  Callers add `use io_smtp::client::SmtpClient;`. The methods keep their names and semantics. Argument types that were borrowed or `impl Into<..>` are now owned or `'static`, so one signature serves both the blocking and the async trait: `SmtpEhloDomain<'static>`, `Cow<'static, str>` for `raw`, and a `Vec<SmtpForwardPath<'static>>` rather than an `impl IntoIterator` for `send`.

- Renamed `client::SmtpClientStdError` to `client::SmtpClientError` and gave it a `Transport` variant. **Breaking.**

  It is now the error type of both client traits rather than of one concrete client, so the name no longer says `Std`. `Transport` carries a boxed error for implementors whose I/O is not `std::io::Error`, such as a JNI upcall.

- Took the SASL mechanisms from io-sasl, replacing the six hand-written exchanges. **Breaking.**

  Each coroutine keeps the SMTP half of its exchange, the `AUTH` command, the `334` challenges, the final reply and the capability refresh, and asks the mechanism what each response carries. The wire bytes are unchanged for ANONYMOUS, LOGIN, PLAIN, XOAUTH2 and SCRAM-SHA-256. Every error type gained a `Mechanism` variant carrying the mechanism's own failure and a `Challenge` variant for an undecodable payload; PLAIN, ANONYMOUS and XOAUTH2 lost `UnexpectedContinuationRequest`, a prompt arriving once a mechanism has nothing left to say now being refused by the mechanism, which is the only party that knows how many messages it exchanges. The `scram` feature keeps `rand` and enables `io-sasl/scram`; `hmac`, `pbkdf2` and `sha2` moved to dev-dependencies with RFC 5802 leaving this crate.

- Took the SASL vocabulary from io-sasl too: `SmtpSessionOpen` and `SmtpClientStd::connect` now take `io_sasl::mechanism::Sasl` rather than `pimalaya_stream::sasl::Sasl`. **Breaking.**

  The credential structs gained their `Creds` suffix (`SaslPlainCreds`, `SaslLoginCreds`, ...) and the SCRAM ones carry the client nonce and the channel binding, so `SmtpSessionOpen::new` no longer takes a separate `nonce` argument. `SmtpClientStd::connect` draws a nonce for SCRAM credentials that carry none, an empty nonce being no nonce at all as far as RFC 5802 is concerned. io-sasl computes more mechanisms than this crate frames, so `SmtpSessionOpenError` gained `UnsupportedMechanism`, naming what it was handed rather than skipping it silently; `ScramSha256NotEnabled` is gone, a build without the `scram` feature having no SCRAM credentials to be handed in the first place.

- `SmtpAuthPlain::new` takes the RFC 4616 authorization identity, and `SmtpAuthOauthbearer::new` takes the account username, the host and the port. **Breaking.**

  The SMTP OAUTHBEARER payload was missing the `host` and `port` fields of the GS2 header that RFC 7628 section 3.1 defines, so a server checking what the token was presented for saw nothing to check.

- `SmtpAuthScramSha256::new` takes a single `SaslScramCreds` in place of the username, password and nonce triple. **Breaking.**

  The credentials also carry the channel binding, which decides whether the exchange announces `SCRAM-SHA-256` or `SCRAM-SHA-256-PLUS`, so a caller extracting binding material from its TLS session no longer has it dropped on the floor.

- Removed `sasl::auth_login::SmtpAuthLoginCommand`, the LOGIN exchange using `rfc4954::auth::SmtpAuthCommand` like every other mechanism. **Breaking.** It rendered the same `AUTH LOGIN\r\n` bytes.

- Made pimalaya-stream an optional dependency again, enabled by the TLS provider features.

  Nothing outside the std client reaches for it now that the SASL vocabulary comes from io-sasl, so a no_std build of the coroutine core no longer pulls in a crate that wraps sockets and TLS sessions.

- Bumped pimalaya-stream to 0.3, whose `Read` and `Write` retry a stream reporting it is not ready. **Behaviour change.**

  A blocking socket is not supposed to report `EAGAIN`, yet callers saw one surface mid-exchange and end the exchange with a bare `Resource temporarily unavailable (os error 35)`, macOS especially and the more readily the longer the exchange ran. The transport now retries such a failure for a minute before giving up with a `TimedOut` naming the budget, and arms a socket read deadline at connect time so a server going silent on a healthy connection stops blocking the caller forever. Its `StreamStd` is renamed `stream::Stream` and its connects take a per-transport options struct, which is what `SmtpClientStd::connect` now calls.

- Raised the minimum supported Rust version from 1.87 to 1.88, following pimalaya-stream.

### Fixed

- Refused the TLS upgrade when the server sends bytes past the STARTTLS `220` reply. **Behaviour change.**

  RFC 3207 forbids trailing bytes, so their presence means an attacker injected plaintext commands the server would replay inside the TLS session. `SmtpSessionOpen` now fails with `SmtpSessionOpenError::StartTlsInjection` instead of upgrading.

- Made `SmtpStartTls` actually return the bytes read past the `220` reply, as its contract promised.

  It delegated to `SmtpCommandSend`, which consumes its whole read buffer and never completes while a trailing line is pending, so the returned vector was always empty and an injected command either stalled the exchange or surfaced as a parse error. The coroutine now owns its read loop, splits the reply at its terminating line and hands the remainder back. Its public API and error type are unchanged.

- Refused a SCRAM-SHA-256 exchange the server ended without proving itself. **Behaviour change.**

  A success reply arriving in place of the server-final-message was reported as a success, with the server signature never verified, and one carrying a signature that did not decode was accepted just the same: mutual authentication skipped by omission. The mechanism is now told when the exchange ends and refuses both, with `SaslScramError::ServerSignatureNotVerified`. RFC 4954 section 4 lets a server send its final message in the success reply, and that form is read and verified rather than discarded.

- Reported the JSON a server sends when it rejects an XOAUTH2 or OAUTHBEARER token.

  The detail was decoded, then dropped in favour of a hard-coded 535 and the text of whatever reply followed. Both errors gained a `RejectedWithError` variant carrying the reply code, the reply text and the payload the server actually sent.

## [0.2.3] - 2026-07-26

### Added

- Added `SmtpClientStd::default_port`, returning the default SMTP port for a scheme (465 for `smtps`, 25 otherwise).

  Exposed so config-based callers derive the fallback port identically to `connect`, which now shares the same helper.

## [0.2.2] - 2026-07-25

### Added

- Added back support for the `unix://` URL scheme in `SmtpClientStd::connect`.

  A `unix://` URL now connects to a local Unix domain socket (via `StreamStd::connect_unix` over its path) rather than erroring on the missing host, so the client can reach a local socket proxy such as sirup. Host extraction for the `smtp`/`smtps` schemes moved into a `tcp_host` helper.

## [0.2.1] - 2026-07-25

### Fixed

- Disabled the post-authentication `EHLO` capability refresh by default.

  A plain SASL authentication adds no security layer, so re-reading capabilities is unnecessary. The extra `EHLO` also broke sending through servers that treat it as a session reset (e.g. Proton Bridge, which then rejected `MAIL FROM` with `no such user`). Re-enable it per mechanism via the `ensure_capabilities` option when a server advertises capabilities only after auth.

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

[unreleased]: https://github.com/pimalaya/io-smtp/compare/v0.3.0..HEAD
[0.3.0]: https://github.com/pimalaya/io-smtp/compare/v0.2.3..v0.3.0
[0.2.3]: https://github.com/pimalaya/io-smtp/compare/v0.2.2..v0.2.3
[0.2.2]: https://github.com/pimalaya/io-smtp/compare/v0.2.1..v0.2.2
[0.2.1]: https://github.com/pimalaya/io-smtp/compare/v0.2.0..v0.2.1
[0.2.0]: https://github.com/pimalaya/io-smtp/compare/v0.1.0..v0.2.0
[0.1.0]: https://github.com/pimalaya/io-smtp/compare/root..v0.1.0
