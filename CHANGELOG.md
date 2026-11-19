# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2026-11-19

### Added

- Added the `server` cargo feature and the `server` module: `server::command::SmtpServerCommand` (command parser), `server::reply::SmtpServerReply` (reply writer, multiline, enhanced status codes) and `server::session::SmtpServerSession`, an I/O-free SMTP submission and LMTP session with PIPELINING, SIZE, 8BITMIME, SMTPUTF8, ENHANCEDSTATUSCODES, DSN, STARTTLS and AUTH PLAIN and LOGIN through the io-sasl server side.

- Added `rfc3461::parameter::xtext_decode`, and `SmtpDsnNotify::is_never` and `SmtpDsnNotify::contains`.

- Added a `server` fuzz target.

### Changed

- **BREAKING**: Changed the io-sasl dependency to 0.3.
- **BREAKING**: Renamed the `client` cargo feature, the std-blocking client, to `std`.

  A consumer enabling it changes `features = ["client"]` to `features = ["std"]`. The TLS features now imply `std`.

- **BREAKING**: Gated the client coroutines behind a new `client` cargo feature, on by default.

  `message`, `send`, `session`, `sasl`, `rfc7628`, `rfc7677`, `rfc3207::starttls`, `rfc4954::auth`, `rfc4954::auth_data` and the command modules of `rfc5321` need it; the wire-format types do not. A `default-features = false` consumer using the coroutines adds `features = ["client"]`.

- **BREAKING**: Required io-sasl with its `client` feature for the client side and its `server` feature for the server side.

## [0.9.0] - 2026-11-13

### Changed

- **BREAKING**: Changed the pimalaya-stream dependency to 0.4.

  Its `tls::Tls` moved the trusted certificate from `cert` to `server`, and gained `client`, the certificate presented when the server asks for one (mutual TLS).

## [0.8.0] - 2026-11-13

### Added

- Added `SmtpSyntaxError`, returned by the constructors of the command arguments.

- Added `TryFrom<&str>` for `SmtpLocalPart`, `SmtpDomain`, `SmtpAddressLiteral`, `SmtpEhloDomain` and `SmtpMailbox`.

  A mailbox parses from its wire form, such as `alice@example.org` or `"john doe"@[192.0.2.1]`. Non-ASCII characters are accepted (RFC 6531 3.3).

- Added `SmtpLocalPart::quote`, building a local part from unquoted content.

- Added `SmtpParameter::new`, with the `keyword` and `value` readers.

- Added `SmtpGeneralAddressLiteral`.

- Added `SmtpString`, the atom or quoted string `NOOP` takes.

- Added `SmtpAuthMechanism`, the SASL mechanism name `AUTH` takes.

- Added `SmtpMessageSendOptions::skip_refused_recipients`, sending to the recipients the server accepts when it refuses others.

  **BREAKING**: a struct literal of the options needs `..Default::default()`.

- Added `SmtpMessageSendRefusal`, a refused recipient with the reply code and text.

- Added `SmtpMessageSendError::NoRecipient`, for a send whose every recipient was refused.

- Added `SmtpResponse::message`, every line of a reply joined by a space.

- Added `SmtpAuthScramSha256Options::scram`, the bounds of the iteration count a server may announce.

  **BREAKING**: a struct literal of the options needs the field.

- Added `SmtpSessionOpenOptions::scram_min_iterations` and `scram_max_iterations`, the same bounds for a session and for `connect`.

  **BREAKING**: a struct literal of the options needs `..Default::default()`.

### Changed

- **BREAKING**: Made the field of `SmtpLocalPart` and of `SmtpDomain` private.

- **BREAKING**: Made the fields of `SmtpParameter` private.

  The keyword is an esmtp-keyword, no `SmtpAtom` any more.

- **BREAKING**: Changed `SmtpAddressLiteral::General` to hold a `SmtpGeneralAddressLiteral`.

- **BREAKING**: Changed `SmtpParameter::envid` and `SmtpParameter::orcpt_rfc822` to return a `Result`.

  They take the value before encoding and refuse what is not printable US-ASCII.

- **BREAKING**: Changed `SmtpNoopCommand::string` to a `SmtpString`.

- **BREAKING**: Changed `SmtpAuthCommand::mechanism` to a `SmtpAuthMechanism`.

- Changed `SmtpMessageSend` to remove the `Resent-Bcc` field too (RFC 5322 3.6.6).

- **BREAKING**: Changed `SmtpMessageSendError::RcptTo` to name the recipient.

  It is `RcptTo { forward_path, error }`.

- **BREAKING**: Changed `SmtpMessageSend` and the `send` method of both client traits to return the refused recipients.

  The list is empty unless `skip_refused_recipients` is set.

- **BREAKING**: Changed `SmtpGreeting::domain` and `SmtpEhloResponse::domain` to a `SmtpText`, the name as the server gave it.

- Changed the `scram` feature to pull no randomness: `rand` comes with the TLS features, without its default features.

  The coroutines with `scram` build without std; only `connect` draws a nonce.

- **BREAKING**: Changed the io-sasl dependency to 0.2.

  PLAIN and SCRAM-SHA-256 now prepare their credentials in every build (RFC 4013): a password SASLprep alters is sent prepared, and one it prohibits fails the exchange. A SCRAM client nonce shorter than 18 bytes is refused.

- **BREAKING**: Changed the `auth_scram_sha256` method of both client traits to take a `SaslScramOptions`.

### Fixed

- Fixed a failed `AUTH` exchange leaving the server waiting for a response.

  When a mechanism refuses a challenge, or a challenge is not base64, the six mechanism coroutines send `*` and read the reply before failing (RFC 4954 4), so the connection takes another command.

- Fixed the `tokio_session` example not requiring the `client` feature.

- Fixed a refused greeting or `EHLO` being reported as a parse error.

  `SmtpGreetingGetError` and `SmtpEhloError` gained `Rejected { code, message }`, so a `554` banner or a `550` to `EHLO` keeps its code and text. **BREAKING**: both enums are exhaustive.

- Fixed the greeting and `EHLO` failing on a server name that is not a strict domain, such as an address literal (RFC 5321 4.2).

- Fixed a rejection keeping only the first line of a multi-line reply.

  Every `Rejected` message joins the lines with a space.

- Fixed `SmtpMessageSend` leaving the transaction open after a refused recipient or a refused `DATA` command.

  It sends `RSET` before failing, so the connection takes another `MAIL FROM`.

- Fixed `SmtpSessionTransport::from_url` keeping the brackets of an IPv6 host.

- Fixed a `Bcc` field following a bare CR line ending being transmitted to every recipient.

  The removal reads lines as `DATA` ends them: at CRLF, a bare CR or a bare LF.

- Fixed a local part needing quotes, such as `john doe`, being sent unquoted.

  `TryFrom<&str>` refuses it and `SmtpLocalPart::quote` quotes it.

- Fixed `ENVID` and `ORCPT` values being sent without their xtext encoding (RFC 3461 4).

### Security

- Fixed caller strings reaching the `MAIL FROM`, `RCPT TO`, `EHLO`, `HELO`, `NOOP` and `AUTH` lines unchecked.

  A CR LF in a local part, a domain, a parameter, an address literal, a `NOOP` string or a mechanism name added commands to the session.

- Fixed SCRAM-SHA-256 deriving its key for whatever iteration count the server announced.

  A count below 4096 or above five million fails the exchange before the derivation, unless the options move the bounds.

## [0.7.1] - 2026-11-03

### Security

- Raised the pimalaya-stream requirement to 0.3.1, fixing RUSTSEC-2026-0346 to RUSTSEC-2026-0349.

  It requires rustls 0.23.46, and its io-proxy 0.1.1 no longer pulls the base64 crate.

## [0.7.0] - 2026-11-03

### Added

- Added `SmtpAuthCapability::available_mechanisms`, the advertised mechanisms this build frames, most preferred first.

- Added a `reply` fuzz target over the reply parsers and the coroutines reading them.

### Changed

- **BREAKING**: Replaced the base64 crate with [base64-codec](https://crates.io/crates/base64-codec) for the `AUTH` payloads.

  `SmtpAuthDataError::Base64` and `SmtpAuthChallengeError::Base64` carry no base64 crate error any more. Payloads decode leniently: a missing padding, non-zero trailing bits and blanks are accepted, any other byte outside the alphabet refused.

- Changed the minimum Rust version to 1.89.

- Changed `SmtpData` and `SmtpMessageSend` to prepare the message in one pass.

  A message needing no rewrite is sent without a copy, up to 14 times faster.

### Fixed

- Fixed a reply whose last line is the code alone, such as `250\r\n`, never completing (RFC 5321 4.2.1).

- Fixed a reply text holding non-ASCII bytes failing the parse.

  Bytes from 0x80 decode as UTF-8, with replacement characters when invalid.

- Fixed bare CR and bare LF line endings reaching the server in `DATA` (RFC 5321 2.3.8).

  `SmtpData` sends every line ending as CRLF and doubles the dot after a bare one too.

- Fixed a reply never ending growing the client memory without limit.

  The greeting, `EHLO`, `STARTTLS` and command coroutines fail with `TooLarge` past `SMTP_MAX_REPLY_LEN`, 64 KiB. **BREAKING**: `SmtpCommandSendError`, `SmtpEhloError` and `SmtpGreetingGetError` gained the `TooLarge` variant.

- Fixed a one-word SCRAM-SHA-256 success reply, such as `235 2.7.0 Accepted`, failing a verified exchange with `UnexpectedChallenge`.

## [0.6.0] - 2026-10-09

### Added

- Added `mail_parameters` and `rcpt_parameters` to `SmtpMessageSendOptions`, the ESMTP parameters of MAIL FROM and of every RCPT TO, such as the DSN ones (RFC 3461).

### Changed

- **BREAKING**: `SmtpMessageSendOptions` gained two fields, so a struct literal needs `..Default::default()`.

## [0.5.0] - 2026-09-29

### Added

- Added `SmtpClientStdConnectOptions`, whose `proxy` field tunnels the connection through a SOCKS5 or HTTP proxy.

### Changed

- **BREAKING**: `SmtpClientStd::connect` takes `(url, domain, opts)`, the TLS configuration, the SASL mechanism and the session options moving into `SmtpClientStdConnectOptions`.

## [0.4.0] - 2026-09-26

### Added

- Added `SmtpMessageSendOptions`, whose `keep_bcc` field transmits the `Bcc` field as given.

### Changed

- **BREAKING**: `SmtpMessageSend::new` and the `send` method of both client traits take a `SmtpMessageSendOptions`.

### Fixed

- Fixed the `Bcc` field being transmitted to every recipient (RFC 5322 3.6.3).

  `SmtpMessageSend` removes it before `DATA`, folded lines included, unless `keep_bcc` is set.

## [0.3.0] - 2026-08-15

### Added

- Added the `session` module and its `SmtpSessionOpen` coroutine, covering everything from an address to an authenticated session.

  It yields transport requests (`WantsTcpConnect`, `WantsTlsConnect`, `WantsUnixConnect`, `WantsTlsUpgrade`), so any runtime answers them with its own sockets. `SmtpSessionTransport::from_url` maps `smtp://` (25), `smtps://` (465) and `unix://`.

- Added the `SmtpClient` and `SmtpClientAsync` traits: implement `run`, inherit every command.

  The futures of `SmtpClientAsync` are `Send`, so its default bodies survive `tokio::spawn`.

- Added `rfc4954::auth_data::parse_challenge`, and a `Challenge` error variant on every SASL coroutine for a payload that is not valid base64.

- Added a tokio session example.

- Added the `url` cargo feature, gating `SmtpSessionTransport::from_url`. The TLS features enable it.

- Added `session::default_alpn` and `session::default_port`, reachable without the `client` feature.

### Changed

- **BREAKING**: `SmtpClientStd::connect` takes `SmtpSessionOpenOptions` in place of `starttls`, and returns the capabilities of the last EHLO.

- **BREAKING**: Moved the command methods from `SmtpClientStd` to the `SmtpClient` trait.

  Their arguments are now owned or `'static`, so one signature serves both traits.

- **BREAKING**: Renamed `SmtpClientStdError` to `SmtpClientError`, with a new `Transport` variant for transports whose errors are not `std::io::Error`.

- **BREAKING**: Took the SASL mechanisms and credentials from io-sasl.

  The coroutines keep the SMTP framing and send the same bytes. Their errors gained a `Mechanism` variant, and `SmtpSessionOpenError::UnsupportedMechanism` names a mechanism this crate does not frame.

- **BREAKING**: `SmtpAuthPlain::new` takes the authorization identity, and `SmtpAuthOauthbearer::new` the username, host and port (RFC 7628 3.1).

- **BREAKING**: `SmtpAuthScramSha256::new` takes a `SaslScramCreds`, which carries the nonce and the channel binding.

- Made pimalaya-stream an optional dependency, enabled by the TLS features.

- Raised the minimum supported Rust version to 1.88.

### Removed

- **BREAKING**: Removed the `UrlMissingHost`, `UrlUnsupportedScheme`, `StartTlsOverTls` and `ScramSha256NotEnabled` client error variants, folded into `SessionOpen`.

- **BREAKING**: Removed `sasl::auth_login::SmtpAuthLoginCommand`, LOGIN now using `SmtpAuthCommand` like every other mechanism.

### Fixed

- Fixed `Resource temporarily unavailable` errors mid-exchange by bumping pimalaya-stream to 0.3.

  A stream reporting it is not ready is retried for a minute, and a read deadline stops a silent server from blocking forever.

- Refused the STARTTLS upgrade when bytes follow the `220` reply, a plaintext injection RFC 3207 forbids.

- Fixed `SmtpStartTls` always returning an empty remainder past the `220` reply.

- Refused a SCRAM-SHA-256 exchange that ends without a verified server signature.

- Fixed the JSON a server sends when rejecting an XOAUTH2 or OAUTHBEARER token being dropped. It now comes back in `RejectedWithError`.

## [0.2.3] - 2026-07-26

### Added

- Added `SmtpClientStd::default_port`: 465 for `smtps`, 25 otherwise.

## [0.2.2] - 2026-07-25

### Added

- Added back the `unix://` URL scheme to `SmtpClientStd::connect`, to reach a local socket proxy such as sirup.

## [0.2.1] - 2026-07-25

### Fixed

- Disabled the `EHLO` capability refresh after authentication by default.

  Some servers treat it as a session reset, Proton Bridge then rejecting `MAIL FROM`. Re-enable it with the `ensure_capabilities` option.

## [0.2.0] - 2026-07-15

### Added

- Added the raw passthrough coroutine and its client method, for simple request/reply commands.

### Changed

- Prefixed every RFC 5321 wire type with `Smtp` (`SmtpDomain`, `SmtpMailbox`, `SmtpResponse` and the rest).

- Renamed `SendSmtpCommand` to `SmtpCommandSend`, along with its `Ok` and `Error` types.

- Moved the free helpers onto their types, such as `SmtpParameter::envid` and `SmtpClientStd::default_alpn`, and made the utils module private.

- Flattened the RFC 5321 wire types into `rfc5321`: `rfc5321::types::domain::SmtpDomain` is now `rfc5321::SmtpDomain`.

- Bumped pimalaya-stream to 0.1.

## [0.1.0] - 2026-06-03

### Added

- Added the `SmtpCoroutine` trait, mirroring `core::ops::Coroutine`, with the shared `SmtpYield`.

- Added the `smtp_try!` macro, the coroutine equivalent of `?`.

- Added `SendSmtpCommand`, the base coroutine sending one command and parsing its reply.

- Added the RFC 5321 coroutines: greeting, EHLO, HELO, MAIL, RCPT, DATA with dot-stuffing, NOOP, QUIT and RSET.

- Added the `SmtpMessageSend` composite coroutine: MAIL FROM, RCPT TO, then DATA.

- Added the STARTTLS coroutine (RFC 3207).

- Added the SASL coroutines ANONYMOUS, LOGIN, PLAIN, XOAUTH2, OAUTHBEARER (RFC 7628) and SCRAM-SHA-256 (RFC 7677, behind the `scram` feature).

- Added the `initial_request` and `ensure_capabilities` options on every authentication coroutine.

- Added the `client` cargo feature and `SmtpClientStd`, a blocking client over any `Read + Write` stream.

- Added the `rustls-ring` (default), `rustls-aws` and `native-tls` cargo features, enabling `SmtpClientStd::connect` over `smtp://` and `smtps://`.

- Added the `vendored` cargo feature, forwarded to pimalaya-stream.

[Unreleased]: https://github.com/pimalaya/io-smtp/compare/v0.10.0..HEAD
[0.10.0]: https://github.com/pimalaya/io-smtp/compare/v0.9.0..v0.10.0
[0.9.0]: https://github.com/pimalaya/io-smtp/compare/v0.8.0..v0.9.0
[0.8.0]: https://github.com/pimalaya/io-smtp/compare/v0.7.1..v0.8.0
[0.7.1]: https://github.com/pimalaya/io-smtp/compare/v0.7.0..v0.7.1
[0.7.0]: https://github.com/pimalaya/io-smtp/compare/v0.6.0..v0.7.0
[0.6.0]: https://github.com/pimalaya/io-smtp/compare/v0.5.0..v0.6.0
[0.5.0]: https://github.com/pimalaya/io-smtp/compare/v0.4.0..v0.5.0
[0.4.0]: https://github.com/pimalaya/io-smtp/compare/v0.3.0..v0.4.0
[0.3.0]: https://github.com/pimalaya/io-smtp/compare/v0.2.3..v0.3.0
[0.2.3]: https://github.com/pimalaya/io-smtp/compare/v0.2.2..v0.2.3
[0.2.2]: https://github.com/pimalaya/io-smtp/compare/v0.2.1..v0.2.2
[0.2.1]: https://github.com/pimalaya/io-smtp/compare/v0.2.0..v0.2.1
[0.2.0]: https://github.com/pimalaya/io-smtp/compare/v0.1.0..v0.2.0
[0.1.0]: https://github.com/pimalaya/io-smtp/compare/root..v0.1.0
