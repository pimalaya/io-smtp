# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
  gone — every higher-level coroutine now manages its own internal
  buffer.

[unreleased]: https://github.com/pimalaya/io-smtp/compare/root..HEAD
