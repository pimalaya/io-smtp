# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added basic I/O-free coroutines.

- Added standard, blocking client.

### Changed

- Unified all standard-shape coroutines under a single `SmtpCoroutine` trait (in `crate::coroutine`) with associated `Output` and `Error`. `resume` now returns `SmtpCoroutineState<Output, Error>` directly; the per-coroutine `Smtp*Result` enums are gone. `SmtpClientStd::run<C: SmtpCoroutine>` drives any coroutine to completion against the wrapped stream, replacing the internal `coroutine!` macro. Exempt (kept as-is with its own result enum because it carries a `WantsStartTls` mid-progression variant): `SmtpStartTls`.

- Migrated `SmtpCoroutine` to the generator-shape trait pattern: `type Yield` + `type Return`, with a two-variant `SmtpCoroutineState<Y, R>` (`Yielded(Y)` / `Complete(R)`) mirroring `core::ops::CoroutineState`. Standard coroutines pick `type Yield = SmtpYield` (`WantsRead` / `WantsWrite(Vec<u8>)`) and `type Return = Result<Output, Error>`. `SmtpStartTls` is now also a regular `SmtpCoroutine` impl with a dedicated `SmtpStartTlsYield` enum (`WantsRead` / `WantsWrite(Vec<u8>)` / `WantsStartTls(Vec<u8>)`); `SmtpStartTlsResult` is gone. `SmtpClientStd::run<C, T, E>` is now constrained to `C::Yield = SmtpYield` and each command method on the client is a one-line call to `run`; `starttls` keeps its own per-method loop to handle `WantsStartTls`.

[unreleased]: https://github.com/pimalaya/io-smtp/compare/root..HEAD
