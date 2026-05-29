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

[unreleased]: https://github.com/pimalaya/io-smtp/compare/root..HEAD
