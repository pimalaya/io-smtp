# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release of io-smtp
- I/O-free coroutine-based SMTP client
- Coroutines for: greeting, ehlo, starttls, authenticate_plain, mail, rcpt, data, noop, rset, quit
- Based on smtp-codec for protocol encoding/decoding
