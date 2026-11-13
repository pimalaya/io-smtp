---
cairn: delta
change: scram-bounds-and-prepared-credentials
---

## ADDED Requirements

### Requirement: The SCRAM iteration count is bounded
The iteration count a server announces SHALL be checked against a floor and a ceiling before any key is derived. The bounds SHALL default to those of io-sasl, 4096 and five million, and SHALL be reachable through `SmtpAuthScramSha256Options::scram`, through `SmtpSessionOpenOptions::scram_min_iterations` and `scram_max_iterations`, present in every build, and through the options argument of `auth_scram_sha256` on both client traits. A count outside the bounds SHALL cancel the exchange and fail with the mechanism's error.

### Requirement: Credentials are prepared
PLAIN and SCRAM-SHA-256 SHALL prepare their credentials with SASLprep (RFC 4013) in every build: what is sent, or derived from, is the prepared form, and a credential holding a prohibited code point SHALL fail the exchange before anything is written.

## MODIFIED Requirements

## REMOVED Requirements
