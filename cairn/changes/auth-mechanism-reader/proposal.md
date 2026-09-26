---
cairn: change
id: auth-mechanism-reader
status: active
created: 2026-08-27
---

# Read the AUTH line into mechanisms, as io-imap does

## Why

A client that wants to offer a user the mechanisms a server actually accepts has to turn the `EHLO` response into the mechanism set it can configure. io-imap does that for its caller: `rfc3501::capability::available_auth_mechanisms(&capabilities)` returns `Vec<SaslMechanism>`, ordering the result most preferred first and dropping what it does not recognise.

io-smtp stops one step short. `SmtpAuthCapability::mechanisms()` yields `&str`, so every caller writes the same string match: uppercase the name, compare against six literals, decide an order, drop the rest. That match belongs beside the parser, where the wire names live and where a new mechanism arrives with its coroutine, not in each consumer.

Neverest is the first consumer to hit it. Its wizard probes IMAP and offers exactly what the server advertised, then reaches SMTP and cannot: it falls back to the mechanism list autodiscovery advertised, which is a weaker source, and the mismatch is documented in the wizard as a limitation of this crate rather than as a decision.

The asymmetry is not a design difference between the protocols. RFC 4954 §4 advertises mechanism names on the `AUTH` line exactly as RFC 3501 advertises them as `AUTH=` capabilities. It is only that one crate wrote the reader and the other did not.

## What

`SmtpAuthCapability::available_mechanisms(&self) -> Vec<SaslMechanism>`, mapping every advertised name this crate frames onto its io-sasl mechanism and dropping the rest.

- Ordered most preferred first, LOGIN last, matching io-imap's ordering so a client offering both protocols presents one list shape.
- SCRAM-SHA-256 appears only in a build with the `scram` feature, since a mechanism this crate cannot frame must not be offered.
- Unlike IMAP, SMTP LOGIN is a SASL mechanism rather than a separate command, so there is no `LOGINDISABLED` equivalent and no last-resort mechanism to add when nothing is advertised: a server offering no `AUTH` line offers nothing, and the reader SHALL return empty rather than inventing a candidate.

`mechanisms()` stays as it is. A caller wanting the wire names, including the ones this crate does not frame, still has them.

## Not in scope

No change to the session, the coroutines or the `UnsupportedMechanism` path. This is a reader over a response the caller already holds, the way io-imap's is, and nothing in the authentication exchange moves.
