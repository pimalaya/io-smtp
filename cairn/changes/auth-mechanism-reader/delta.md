---
cairn: change
change: auth-mechanism-reader
---

# Delta

## MODIFIED Requirements

### Requirement: The advertised mechanisms are readable from the EHLO response
`SmtpAuthCapability::parse` SHALL read the raw `AUTH` capability line, rejecting a line whose first token is not `AUTH`, and SHALL expose the advertised mechanism names through `has` (case-insensitive) and `mechanisms`. Both SHALL borrow from the capability line rather than allocating names, the response outliving the read.

`available_mechanisms` SHALL additionally return the advertised names this crate frames, as `SaslMechanism` values, ordered most preferred first with LOGIN last, so a client offers what the server accepts without writing the mapping itself. A name this crate does not frame SHALL be dropped rather than returned, and SCRAM-SHA-256 SHALL appear only in a build carrying the `scram` feature: the reader answers what this build can authenticate with, not what the server said.

A server advertising no `AUTH` line SHALL yield an empty result. Unlike IMAP, where the `LOGIN` command is a last-resort mechanism available unless `LOGINDISABLED` is advertised, SMTP LOGIN is a SASL mechanism like any other, so there is no candidate to add when nothing is advertised.

`mechanisms` SHALL keep returning the wire names verbatim, including the ones this crate does not frame.
