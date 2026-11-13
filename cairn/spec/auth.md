---
cairn: spec
capability: auth
status: current
---

# Authentication

The `AUTH` extension (RFC 4954) and the SASL mechanisms io-smtp frames over it. Two surfaces: the mechanism coroutines a caller drives to authenticate, and the reading of the `AUTH` line a server advertises in its `EHLO` response.

## Requirement: One coroutine per framed mechanism

io-smtp SHALL frame ANONYMOUS (RFC 4505), LOGIN, PLAIN (RFC 4616), OAUTHBEARER (RFC 7628), XOAUTH2 and SCRAM-SHA-256 (RFC 7677), each as its own coroutine under the `sasl` module. SCRAM-SHA-256 SHALL sit behind the `scram` feature, which is what pulls the hash crates; the rest SHALL be unconditional.

The `scram` feature SHALL NOT pull `rand`: the coroutine takes the client nonce with the credentials, so the coroutine layer with `scram` builds without std. `rand` SHALL come with the TLS features (`rustls-ring`, `rustls-aws`, `native-tls`), the connect they gate being the only code drawing a nonce, and without its default features beyond `thread_rng`.

io-sasl computes more mechanisms than this crate frames. A session opened with credentials for one io-smtp has no coroutine for SHALL fail with `SmtpSessionOpenError::UnsupportedMechanism`, naming the mechanism, rather than skipping the exchange silently: a caller learns which of its credentials this crate cannot use. A mechanism io-sasl gains under a feature this crate does not enable falls into that same arm, so a build combining the two cannot authenticate by accident.

## Requirement: A session authenticates at most once, after any upgrade

`SmtpSessionOpen` SHALL take an `Option<Sasl>` and, given `None`, SHALL stop after the `EHLO` exchange, sending no `AUTH` command at all. That is the unauthenticated relay, and it SHALL NOT be reported as an error.

Given credentials, the `AUTH` exchange SHALL follow the STARTTLS upgrade and the second `EHLO` it requires, never precede them, so a mechanism carrying a password or a token is never framed over cleartext on a connection that was going to be upgraded.

## Requirement: The advertised mechanisms are readable from the EHLO response

`SmtpAuthCapability::parse` SHALL read the raw `AUTH` capability line, rejecting a line whose first token is not `AUTH`, and SHALL expose the advertised mechanism names through `has` (case-insensitive) and `mechanisms`. Both SHALL borrow from the capability line rather than allocating names, the response outliving the read.

`available_mechanisms` SHALL additionally return the advertised names this crate frames, as `SaslMechanism` values, ordered most preferred first with LOGIN last, so a client offers what the server accepts without writing the mapping itself. A name this crate does not frame SHALL be dropped rather than returned, and SCRAM-SHA-256 SHALL appear only in a build carrying the `scram` feature: the reader answers what this build can authenticate with, not what the server said.

A server advertising no `AUTH` line SHALL yield an empty result. Unlike IMAP, where the `LOGIN` command is a last-resort mechanism available unless `LOGINDISABLED` is advertised, SMTP LOGIN is a SASL mechanism like any other, so there is no candidate to add when nothing is advertised.

`mechanisms` SHALL keep returning the wire names verbatim, including the ones this crate does not frame.

## Requirement: The OAuth mechanisms are verified live

OAUTHBEARER and XOAUTH2 SHALL each be exercised by an ignored live test against Gmail's submission service, authenticating as a Workspace test user with a token the test mints from a service account key, so the suite runs unattended. The tests SHALL go through `SmtpClientStd::connect`, one over implicit TLS and one over STARTTLS, so the session layer and the upgrade are verified against a real server too. XOAUTH2 SHALL also be exercised against Exchange Online's submission service, over STARTTLS, acting on a test mailbox with an app-only token the test mints through the client credentials grant; Exchange advertises no OAUTHBEARER. Each test message SHALL go to the authenticated mailbox only.

## Requirement: A rejected token and a whole message are verified live

An ignored live test against Exchange Online SHALL connect with a token the server refuses and expect the failure at the XOAUTH2 step, refused outright with no error challenge. Another SHALL send one message through `SmtpClient::send`, the one-call exchange a mail client uses, to the authenticated mailbox only.

## Requirement: The XOAUTH2 error challenge is verified live

An ignored live test against Gmail SHALL connect with a token the server refuses, for an address no account holds, and expect the failure to carry the JSON from the server's error challenge, so the challenge and the empty answer it wants are exercised against a real server. Exchange Online refuses without a challenge and cannot reach that branch.

## Requirement: AUTH payloads decode leniently

Challenges and continuation lines SHALL decode leniently, accepting a missing padding, non-zero trailing bits and blanks, and SHALL fail with the `Base64` variant of their error on any other byte outside the alphabet or on data after the padding.

The text of a SCRAM-SHA-256 success reply SHALL be read as the server-final-message only when, past its enhanced status code, it is one blank-free token decoding to a message starting with `v=` or `e=`. Any other text, such as `Authentication successful` or `Accepted`, is human text and leaves the mechanism to refuse the unverified exchange or to complete the verified one.

### Scenario: A one-word success text after a verified exchange
- GIVEN a SCRAM-SHA-256 exchange whose server-final-message came in a 334 challenge
- WHEN the server replies `235 2.7.0 Accepted`
- THEN the exchange completes `Ok`, the text never reaching the mechanism

## Requirement: An exchange the client gives up is cancelled

When a 334 challenge cannot be answered, its payload not being base64, the mechanism refusing it, or LOGIN being prompted a third time, every mechanism coroutine SHALL send the `*` line (RFC 4954 4), read one reply, and then fail with the error that made it give up, whatever that reply is and even when the connection ends under it. The server is so left expecting a command, not a response, and the caller may try another mechanism on the same connection.

No `*` SHALL be sent where the server is not waiting: after a rejection, after a transport failure, or after a success reply the mechanism refuses (a server signature that does not verify in a 235, a success before the expected challenge). In that last case the server holds the session authenticated while the client does not trust it: the connection is not fit for further use.

### Scenario: A server-first message SCRAM refuses
- GIVEN a SCRAM-SHA-256 exchange and a server answering `334 Zm9v`
- WHEN the mechanism refuses the message
- THEN the client writes `*`, reads the reply, and fails with the mechanism's error
