---
cairn: delta
change: cancelled-auth-and-scram-without-rand
---

## ADDED Requirements

### Requirement: An exchange the client gives up is cancelled
When a 334 challenge cannot be answered, its payload not being base64, the mechanism refusing it, or LOGIN being prompted a third time, every mechanism coroutine SHALL send the `*` line (RFC 4954 4), read one reply, and then fail with the error that made it give up, whatever that reply is and even when the connection ends under it. No `*` SHALL be sent where the server is not waiting: after a rejection, after a transport failure, or after a success reply the mechanism refuses.

## MODIFIED Requirements

### Requirement: One coroutine per framed mechanism
SCRAM-SHA-256 SHALL sit behind the `scram` feature, which is what pulls the hash crates. The `scram` feature SHALL NOT pull `rand`: the coroutine takes the client nonce with the credentials, so the coroutine layer with `scram` builds without std. `rand` SHALL come with the TLS features, the connect they gate being the only code drawing a nonce, and without its default features beyond `thread_rng`.

## REMOVED Requirements
