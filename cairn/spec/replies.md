---
cairn: spec
capability: replies
status: current
---

# Replies

How the coroutines read what a server answers: the greeting, the `EHLO` response and the reply to every other command (RFC 5321 4.2).

## Requirement: Replies are bounded

The coroutines reading a reply (the greeting, `EHLO`, `STARTTLS` and every command) SHALL fail with `TooLarge(SMTP_MAX_REPLY_LEN)` once the bytes buffered for one reply exceed `SMTP_MAX_REPLY_LEN`, 64 KiB, instead of reading on. A reply line holds 512 bytes at most (RFC 5321 4.5.3.1.5), so the limit leaves room for the longest `EHLO` response while a server that never ends its reply cannot exhaust memory.

### Scenario: An endless multi-line reply
- GIVEN a server answering with `250-` continuation lines forever
- WHEN the coroutine has buffered more than 64 KiB
- THEN it completes with `TooLarge(65536)` and asks for no further read

## Requirement: Replies are fuzzed

A `reply` fuzz target SHALL feed arbitrary reads followed by EOF to the reading coroutines and to the LOGIN and SCRAM-SHA-256 exchanges, and the first read to the reply, greeting, EHLO and challenge parsers, asserting no panic, no read asked for after EOF more than twice, and no `TooLarge` before the limit was passed. It SHALL also assert that a reply parses as a greeting exactly when its code is 220 and as an `EHLO` response exactly when it is 250, and that neither coroutine reports such a reply as refused.

## Requirement: A last line may be the code alone

The reply, greeting and `EHLO` parsers and their completeness checks SHALL take a last line of the code alone, with or without its space, as the end of the reply (RFC 5321 4.2.1), its text being empty.

### Scenario: A bare code
- GIVEN a server answering `250-First line\r\n250\r\n`
- WHEN the reply is read
- THEN it completes with code 250 and an empty last line

## Requirement: Any reply text is acceptable

Reply text SHALL accept HT, every byte from 0x20 but DEL, decoded as UTF-8 with replacement characters for invalid sequences (RFC 5321 4.2), so a server answering in UTF-8 still yields its code.

## Requirement: A refused greeting or EHLO is a rejection

`SmtpGreetingGet` and `SmtpEhlo` SHALL read their reply as any other reply, and SHALL complete with `Rejected { code, message }` when its code is not 220, respectively 250. `ParseResponse` SHALL be left to bytes that are no reply at all. A caller can so tell a transient refusal from a permanent one, and an `EHLO` the server does not know (500, 502) from the rest.

### Scenario: A banner turning the client away
- GIVEN a server greeting with `554-5.7.1 Service unavailable\r\n554 5.7.1 client host blocked\r\n`
- WHEN the greeting is read
- THEN it completes with `Rejected { code: 554, message: "5.7.1 Service unavailable 5.7.1 client host blocked" }`

## Requirement: A rejection carries every line

The `message` of every `Rejected` error SHALL be the text of all the lines of the reply, joined by a space, empty lines left out.

## Requirement: The server name is taken as given

The greeting and the `EHLO` response SHALL take the first word of their first line as the name the server gives itself, without checking it against a grammar, and the rest of that line as text. A first line with no word SHALL yield an empty name. Every other line of an `EHLO` response that is not empty SHALL be a capability. The strict `Domain` production stays with what the client sends.

### Scenario: An address literal in the banner
- GIVEN a server greeting with `220 [192.0.2.1] ESMTP ready\r\n`
- WHEN the greeting is read
- THEN it completes with the name `[192.0.2.1]` and the text `ESMTP ready`
