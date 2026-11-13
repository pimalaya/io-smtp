---
cairn: log
change: reported-refusals-and-server-names
landed: 2026-11-13
---

# Refusals are reported, the server name is taken as given

Five findings of the family audit of 2026-11-13 (SMTP-03, SMTP-05, SMTP-06, SMTP-09, SMTP-10). Five tests on the previous code failed: a `554` banner completed with `SMTP greeting failed: parse error: expected greeting, found '5' at byte 0`, a `550` to `EHLO` with `parse error: expected '2', found '5' at byte 0`, `220 [192.0.2.1] ESMTP ready` did not parse, a send whose second recipient got `550 5.1.1 User unknown` failed with `SMTP RCPT TO failed: rejected 550 5.1.1 User unknown`, naming nobody and writing no `RSET`, and `smtp://[2001:db8::25]:587` gave the host `[2001:db8::25]`.

## Greeting and EHLO

Both coroutines now parse their reply with `SmtpResponse::parse`, and `SmtpGreeting` and `SmtpEhloResponse` are read out of that reply, so the two grammars of their own are deleted and the public `parse` of each is the generic parser plus a check of the code. A code other than 220, respectively 250, completes with the new `Rejected { code, message }`; `ParseResponse` is left to bytes that are no reply.

The server name is the first word of the first line, whatever it holds, typed `SmtpText` instead of `SmtpDomain`: the validated `SmtpDomain` of what the client sends and a lenient server name could not be one type. A first line with no word gives an empty name rather than an error, since a bare `220` still means the service is ready. The generic parser does not require the continuation lines to repeat the final code, so a greeting no longer does either; `EHLO` capability lines now take the bytes any reply text takes, and an empty continuation line is skipped instead of failing the parse.

`SmtpResponse::message` joins the lines of a reply with a space, and every `Rejected` of the crate carries it, the twenty places that kept the first line included: a multi-line refusal used to be cut in the middle of its sentence.

**Breaking**: `SmtpGreetingGetError` and `SmtpEhloError` gained `Rejected`; `SmtpGreeting::domain`, `SmtpEhloResponse::domain` and the first parameter of `SmtpGreeting::new` are a `SmtpText`.

## Refused recipients

`SmtpMessageSendError::RcptTo` is now `{ forward_path, error }`. The default stays all or nothing, which suits a client submitting one message, and is now written down. `SmtpMessageSendOptions::skip_refused_recipients` records a refusal and goes on; the send completes with the refused recipients, as `SmtpMessageSendRefusal` values, and with `SmtpMessageSendError::NoRecipient` when none was accepted, without sending `DATA`. The return type of the coroutine and of the `send` method of both client traits therefore went from `()` to `Vec<SmtpMessageSendRefusal>`, always empty without the option.

Before failing on a refused recipient, on every recipient refused, or on a refused `DATA` command, the composite sends `RSET` and ignores how it ends: the caller gets the refusal. It sends none where it would be wrong or useless: after an EOF or a reply it could not read, the state of the session being unknown; after a 421, the server closing the connection (a 421 to `RCPT TO` is never skipped either); after a refused `MAIL FROM`, no transaction being open; once the content was answered, the transaction being over. One limit remains outside the coroutine: if writing `RSET` fails at the transport, a client reports that I/O error, not the refusal.

**Breaking**: the shape of `RcptTo`, the return type, and one more field in `SmtpMessageSendOptions`. The applications matching `SmtpMessageSendError::RcptTo(SmtpRcptError::Rejected { .. })` match `RcptTo { error: SmtpRcptError::Rejected { .. }, .. }` instead, and the one calling `rset()` itself after a failed send no longer needs to.

## Stale bytes and URL hosts

Every sub-coroutine call inside a loop takes `arg` (session, message send, `DATA`, the six mechanisms). Nothing observable changes, each next step writing before it reads, so no test could fail on the previous code and none was added.

`SmtpSessionTransport::from_url` matches on `Url::host`. A non-ASCII domain is still passed as the url crate gives it, percent-encoded for these non-special schemes: converting it needs an IDNA dependency, left out.

Capabilities moved: replies (ADDED "A refused greeting or EHLO is a rejection", "A rejection carries every line", "The server name is taken as given"; MODIFIED "Replies are fuzzed"), submission (ADDED "A refused recipient is named", "A failed transaction is reset"), client (ADDED "The URL host is what a socket takes").

Existing tests changed: the two `parse_error_returns_parse_error` tests fed `250 wrong code` to the greeting and `500 syntax error` to `EHLO` and expected `ParseResponse`, the very behaviour reported; they now feed `999 not a reply code`, and the refusals have their own tests. The live-test helper in tests/common.rs matches the new return value.

Verified: `cargo test --all-features` 163 unit tests (14 new), 11 + 43 + 7 integration tests and 19 doc tests passed; `cargo clippy --all-features --all-targets -- -D warnings` clean, also without default features; `cargo build --no-default-features` passes. The `reply` fuzz target, whose oracle now ties the greeting and `EHLO` parsers to the reply code, ran 121 seconds on the final code: 940,759 executions, no finding (coverage 2124).
