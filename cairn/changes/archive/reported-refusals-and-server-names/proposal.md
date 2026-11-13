---
cairn: change
id: reported-refusals-and-server-names
status: landed
created: 2026-11-13
---

# Report what the server refused, take its name as given

## Why

Five findings of the family audit of 2026-11-13, all about what the client makes of a server's answer.

- SMTP-03. The greeting parser wanted the literal code 220 and the `EHLO` parser 250, and neither error enum had a rejection variant. A `554 5.7.1 client host blocked` banner or a `550 Access denied` to `EHLO`, the two places servers most often turn a client away, came out as `ParseResponse("expected '2', found '5'")`: code and reason lost, a transient 421 indistinguishable from a permanent 554, and the 500 or 502 that should trigger the `HELO` fallback undetectable. Every other `Rejected` kept the first line only of a multi-line reply.
- SMTP-06. Both parsers also required a strict `Domain` as the server name. A banner with an address literal, which RFC 5321 4.2 allows, an underscore or a trailing dot failed the session before `EHLO`, over a name the session throws away.
- SMTP-05. `SmtpMessageSend` stopped at the first refused recipient with an error holding a code and a text but no recipient, and left the transaction open: the next `MAIL FROM` on that connection was a nested one (RFC 5321 4.1.4), which some servers answer with 503. Neither the stop nor the open transaction was documented.
- SMTP-09. The composites passed the bytes that completed one step on to the next step. Harmless today, every next step writing before it reads.
- SMTP-10. `SmtpSessionTransport::from_url` took `Url::host_str`, which keeps the brackets of an IPv6 address: the connect request and the certificate name were `[2001:db8::25]`.

## What

- The greeting and `EHLO` coroutines parse their reply with the generic reply parser, then complete with `Rejected { code, message }` when the code is not 220 or 250. `SmtpGreeting` and `SmtpEhloResponse` are read out of the generic reply: the grammars of their own are gone.
- The server name is the first word of the first line, kept as a `SmtpText`. `SmtpDomain` and its strict parser stay with what the client sends.
- `SmtpResponse::message` joins every line of a reply with a space, and every `Rejected` in the crate uses it.
- `SmtpMessageSendError::RcptTo` names the recipient. `SmtpMessageSendOptions::skip_refused_recipients` goes on with the accepted ones and the send returns the refused ones; `SmtpMessageSendError::NoRecipient` when none is left.
- The composite sends `RSET` before failing on a refused recipient or a refused `DATA` command, and never lets the `RSET` outcome replace the refusal. It sends none when the session state is unknown (EOF, oversized or unparsable reply), on 421, after a refused `MAIL FROM` or once the content was answered.
- `arg.take()` at every sub-coroutine call inside a loop.
- `from_url` matches on `Url::host` and renders an IPv6 address bare.
