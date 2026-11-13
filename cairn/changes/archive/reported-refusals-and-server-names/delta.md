---
cairn: delta
change: reported-refusals-and-server-names
---

## ADDED Requirements

### Requirement: A refused greeting or EHLO is a rejection
`SmtpGreetingGet` and `SmtpEhlo` SHALL read their reply as any other reply, and SHALL complete with `Rejected { code, message }` when its code is not 220, respectively 250. `ParseResponse` SHALL be left to bytes that are no reply at all.

### Requirement: A rejection carries every line
The `message` of every `Rejected` error SHALL be the text of all the lines of the reply, joined by a space, empty lines left out.

### Requirement: The server name is taken as given
The greeting and the `EHLO` response SHALL take the first word of their first line as the name the server gives itself, without checking it against a grammar, and the rest of that line as text. Every other line of an `EHLO` response that is not empty SHALL be a capability.

### Requirement: A refused recipient is named
By default `SmtpMessageSend` SHALL stop at the first `RCPT TO` the server refuses and fail with `SmtpMessageSendError::RcptTo`, carrying the forward path and the reply. With `SmtpMessageSendOptions::skip_refused_recipients` it SHALL send to the accepted recipients and complete with the list of the refused ones, or fail with `SmtpMessageSendError::NoRecipient` when the server refused them all.

### Requirement: A failed transaction is reset
When the server refuses a recipient, every recipient, or the `DATA` command, `SmtpMessageSend` SHALL send `RSET` before it fails, and SHALL fail with the refusal whatever `RSET` ends with. It SHALL send none after an EOF, an oversized or unparsable reply, a 421 reply, a refused `MAIL FROM`, or a reply to the message content.

### Requirement: The URL host is what a socket takes
`SmtpSessionTransport::from_url` SHALL yield a domain as written, an IPv4 address in dotted form, and an IPv6 address without the brackets the URL syntax puts around it.

## MODIFIED Requirements

### Requirement: Replies are fuzzed
The `reply` fuzz target SHALL also assert that a reply parses as a greeting exactly when its code is 220 and as an `EHLO` response exactly when it is 250, and that neither coroutine reports such a reply as refused.

## REMOVED Requirements
