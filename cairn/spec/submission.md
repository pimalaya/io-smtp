---
cairn: spec
capability: submission
status: current
---

# Submission

`SmtpMessageSend`, the composite that submits one message: `MAIL FROM`, one `RCPT TO` per forward path, then `DATA`. Its callers are mail clients handing a message to their submission server, not relays, which is why it may touch the content it transmits.

## Requirement: Blind recipients stay blind

`SmtpMessageSend` SHALL remove every `Bcc` and `Resent-Bcc` field from the header section of the transmitted message (RFC 5322 3.6.3, 3.6.6), matching the name case-insensitively and with the obsolete whitespace before the colon, removing its folded lines too, and leaving everything after the first empty line untouched. The forward paths are untouched, so the blind recipients still receive the message.

The removal SHALL read lines as `DATA` ends them, at CRLF, a bare CR or a bare LF, an empty line under any of the three ending the header section: the payload SHALL be the one transmitted with the fields kept, less their lines and nothing else. A bare CR ending the line before a removed field is transmitted as CRLF either way.

`SmtpMessageSendOptions::keep_bcc` SHALL transmit the header section as given, for a caller whose `Bcc` field must reach the server. The `DATA` rules on line endings and dots still apply.

### Scenario: A message with a blind recipient
- GIVEN a message carrying `Bcc: c@x` and default options
- WHEN it is sent
- THEN the `DATA` payload carries no `Bcc` field, and a `Bcc:` line in the body is left alone

### Scenario: A blind field after a bare CR
- GIVEN the message `To: b@x\rBcc: c@x\r\n\r\nbody\r\n` and default options
- WHEN it is sent
- THEN the `DATA` payload is `To: b@x\r\n\r\nbody\r\n.\r\n`

## Requirement: Envelope parameters

`SmtpMessageSendOptions::mail_parameters` SHALL be sent on `MAIL FROM` and `SmtpMessageSendOptions::rcpt_parameters` on every `RCPT TO`, in the given order (RFC 5321 4.1.1.2, 4.1.1.3). Both default to empty. The composite does not check the server announced the matching extension: the caller holds the EHLO capabilities and decides. A caller needing different parameters per recipient drives the single steps instead.

### Scenario: A delivery status notification request
- GIVEN `RET=HDRS` and `ENVID=abc123` as MAIL parameters and `NOTIFY=SUCCESS,FAILURE` as RCPT parameters
- WHEN the message is sent
- THEN the server reads `MAIL FROM:<a@x> RET=HDRS ENVID=abc123` and `RCPT TO:<c@x> NOTIFY=SUCCESS,FAILURE`

## Requirement: DATA lines end with CRLF

`SmtpData` SHALL transmit every bare CR and every bare LF of the message as CRLF (RFC 5321 2.3.8), SHALL double the dot starting any line, a line after a bare line ending included (RFC 5321 4.5.2), SHALL end the last line with CRLF, and SHALL then send the `.` line. A message already in that form SHALL be transmitted byte for byte.

### Scenario: A message with Unix line endings
- GIVEN the message `a\n.\nb`
- WHEN it is sent
- THEN the `DATA` payload is `a\r\n..\r\nb\r\n.\r\n`

## Requirement: A refused recipient is named

By default `SmtpMessageSend` SHALL send to every recipient or to none: at the first `RCPT TO` the server refuses it SHALL stop and fail with `SmtpMessageSendError::RcptTo`, carrying the forward path of that recipient and the reply.

With `SmtpMessageSendOptions::skip_refused_recipients` it SHALL go on with the next recipient, send the message to those the server accepted, and complete with the list of the refused ones, each a `SmtpMessageSendRefusal` (forward path, code, text). When the server refused them all it SHALL send no `DATA` and fail with `SmtpMessageSendError::NoRecipient`, carrying that list. Without the option the list a successful send completes with is empty.

### Scenario: The second of three recipients is unknown
- GIVEN recipients `c@x`, `d@x`, `e@x`, default options and a server answering `550 5.1.1 User unknown` to `d@x`
- WHEN the message is sent
- THEN the send fails with `RcptTo { forward_path: <d@x>, error: Rejected { code: 550, .. } }`, and `e@x` is never declared

### Scenario: Going on without the refused recipient
- GIVEN recipients `c@x` and `d@x`, `skip_refused_recipients`, and a server refusing `c@x` with 550
- WHEN the message is sent
- THEN `d@x` receives it and the send completes with one refusal, `c@x` with code 550

## Requirement: A failed transaction is reset

When the server refuses a recipient, every recipient, or the `DATA` command, `SmtpMessageSend` SHALL send `RSET` before it fails (RFC 5321 4.1.1.5), so the connection takes another `MAIL FROM`. Whatever `RSET` ends with, the send SHALL fail with the refusal that caused it.

It SHALL send no `RSET` when the state of the session is unknown or the transaction is already over: after an EOF, an oversized or unparsable reply, a 421 reply (the server is closing the connection), a refused `MAIL FROM`, or a reply to the message content. After the first three the connection is not fit for another transaction.

### Scenario: A refused recipient
- GIVEN a server answering 250 to `MAIL FROM` and 550 to the only `RCPT TO`
- WHEN the message is sent
- THEN the client writes `MAIL FROM`, `RCPT TO`, `RSET` and nothing else
