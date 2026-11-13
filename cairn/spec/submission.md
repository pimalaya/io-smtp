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
