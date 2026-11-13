---
cairn: delta
change: noop-auth-arguments-and-bcc-lines
---

## ADDED Requirements

## MODIFIED Requirements

### Requirement: Arguments are valid by construction
Every caller string reaching a `MAIL FROM`, `RCPT TO`, `EHLO`, `HELO`, `NOOP` or `AUTH` line SHALL pass a constructor enforcing its production and failing with `SmtpSyntaxError` otherwise: `SmtpLocalPart` (Dot-string or Quoted-string), `SmtpDomain` (Domain), `SmtpAddressLiteral` and `SmtpGeneralAddressLiteral` (RFC 5321 4.1.3), `SmtpParameter` (esmtp-keyword and esmtp-value), `SmtpString` (Atom or Quoted-string) and `SmtpAuthMechanism` (sasl-mech, RFC 4422 3.1). These types SHALL expose no writable field, so the six commands always serialise to one line. `SmtpRaw` is the one exception: it SHALL send its line as given, which its documentation states.

### Requirement: Blind recipients stay blind
`SmtpMessageSend` SHALL remove every `Bcc` and `Resent-Bcc` field from the header section of the transmitted message (RFC 5322 3.6.3, 3.6.6). The removal SHALL read lines as `DATA` ends them, at CRLF, a bare CR or a bare LF, an empty line under any of the three ending the header section: the payload SHALL be the one transmitted with the fields kept, less their lines and nothing else.

## REMOVED Requirements
