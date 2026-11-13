---
cairn: delta
change: validated-command-arguments
---

## ADDED Requirements

### Requirement: Arguments are valid by construction
Every caller string reaching a `MAIL FROM`, `RCPT TO`, `EHLO` or `HELO` line SHALL pass a constructor enforcing its production and failing with `SmtpSyntaxError` otherwise: `SmtpLocalPart` (Dot-string or Quoted-string), `SmtpDomain` (Domain), `SmtpAddressLiteral` and `SmtpGeneralAddressLiteral` (RFC 5321 4.1.3), `SmtpParameter` (esmtp-keyword and esmtp-value). These types SHALL expose no writable field, so the four commands always serialise to one line.

### Requirement: Non-ASCII characters are accepted
A local part, a domain and a parameter value SHALL accept non-ASCII characters where the production takes atext, qtextSMTP, Let-dig or esmtp-value (RFC 6531 3.3). A parameter keyword, an address literal and the `ENVID` and `ORCPT` values SHALL stay US-ASCII.

### Requirement: Addresses parse from their wire form
`SmtpMailbox::try_from` SHALL read a local part, an at sign, then a domain or a bracketed address literal. `SmtpEhloDomain::try_from` SHALL read an address literal when the string starts with a bracket and a domain otherwise. `SmtpAddressLiteral::try_from` SHALL read an IPv4 address, an IPv6 address after the `IPv6:` tag in any case, or a general literal.

### Requirement: A local part is quoted when needed
`SmtpLocalPart::quote` SHALL return its argument as is when it is a Dot-string, and otherwise a Quoted-string escaping the double quote and the backslash. It SHALL refuse control characters.

### Requirement: DSN values are xtext-encoded
`SmtpParameter::envid` and `SmtpParameter::orcpt_rfc822` SHALL send their argument xtext-encoded (RFC 3461 4), a space, `+` and `=` becoming `+20`, `+2B` and `+3D`, and SHALL refuse an empty argument or one holding anything but printable US-ASCII.

## MODIFIED Requirements

## REMOVED Requirements
