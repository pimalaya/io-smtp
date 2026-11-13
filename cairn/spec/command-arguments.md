---
cairn: spec
capability: command-arguments
status: current
---

# Command arguments

What the caller puts in a command: the mailboxes of `MAIL FROM` and `RCPT TO`, their ESMTP parameters, and the identity of `EHLO` and `HELO` (RFC 5321 4.1.2). What the server sends back belongs to the replies capability. `SmtpRaw` sends its line as given and is outside these rules.

## Requirement: Arguments are valid by construction

Every caller string reaching a `MAIL FROM`, `RCPT TO`, `EHLO` or `HELO` line SHALL pass a constructor enforcing its production and failing with `SmtpSyntaxError` otherwise: `SmtpLocalPart` (Dot-string or Quoted-string), `SmtpDomain` (Domain), `SmtpAddressLiteral` and `SmtpGeneralAddressLiteral` (RFC 5321 4.1.3), `SmtpParameter` (esmtp-keyword and esmtp-value). These types SHALL expose no writable field, so the four commands always serialise to one line, and their coroutines take them without a check of their own.

### Scenario: A local part carrying a second command
- GIVEN the address `a@x>\r\nRCPT TO:<eve@evil.example>@example.com`
- WHEN `SmtpMailbox::try_from` reads it
- THEN it fails with a `SmtpSyntaxError` and no command can be built from it

### Scenario: A parameter value with a space
- GIVEN the keyword `SIZE` and the value `1 SMTPUTF8`
- WHEN `SmtpParameter::new` reads them
- THEN it fails with `SmtpSyntaxError::ParameterValue`

## Requirement: Non-ASCII characters are accepted

A local part, a domain and a parameter value SHALL accept non-ASCII characters where the production takes atext, qtextSMTP, Let-dig or esmtp-value (RFC 6531 3.3). A parameter keyword, an address literal and the `ENVID` and `ORCPT` values SHALL stay US-ASCII. The caller decides whether to send the `SMTPUTF8` parameter, as it holds the EHLO capabilities.

## Requirement: Addresses parse from their wire form

`SmtpMailbox::try_from` SHALL read a local part, an at sign, then a domain or a bracketed address literal. `SmtpEhloDomain::try_from` SHALL read an address literal when the string starts with a bracket and a domain otherwise. `SmtpAddressLiteral::try_from` SHALL read an IPv4 address, an IPv6 address after the `IPv6:` tag in any case, or a general literal.

### Scenario: A quoted local part holding an at sign
- GIVEN the address `"a@b"@example.org`
- WHEN `SmtpMailbox::try_from` reads it
- THEN the local part is `"a@b"` and the domain `example.org`

## Requirement: A local part is quoted when needed

`SmtpLocalPart::quote` SHALL return its argument as is when it is a Dot-string, and otherwise a Quoted-string escaping the double quote and the backslash. It SHALL refuse control characters.

### Scenario: A local part with a space
- GIVEN the content `john doe`
- WHEN it is quoted and sent to the domain `x`
- THEN the server reads `RCPT TO:<"john doe"@x>`

## Requirement: DSN values are xtext-encoded

`SmtpParameter::envid` and `SmtpParameter::orcpt_rfc822` SHALL send their argument xtext-encoded (RFC 3461 4), a space, `+` and `=` becoming `+20`, `+2B` and `+3D`, and SHALL refuse an empty argument or one holding anything but printable US-ASCII.

### Scenario: An original recipient with a plus sign
- GIVEN the address `a+b@x`
- WHEN `SmtpParameter::orcpt_rfc822` builds the parameter
- THEN the server reads `ORCPT=rfc822;a+2Bb@x`
