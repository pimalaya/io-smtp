---
cairn: spec
capability: client
status: current
---

# Client

The std-blocking client, the only place this crate touches a socket.

## Requirement: Features

The std-blocking client SHALL sit behind the `std` feature, which implies `client`, the feature gating the client coroutines. The TLS features SHALL imply `std`.

## Requirement: End-to-end connect

With a TLS feature enabled, `SmtpClientStd::connect` SHALL open a whole authenticated session from a URL and an EHLO domain, answering the session coroutine's transport requests with a `pimalaya_stream::stream::Stream`, and SHALL own no protocol decision of its own.

It SHALL take the URL and the EHLO domain as its only required arguments and every optional setting in `SmtpClientStdConnectOptions` (`tls`, `proxy`, `sasl`, `session`), whose default connects directly or through the proxy the environment names, without authenticating. The proxy SHALL tunnel the TCP and TLS transports and SHALL be ignored for a local socket.

### Scenario: Default options
- GIVEN `SmtpClientStdConnectOptions::default()`
- WHEN connecting to `smtps://host`
- THEN the connection goes through `Proxy::System` and no `AUTH` is sent

## Requirement: The URL host is what a socket takes

`SmtpSessionTransport::from_url` SHALL yield the host as a connect call and a certificate check take it: a domain as written, an IPv4 address in dotted form, an IPv6 address without the brackets the URL syntax puts around it.

### Scenario: An IPv6 server
- GIVEN the URL `smtp://[2001:db8::25]:587`
- WHEN the transport is read from it
- THEN it is `Tcp { host: "2001:db8::25", port: 587 }`
