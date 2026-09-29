---
cairn: spec
capability: client
status: current
---

# Client

The std-blocking client, the only place this crate touches a socket.

## Requirement: End-to-end connect

With a TLS feature enabled, `SmtpClientStd::connect` SHALL open a whole authenticated session from a URL and an EHLO domain, answering the session coroutine's transport requests with a `pimalaya_stream::stream::Stream`, and SHALL own no protocol decision of its own.

It SHALL take the URL and the EHLO domain as its only required arguments and every optional setting in `SmtpClientStdConnectOptions` (`tls`, `proxy`, `sasl`, `session`), whose default connects directly or through the proxy the environment names, without authenticating. The proxy SHALL tunnel the TCP and TLS transports and SHALL be ignored for a local socket.

### Scenario: Default options
- GIVEN `SmtpClientStdConnectOptions::default()`
- WHEN connecting to `smtps://host`
- THEN the connection goes through `Proxy::System` and no `AUTH` is sent
