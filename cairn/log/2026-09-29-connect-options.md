---
cairn: log
change: connect-options
landed: 2026-09-29
---

# Connect options

Requested in pimalaya/himalaya#742: a per-account proxy. pimalaya-stream already tunnels through SOCKS5 and HTTP CONNECT, but `connect` always asked it for `Proxy::System`, so a caller could only reach a proxy through the environment.

**`SmtpClientStdConnectOptions`** (client/connect.rs) replaces every optional argument of `SmtpClientStd::connect`, which now takes `(url, domain, opts)`. Its fields are `tls`, `proxy`, `sasl` (now a plain `Option<Sasl>`) and `session`, the unchanged `SmtpSessionOpenOptions`. The URL and the EHLO domain stay arguments because they are the only inputs without a default. The same shape lands across io-imap, io-managesieve, io-jmap, io-gmail and io-msgraph, so one setting reaches every Pimalaya client the same way.

**The proxy** reaches the TCP and TLS connects; STARTTLS upgrades the already tunnelled stream and a local socket ignores it. The default stays `Proxy::System`.

**Breaking**: the signature of `connect`.

Verified: unit tests green, clippy clean on the touched files.

Spec updated: `client` (new capability, ADDED: "End-to-end connect").
