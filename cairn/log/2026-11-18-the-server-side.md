---
cairn: log
change: the-server-side
landed: 2026-11-18
---

# The server side

Pimalaya Server needs SMTP submission and LMTP, so the crate grew a `server` feature and module, I/O-free and no_std like the client: `server::command` parses command lines, `server::reply` writes replies, and `server::session::SmtpServerSession` runs a whole session. It is fed the bytes the caller reads and yields the bytes to write next to the decisions only the caller can take (credentials, sender, recipients, message, TLS upgrade); AUTH PLAIN and LOGIN go through the new server side of io-sasl.

The features were reshaped around it, which is breaking. The old `client` feature, the std-blocking client, is now `std`; `client` now gates the client coroutines (on by default), so a server build compiles no client code; the wire-format types build in every shape. io-sasl is taken with `default-features = false` plus its `client` or `server` feature, and patched to ../io-sasl until it is released.

Tests replay RFC 5321 appendix D (D.1, D.2, VRFY), the RFC 2033 LMTP example with its per-recipient replies, and the RFC 3461 DSN example; they cover pipelining in one write, dot-unstuffing and the terminator split at every chunk size from 1 to 64 bytes (which found a CR LF split across reads not starting a line, fixed before landing), bare LF never ending data, the size cap, STARTTLS with buffered-input discard, AUTH required and AUTH over TLS only, and the crate's own `SmtpSessionOpen` and `SmtpMessageSend` pumped in memory against the session with AUTH PLAIN. A `server` fuzz target ran a 60 s smoke run clean.

Not done: BDAT/CHUNKING (BINARYMIME is refused for that reason), EXPN, a caller-initiated 421 shutdown helper, and SASLprep of the PLAIN credentials on the server side (the caller compares).

Capabilities moved: server (new), client (features).
