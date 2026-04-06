# I/O SMTP [![Documentation](https://img.shields.io/docsrs/io-smtp?style=flat&logo=docs.rs&logoColor=white)](https://docs.rs/io-smtp/latest/io_smtp) [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

**I/O-free** SMTP client library written in Rust, based on [io-socket](https://github.com/pimalaya/io-socket)

## Table of contents

- [RFC coverage](#rfc-coverage)
- [Examples](#examples)
  - [Send EHLO via SMTP (blocking)](#send-ehlo-via-smtp-blocking)
  - [Send a message via SMTP (async)](#send-a-message-via-smtp-async)
- [More examples](#more-examples)
- [License](#license)
- [Social](#social)
- [Sponsoring](#sponsoring)

## RFC coverage

This library implements SMTP as I/O-agnostic coroutines — no sockets, no async runtime, no `std` required.

| Module   | What it covers                                                                   |
|----------|----------------------------------------------------------------------------------|
| `login`  | LOGIN — legacy de-facto AUTH mechanism (no RFC)                                  |
| [3207]   | STARTTLS — upgrade a plain connection to TLS                                     |
| [3461]   | DSN — `RET`, `ENVID`, `NOTIFY`, `ORCPT` ESMTP parameters for MAIL FROM / RCPT TO |
| [4616]   | PLAIN — SASL PLAIN authentication mechanism                                      |
| [4954]   | AUTH — SASL exchange protocol (`AuthenticateData`)                               |
| [5321]   | SMTP — greeting, EHLO, HELO, MAIL FROM, RCPT TO, DATA, NOOP, RSET, QUIT          |
| [7628]   | OAUTHBEARER — OAuth 2.0 bearer token SASL mechanism                              |
| [7677]   | SCRAM-SHA-256 — SASL SCRAM-SHA-256 mechanism (feature `scram`)                   |

[3207]: https://www.rfc-editor.org/rfc/rfc3207
[3461]: https://www.rfc-editor.org/rfc/rfc3461
[4616]: https://www.rfc-editor.org/rfc/rfc4616
[4954]: https://www.rfc-editor.org/rfc/rfc4954
[5321]: https://www.rfc-editor.org/rfc/rfc5321
[7628]: https://www.rfc-editor.org/rfc/rfc7628
[7677]: https://www.rfc-editor.org/rfc/rfc7677

## Examples

### Send EHLO via SMTP (blocking)

```rust,ignore
use std::net::TcpStream;

use io_smtp::rfc5321::{
    ehlo::{SmtpEhlo, SmtpEhloResult},
    greeting::{GetSmtpGreeting, GetSmtpGreetingResult},
    types::domain::Domain,
};
use io_socket::runtimes::std_stream::handle;

let mut stream = TcpStream::connect("smtp.example.com:25").unwrap();
let domain = Domain::parse(b"localhost").unwrap();

// Read greeting
let mut coroutine = GetSmtpGreeting::new();
let mut arg = None;

loop {
    match coroutine.resume(arg.take()) {
        GetSmtpGreetingResult::Ok { .. } => break,
        GetSmtpGreetingResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
        GetSmtpGreetingResult::Err { err } => panic!("{err}"),
    }
}

// Send EHLO
let mut coroutine = SmtpEhlo::new(domain.into());
let mut arg = None;

let capabilities = loop {
    match coroutine.resume(arg.take()) {
        SmtpEhloResult::Ok { capabilities } => break capabilities,
        SmtpEhloResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
        SmtpEhloResult::Err { err } => panic!("{err}"),
    }
};

println!("Server capabilities: {capabilities:?}");
```

### Send a message via SMTP (async)

```rust,ignore
use io_smtp::send::{SmtpMessageSend, SmtpMessageSendResult};
use io_smtp::rfc5321::types::{forward_path::ForwardPath, reverse_path::ReversePath};
use io_socket::runtimes::tokio_stream::handle;
use tokio::net::TcpStream;

let mut stream = TcpStream::connect("smtp.example.com:25").await.unwrap();

let from: ReversePath = "<sender@example.com>".parse().unwrap();
let to: ForwardPath = "<recipient@example.com>".parse().unwrap();
let message = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nHello!".to_vec();

let mut coroutine = SmtpMessageSend::new(from, [to], message);
let mut arg = None;

loop {
    match coroutine.resume(arg.take()) {
        SmtpMessageSendResult::Ok => break,
        SmtpMessageSendResult::Io { input } => arg = Some(handle(&mut stream, input).await.unwrap()),
        SmtpMessageSendResult::Err { err } => panic!("{err}"),
    }
}
```

*See complete examples at [./examples](https://github.com/pimalaya/io-smtp/blob/master/examples).*

## More examples

Have a look at projects built on top of this library:

- [himalaya](https://github.com/pimalaya/himalaya): CLI to manage emails

## License

This project is licensed under either of:

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

## Social

- Chat on [Matrix](https://matrix.to/#/#pimalaya:matrix.org)
- News on [Mastodon](https://fosstodon.org/@pimalaya) or [RSS](https://fosstodon.org/@pimalaya.rss)
- Mail at [pimalaya.org@posteo.net](mailto:pimalaya.org@posteo.net)

## Sponsoring

[![nlnet](https://nlnet.nl/logo/banner-160x60.png)](https://nlnet.nl/)

Special thanks to the [NLnet foundation](https://nlnet.nl/) and the [European Commission](https://www.ngi.eu/) that have been financially supporting the project for years:

- 2022: [NGI Assure](https://nlnet.nl/project/Himalaya/)
- 2023: [NGI Zero Entrust](https://nlnet.nl/project/Pimalaya/)
- 2024: [NGI Zero Core](https://nlnet.nl/project/Pimalaya-PIM/) *(still ongoing in 2026)*

If you appreciate the project, feel free to donate using one of the following providers:

[![GitHub](https://img.shields.io/badge/-GitHub%20Sponsors-fafbfc?logo=GitHub%20Sponsors)](https://github.com/sponsors/soywod)
[![Ko-fi](https://img.shields.io/badge/-Ko--fi-ff5e5a?logo=Ko-fi&logoColor=ffffff)](https://ko-fi.com/soywod)
[![Buy Me a Coffee](https://img.shields.io/badge/-Buy%20Me%20a%20Coffee-ffdd00?logo=Buy%20Me%20A%20Coffee&logoColor=000000)](https://www.buymeacoffee.com/soywod)
[![Liberapay](https://img.shields.io/badge/-Liberapay-f6c915?logo=Liberapay&logoColor=222222)](https://liberapay.com/soywod)
[![thanks.dev](https://img.shields.io/badge/-thanks.dev-000000?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQuMDk3IiBoZWlnaHQ9IjE3LjU5NyIgY2xhc3M9InctMzYgbWwtMiBsZzpteC0wIHByaW50Om14LTAgcHJpbnQ6aW52ZXJ0IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik05Ljc4MyAxNy41OTdINy4zOThjLTEuMTY4IDAtMi4wOTItLjI5Ny0yLjc3My0uODktLjY4LS41OTMtMS4wMi0xLjQ2Mi0xLjAyLTIuNjA2di0xLjM0NmMwLTEuMDE4LS4yMjctMS43NS0uNjc4LTIuMTk1LS40NTItLjQ0Ni0xLjIzMi0uNjY5LTIuMzQtLjY2OUgwVjcuNzA1aC41ODdjMS4xMDggMCAxLjg4OC0uMjIyIDIuMzQtLjY2OC40NTEtLjQ0Ni42NzctMS4xNzcuNjc3LTIuMTk1VjMuNDk2YzAtMS4xNDQuMzQtMi4wMTMgMS4wMjEtMi42MDZDNS4zMDUuMjk3IDYuMjMgMCA3LjM5OCAwaDIuMzg1djEuOTg3aC0uOTg1Yy0uMzYxIDAtLjY4OC4wMjctLjk4LjA4MmExLjcxOSAxLjcxOSAwIDAgMC0uNzM2LjMwN2MtLjIwNS4xNTYtLjM1OC4zODQtLjQ2LjY4Mi0uMTAzLjI5OC0uMTU0LjY4Mi0uMTU0IDEuMTUxVjUuMjNjMCAuODY3LS4yNDkgMS41ODYtLjc0NSAyLjE1NS0uNDk3LjU2OS0xLjE1OCAxLjAwNC0xLjk4MyAxLjMwNXYuMjE3Yy44MjUuMyAxLjQ4Ni43MzYgMS45ODMgMS4zMDUuNDk2LjU3Ljc0NSAxLjI4Ny43NDUgMi4xNTR2MS4wMjFjMCAuNDcuMDUxLjg1NC4xNTMgMS4xNTIuMTAzLjI5OC4yNTYuNTI1LjQ2MS42ODIuMTkzLjE1Ny40MzcuMjYuNzMyLjMxMi4yOTUuMDUuNjIzLjA3Ni45ODQuMDc2aC45ODVabTE0LjMxNC03LjcwNmgtLjU4OGMtMS4xMDggMC0xLjg4OC4yMjMtMi4zNC42NjktLjQ1LjQ0NS0uNjc3IDEuMTc3LS42NzcgMi4xOTVWMTQuMWMwIDEuMTQ0LS4zNCAyLjAxMy0xLjAyIDIuNjA2LS42OC41OTMtMS42MDUuODktMi43NzQuODloLTIuMzg0di0xLjk4OGguOTg0Yy4zNjIgMCAuNjg4LS4wMjcuOTgtLjA4LjI5Mi0uMDU1LjUzOC0uMTU3LjczNy0uMzA4LjIwNC0uMTU3LjM1OC0uMzg0LjQ2LS42ODIuMTAzLS4yOTguMTU0LS42ODIuMTU0LTEuMTUydi0xLjAyYzAtLjg2OC4yNDgtMS41ODYuNzQ1LTIuMTU1LjQ5Ny0uNTcgMS4xNTgtMS4wMDQgMS45ODMtMS4zMDV2LS4yMTdjLS44MjUtLjMwMS0xLjQ4Ni0uNzM2LTEuOTgzLTEuMzA1LS40OTctLjU3LS43NDUtMS4yODgtLjc0NS0yLjE1NXYtMS4wMmMwLS40Ny0uMDUxLS44NTQtLjE1NC0xLjE1Mi0uMTAyLS4yOTgtLjI1Ni0uNTI2LS40Ni0uNjgyYTEuNzE5IDEuNzE5IDAgMCAwLS43MzctLjMwNyA1LjM5NSA1LjM5NSAwIDAgMC0uOTgtLjA4MmgtLjk4NFYwaDIuMzg0YzEuMTY5IDAgMi4wOTMuMjk3IDIuNzc0Ljg5LjY4LjU5MyAxLjAyIDEuNDYyIDEuMDIgMi42MDZ2MS4zNDZjMCAxLjAxOC4yMjYgMS43NS42NzggMi4xOTUuNDUxLjQ0NiAxLjIzMS42NjggMi4zNC42NjhoLjU4N3oiIGZpbGw9IiNmZmYiLz48L3N2Zz4=)](https://thanks.dev/soywod)
[![PayPal](https://img.shields.io/badge/-PayPal-0079c1?logo=PayPal&logoColor=ffffff)](https://www.paypal.com/paypalme/soywod)
