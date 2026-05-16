# I/O SMTP [![Documentation](https://img.shields.io/docsrs/io-smtp?style=flat&logo=docs.rs&logoColor=white)](https://docs.rs/io-smtp/latest/io_smtp) [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

SMTP client library, written in Rust

## Table of contents

- [Features](#features)
- [RFC coverage](#rfc-coverage)
- [Examples](#examples)
  - [As a no-std coroutine library](#as-a-no-std-coroutine-library)
  - [As a light std client (BYO stream)](#as-a-light-std-client-byo-stream)
  - [As a full std client (TCP + TLS)](#as-a-full-std-client-tcp--tls)
- [More examples](#more-examples)
- [License](#license)
- [Social](#social)
- [Sponsoring](#sponsoring)

## Features

- **I/O-free** coroutines: every SMTP command is exposed as a `resume(arg: Option<&[u8]>)` state machine. No sockets, no async runtime, no `std` required. Drive against any blocking, async, or fuzz harness.
- **Standard, blocking client**:
  - Light client (requires `client` feature): `SmtpClientStd::new(stream)` wraps a connected `Read + Write` stream and exposes one method per coroutine. You still own TCP / TLS / STARTTLS.
  - Full std client (requires `rustls-ring`, `rustls-aws`, or `native-tls` feature): `SmtpClientStd::connect(url, tls, starttls, domain, sasl)` opens `smtp://` / `smtps://` URLs via [pimalaya/stream](https://github.com/pimalaya/stream), reads the greeting, sends the initial EHLO, drives the optional STARTTLS upgrade with a fresh EHLO over TLS, and runs the chosen SASL mechanism, returning a ready-to-use authenticated client.
- **SASL mechanisms**:
  - `LOGIN`, `PLAIN` and `OAUTHBEARER` built-in
  - `SCRAM-SHA-256` (requires `scram` feature)

*The `io-smtp` library is written in [Rust](https://www.rust-lang.org/), and relies on [cargo features](https://doc.rust-lang.org/cargo/reference/features.html) to enable or disable functionalities. Default features can be found in the `features` section of the [`Cargo.toml`](https://github.com/pimalaya/io-smtp/blob/master/Cargo.toml), or on [docs.rs](https://docs.rs/crate/io-smtp/latest/features).*

## RFC coverage

This library implements SMTP as I/O-agnostic coroutines: no sockets, no async runtime, no `std` required.

| Module  | What it covers                                                                   |
|---------|----------------------------------------------------------------------------------|
| `login` | LOGIN: legacy de-facto AUTH mechanism (no RFC)                                   |
| [1870]  | SIZE: maximum message size declaration                                           |
| [3207]  | STARTTLS: upgrade a plain connection to TLS                                      |
| [3461]  | DSN: `RET`, `ENVID`, `NOTIFY`, `ORCPT` ESMTP parameters for MAIL FROM / RCPT TO  |
| [3463]  | Enhanced status codes: `EnhancedStatusCode` type                                 |
| [4616]  | PLAIN: SASL PLAIN authentication mechanism                                       |
| [4954]  | AUTH: SASL exchange protocol                                                     |
| [5321]  | SMTP: greeting, EHLO, HELO, MAIL FROM, RCPT TO, DATA, NOOP, RSET, QUIT           |
| [7628]  | OAUTHBEARER: OAuth 2.0 bearer token SASL mechanism                               |
| [7677]  | SCRAM-SHA-256: SASL SCRAM-SHA-256 mechanism (feature `scram`)                    |

[1870]: https://www.rfc-editor.org/rfc/rfc1870
[3207]: https://www.rfc-editor.org/rfc/rfc3207
[3461]: https://www.rfc-editor.org/rfc/rfc3461
[3463]: https://www.rfc-editor.org/rfc/rfc3463
[4616]: https://www.rfc-editor.org/rfc/rfc4616
[4954]: https://www.rfc-editor.org/rfc/rfc4954
[5321]: https://www.rfc-editor.org/rfc/rfc5321
[7628]: https://www.rfc-editor.org/rfc/rfc7628
[7677]: https://www.rfc-editor.org/rfc/rfc7677

## Examples

`io-smtp` can be consumed three ways, depending on how much of the I/O stack you want to own. Each mode is gated by cargo features.

Whichever mode you pick, every coroutine exposes `resume(arg: Option<&[u8]>)` returning a result enum with four shapes:

- `WantsRead`: caller reads more bytes from the socket and feeds them back on the next call. Pass `Some(&[])` to signal EOF.
- `WantsWrite(Vec<u8>)`: caller writes these bytes to the socket. The next call typically passes `None`.
- `Ok { … }` (or unit `Ok`): terminal success.
- `Err(…)`: terminal failure.

### As a no-std coroutine library

No features required: works in `#![no_std]`, no sockets, no async runtime. You own the loop and the bytes; the library only produces command bytes and consumes server responses.

Read the SMTP greeting against a blocking TCP socket (the same shape works under async, fuzzing, or in-memory replay):

```rust,ignore
use std::{io::Read, net::TcpStream};

use io_smtp::rfc5321::greeting::*;

let mut stream = TcpStream::connect("smtp.example.com:25").unwrap();
let mut buf = [0u8; 4 * 1024];

let mut coroutine = GetSmtpGreeting::new();
let mut arg: Option<&[u8]> = None;

let greeting = loop {
    match coroutine.resume(arg.take()) {
        GetSmtpGreetingResult::Ok { greeting, .. } => break greeting,
        GetSmtpGreetingResult::WantsRead => {
            let n = stream.read(&mut buf).unwrap();
            arg = Some(&buf[..n]);
        }
        GetSmtpGreetingResult::Err(err) => panic!("{err}"),
    }
};

println!("{greeting:?}");
```

Drive a multi-step command (EHLO) the same way:

```rust,ignore
use std::{io::{Read, Write}, net::TcpStream};

use io_smtp::rfc5321::{
    ehlo::*,
    types::{domain::Domain, ehlo_domain::EhloDomain},
};

# let mut stream = TcpStream::connect("smtp.example.com:25").unwrap();
# let mut buf = [0u8; 4 * 1024];
let domain: EhloDomain<'_> = Domain::parse(b"localhost").unwrap().into();
let mut coroutine = SmtpEhlo::new(domain);
let mut arg: Option<&[u8]> = None;

let capabilities = loop {
    match coroutine.resume(arg.take()) {
        SmtpEhloResult::Ok { capabilities, .. } => break capabilities,
        SmtpEhloResult::WantsRead => {
            let n = stream.read(&mut buf).unwrap();
            arg = Some(&buf[..n]);
        }
        SmtpEhloResult::WantsWrite(bytes) => {
            stream.write_all(&bytes).unwrap();
            arg = None;
        }
        SmtpEhloResult::Err(err) => panic!("{err}"),
    }
};

for line in capabilities {
    println!("{line}");
}
```

### As a light std client (BYO stream)

Enable the `client` feature. `SmtpClientStd::new(stream)` wraps any blocking `Read + Write` and exposes one method per SMTP command. You still open the TCP socket, run TLS / STARTTLS yourself, and hand over a ready-to-talk stream; the client takes it from there.

```toml,ignore
[dependencies]
io-smtp = { version = "0.0.1", default-features = false, features = ["client"] }
```

```rust,ignore
use std::net::TcpStream;

use io_smtp::{
    client::SmtpClientStd,
    rfc5321::types::{domain::Domain, ehlo_domain::EhloDomain},
};

let stream = TcpStream::connect("smtp.example.com:25")?;
let mut client = SmtpClientStd::new(stream);

let (greeting, _) = client.greeting()?;
println!("server greeting: {greeting:?}");

let domain: EhloDomain<'_> = Domain::parse(b"localhost")?.into();
let (capabilities, _) = client.ehlo(domain)?;
for line in capabilities {
    println!("{line}");
}
```

### As a full std client (TCP + TLS)

Enable one of the TLS feature flags: `rustls-ring` (default), `rustls-aws`, or `native-tls`. `SmtpClientStd::connect(url, tls, starttls, domain, sasl)` opens `smtp://` (plain TCP) or `smtps://` (implicit TLS) via [pimalaya/stream](https://github.com/pimalaya/stream), reads the greeting, sends the initial EHLO, drives the optional STARTTLS upgrade plus a fresh EHLO over TLS, then runs the chosen SASL mechanism, returning a ready-to-use authenticated client.

```toml,ignore
[dependencies]
io-smtp = "0.0.1" # rustls-ring is enabled by default
```

```rust,ignore
use io_smtp::{
    client::SmtpClientStd,
    rfc5321::types::{
        domain::Domain, ehlo_domain::EhloDomain,
        forward_path::ForwardPath, reverse_path::ReversePath,
    },
};
use pimalaya_stream::{sasl::SaslPlain, tls::Tls};
use secrecy::SecretString;
use url::Url;

let url = Url::parse("smtps://smtp.example.com")?;
let tls = Tls::default();
let domain: EhloDomain<'_> = Domain::parse(b"localhost")?.into();
let sasl = SaslPlain {
    authzid: None,
    authcid: "alice@example.com".into(),
    passwd: SecretString::from("hunter2".to_owned()),
};

let mut client = SmtpClientStd::connect(&url, &tls, false, domain, Some(sasl))?;

// session is already authenticated; send a message
let from: ReversePath = "<alice@example.com>".parse()?;
let to: ForwardPath = "<bob@example.com>".parse()?;
let message =
    b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello!".to_vec();
client.send(from, [to], message)?;
client.quit()?;
```

The `sasl` argument is `Option<impl Into<Sasl>>`, so any of the per-mechanism structs (`SaslLogin`, `SaslPlain`, `SaslOauthbearer`, `SaslScramSha256` behind the `scram` feature) can be passed in `Some(...)` directly without wrapping in a `Sasl` variant. `SaslAnonymous` and `SaslXoauth2` are not supported by SMTP.

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

- 2022 → 2023: [NGI Assure](https://nlnet.nl/project/Himalaya/)
- 2023 → 2024: [NGI Zero Entrust](https://nlnet.nl/project/Pimalaya/)
- 2024 → 2026: [NGI Zero Core](https://nlnet.nl/project/Pimalaya-PIM/)
- *2027 in preparation…*

If you appreciate the project, feel free to donate using one of the following providers:

[![GitHub](https://img.shields.io/badge/-GitHub%20Sponsors-fafbfc?logo=GitHub%20Sponsors)](https://github.com/sponsors/soywod)
[![Ko-fi](https://img.shields.io/badge/-Ko--fi-ff5e5a?logo=Ko-fi&logoColor=ffffff)](https://ko-fi.com/soywod)
[![Buy Me a Coffee](https://img.shields.io/badge/-Buy%20Me%20a%20Coffee-ffdd00?logo=Buy%20Me%20A%20Coffee&logoColor=000000)](https://www.buymeacoffee.com/soywod)
[![Liberapay](https://img.shields.io/badge/-Liberapay-f6c915?logo=Liberapay&logoColor=222222)](https://liberapay.com/soywod)
[![thanks.dev](https://img.shields.io/badge/-thanks.dev-000000?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQuMDk3IiBoZWlnaHQ9IjE3LjU5NyIgY2xhc3M9InctMzYgbWwtMiBsZzpteC0wIHByaW50Om14LTAgcHJpbnQ6aW52ZXJ0IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik05Ljc4MyAxNy41OTdINy4zOThjLTEuMTY4IDAtMi4wOTItLjI5Ny0yLjc3My0uODktLjY4LS41OTMtMS4wMi0xLjQ2Mi0xLjAyLTIuNjA2di0xLjM0NmMwLTEuMDE4LS4yMjctMS43NS0uNjc4LTIuMTk1LS40NTItLjQ0Ni0xLjIzMi0uNjY5LTIuMzQtLjY2OUgwVjcuNzA1aC41ODdjMS4xMDggMCAxLjg4OC0uMjIyIDIuMzQtLjY2OC40NTEtLjQ0Ni42NzctMS4xNzcuNjc3LTIuMTk1VjMuNDk2YzAtMS4xNDQuMzQtMi4wMTMgMS4wMjEtMi42MDZDNS4zMDUuMjk3IDYuMjMgMCA3LjM5OCAwaDIuMzg1djEuOTg3aC0uOTg1Yy0uMzYxIDAtLjY4OC4wMjctLjk4LjA4MmExLjcxOSAxLjcxOSAwIDAgMC0uNzM2LjMwN2MtLjIwNS4xNTYtLjM1OC4zODQtLjQ2LjY4Mi0uMTAzLjI5OC0uMTU0LjY4Mi0uMTU0IDEuMTUxVjUuMjNjMCAuODY3LS4yNDkgMS41ODYtLjc0NSAyLjE1NS0uNDk3LjU2OS0xLjE1OCAxLjAwNC0xLjk4MyAxLjMwNXYuMjE3Yy44MjUuMyAxLjQ4Ni43MzYgMS45ODMgMS4zMDUuNDk2LjU3Ljc0NSAxLjI4Ny43NDUgMi4xNTR2MS4wMjFjMCAuNDcuMDUxLjg1NC4xNTMgMS4xNTIuMTAzLjI5OC4yNTYuNTI1LjQ2MS42ODIuMTkzLjE1Ny40MzcuMjYuNzMyLjMxMi4yOTUuMDUuNjIzLjA3Ni45ODQuMDc2aC45ODVabTE0LjMxNC03LjcwNmgtLjU4OGMtMS4xMDggMC0xLjg4OC4yMjMtMi4zNC42NjktLjQ1LjQ0Ni0uNjc3IDEuMTc3LS42NzcgMi4xOTVWMTQuMWMwIDEuMTQ0LS4zNCAyLjAxMy0xLjAyIDIuNjA2LS42OC41OTMtMS42MDUuODktMi43NzQuODloLTIuMzg0di0xLjk4OGguOTg0Yy4zNjIgMCAuNjg4LS4wMjcuOTgtLjA4LjI5Mi0uMDU1LjUzOC0uMTU3LjczNy0uMzA4LjIwNC0uMTU3LjM1OC0uMzg0LjQ2LS42ODIuMTAzLS4yOTguMTU0LS42ODIuMTU0LTEuMTUydi0xLjAyYzAtLjg2OC4yNDgtMS41ODYuNzQ1LTIuMTU1LjQ5Ny0uNTcgMS4xNTgtMS4wMDQgMS45ODMtMS4zMDV2LS4yMTdjLS44MjUtLjMwMS0xLjQ4Ni0uNzM2LTEuOTgzLTEuMzA1LS40OTctLjU3LS43NDUtMS4yODgtLjc0NS0yLjE1NXYtMS4wMmMwLS40Ny0uMDUxLS44NTQtLjE1NC0xLjE1Mi0uMTAyLS4yOTgtLjI1Ni0uNTI2LS40Ni0uNjgyYTEuNzE5IDEuNzE5IDAgMCAwLS43MzctLjMwNyA1LjM5NSA1LjM5NSAwIDAgMC0uOTgtLjA4MmgtLjk4NFYwaDIuMzg0YzEuMTY5IDAgMi4wOTMuMjk3IDIuNzc0Ljg5LjY4LjU5MyAxLjAyIDEuNDYyIDEuMDIgMi42MDZ2MS4zNDZjMCAxLjAxOC4yMjYgMS43NS42NzggMi4xOTUuNDUxLjQ0NiAxLjIzMS42NjggMi4zNC42NjhoLjU4N3oiIGZpbGw9IiNmZmYiLz48L3N2Zz4=)](https://thanks.dev/soywod)
[![PayPal](https://img.shields.io/badge/-PayPal-0079c1?logo=PayPal&logoColor=ffffff)](https://www.paypal.com/paypalme/soywod)
