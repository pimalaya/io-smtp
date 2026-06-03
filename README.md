# I/O SMTP [![Documentation](https://img.shields.io/docsrs/io-smtp?style=flat&logo=docs.rs&logoColor=white)](https://docs.rs/io-smtp/latest/io_smtp) [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

SMTP client library, written in Rust

This library is composed of 3 feature-gated layers:

- Low-level **I/O-free** coroutines: these `no_std`-compatible state machines contain the whole SMTP logic and can be used anywhere
- Mid-level **light client**: a standard, blocking SMTP client using a `Stream: Read + Write`
- High-level **full client**: light client + TCP connections and TLS negotiations handled for you

## Table of contents

- [Features](#features)
- [RFC coverage](#rfc-coverage)
- [Usage](#usage)
  - [Coroutine](#coroutine)
  - [Light client](#light-client)
  - [Full client](#full-client)
- [Examples](#examples)
- [AI disclosure](#ai-disclosure)
- [License](#license)
- [Social](#social)
- [Sponsoring](#sponsoring)

## Features

- **I/O-free** coroutines: `no_std` state machines; no sockets, no async runtime, no `std` required, drive against any blocking, async, or fuzz harness.
- Light standard, blocking client (requires `client` feature)
- Full standard, blocking client with **TLS** support:
  - [Rustls](https://crates.io/crates/rustls) with ring crypto (requires `rustls-ring` feature)
  - [Rustls](https://crates.io/crates/rustls) with aws crypto (requires `rustls-aws` feature)
  - [Native TLS](https://crates.io/crates/native-tls) (requires `native-tls` feature)
- **SASL mechanisms**:
  - `ANONYMOUS`, `LOGIN`, `PLAIN`, `XOAUTH2` and `OAUTHBEARER` built-in
  - `SCRAM-SHA-256` (requires `scram` feature)
- SMTP extensions: `STARTTLS`, `AUTH`, `SIZE`, `DSN`, `ENHANCEDSTATUSCODES` (see [RFC coverage](#rfc-coverage))

> [!TIP]
> I/O SMTP is written in [Rust](https://www.rust-lang.org/) and uses [cargo features](https://doc.rust-lang.org/cargo/reference/features.html) to gate backend support. The default feature set is declared in [Cargo.toml](./Cargo.toml) or on [docs.rs](https://docs.rs/crate/io-smtp/latest/features).

## RFC coverage

| Module                            | What it covers                                                                   |
|-----------------------------------|----------------------------------------------------------------------------------|
| [1870]                            | SIZE: maximum message size declaration                                           |
| [3207]                            | STARTTLS: upgrade a plain connection to TLS                                      |
| [3461]                            | DSN: `RET`, `ENVID`, `NOTIFY`, `ORCPT` ESMTP parameters for MAIL FROM / RCPT TO  |
| [3463]                            | Enhanced status codes: `EnhancedStatusCode` type                                 |
| [4954]                            | AUTH: SASL exchange protocol (verb, command, continuation data)                  |
| [5321]                            | SMTP: greeting, EHLO, HELO, MAIL FROM, RCPT TO, DATA, NOOP, RSET, QUIT           |
| [7628]                            | OAUTHBEARER: OAuth 2.0 bearer token SASL mechanism                               |
| [7677]                            | SCRAM-SHA-256: SASL SCRAM-SHA-256 mechanism (feature `scram`)                    |
| `sasl::auth_anonymous` ([4505])   | ANONYMOUS: SASL ANONYMOUS mechanism                                              |
| `sasl::auth_login`                | LOGIN: legacy de-facto AUTH mechanism (no RFC)                                   |
| `sasl::auth_plain` ([4616])       | PLAIN: SASL PLAIN authentication mechanism                                       |
| `sasl::auth_xoauth2`              | XOAUTH2: Google's pre-standard OAuth 2.0 SASL mechanism (no RFC)                 |

[1870]: https://www.rfc-editor.org/rfc/rfc1870
[3207]: https://www.rfc-editor.org/rfc/rfc3207
[3461]: https://www.rfc-editor.org/rfc/rfc3461
[3463]: https://www.rfc-editor.org/rfc/rfc3463
[4505]: https://www.rfc-editor.org/rfc/rfc4505
[4616]: https://www.rfc-editor.org/rfc/rfc4616
[4954]: https://www.rfc-editor.org/rfc/rfc4954
[5321]: https://www.rfc-editor.org/rfc/rfc5321
[7628]: https://www.rfc-editor.org/rfc/rfc7628
[7677]: https://www.rfc-editor.org/rfc/rfc7677

## Usage

I/O-SMTP can be consumed three ways, depending on how much of the I/O stack you want to own. Each mode is gated by cargo features.

Whichever mode you pick, every coroutine implements the `SmtpCoroutine` trait. Its `resume(Option<&[u8]>)` method returns `SmtpCoroutineState<Yield, Return>` with two shapes:

- `Yielded(Yield)`: intermediate progress. Every coroutine in this crate picks the standard `SmtpYield` (`WantsRead` / `WantsWrite(Vec<u8>)`); the caller reads or writes bytes accordingly. Pass `Some(&[])` to signal EOF on the next resume.
- `Complete(Return)`: terminal value. By convention `Return = Result<Output, Error>` where the ok arm carries the coroutine's final output and the error arm carries the cause. `SmtpStartTls` uses `Result<Vec<u8>, _>`: the ok arm's `Vec<u8>` carries any bytes the coroutine pre-read past the `220` reply (a non-empty value signals STARTTLS-injection per RFC 3207 §6).

Each higher-level coroutine internally delegates to a shared `SendSmtpCommand<Cmd>` base coroutine (in `crate::send`) that owns the serialise → write → read → parse loop.

### Coroutine

No features required: works in `#![no_std]`, no sockets, no async runtime. You own the loop and the bytes; the library only produces command bytes and consumes server responses.

Read the SMTP greeting against a blocking TCP socket (the same shape works under async, fuzzing, or in-memory replay):

```rust,no_run
use std::{io::Read, net::TcpStream};

use io_smtp::{coroutine::*, rfc5321::greeting::*};

let mut stream = TcpStream::connect("smtp.example.com:25").unwrap();
let mut buf = [0u8; 16 * 1024];

let mut coroutine = SmtpGreetingGet::new();
let mut arg: Option<&[u8]> = None;

let greeting = loop {
    match coroutine.resume(arg.take()) {
        SmtpCoroutineState::Complete(Ok(greeting)) => break greeting,
        SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
        SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
            let n = stream.read(&mut buf).unwrap();
            arg = Some(&buf[..n]);
        }
        SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(_)) => unreachable!(),
    }
};

println!("{greeting:?}");
```

Drive a multi-step command (EHLO) the same way:

```rust,no_run
use std::{borrow::Cow, io::{Read, Write}, net::TcpStream};

use io_smtp::{
    coroutine::*,
    rfc5321::{
        ehlo::*,
        types::{domain::Domain, ehlo_domain::EhloDomain},
    },
};

# let mut stream = TcpStream::connect("smtp.example.com:25").unwrap();
# let mut buf = [0u8; 16 * 1024];
let domain = EhloDomain::Domain(Domain(Cow::Borrowed("localhost")));
let mut coroutine = SmtpEhlo::new(domain);
let mut arg: Option<&[u8]> = None;

let capabilities = loop {
    match coroutine.resume(arg.take()) {
        SmtpCoroutineState::Complete(Ok(capabilities)) => break capabilities,
        SmtpCoroutineState::Complete(Err(err)) => panic!("{err}"),
        SmtpCoroutineState::Yielded(SmtpYield::WantsRead) => {
            let n = stream.read(&mut buf).unwrap();
            arg = Some(&buf[..n]);
        }
        SmtpCoroutineState::Yielded(SmtpYield::WantsWrite(bytes)) => {
            stream.write_all(&bytes).unwrap();
            arg = None;
        }
    }
};

for line in capabilities {
    println!("{line}");
}
```

### Light client

Enable the `client` feature. `SmtpClientStd::new(stream)` wraps any blocking `Read + Write` and exposes one method per SMTP command. You still open the TCP socket, run TLS / STARTTLS yourself, and hand over a ready-to-talk stream; the client takes it from there.

```toml,ignore
[dependencies]
io-smtp = { version = "0.0.1", default-features = false, features = ["client"] }
```

```rust,no_run
use std::{borrow::Cow, error::Error, net::TcpStream};

use io_smtp::{
    client::SmtpClientStd,
    rfc5321::types::{domain::Domain, ehlo_domain::EhloDomain},
};

fn main() -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect("smtp.example.com:25")?;
    let mut client = SmtpClientStd::new(stream);

    let greeting = client.greeting()?;
    println!("server greeting: {greeting:?}");

    let domain = EhloDomain::Domain(Domain(Cow::Borrowed("localhost")));
    let capabilities = client.ehlo(domain)?;
    for line in capabilities {
        println!("{line}");
    }

    Ok(())
}
```

### Full client

Enable one of the TLS feature flags: `rustls-ring` (default), `rustls-aws`, or `native-tls`. `SmtpClientStd::connect(url, tls, starttls, domain, sasl)` opens `smtp://` (plain TCP) or `smtps://` (implicit TLS) via [pimalaya/stream](https://github.com/pimalaya/stream), reads the greeting, sends the initial EHLO, drives the optional STARTTLS upgrade plus a fresh EHLO over TLS, then runs the chosen SASL mechanism, returning a ready-to-use authenticated client.

```toml,ignore
[dependencies]
io-smtp = { version = "0.0.1", default-features = false, features = ["rustls-ring"] }
```

```rust,no_run
use std::{borrow::Cow, error::Error};

use io_smtp::{
    client::SmtpClientStd,
    rfc5321::types::{
        domain::Domain, ehlo_domain::EhloDomain, forward_path::ForwardPath,
        local_part::LocalPart, mailbox::Mailbox, reverse_path::ReversePath,
    },
};
use pimalaya_stream::{sasl::SaslPlain, tls::Tls};
use secrecy::SecretString;
use url::Url;

fn main() -> Result<(), Box<dyn Error>> {
    let url = Url::parse("smtps://smtp.example.com")?;
    let tls = Tls::default();
    let domain = EhloDomain::Domain(Domain(Cow::Borrowed("localhost")));
    let sasl = SaslPlain {
        authzid: None,
        authcid: "alice@example.com".into(),
        passwd: SecretString::from("hunter2".to_owned()),
    };

    let mut client = SmtpClientStd::connect(&url, &tls, false, domain, Some(sasl))?;

    // session is already authenticated; send a message
    let alice = Mailbox {
        local_part: LocalPart(Cow::Borrowed("alice")),
        domain: EhloDomain::Domain(Domain(Cow::Borrowed("example.com"))),
    };
    let bob = Mailbox {
        local_part: LocalPart(Cow::Borrowed("bob")),
        domain: EhloDomain::Domain(Domain(Cow::Borrowed("example.com"))),
    };
    let message =
        b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\n\r\nHello!".to_vec();
    client.send(ReversePath::Mailbox(alice), [ForwardPath(bob)], message)?;
    client.quit()?;

    Ok(())
}
```

The `sasl` argument is `Option<impl Into<Sasl>>`, so any of the per-mechanism structs (`SaslLogin`, `SaslPlain`, `SaslOauthbearer`, `SaslScramSha256` behind the `scram` feature) can be passed in `Some(...)` directly without wrapping in a `Sasl` variant. `SaslAnonymous` and `SaslXoauth2` are not supported by SMTP.

## Examples

See complete examples at [./examples](https://github.com/pimalaya/io-smtp/blob/master/examples).

Have also a look at real-world projects built on top of this library:

- [Himalaya CLI](https://github.com/pimalaya/himalaya): CLI to manage emails
- [Himalaya TUI](https://github.com/pimalaya/himalaya-tui): TUI to manage emails
- [Sirup](https://github.com/pimalaya/sirup): CLI to spawn pre-authenticated IMAP/SMTP sessions and expose them via Unix sockets

## AI disclosure

This project is developed with AI assistance. This section documents how, so users and downstream packagers can make informed decisions.

- **Tools**: Claude Code (Anthropic), Opus 4.7, invoked locally with a persistent project-scoped memory and a small set of repo-specific rules.

- **Used for**: Refactors, mechanical multi-file edits, boilerplate (feature gates, error enums, derive macros, trait impls), test scaffolding, doc polish, exploratory design conversations.

- **Not used for**: Engineering, critical code, git manipulation (commit, merge, rebase…), real-world tests.

- **Verification**: Every AI-assisted change is read, compiled, tested, and formatted before commit (`nix develop --command cargo check / cargo test / cargo
fmt`). Behavioural correctness is verified against the relevant RFC or upstream spec, not assumed from the model output. Tests are never adjusted to fit
AI-generated code; the code is adjusted to fit correct behaviour.

- **Limitations**: AI models occasionally produce code that compiles and passes tests but is subtly wrong: off-by-one errors, missed edge cases, plausible
but nonexistent APIs, stale RFC references. The verification workflow catches most of this; it does not catch all of it. Bug reports are welcome and taken
seriously.

- **Last reviewed**: 03/06/2026

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
