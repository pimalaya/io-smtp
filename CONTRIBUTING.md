# Contributing guide

Thank you for investing your time in contributing to I/O SMTP.

Whether you are a human or an AI agent, read these in order before touching the code:

1. the [Pimalaya README](https://github.com/pimalaya) for what the project is and how its repositories stack;
2. the [Pimalaya CONTRIBUTING](https://github.com/pimalaya/.github/blob/master/CONTRIBUTING.md) guide, which chains to the shared architecture and guidelines;
3. the inline header documentation, starting with src/lib.rs: it is the architecture document of this crate;
4. the docs/ folder for the development history and living plans.

Everything below documents only what differs from the Pimalaya standards.

## Feature matrix

On top of the standard layered checks, io-smtp gates the SCRAM-SHA-256 mechanism behind the scram feature (it pulls the hmac, pbkdf2, rand and sha2 crates), so build both sides of that gate too:

```sh
cargo build --no-default-features                    # coroutines only, no std leak
cargo build --no-default-features --features scram   # coroutines + SCRAM-SHA-256
cargo build --no-default-features --features client  # light client, no TLS deps
cargo build --release                                # full client (default TLS + scram)
```

## Provider tests

The tests folder ships ignored end-to-end tests against real servers: fastmail and gmail read credentials from environment variables (documented in each file's header), stalwart expects a local instance started with tests/stalwart.sh. Run one with cargo test --test followed by its name and -- --ignored.
