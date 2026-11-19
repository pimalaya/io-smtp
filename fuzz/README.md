# Fuzzing

Coverage-guided fuzzing of the reply parsers with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer).

The `reply` target feeds arbitrary bytes, split into arbitrary reads and followed by EOF, to the greeting, EHLO, STARTTLS and command coroutines and to the LOGIN and SCRAM-SHA-256 exchanges, and the first read to the reply, greeting, EHLO and challenge parsers. Its oracle is that whatever a server sends, the coroutines answer or fail, never panic, never keep asking for reads after EOF, and never fail with `TooLarge` before the server sent more than `SMTP_MAX_REPLY_LEN` bytes. A reply reads as a greeting exactly when its code is 220 and as an EHLO response exactly when it is 250, and neither coroutine reports such a reply as refused.

The `server` target feeds arbitrary bytes, split into arbitrary reads and followed by EOF, to an SMTP or LMTP `SmtpServerSession` under fuzzed configurations, answering every decision with a fuzzed reply. Its oracle is that the session never panics, writes only reply lines (three digits then a space or a dash, CRLF-terminated, no CR inside) or AUTH challenges, never asks for a verdict on a message without recipients, and stays complete once it completed.

cargo-fuzz needs a nightly toolchain, which the `fuzz` devShell of the repository flake carries along with cargo-fuzz itself. Bound a run with the libFuzzer flags after the `--` separator:

```sh
nix develop .#fuzz --command bash -c "cargo fuzz run reply -- -max_total_time=60"
nix develop .#fuzz --command bash -c "cargo fuzz run server -- -max_total_time=60"
```

New interesting inputs land in `fuzz/corpus/reply/` and crashes in `fuzz/artifacts/reply/` (both gitignored), from where a crash is replayed with `cargo fuzz run reply fuzz/artifacts/reply/<file>`.
