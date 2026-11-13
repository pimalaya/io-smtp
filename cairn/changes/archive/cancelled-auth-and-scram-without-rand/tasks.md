---
cairn: tasks
change: cancelled-auth-and-scram-without-rand
---

# Tasks

- [x] Reproduce: each mechanism completes right after a 334 it cannot answer (eight failing tests)
- [x] Add the cancel state to the six mechanism coroutines
- [x] Record the `rand` feature tree of a `scram` only build, before and after
- [x] Move `rand` from `scram` to the TLS features, without default features
- [x] Require `client` for the `tokio_session` example
- [x] Run the `reply` fuzz target on the LOGIN and SCRAM coroutines
- [x] CHANGELOG, CONTRIBUTING, spec, log
