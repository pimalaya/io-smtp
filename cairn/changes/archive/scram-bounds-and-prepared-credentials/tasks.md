---
cairn: tasks
change: scram-bounds-and-prepared-credentials
---

# Tasks

- [x] Raise io-sasl to 0.2 in the manifest and in the fuzz manifest, refresh both lockfiles, one io-sasl in the graph
- [x] Hand `SaslScramOptions` to the mechanism from `SmtpAuthScramSha256Options::scram`
- [x] Carry the two bounds in `SmtpSessionOpenOptions` and in `auth_scram_sha256`
- [x] Test a count above the ceiling: cancelled, no key derived
- [x] Test the session options reaching the mechanism
- [x] Test a PLAIN password SASLprep alters, failing against io-sasl 0.1.1
- [x] Bound the iteration count in the `reply` fuzz target
- [x] CHANGELOG, spec, log
