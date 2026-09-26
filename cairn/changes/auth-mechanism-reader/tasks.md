---
cairn: tasks
change: auth-mechanism-reader
---

# Tasks

- [ ] Add `SmtpAuthCapability::available_mechanisms`, ordered most preferred first and LOGIN last.
- [ ] Gate the SCRAM-SHA-256 arm on the `scram` feature.
- [ ] Cover an unrecognised name, an empty AUTH line, the ordering, and both sides of the `scram` gate.
- [ ] CHANGELOG.md.
- [ ] Fold the delta into cairn/spec/auth.md and log it.
