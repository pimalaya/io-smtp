---
cairn: log
change: gmail-xoauth2-rejected
landed: 2026-10-02
---

# The XOAUTH2 error challenge verified live against Gmail

tests/gmail.rs gains `oauth_xoauth2_rejected`: a bogus token for a made-up address, over implicit TLS, surfacing as `SmtpAuthXoauth2Error::RejectedWithError` with Google's `"status":"400"` JSON. Green live, no credentials needed; clippy clean.

Tarpaulin on that test alone covers the challenge branch of src/sasl/auth_xoauth2.rs (44/100 lines): the `334` arm, `parse_challenge`, the empty answer, the `535` mapped through the mechanism. Exchange Online never reached it: it refuses a bad token with a 535 straight away.

No library change. The [auth](../spec/auth.md) capability moved: ADDED "The XOAUTH2 error challenge is verified live", MODIFIED "A rejected token and a whole message are verified live" (the Exchange test no longer claims the challenge).
