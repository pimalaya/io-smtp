---
cairn: log
change: google-oauth-live-suite
landed: 2026-10-01
---

# OAuth mechanisms verified live against Gmail

The live suite gains `oauth_xoauth2` and `oauth_oauthbearer` (tests/gmail.rs) against `smtp.gmail.com:465`, authenticating as `google@pimalaya.org` with a token minted from the pimalaya.org service account (domain-wide delegation, scope `https://mail.google.com/`). The shared flow's `Auth` gains the two variants and threads host and port through for OAUTHBEARER. The app-password test stays.

Each run leaves one message in the subject's inbox; io-smtp does not depend on the Gmail API to delete it.

CI reads the `SMTP_GOOGLE_SERVICE_ACCOUNT_KEY` secret in the existing Gmail job. Trace logs checked: the SASL payload does not appear.

Verified: both green live, offline suite green, clippy clean on the test targets (one pre-existing `collapsible_if` in src/rfc7677/auth_scram_sha_256.rs under clippy 1.96, untouched).

No library change. The [auth](../spec/auth.md) capability moved: ADDED "The OAuth mechanisms are verified live".
