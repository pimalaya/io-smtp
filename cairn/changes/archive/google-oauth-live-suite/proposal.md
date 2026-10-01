---
cairn: change
id: google-oauth-live-suite
status: landed
created: 2026-10-01
---

# OAuth mechanisms verified live against Gmail

## Why

io-smtp frames OAUTHBEARER and XOAUTH2, but no live suite drives either: the Gmail test logs in with an app password over PLAIN. A token-shaped regression (framing, base64, the `%x01` error dance) would only surface in a consumer.

Pimalaya now owns a Workspace on pimalaya.org with a service account holding domain-wide delegation, so a test can mint its own token for `google@pimalaya.org` with no human and no expiry problem, in CI too.

## What

- tests/common.rs: `Auth` gains `Xoauth2` and `Oauthbearer`; the flow passes host and port through for OAUTHBEARER's `host`/`port` fields.
- tests/gmail.rs: two ignored tests, `oauth_xoauth2` and `oauth_oauthbearer`, against `smtp.gmail.com:465`. Token from `SMTP_GOOGLE_ACCESS_TOKEN`, or minted from `SMTP_GOOGLE_SERVICE_ACCOUNT_KEY{,_FILE}` acting as `SMTP_GOOGLE_SERVICE_ACCOUNT_SUBJECT` (default `google@pimalaya.org`), scope `https://mail.google.com/`. The app-password test stays.
- The message is sent to the subject itself and stays in that inbox: io-smtp does not depend on io-gmail to delete it. A Gmail filter or the io-gmail suite can sweep `subject:"io-smtp integration test"`.
- CI: the OAuth tests run in their own step at `RUST_LOG=debug`, reading the `SMTP_GOOGLE_SERVICE_ACCOUNT_KEY` secret.

No library code changes.
