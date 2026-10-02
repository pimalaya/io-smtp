---
cairn: log
change: microsoft-oauth-live-suite
landed: 2026-10-02
---

# XOAUTH2 verified live against Exchange Online

The live suite gains `oauth_xoauth2` (tests/outlook.rs) against `smtp.office365.com:587` over STARTTLS, through `SmtpClientStd::connect`, sending as `microsoft@pimalaya.onmicrosoft.com` with an app-only token minted through the client credentials grant (app "Pimalaya live tests", `SMTP.SendAsApp`, scope `https://outlook.office365.com/.default`). Exchange advertises `AUTH LOGIN XOAUTH2` only, so there is no OAUTHBEARER test.

Each run leaves one message in that inbox; io-smtp does not depend on Graph to delete it.

CI: an `outlook-tests` job at `RUST_LOG=debug`, reading the `MICROSOFT_TENANT_ID`, `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET` organisation secrets. Debug logs checked: neither the token nor the SASL initial response appears.

Verified: green live, delivery confirmed in the inbox through Graph, clippy clean on the test target (the pre-existing `collapsible_if` in src/rfc7677/auth_scram_sha_256.rs still stands, untouched).

No library change. The [auth](../spec/auth.md) capability moved: MODIFIED "The OAuth mechanisms are verified live".
