---
cairn: change
id: microsoft-oauth-live-suite
status: landed
created: 2026-10-02
---

# XOAUTH2 verified live against Exchange Online

## Why

The OAuth mechanisms are verified live against Gmail only. Exchange Online is the other submission service most users reach with a token, and it differs where a regression would hide: it offers STARTTLS on 587 only, advertises `AUTH LOGIN XOAUTH2` and nothing else, and authenticates an app-only token against the mailbox the SASL username names.

Pimalaya now owns an Exchange Online tenant with a test mailbox and an app registration allowed to send as it (`SMTP.SendAsApp`), so a test can mint its own token with no human, in CI too.

## What

- tests/outlook.rs: one ignored test, `oauth_xoauth2`, against `smtp.office365.com:587` over STARTTLS, through `SmtpClientStd::connect`. Token from `SMTP_MICROSOFT_ACCESS_TOKEN`, or minted through the client credentials grant from `SMTP_MICROSOFT_TENANT_ID`, `SMTP_MICROSOFT_CLIENT_ID` and `SMTP_MICROSOFT_CLIENT_SECRET`, scope `https://outlook.office365.com/.default`, acting on `SMTP_MICROSOFT_USER` (default `microsoft@pimalaya.onmicrosoft.com`).
- No OAUTHBEARER test: Exchange does not advertise it.
- The message goes to the mailbox itself and stays there, as with Gmail; the io-msgraph suite or an Outlook rule can sweep `io-smtp integration test`.
- CI: an `outlook-tests` job at `RUST_LOG=debug`, reading the `MICROSOFT_*` organisation secrets.

No library code changes.
