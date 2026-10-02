---
cairn: delta
change: microsoft-oauth-live-suite
---

# Delta

## ADDED Requirements

## MODIFIED Requirements

### Requirement: The OAuth mechanisms are verified live
OAUTHBEARER and XOAUTH2 SHALL each be exercised by an ignored live test against Gmail's submission service, authenticating as a Workspace test user with a token the test mints from a service account key, so the suite runs unattended. The tests SHALL go through `SmtpClientStd::connect`, one over implicit TLS and one over STARTTLS, so the session layer and the upgrade are verified against a real server too. XOAUTH2 SHALL also be exercised against Exchange Online's submission service, over STARTTLS, acting on a test mailbox with an app-only token the test mints through the client credentials grant; Exchange advertises no OAUTHBEARER. Each test message SHALL go to the authenticated mailbox only.

## REMOVED Requirements
