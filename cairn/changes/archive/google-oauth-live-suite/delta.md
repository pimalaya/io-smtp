---
cairn: change
change: google-oauth-live-suite
---

# Delta

## ADDED Requirements

### Requirement: The OAuth mechanisms are verified live
OAUTHBEARER and XOAUTH2 SHALL each be exercised by an ignored live test against Gmail's submission service, authenticating as a Workspace test user with a token the test mints from a service account key, so the suite runs unattended. The test message SHALL go to that user only.
