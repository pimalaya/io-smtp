---
cairn: change
id: gmail-xoauth2-rejected
status: landed
created: 2026-10-02
---

# The XOAUTH2 error challenge verified live against Gmail

## Why

`exchange-live-gaps` added a rejected-token test against Exchange Online, but Exchange refuses a bad token outright with a 535: it never sends the error challenge, so the branch it was meant to cover (the `334` carrying the JSON, the empty answer, the `RejectedWithError` mapping, about 60% of src/sasl/auth_xoauth2.rs) is still only reached offline. Gmail takes that branch, for any address, so a made-up one keeps failed sign-ins off the Workspace admin.

## What

- tests/gmail.rs: `oauth_xoauth2_rejected` connects to `smtps://smtp.gmail.com:465` (implicit TLS, the Exchange test covers STARTTLS) with a bogus token for a made-up address and expects `SmtpAuthXoauth2Error::RejectedWithError`, its payload holding Google's `"status":"400"`.
- CI runs the whole Gmail file, so it is picked up with no new secret.

No library code changes.
