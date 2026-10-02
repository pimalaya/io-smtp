---
cairn: delta
change: gmail-xoauth2-rejected
---

# Delta

## ADDED Requirements

### Requirement: The XOAUTH2 error challenge is verified live
An ignored live test against Gmail SHALL connect with a token the server refuses, for an address no account holds, and expect the failure to carry the JSON from the server's error challenge, so the challenge and the empty answer it wants are exercised against a real server. Exchange Online refuses without a challenge and cannot reach that branch.

## MODIFIED Requirements

### Requirement: A rejected token and a whole message are verified live
An ignored live test against Exchange Online SHALL connect with a token the server refuses and expect the failure at the XOAUTH2 step, refused outright with no error challenge. Another SHALL send one message through `SmtpClient::send`, the one-call exchange a mail client uses, to the authenticated mailbox only.

## REMOVED Requirements
