---
cairn: delta
change: exchange-live-gaps
---

# Delta

## ADDED Requirements

### Requirement: A rejected token and a whole message are verified live
An ignored live test against Exchange Online SHALL connect with a token the server refuses and expect the failure at the XOAUTH2 step, so the error challenge is answered against a real server. Another SHALL send one message through `SmtpClient::send`, the one-call exchange a mail client uses, to the authenticated mailbox only.

## MODIFIED Requirements

## REMOVED Requirements
