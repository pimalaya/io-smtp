---
cairn: change
id: exchange-live-gaps
status: landed
created: 2026-10-02
---

# The XOAUTH2 failure and the one-call send verified live

## Why

A live coverage pass against Exchange Online left two paths unexercised: the XOAUTH2 failure branch (the server's error challenge and the empty answer it wants, about two thirds of src/sasl/auth_xoauth2.rs) and `SmtpMessageSend` (src/message.rs, 0%), the one-call MAIL FROM, RCPT TO and DATA exchange himalaya sends through.

## What

- tests/outlook.rs: `oauth_xoauth2_rejected` connects with a forged token and expects the connection to fail at the XOAUTH2 step; `oauth_message_send` sends one message through `SmtpClient::send`, a `Bcc:` header included.
- The message goes to the mailbox itself, under the subject the suite already sweeps.

No library code changes.
