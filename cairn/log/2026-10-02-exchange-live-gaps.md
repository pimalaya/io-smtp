---
cairn: log
change: exchange-live-gaps
landed: 2026-10-02
---

# The XOAUTH2 failure and the one-call send verified live

tests/outlook.rs gains `oauth_xoauth2_rejected`, a forged token refused by Exchange Online and surfacing as the XOAUTH2 step's failure, and `oauth_message_send`, one message through `SmtpClient::send` (`SmtpMessageSend`), a `Bcc:` header included. Both green live; clippy clean.

They close the two gaps a live coverage pass against Exchange showed: the XOAUTH2 failure branch and src/message.rs, which no live test reached.

No library change. The [auth](../spec/auth.md) capability moved: ADDED "A rejected token and a whole message are verified live".
