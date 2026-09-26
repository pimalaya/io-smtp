---
cairn: log
change: blind-recipients-stay-blind
landed: 2026-09-26
---

# Blind recipients stay blind

Reported against Himalaya in pimalaya/himalaya#747, with a fix at the app level in pimalaya/himalaya#761 by @gianlucamazza. Every Pimalaya client derived its forward paths from `To`, `Cc` and `Bcc` and then handed the message to `DATA` unchanged, so each recipient could read the blind-copied addresses. The removal moved down here so every consumer of `SmtpMessageSend` gets it.

**`SmtpMessageSendOptions`** (message.rs) is a new last argument of `SmtpMessageSend::new` and of the `send` method of `SmtpClient` and `SmtpClientAsync`. Its one field, `keep_bcc`, defaults to false, so removing is the default and keeping is the opt-in, for a caller that sets its own envelope and wants its bytes verbatim.

**The removal** runs on the message before dot-stuffing. It walks the header section line by line, drops each `Bcc` field and its folded lines, and copies the rest from the first empty line on. It is byte-preserving on purpose: re-serializing a parsed message would rewrite encodings and folding, and could break a signature already over it.

**Breaking**: the extra argument changes `SmtpMessageSend::new` and both `send` methods.

Verified: 105 unit tests green, five new ones over the removal (four ported from #761) and the transmitted `DATA` with and without `keep_bcc`. Clippy clean on the touched files, and both sides of the `client` gate build.

Spec updated: `submission` (new capability, ADDED: "Blind recipients stay blind").
