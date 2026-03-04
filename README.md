# io-smtp

I/O-free SMTP client library.

This library provides I/O-free coroutines for managing SMTP streams. It is based on the [smtp-codec](https://github.com/pimalaya/smtp-codec) crate for protocol encoding/decoding.

## Features

- I/O-free coroutine-based design
- No runtime dependencies (works with any async/sync I/O)
- Full SMTP protocol support
- STARTTLS support
- AUTH PLAIN authentication

## Available Coroutines

- `greeting` - Read server greeting (220)
- `ehlo` - Send EHLO and receive capabilities
- `starttls` - Upgrade to TLS
- `authenticate_plain` - AUTH PLAIN authentication
- `mail` - MAIL FROM command
- `rcpt` - RCPT TO command
- `data` - DATA command with message body
- `noop` - NOOP command
- `rset` - RSET command
- `quit` - QUIT command

## Example

```rust
use io_smtp::{context::SmtpContext, coroutines::greeting::GetSmtpGreeting};

let context = SmtpContext::new();
let mut coroutine = GetSmtpGreeting::new(context);

loop {
    match coroutine.resume(io_result) {
        GetSmtpGreetingResult::Ok { context, greeting } => {
            // Connection established, server ready
            break;
        }
        GetSmtpGreetingResult::Io { io } => {
            // Perform I/O operation and feed result back
            io_result = Some(perform_io(&mut stream, io));
        }
        GetSmtpGreetingResult::Err { err, .. } => {
            panic!("Error: {err}");
        }
    }
}
```

## License

MIT
