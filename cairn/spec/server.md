---
cairn: spec
capability: server
status: current
---

# Server

The server side, behind the `server` feature: a command parser, a reply writer and one I/O-free session state machine for SMTP submission and LMTP. The crate stays no_std; the caller owns the socket, the TLS and the storage.

## Requirement: Command parser

`SmtpServerCommand::parse` SHALL read one command line without its CRLF: EHLO, HELO, LHLO, MAIL FROM (SIZE, BODY=7BIT|8BITMIME|BINARYMIME, SMTPUTF8, RET, ENVID, AUTH), RCPT TO (NOTIFY, ORCPT), DATA, RSET, NOOP, QUIT, VRFY, HELP, STARTTLS and AUTH. Verbs and parameter keywords SHALL be case-insensitive, `<>` SHALL be the null reverse path, a source route SHALL be accepted and dropped, the bare `<Postmaster>` recipient SHALL parse as `None`, addresses MAY hold UTF-8, and ENVID, ORCPT and AUTH= SHALL be xtext-decoded. An unknown verb, a known but unimplemented one (EXPN, BDAT, TURN, ...), a syntax error, an invalid address, an unknown parameter and an invalid or repeated one SHALL be told apart.

## Requirement: Reply writer

`SmtpServerReply` SHALL write `code-text` lines then `code text`, prefixing every line with its enhanced status code when the session advertises ENHANCEDSTATUSCODES, and SHALL turn a CR or LF inside a text into a space so a text cannot inject a reply.

## Requirement: Session

`SmtpServerSession::new(mode, config)` SHALL take its mode (SMTP or LMTP) and a config (hostname, size cap, recipient cap, line cap, error cap, advertised extensions, AUTH mechanisms, whether AUTH is required, whether AUTH needs TLS, whether TLS is active). `resume(SmtpServerArg)` SHALL return `SmtpCoroutineState<SmtpServerYield, Result<(), SmtpServerError>>`: `WantsRead`, `WantsWrite`, `WantsTlsUpgrade`, and the decisions `WantsAuth`, `WantsMailFrom`, `WantsRcptTo` and `WantsMessage`, answered with `Accept`, `Reply` (accepting when 2xx) or, for an LMTP message, `Replies` (one per accepted recipient, a missing one written as 451 4.3.0). The session SHALL complete `Ok` after QUIT, `Err(Eof)` on EOF, `Err(TooManyErrors)` after writing 421 4.7.0, and `Err(UnexpectedArg)` when resumed out of turn.

## Requirement: Pipelining

The session SHALL process every complete line in its buffer before asking for a read, writing the replies in command order, and SHALL flush its pending replies before asking for a TLS upgrade or completing.

## Requirement: Message data

DATA SHALL be dot-unstuffed and SHALL end only at `CRLF.CRLF`, found across any read boundary; a bare LF SHALL never end it. A message over the size cap SHALL be read to its end, then refused with 552 5.3.4 without reaching the caller. A message SHALL reach the caller only with at least one accepted recipient; DATA with none SHALL get 554 5.5.1.

## Requirement: Sequencing and limits

MAIL before a hello, a nested MAIL, RCPT or DATA without MAIL, and AUTH twice or inside a transaction SHALL get 503 5.5.1. MAIL without AUTH when AUTH is required SHALL get 530 5.7.0, and AUTH without TLS when it needs TLS 530 5.7.0, AUTH then being left out of the EHLO reply. A parameter of an unadvertised extension SHALL get 555 5.5.4, BINARYMIME 504 5.5.4, a declared SIZE over the cap 552 5.3.4, a UTF-8 address without SMTPUTF8 553 5.6.7, and a recipient over the cap 452 4.5.3. A command line over the line cap (AUTH lines being allowed 12288 bytes) SHALL get 500 5.5.2 once its end arrives. VRFY SHALL get 252. Failed commands SHALL be counted, and reaching the error cap SHALL write 421 4.7.0 and close.

## Requirement: STARTTLS

STARTTLS SHALL be honoured only when advertised and TLS is not active. After its 220 the session SHALL drop any byte already buffered, ask for the upgrade, then forget the hello, the identity and the transaction.

## Requirement: AUTH

AUTH SHALL run through `io_sasl::server::SaslServer`: an initial response `=` is empty, challenges go out as `334` plus base64, `*` cancels with 501, invalid base64 gets 501 5.5.2, an unknown mechanism 504 5.5.4. The caller verifies the credentials on `WantsAuth`; success writes 235 2.7.0, refusal the caller's reply or 535 5.7.8.
