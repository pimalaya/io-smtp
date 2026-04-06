//! Functions that may come in handy.

use alloc::{borrow::Cow, string::String, vec::Vec};

/// Converts bytes into a ready-to-be-printed form.
pub fn escape_byte_string(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();

    bytes
        .iter()
        .map(|byte| match byte {
            0x00..=0x08 => format!("\\x{byte:02x}"),
            0x09 => String::from("\\t"),
            0x0A => String::from("\\n"),
            0x0B => format!("\\x{byte:02x}"),
            0x0C => format!("\\x{byte:02x}"),
            0x0D => String::from("\\r"),
            0x0e..=0x1f => format!("\\x{byte:02x}"),
            0x20..=0x21 => format!("{}", *byte as char),
            0x22 => String::from("\\\""),
            0x23..=0x5B => format!("{}", *byte as char),
            0x5C => String::from("\\\\"),
            0x5D..=0x7E => format!("{}", *byte as char),
            0x7f => format!("\\x{byte:02x}"),
            0x80..=0xff => format!("\\x{byte:02x}"),
        })
        .collect::<Vec<String>>()
        .join("")
}

pub mod indicators {
    //! Character class indicators for SMTP (RFC 5321).

    /// Any 7-bit US-ASCII character, excluding NUL
    ///
    /// CHAR = %x01-7F
    #[inline]
    pub fn is_char(byte: u8) -> bool {
        matches!(byte, 0x01..=0x7f)
    }

    /// Controls
    ///
    /// CTL = %x00-1F / %x7F
    #[inline]
    pub fn is_ctl(byte: u8) -> bool {
        matches!(byte, 0x00..=0x1f | 0x7f)
    }

    /// SMTP atext characters (RFC 5321/5322)
    ///
    /// ```abnf
    /// atext = ALPHA / DIGIT /
    ///         "!" / "#" / "$" / "%" / "&" / "'" / "*" /
    ///         "+" / "-" / "/" / "=" / "?" / "^" / "_" /
    ///         "`" / "{" / "|" / "}" / "~"
    /// ```
    #[inline]
    pub fn is_atext(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'/'
                    | b'='
                    | b'?'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'{'
                    | b'|'
                    | b'}'
                    | b'~'
            )
    }

    /// SMTP qtext characters (RFC 5321)
    ///
    /// ```abnf
    /// qtext = %d32-33 / %d35-91 / %d93-126  ; printable except \ and "
    /// ```
    #[inline]
    pub fn is_qtext(byte: u8) -> bool {
        matches!(byte, 32..=33 | 35..=91 | 93..=126)
    }

    /// Text string characters for SMTP response text
    ///
    /// ```abnf
    /// textstring = 1*(%d09 / %d32-126)  ; HT, SP, Printable US-ASCII
    /// ```
    #[inline]
    pub fn is_text_char(byte: u8) -> bool {
        byte == 0x09 || matches!(byte, 0x20..=0x7e)
    }

    /// Let-dig: alphanumeric character (RFC 5321)
    ///
    /// ```abnf
    /// Let-dig = ALPHA / DIGIT
    /// ```
    #[inline]
    pub fn is_let_dig(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
    }

    /// Ldh-str character: alphanumeric or hyphen (RFC 5321)
    ///
    /// ```abnf
    /// Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig
    /// ```
    #[inline]
    pub fn is_ldh_str_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'-'
    }

    /// ESMTP keyword character (RFC 5321)
    ///
    /// ```abnf
    /// esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
    /// ```
    #[inline]
    pub fn is_esmtp_keyword_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'-'
    }

    /// ESMTP value character (RFC 5321)
    ///
    /// ```abnf
    /// esmtp-value = 1*(%d33-60 / %d62-126)  ; any CHAR excluding "=", SP, and CTL
    /// ```
    #[inline]
    pub fn is_esmtp_value_char(byte: u8) -> bool {
        matches!(byte, 33..=60 | 62..=126)
    }

    /// Reply code digit (RFC 5321)
    #[inline]
    pub fn is_digit(byte: u8) -> bool {
        byte.is_ascii_digit()
    }

    /// Dcontent character for address literals (RFC 5321)
    ///
    /// ```abnf
    /// dcontent = %d33-90 / %d94-126  ; printable except [ \ ]
    /// ```
    #[inline]
    pub fn is_dcontent(byte: u8) -> bool {
        matches!(byte, 33..=90 | 94..=126)
    }
}

pub fn escape_quoted(unescaped: &str) -> Cow<'_, str> {
    let mut escaped = Cow::Borrowed(unescaped);

    if escaped.contains('\\') {
        escaped = Cow::Owned(escaped.replace('\\', "\\\\"));
    }

    if escaped.contains('\"') {
        escaped = Cow::Owned(escaped.replace('"', "\\\""));
    }

    escaped
}

pub fn unescape_quoted(escaped: &str) -> Cow<'_, str> {
    let mut unescaped = Cow::Borrowed(escaped);

    if unescaped.contains("\\\\") {
        unescaped = Cow::Owned(unescaped.replace("\\\\", "\\"));
    }

    if unescaped.contains("\\\"") {
        unescaped = Cow::Owned(unescaped.replace("\\\"", "\""));
    }

    unescaped
}

pub mod parsers {
    //! Chumsky parser helpers for SMTP byte-slice parsing.

    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };
    use core::str::from_utf8;

    use chumsky::{
        error::{RichPattern, RichReason},
        extra,
        prelude::*,
    };

    pub type Extra<'a> = extra::Err<Rich<'a, u8>>;

    /// Format a single byte as a printable character or hex escape.
    fn fmt_byte(b: u8) -> String {
        if b.is_ascii_graphic() || b == b' ' {
            format!("'{}'", b as char)
        } else {
            format!("0x{b:02x}")
        }
    }

    /// Format a RichPattern for display in error messages.
    fn fmt_pattern(p: &RichPattern<'_, u8>) -> String {
        match p {
            RichPattern::Token(t) => fmt_byte(**t),
            RichPattern::Label(l) => (*l).to_string(),
            RichPattern::EndOfInput => "end of input".to_string(),
            RichPattern::Identifier(s) => s.clone(),
            RichPattern::Any => "any byte".to_string(),
            RichPattern::SomethingElse => "something else".to_string(),
        }
    }

    /// Format chumsky parse errors into a human-readable string.
    ///
    /// Displays bytes as printable characters where possible, includes byte
    /// positions and label context chains added by `.labelled("...")`.
    pub fn format_rich_errors(errs: Vec<Rich<'_, u8>>) -> String {
        errs.iter()
            .map(|e| {
                let span_start = e.span().start;
                let contexts: Vec<String> = e.contexts().map(|(p, _)| fmt_pattern(p)).collect();

                let msg = match e.reason() {
                    RichReason::Custom(msg) => format!("{msg}"),
                    RichReason::ExpectedFound { expected, found } => {
                        let found_str = found
                            .as_ref()
                            .map(|b| fmt_byte(**b))
                            .unwrap_or_else(|| "end of input".to_string());

                        let exp_strs: Vec<String> =
                            expected.iter().map(|p| fmt_pattern(p)).collect();

                        if exp_strs.is_empty() {
                            format!("unexpected {found_str}")
                        } else {
                            format!("expected {}, found {found_str}", exp_strs.join(" or "))
                        }
                    }
                };

                if contexts.is_empty() {
                    format!("{msg} at byte {span_start}")
                } else {
                    format!(
                        "{msg} at byte {span_start} while parsing {}",
                        contexts.join(" > ")
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Match `\r\n`.
    pub fn crlf<'src>() -> impl Parser<'src, &'src [u8], (), Extra<'src>> + Clone {
        just(b'\r').then(just(b'\n')).ignored()
    }

    /// Match a single space.
    pub fn sp<'src>() -> impl Parser<'src, &'src [u8], (), Extra<'src>> + Clone {
        just(b' ').ignored()
    }

    /// Match the exact bytes in `kw` (case-insensitive ASCII).
    ///
    /// Prefer `just(kw)` for case-sensitive matches — chumsky generates better
    /// `ExpectedFound` errors automatically. Use this only when case-folding is needed.
    pub fn tag_no_case<'src>(
        kw: &'static [u8],
    ) -> impl Parser<'src, &'src [u8], (), Extra<'src>> + Clone {
        any()
            .repeated()
            .at_least(kw.len())
            .at_most(kw.len())
            .to_slice()
            .try_map(move |bytes: &[u8], span| {
                if bytes.eq_ignore_ascii_case(kw) {
                    Ok(())
                } else {
                    let expected = from_utf8(kw).unwrap_or("<binary>").to_uppercase();
                    let found = from_utf8(bytes)
                        .map(|s| format!("{s:?}"))
                        .unwrap_or_else(|_| format!("{bytes:?}"));
                    Err(Rich::custom(
                        span,
                        format!("expected {expected:?} (case-insensitive), found {found}"),
                    ))
                }
            })
    }

    /// Match zero or more bytes satisfying `f`, return the matched slice.
    pub fn take_while<'src, F>(
        f: F,
    ) -> impl Parser<'src, &'src [u8], &'src [u8], Extra<'src>> + Clone
    where
        F: Fn(&u8) -> bool + Clone + 'src,
    {
        any().filter(move |b| f(b)).repeated().to_slice()
    }

    /// Match one or more bytes satisfying `f`, return the matched slice.
    pub fn take_while1<'src, F>(
        f: F,
    ) -> impl Parser<'src, &'src [u8], &'src [u8], Extra<'src>> + Clone
    where
        F: Fn(&u8) -> bool + Clone + 'src,
    {
        any()
            .filter(move |b| f(b))
            .repeated()
            .at_least(1)
            .to_slice()
    }

    #[cfg(test)]
    mod tests {
        use alloc::string::String;
        use chumsky::prelude::*;

        use super::{Extra, format_rich_errors, tag_no_case};

        fn parse_errors<'src, P, O>(parser: P, input: &'src [u8]) -> String
        where
            P: Parser<'src, &'src [u8], O, Extra<'src>>,
        {
            format_rich_errors(parser.parse(input).into_errors())
        }

        #[test]
        fn expected_found_shows_printable_chars() {
            // just(b'A') expects 'A', gets 'B'
            let msg = parse_errors(just(b'A'), b"B");
            assert!(msg.contains("'A'"), "expected char literal in: {msg}");
            assert!(msg.contains("'B'"), "found char literal in: {msg}");
        }

        #[test]
        fn expected_found_shows_hex_for_non_printable() {
            // just(b'\x01') expects 0x01, gets 0x02
            let msg = parse_errors(just(b'\x01'), b"\x02");
            assert!(msg.contains("0x01"), "expected hex in: {msg}");
            assert!(msg.contains("0x02"), "found hex in: {msg}");
        }

        #[test]
        fn expected_found_shows_end_of_input() {
            // any() on empty input → "found end of input"
            let msg = parse_errors(any(), b"");
            assert!(msg.contains("end of input"), "should mention EOF in: {msg}");
        }

        #[test]
        fn byte_position_is_included() {
            // just(b"AB") on b"AC" fails at byte 1 (the 'C')
            let msg = parse_errors(just(b"AB" as &[u8]), b"AC");
            assert!(
                msg.contains("byte"),
                "should include byte position in: {msg}"
            );
        }

        #[test]
        fn custom_error_message_is_preserved() {
            let parser = any().try_map(|b: u8, span| {
                if b == b'X' {
                    Ok(b)
                } else {
                    Err(Rich::custom(span, "only 'X' is allowed here"))
                }
            });
            let msg = parse_errors(parser, b"Y");
            assert!(
                msg.contains("only 'X' is allowed here"),
                "custom msg in: {msg}"
            );
        }

        #[test]
        fn label_context_appears_in_error() {
            let labelled = just(b'A').labelled("my-token");
            let msg = parse_errors(labelled, b"B");
            assert!(msg.contains("my-token"), "label context in: {msg}");
        }

        #[test]
        fn tag_no_case_shows_expected_and_found() {
            let msg = parse_errors(tag_no_case(b"EHLO"), b"QUIT");
            assert!(msg.contains("EHLO"), "expected keyword in: {msg}");
            assert!(msg.contains("QUIT"), "found value in: {msg}");
        }

        #[test]
        fn multiple_errors_are_joined_with_semicolon() {
            // Use choice with two alternatives both failing — produces two errors
            let parser = choice((just(b'A'), just(b'B')));
            let msg = parse_errors(parser, b"C");
            // Should mention both 'A' and 'B' (chumsky merges into one ExpectedFound)
            assert!(
                msg.contains("'A'") || msg.contains("'B'"),
                "alternatives in: {msg}"
            );
        }
    }
}
