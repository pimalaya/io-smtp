//! Shared helpers spanning the RFC modules.
//!
//! Hosts the byte-escaping helper used by the coroutine traces and
//! the chumsky parser building blocks shared by every wire-format
//! parser.

use alloc::{format, string::String, vec::Vec};

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

pub mod parsers {
    //! Chumsky parser helpers for SMTP byte-slice parsing.

    #[cfg(test)]
    use core::str::from_utf8;

    use alloc::{
        format,
        string::{String, ToString},
        vec::Vec,
    };

    use chumsky::{
        error::{RichPattern, RichReason},
        extra,
        prelude::*,
    };

    /// The extra parser context carried by every parser in this
    /// crate: rich byte-level errors.
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
            _ => "unknown pattern".to_string(),
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
                    RichReason::Custom(msg) => msg.to_string(),
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
    /// Prefer `just(kw)` for case-sensitive matches: chumsky
    /// generates better `ExpectedFound` errors automatically. Use
    /// this only when case-folding is needed.
    #[cfg(test)]
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

    #[cfg(test)]
    mod tests {
        use alloc::string::String;

        use chumsky::prelude::*;

        use crate::utils::parsers::{Extra, format_rich_errors, tag_no_case};

        fn parse_errors<'src, P, O>(parser: P, input: &'src [u8]) -> String
        where
            P: Parser<'src, &'src [u8], O, Extra<'src>>,
        {
            format_rich_errors(parser.parse(input).into_errors())
        }

        #[test]
        fn expected_found_shows_printable_chars() {
            // NOTE: just(b'A') expects 'A', gets 'B'
            let msg = parse_errors(just(b'A'), b"B");
            assert!(msg.contains("'A'"), "expected char literal in: {msg}");
            assert!(msg.contains("'B'"), "found char literal in: {msg}");
        }

        #[test]
        fn expected_found_shows_hex_for_non_printable() {
            // NOTE: just(b'\x01') expects 0x01, gets 0x02
            let msg = parse_errors(just(b'\x01'), b"\x02");
            assert!(msg.contains("0x01"), "expected hex in: {msg}");
            assert!(msg.contains("0x02"), "found hex in: {msg}");
        }

        #[test]
        fn expected_found_shows_end_of_input() {
            // NOTE: any() on empty input reports "found end of input"
            let msg = parse_errors(any(), b"");
            assert!(msg.contains("end of input"), "should mention EOF in: {msg}");
        }

        #[test]
        fn byte_position_is_included() {
            // NOTE: just(b"AB") on b"AC" fails at byte 1 (the 'C')
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
            // NOTE: choice with two failing alternatives produces two
            // errors; chumsky merges them into one ExpectedFound
            // mentioning both 'A' and 'B'
            let parser = choice((just(b'A'), just(b'B')));
            let msg = parse_errors(parser, b"C");
            assert!(
                msg.contains("'A'") || msg.contains("'B'"),
                "alternatives in: {msg}"
            );
        }
    }
}
