//! SMTP response (RFC 5321 §4.2).
//!
//! A complete reply, one code and one or more text lines, as parsed
//! from the wire.

use alloc::vec::Vec;

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use crate::rfc5321::types::{reply_code::SmtpReplyCode, text::SmtpText, vec1::SmtpVec1};

/// A complete SMTP response (possibly multi-line).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct SmtpResponse<'a> {
    /// The 3-digit reply code
    pub code: SmtpReplyCode,
    /// One or more response lines
    pub lines: SmtpVec1<SmtpText<'a>>,
}

impl SmtpResponse<'_> {
    /// Returns true if `buf` contains a complete SMTP response.
    ///
    /// A response is complete when the last CRLF-terminated line has
    /// `ddd SP` (not `ddd -`).
    pub fn is_complete(buf: &[u8]) -> bool {
        if !buf.ends_with(b"\r\n") {
            return false;
        }

        let body = &buf[..buf.len() - 2];
        let line_start = body
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(0);

        let last_line = &body[line_start..];
        last_line.len() >= 4 && last_line[3] == b' '
    }

    /// Parses a response from raw bytes.
    pub fn parse<'a>(buf: &'a [u8]) -> Result<SmtpResponse<'a>, Vec<Rich<'a, u8>>> {
        parsers::response().parse(buf).into_result()
    }

    /// Creates a new single-line response.
    pub fn new<'a>(code: SmtpReplyCode, text: SmtpText<'a>) -> SmtpResponse<'a> {
        SmtpResponse {
            code,
            lines: SmtpVec1::from(text),
        }
    }

    /// Creates a new multi-line response.
    pub fn new_multiline<'a>(
        code: SmtpReplyCode,
        lines: SmtpVec1<SmtpText<'a>>,
    ) -> SmtpResponse<'a> {
        SmtpResponse { code, lines }
    }

    /// Returns true if this is a success response.
    pub fn is_success(&self) -> bool {
        self.code.is_success()
    }

    /// Returns true if this is an error response.
    pub fn is_error(&self) -> bool {
        self.code.is_error()
    }

    /// Returns the first (or only) line of text.
    pub fn text(&self) -> &SmtpText<'_> {
        &self.lines.as_ref()[0]
    }
}

pub(crate) mod parsers {
    //! Chumsky parser for the SMTP response.

    use alloc::{borrow::Cow, vec::Vec};

    use chumsky::prelude::*;

    use crate::{
        rfc5321::types::{
            reply_code::parsers::reply_code as reply_code_parser,
            response::SmtpResponse,
            text::{SmtpText, parsers::text as text_parser},
            vec1::SmtpVec1,
        },
        utils::parsers::{Extra, crlf, sp},
    };

    /// SMTP response parser.
    ///
    /// ```abnf
    /// Replies        = *( Reply-line ) Final-Reply
    /// Reply-line     = Reply-code "-" [ textstring ] CRLF
    /// Final-Reply    = Reply-code SP [ textstring ] CRLF
    /// Reply-code     = %x32-35 %x30-35 %x30-39
    /// ```
    pub(crate) fn response<'a>() -> impl Parser<'a, &'a [u8], SmtpResponse<'a>, Extra<'a>> + Clone {
        // NOTE: continuation: code '-' [text] CRLF
        let cont = reply_code_parser()
            .then_ignore(just(b'-'))
            .then(text_parser().or_not())
            .then_ignore(crlf());
        // NOTE: final: code SP [text] CRLF
        let last = reply_code_parser()
            .then_ignore(sp())
            .then(text_parser().or_not())
            .then_ignore(crlf());

        cont.repeated()
            .collect::<Vec<_>>()
            .then(last)
            .map(|(conts, (code, last_text))| {
                let mut lines: Vec<SmtpText> = conts
                    .into_iter()
                    .map(|(_, t)| t.unwrap_or(SmtpText(Cow::Borrowed(""))))
                    .collect();
                lines.push(last_text.unwrap_or(SmtpText(Cow::Borrowed(""))));
                let lines = SmtpVec1::unvalidated(lines);
                SmtpResponse::new_multiline(code, lines)
            })
            .labelled("SMTP response")
    }
}
