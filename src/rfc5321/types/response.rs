//! Module dedicated to the SMTP response.

use bounded_static_derive::ToStatic;
use chumsky::prelude::*;

use super::{reply_code::ReplyCode, text::Text, vec1::Vec1};

/// A complete SMTP response (possibly multi-line).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Response<'a> {
    /// The 3-digit reply code
    pub code: ReplyCode,
    /// One or more response lines
    pub lines: Vec1<Text<'a>>,
}

impl Response<'_> {
    /// Returns true if `buf` contains a complete SMTP response.
    /// A response is complete when the last CRLF-terminated line has `ddd SP` (not `ddd -`).
    pub fn is_complete(buf: &[u8]) -> bool {
        if !buf.ends_with(b"\r\n") {
            return false;
        }
        let body = &buf[..buf.len() - 2]; // strip final CRLF
        let line_start = body
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(0);
        let last_line = &body[line_start..];
        last_line.len() >= 4 && last_line[3] == b' '
    }

    pub fn parse<'a>(buf: &'a [u8]) -> Result<Response<'a>, Vec<Rich<'a, u8>>> {
        parsers::response().parse(buf).into_result()
    }

    /// Creates a new single-line response.
    pub fn new<'a>(code: ReplyCode, text: Text<'a>) -> Response<'a> {
        Response {
            code,
            lines: Vec1::from(text),
        }
    }

    /// Creates a new multi-line response.
    pub fn new_multiline<'a>(code: ReplyCode, lines: Vec1<Text<'a>>) -> Response<'a> {
        Response { code, lines }
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
    pub fn text(&self) -> &Text<'_> {
        &self.lines.as_ref()[0]
    }
}

pub(crate) mod parsers {
    use std::borrow::Cow;

    use chumsky::prelude::*;

    use crate::rfc5321::types::{
        reply_code::parsers::reply_code as reply_code_parser,
        text::{Text, parsers::text as text_parser},
        vec1::Vec1,
    };
    use crate::utils::parsers::{Extra, crlf, sp};

    use super::Response;

    /// SMTP response parser.
    ///
    /// ```abnf
    /// Replies        = *( Reply-line ) Final-Reply
    /// Reply-line     = Reply-code "-" [ textstring ] CRLF
    /// Final-Reply    = Reply-code SP [ textstring ] CRLF
    /// Reply-code     = %x32-35 %x30-35 %x30-39
    /// ```
    pub(crate) fn response<'a>() -> impl Parser<'a, &'a [u8], Response<'a>, Extra<'a>> + Clone {
        // continuation: code '-' [text] CRLF
        let cont = reply_code_parser()
            .then_ignore(just(b'-'))
            .then(text_parser().or_not())
            .then_ignore(crlf());
        // final: code SP [text] CRLF
        let last = reply_code_parser()
            .then_ignore(sp())
            .then(text_parser().or_not())
            .then_ignore(crlf());

        cont.repeated()
            .collect::<Vec<_>>()
            .then(last)
            .map(|(conts, (code, last_text))| {
                let mut lines: Vec<Text> = conts
                    .into_iter()
                    .map(|(_, t)| t.unwrap_or_else(|| Text(Cow::Borrowed(""))))
                    .collect();
                lines.push(last_text.unwrap_or_else(|| Text(Cow::Borrowed(""))));
                let lines = Vec1::unvalidated(lines);
                Response::new_multiline(code, lines)
            })
            .labelled("SMTP response")
    }
}
