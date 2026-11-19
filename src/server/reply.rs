//! Server-side reply writer (RFC 5321 section 4.2, RFC 3463).
//!
//! A reply is a code, an optional enhanced status code and one or more
//! text lines, written as `250-first`, `250-second`, `250 last`. The
//! enhanced code prefixes the text of every line.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::fmt::Write;

use crate::{rfc3463::enhanced_status_code::SmtpEnhancedStatusCode, rfc5321::SmtpReplyCode};

/// A reply a server sends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpServerReply {
    /// The reply code.
    pub code: SmtpReplyCode,
    /// The enhanced status code, written only when the session
    /// advertises ENHANCEDSTATUSCODES.
    pub enhanced: Option<SmtpEnhancedStatusCode>,
    /// The text lines, at least one being written.
    pub lines: Vec<String>,
}

impl SmtpServerReply {
    /// Builds a one-line reply.
    pub fn new(
        code: SmtpReplyCode,
        enhanced: Option<SmtpEnhancedStatusCode>,
        text: impl ToString,
    ) -> Self {
        Self {
            code,
            enhanced,
            lines: vec![text.to_string()],
        }
    }

    /// Builds a reply from a numeric code, an optional enhanced code as
    /// `(class, subject, detail)` and a text, `None` when either code is
    /// out of range.
    pub fn from_codes(
        code: u16,
        enhanced: Option<(u8, u16, u16)>,
        text: impl ToString,
    ) -> Option<Self> {
        let code = smtp_reply_code(code)?;
        let enhanced = match enhanced {
            Some((class, subject, detail)) => {
                Some(SmtpEnhancedStatusCode::new(class, subject, detail)?)
            }
            None => None,
        };

        Some(Self::new(code, enhanced, text))
    }

    /// Appends a text line.
    #[must_use]
    pub fn with_line(mut self, text: impl ToString) -> Self {
        self.lines.push(text.to_string());
        self
    }

    /// Whether the code is a positive completion (2xx).
    pub fn is_positive(&self) -> bool {
        self.code.is_positive_completion()
    }

    /// Appends the wire form to `out`, with or without the enhanced
    /// status code. CR and LF inside a text line become spaces.
    pub fn encode(&self, enhanced: bool, out: &mut Vec<u8>) {
        let empty = [String::new()];
        let lines = if self.lines.is_empty() {
            &empty[..]
        } else {
            &self.lines[..]
        };

        let mut buf = String::new();

        for (i, line) in lines.iter().enumerate() {
            let sep = if i + 1 == lines.len() { ' ' } else { '-' };
            let _ = write!(buf, "{}{sep}", self.code.code());

            if enhanced && let Some(status) = self.enhanced {
                let _ = write!(buf, "{status}");

                if !line.is_empty() {
                    buf.push(' ');
                }
            }

            buf.extend(line.chars().map(|c| match c {
                '\r' | '\n' => ' ',
                c => c,
            }));

            if buf.ends_with(' ') && line.is_empty() {
                buf.pop();
            }

            buf.push_str("\r\n");
        }

        out.extend_from_slice(buf.as_bytes());
    }

    /// Returns the wire form, with or without the enhanced status code.
    pub fn to_bytes(&self, enhanced: bool) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(enhanced, &mut out);
        out
    }
}

/// Builds a reply code from its numeric form.
pub fn smtp_reply_code(code: u16) -> Option<SmtpReplyCode> {
    if !(200..600).contains(&code) {
        return None;
    }

    Some(SmtpReplyCode {
        class: (code / 100) as u8,
        subject: (code / 10 % 10) as u8,
        detail: (code % 10) as u8,
    })
}

#[cfg(test)]
mod tests {
    use crate::server::reply::*;

    #[test]
    fn single_line_with_and_without_enhanced_code() {
        let reply = SmtpServerReply::from_codes(250, Some((2, 1, 0)), "Sender OK").unwrap();
        assert_eq!(reply.to_bytes(true), b"250 2.1.0 Sender OK\r\n");
        assert_eq!(reply.to_bytes(false), b"250 Sender OK\r\n");
    }

    #[test]
    fn multiline_marks_every_line_but_the_last() {
        let reply = SmtpServerReply::from_codes(250, None, "mx.example")
            .unwrap()
            .with_line("PIPELINING")
            .with_line("SIZE 1000");
        assert_eq!(
            reply.to_bytes(true),
            b"250-mx.example\r\n250-PIPELINING\r\n250 SIZE 1000\r\n"
        );
    }

    #[test]
    fn line_breaks_in_text_cannot_inject_a_reply() {
        let reply = SmtpServerReply::from_codes(550, Some((5, 1, 1)), "no\r\n250 ok").unwrap();
        assert_eq!(reply.to_bytes(true), b"550 5.1.1 no  250 ok\r\n");
    }

    #[test]
    fn empty_text_writes_the_bare_code() {
        let reply = SmtpServerReply::from_codes(250, None, "").unwrap();
        assert_eq!(reply.to_bytes(true), b"250\r\n");

        let mut reply = SmtpServerReply::from_codes(250, Some((2, 0, 0)), "").unwrap();
        assert_eq!(reply.to_bytes(true), b"250 2.0.0\r\n");
        reply.lines.clear();
        assert_eq!(reply.to_bytes(false), b"250\r\n");
    }

    #[test]
    fn out_of_range_codes_are_refused() {
        assert!(SmtpServerReply::from_codes(199, None, "").is_none());
        assert!(SmtpServerReply::from_codes(600, None, "").is_none());
        assert!(SmtpServerReply::from_codes(250, Some((3, 0, 0)), "").is_none());
    }
}
