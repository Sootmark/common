//! JSON (RFC 8259): a value type, compact and pretty output, and a strict
//! parser for untrusted input (collector metadata, imported results).

use core::fmt::{self, Write};

/// Maximum nesting depth accepted by the parser.
const MAX_DEPTH: usize = 128;

/// A JSON value. Objects keep their members in order, so output is
/// deterministic.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number without fraction or exponent that fits an `i64`.
    Int(i64),
    /// A non-negative integer too large for `i64`.
    UInt(u64),
    /// Any other number.
    Float(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, members in order.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// An object from `(name, value)` pairs.
    pub fn object<K: Into<String>>(members: impl IntoIterator<Item = (K, Json)>) -> Self {
        Self::Object(members.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// The member `name` of an object.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Self::Object(members) => members.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The number, if this is an integer that fits an `i64`.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Self::Int(n) => Some(n),
            Self::UInt(n) => i64::try_from(n).ok(),
            _ => None,
        }
    }

    /// The number, if this is a non-negative integer.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Self::Int(n) => u64::try_from(n).ok(),
            Self::UInt(n) => Some(n),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Indented output, two spaces per level.
    #[must_use]
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out
    }

    fn write_pretty(&self, out: &mut String, depth: usize) {
        let indent = |out: &mut String, depth: usize| {
            for _ in 0..depth {
                out.push_str("  ");
            }
        };
        match self {
            Self::Array(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    indent(out, depth + 1);
                    item.write_pretty(out, depth + 1);
                    out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
                }
                indent(out, depth);
                out.push(']');
            }
            Self::Object(members) if !members.is_empty() => {
                out.push_str("{\n");
                for (i, (name, value)) in members.iter().enumerate() {
                    indent(out, depth + 1);
                    write_string(out, name);
                    out.push_str(": ");
                    value.write_pretty(out, depth + 1);
                    out.push_str(if i + 1 < members.len() { ",\n" } else { "\n" });
                }
                indent(out, depth);
                out.push('}');
            }
            scalar_or_empty => {
                let _ = write!(out, "{scalar_or_empty}");
            }
        }
    }
}

impl fmt::Display for Json {
    /// Compact output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::UInt(n) => write!(f, "{n}"),
            Self::Float(n) if n.is_finite() => write!(f, "{n}"),
            // JSON has no NaN or infinity.
            Self::Null | Self::Float(_) => f.write_str("null"),
            Self::String(s) => {
                let mut out = String::new();
                write_string(&mut out, s);
                f.write_str(&out)
            }
            Self::Array(items) => {
                f.write_char('[')?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_char(']')
            }
            Self::Object(members) => {
                f.write_char('{')?;
                for (i, (name, value)) in members.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    let mut key = String::new();
                    write_string(&mut key, name);
                    write!(f, "{key}:{value}")?;
                }
                f.write_char('}')
            }
        }
    }
}

macro_rules! from_value {
    ($($ty:ty => $variant:ident $(as $cast:ty)?),* $(,)?) => {
        $(impl From<$ty> for Json {
            fn from(value: $ty) -> Self {
                Self::$variant(value $(as $cast)?)
            }
        })*
    };
}

from_value!(bool => Bool, i64 => Int, u64 => UInt, f64 => Float, String => String, u32 => Int as i64, u16 => Int as i64);

impl From<&str> for Json {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl<T: Into<Json>> From<Option<T>> for Json {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}

impl<T: Into<Json>> From<Vec<T>> for Json {
    fn from(items: Vec<T>) -> Self {
        Self::Array(items.into_iter().map(Into::into).collect())
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Why a document isn't valid JSON, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset of the problem.
    pub offset: usize,
    /// What was expected.
    pub expected: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid JSON at byte {}: expected {}",
            self.offset, self.expected
        )
    }
}

impl std::error::Error for ParseError {}

/// Parse a complete JSON document.
///
/// # Errors
/// [`ParseError`] on invalid JSON, trailing content, or nesting deeper than
/// the parser allows.
pub fn parse(text: &str) -> Result<Json, ParseError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        text,
        position: 0,
    };
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.position != parser.bytes.len() {
        return Err(parser.error("end of document"));
    }
    Ok(value)
}

struct Parser<'t> {
    bytes: &'t [u8],
    text: &'t str,
    position: usize,
}

impl Parser<'_> {
    fn error(&self, expected: &'static str) -> ParseError {
        ParseError {
            offset: self.position,
            expected,
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.position),
            Some(b' ' | b'\t' | b'\n' | b'\r')
        ) {
            self.position += 1;
        }
    }

    fn expect(&mut self, literal: &'static str) -> Result<(), ParseError> {
        if self.text[self.position..].starts_with(literal) {
            self.position += literal.len();
            Ok(())
        } else {
            Err(self.error(literal))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.error("less nesting"));
        }
        self.skip_whitespace();
        match self.bytes.get(self.position) {
            Some(b'n') => self.expect("null").map(|()| Json::Null),
            Some(b't') => self.expect("true").map(|()| Json::Bool(true)),
            Some(b'f') => self.expect("false").map(|()| Json::Bool(false)),
            Some(b'"') => self.string().map(Json::String),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("a value")),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.position += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.error("',' or ']'")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.position += 1;
        let mut members = Vec::new();
        self.skip_whitespace();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_whitespace();
            if self.bytes.get(self.position) != Some(&b'"') {
                return Err(self.error("a member name"));
            }
            let name = self.string()?;
            self.skip_whitespace();
            self.expect(":")?;
            members.push((name, self.value(depth + 1)?));
            self.skip_whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(Json::Object(members));
                }
                _ => return Err(self.error("',' or '}'")),
            }
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.position += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.position;
            while let Some(&b) = self.bytes.get(self.position) {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.position += 1;
            }
            out.push_str(&self.text[start..self.position]);
            match self.bytes.get(self.position) {
                Some(b'"') => {
                    self.position += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.position += 1;
                    out.push(self.escape()?);
                }
                _ => return Err(self.error("a closing quote")),
            }
        }
    }

    fn escape(&mut self) -> Result<char, ParseError> {
        let c = match self.bytes.get(self.position) {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.position += 1;
                return self.unicode_escape();
            }
            _ => return Err(self.error("an escape character")),
        };
        self.position += 1;
        Ok(c)
    }

    /// `XXXX` after `\u`, including a following `\uXXXX` low surrogate.
    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let high = self.hex4()?;
        if !(0xd800..0xdc00).contains(&high) {
            return char::from_u32(u32::from(high)).ok_or_else(|| self.error("a valid code point"));
        }
        self.expect("\\u")?;
        let low = self.hex4()?;
        if !(0xdc00..0xe000).contains(&low) {
            return Err(self.error("a low surrogate"));
        }
        let code = 0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
        char::from_u32(code).ok_or_else(|| self.error("a valid code point"))
    }

    fn hex4(&mut self) -> Result<u16, ParseError> {
        let digits = self
            .text
            .get(self.position..self.position + 4)
            .ok_or_else(|| self.error("4 hex digits"))?;
        let value = u16::from_str_radix(digits, 16).map_err(|_| self.error("4 hex digits"))?;
        self.position += 4;
        Ok(value)
    }

    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.position;
        let digits = |p: &mut Self| {
            let from = p.position;
            while p.bytes.get(p.position).is_some_and(u8::is_ascii_digit) {
                p.position += 1;
            }
            p.position > from
        };
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        if !digits(self) {
            return Err(self.error("digits"));
        }
        let mut integral = true;
        if self.bytes.get(self.position) == Some(&b'.') {
            self.position += 1;
            integral = false;
            if !digits(self) {
                return Err(self.error("fraction digits"));
            }
        }
        if matches!(self.bytes.get(self.position), Some(b'e' | b'E')) {
            self.position += 1;
            integral = false;
            if matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !digits(self) {
                return Err(self.error("exponent digits"));
            }
        }
        let literal = &self.text[start..self.position];
        if integral {
            if let Ok(n) = literal.parse::<i64>() {
                return Ok(Json::Int(n));
            }
            if let Ok(n) = literal.parse::<u64>() {
                return Ok(Json::UInt(n));
            }
        }
        literal
            .parse::<f64>()
            .map(Json::Float)
            .map_err(|_| self.error("a number"))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn typed_accessors() {
        let value =
            parse(r#"{"n": -3, "big": 18446744073709551615, "list": [1, "a"], "s": "x"}"#).unwrap();
        assert_eq!(value.get("n").and_then(Json::as_i64), Some(-3));
        assert_eq!(value.get("n").and_then(Json::as_u64), None);
        assert_eq!(value.get("big").and_then(Json::as_u64), Some(u64::MAX));
        assert_eq!(value.get("big").and_then(Json::as_i64), None);
        assert_eq!(
            value
                .get("list")
                .and_then(Json::as_array)
                .map(<[Json]>::len),
            Some(2)
        );
        assert_eq!(value.get("s").and_then(Json::as_array), None);
        assert_eq!(value.get("s").and_then(Json::as_i64), None);
    }
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_a_collector_metadata_document() {
        let doc = parse(r#"{"ClientId":"C.1","Hostname":"FS01","Ports":[443, 8000],"Ok":true,"Load":0.5,"Note":null}"#).unwrap();
        assert_eq!(doc.get("Hostname").and_then(Json::as_str), Some("FS01"));
        assert_eq!(
            doc.get("Ports"),
            Some(&Json::Array(vec![Json::Int(443), Json::Int(8000)]))
        );
        assert_eq!(doc.get("Load"), Some(&Json::Float(0.5)));
        assert_eq!(doc.get("Note"), Some(&Json::Null));
    }

    #[test]
    fn decodes_escapes_and_surrogate_pairs() {
        assert_eq!(
            parse(r#""a\"b\\c\n\u00e9\ud83d\ude00""#).unwrap(),
            Json::String("a\"b\\c\né😀".into())
        );
    }

    #[test]
    fn keeps_large_integers_exact() {
        assert_eq!(parse("18446744073709551615").unwrap(), Json::UInt(u64::MAX));
        assert_eq!(parse("-9223372036854775808").unwrap(), Json::Int(i64::MIN));
    }

    #[test]
    fn rejects_invalid_documents() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\" 1}",
            "01x",
            "\"\\ud800\"",
            "tru",
            "1 2",
            "\"\u{1}\"",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn rejects_hostile_nesting() {
        let deep = "[".repeat(10_000) + &"]".repeat(10_000);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn writes_compact_and_pretty() {
        let doc = Json::object([
            ("host", Json::from("WS-042")),
            ("files", Json::from(vec![1u64, 2])),
            ("hint", Json::from(None::<String>)),
        ]);
        assert_eq!(
            doc.to_string(),
            r#"{"host":"WS-042","files":[1,2],"hint":null}"#
        );
        assert_eq!(
            doc.to_pretty(),
            "{\n  \"host\": \"WS-042\",\n  \"files\": [\n    1,\n    2\n  ],\n  \"hint\": null\n}"
        );
    }

    proptest! {
        #[test]
        fn strings_round_trip(s in "\\PC*") {
            let written = Json::String(s.clone()).to_string();
            prop_assert_eq!(parse(&written).unwrap(), Json::String(s));
        }

        #[test]
        fn never_panics_on_garbage(text in "\\PC{0,64}") {
            let _ = parse(&text);
        }
    }
}
