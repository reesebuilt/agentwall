//! A JSON reader that keeps the source lexemes.
//!
//! `docs/audit-format.md` forbids reserializing a parsed value: "A conforming verifier MUST NOT
//! reserialize parsed values. It parses only enough to know the structure and the decoded key
//! strings, and it emits the original lexemes." So this is not a general JSON parser with a
//! canonical printer bolted on. Every scalar is kept as the byte range it occupied in the line,
//! and object members are kept in a list, in source order, each holding both its key lexeme and
//! its decoded key.
//!
//! Two consequences fall out of that shape, and both are required by the format:
//!
//! - Duplicate keys survive parsing. "A verifier MUST detect the duplicate in the raw line,
//!   before handing it to a parser ... Once a parser has returned, the second member is gone and
//!   no later check can see it was ever there." A `Vec` of members loses nothing, so the check
//!   below sees both occurrences; there is no point at which one is silently dropped.
//! - Keys decode to UTF-16 code units, because that is the ordering the format specifies and it
//!   is also the right granularity for deciding two keys are the same key.

use std::fmt;

/// How deep nesting may go before a line is refused. A verifier reads attacker-influenced input
/// and the parser recurses, so an unbounded document is a stack overflow waiting to be posted.
const MAX_DEPTH: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    /// `null`, `true`, `false`, a number, or a string: the source lexeme, byte for byte,
    /// including a string's surrounding quotes and escapes exactly as written.
    Scalar(&'a str),
    Array(Vec<Value<'a>>),
    Object(Object<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member<'a> {
    pub key_lexeme: &'a str,
    /// The key decoded to UTF-16 code units. Sorting and equality both use this; emission uses
    /// `key_lexeme`. The format calls out that asymmetry as the likeliest place for two
    /// implementations to differ.
    pub key: Vec<u16>,
    pub value: Value<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object<'a> {
    pub members: Vec<Member<'a>>,
}

impl<'a> Object<'a> {
    pub fn get(&self, name: &str) -> Option<&Value<'a>> {
        let wanted: Vec<u16> = name.encode_utf16().collect();
        self.members
            .iter()
            .find(|m| m.key == wanted)
            .map(|m| &m.value)
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

impl<'a> Value<'a> {
    pub fn as_object(&self) -> Option<&Object<'a>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn lexeme(&self) -> Option<&'a str> {
        match self {
            Value::Scalar(s) => Some(s),
            _ => None,
        }
    }

    /// The decoded contents of a string scalar, or `None` for any other shape. Used only for
    /// values the verifier must interpret, never for anything that feeds a hash.
    pub fn as_str(&self) -> Option<String> {
        let lex = self.lexeme()?;
        if !lex.starts_with('"') {
            return None;
        }
        let units = decode_string(lex)?;
        String::from_utf16(&units).ok()
    }

    /// A JSON integer as i64. Rejects anything carrying a fraction or an exponent, because an
    /// index that is not a plain integer cannot be compared against its neighbours.
    pub fn as_i64(&self) -> Option<i64> {
        let lex = self.lexeme()?;
        if lex.contains('.') || lex.contains('e') || lex.contains('E') {
            return None;
        }
        lex.parse::<i64>().ok()
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Scalar("null"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The line ended in the middle of a value. Reported separately because the format wants a
    /// truncated final line diagnosed as a torn tail rather than as tampering.
    Truncated,
    Invalid(String),
    /// Two members of one object decode to the same key.
    DuplicateKey(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "line ends mid-value"),
            ParseError::Invalid(m) => write!(f, "{m}"),
            ParseError::DuplicateKey(k) => write!(f, "duplicate key {k}"),
        }
    }
}

pub fn parse(src: &str) -> Result<Value<'_>, ParseError> {
    let mut p = Parser {
        src,
        bytes: src.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(ParseError::Invalid("trailing bytes after value".into()));
    }
    Ok(v)
}

struct Parser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn value(&mut self, depth: usize) -> Result<Value<'a>, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::Invalid(format!(
                "nesting deeper than {MAX_DEPTH}"
            )));
        }
        match self.peek() {
            None => Err(ParseError::Truncated),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::Scalar(self.string()?)),
            Some(b't') => self.literal("true"),
            Some(b'f') => self.literal("false"),
            Some(b'n') => self.literal("null"),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(ParseError::Invalid(format!(
                "unexpected byte {:#04x} at offset {}",
                c, self.pos
            ))),
        }
    }

    fn literal(&mut self, word: &'static str) -> Result<Value<'a>, ParseError> {
        let end = self.pos + word.len();
        if end > self.bytes.len() {
            // A line cut short inside `tru` or `nul` is truncation, not a bad token.
            if word.as_bytes().starts_with(&self.bytes[self.pos..]) {
                return Err(ParseError::Truncated);
            }
            return Err(ParseError::Invalid(format!("bad literal at {}", self.pos)));
        }
        if &self.src[self.pos..end] != word {
            return Err(ParseError::Invalid(format!("bad literal at {}", self.pos)));
        }
        let lex = &self.src[self.pos..end];
        self.pos = end;
        Ok(Value::Scalar(lex))
    }

    fn number(&mut self) -> Result<Value<'a>, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let int_start = self.pos;
        match self.peek() {
            None => return Err(ParseError::Truncated),
            Some(b'0') => self.pos += 1,
            Some(c) if c.is_ascii_digit() => {
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            Some(_) => return Err(ParseError::Invalid(format!("bad number at {start}"))),
        }
        if self.pos == int_start {
            return Err(ParseError::Invalid(format!("bad number at {start}")));
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let frac_start = self.pos;
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err(if self.pos == self.bytes.len() {
                    ParseError::Truncated
                } else {
                    ParseError::Invalid(format!("bad number at {start}"))
                });
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err(if self.pos == self.bytes.len() {
                    ParseError::Truncated
                } else {
                    ParseError::Invalid(format!("bad number at {start}"))
                });
            }
        }
        Ok(Value::Scalar(&self.src[start..self.pos]))
    }

    /// Returns the string's source lexeme, quotes included.
    fn string(&mut self) -> Result<&'a str, ParseError> {
        let start = self.pos;
        debug_assert_eq!(self.bytes[start], b'"');
        self.pos += 1;
        loop {
            let c = match self.peek() {
                None => return Err(ParseError::Truncated),
                Some(c) => c,
            };
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(&self.src[start..self.pos]);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = match self.peek() {
                        None => return Err(ParseError::Truncated),
                        Some(e) => e,
                    };
                    match esc {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => self.pos += 1,
                        b'u' => {
                            self.pos += 1;
                            if self.pos + 4 > self.bytes.len() {
                                return Err(ParseError::Truncated);
                            }
                            for i in 0..4 {
                                if !self.bytes[self.pos + i].is_ascii_hexdigit() {
                                    return Err(ParseError::Invalid(format!(
                                        "bad unicode escape at {}",
                                        self.pos
                                    )));
                                }
                            }
                            self.pos += 4;
                        }
                        _ => {
                            return Err(ParseError::Invalid(format!("bad escape at {}", self.pos)))
                        }
                    }
                }
                // RFC 8259 requires control characters to be escaped. The format leans on this:
                // "JSON text cannot contain an unescaped control character", which is why the
                // hash material needs only two escapes.
                0x00..=0x1f => {
                    return Err(ParseError::Invalid(format!(
                        "unescaped control byte {:#04x} at {}",
                        c, self.pos
                    )))
                }
                _ => self.pos += 1,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value<'a>, ParseError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                None => return Err(ParseError::Truncated),
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                Some(c) => {
                    return Err(ParseError::Invalid(format!(
                        "expected comma or bracket at {}, found {:?}",
                        self.pos, c as char
                    )))
                }
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value<'a>, ParseError> {
        self.pos += 1; // '{'
        let mut members: Vec<Member<'a>> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(Object { members }));
        }
        loop {
            self.skip_ws();
            if self.peek().is_none() {
                return Err(ParseError::Truncated);
            }
            if self.peek() != Some(b'"') {
                return Err(ParseError::Invalid(format!(
                    "expected a key string at {}",
                    self.pos
                )));
            }
            let key_lexeme = self.string()?;
            let key = decode_string(key_lexeme)
                .ok_or_else(|| ParseError::Invalid(format!("undecodable key at {}", self.pos)))?;
            self.skip_ws();
            match self.peek() {
                None => return Err(ParseError::Truncated),
                Some(b':') => self.pos += 1,
                Some(_) => return Err(ParseError::Invalid(format!("expected : at {}", self.pos))),
            }
            self.skip_ws();
            let value = self.value(depth + 1)?;
            members.push(Member {
                key_lexeme,
                key,
                value,
            });
            self.skip_ws();
            match self.peek() {
                None => return Err(ParseError::Truncated),
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    check_duplicates(&members)?;
                    return Ok(Value::Object(Object { members }));
                }
                Some(c) => {
                    return Err(ParseError::Invalid(format!(
                        "expected comma or brace at {}, found {:?}",
                        self.pos, c as char
                    )))
                }
            }
        }
    }
}

fn check_duplicates(members: &[Member<'_>]) -> Result<(), ParseError> {
    if members.len() < 2 {
        return Ok(());
    }
    let mut order: Vec<usize> = (0..members.len()).collect();
    order.sort_by(|&a, &b| members[a].key.cmp(&members[b].key));
    for pair in order.windows(2) {
        if members[pair[0]].key == members[pair[1]].key {
            return Err(ParseError::DuplicateKey(String::from_utf16_lossy(
                &members[pair[0]].key,
            )));
        }
    }
    Ok(())
}

/// Decode a JSON string lexeme, quotes included, to UTF-16 code units.
///
/// A `\uXXXX` escape contributes its code unit directly and is not paired with a neighbouring
/// surrogate, which is what makes an astral character two units and puts its high surrogate, in
/// `0xD800` to `0xDBFF`, in front for ordering purposes. A literal character contributes the
/// units of its UTF-16 encoding. Unpaired surrogates are preserved rather than replaced: they
/// still have to compare and sort, and nothing here re-emits them.
pub fn decode_string(lexeme: &str) -> Option<Vec<u16>> {
    let b = lexeme.as_bytes();
    if b.len() < 2 || b[0] != b'"' || b[b.len() - 1] != b'"' {
        return None;
    }
    let inner = &lexeme[1..lexeme.len() - 1];
    let mut out = Vec::with_capacity(inner.len());
    let mut chars = inner.char_indices();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            let mut buf = [0u16; 2];
            out.extend_from_slice(c.encode_utf16(&mut buf));
            continue;
        }
        let (_, esc) = chars.next()?;
        match esc {
            '"' => out.push(0x0022),
            '\\' => out.push(0x005c),
            '/' => out.push(0x002f),
            'b' => out.push(0x0008),
            'f' => out.push(0x000c),
            'n' => out.push(0x000a),
            'r' => out.push(0x000d),
            't' => out.push(0x0009),
            'u' => {
                let start = i + 2;
                let hex = inner.get(start..start + 4)?;
                let unit = u16::from_str_radix(hex, 16).ok()?;
                out.push(unit);
                for _ in 0..4 {
                    chars.next()?;
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_source_lexemes() {
        let v = parse(r#"{"a":1e+21,"b":-0,"c":"x\u00c4y"}"#).unwrap();
        let o = v.as_object().unwrap();
        assert_eq!(o.get("a").unwrap().lexeme(), Some("1e+21"));
        assert_eq!(o.get("b").unwrap().lexeme(), Some("-0"));
        assert_eq!(o.get("c").unwrap().lexeme(), Some(r#""x\u00c4y""#));
    }

    #[test]
    fn detects_duplicate_keys_however_they_are_spelled() {
        // Same decoded key, different lexemes. A parser that built a map would keep one.
        assert_eq!(
            parse("{\"\\u00c4\":1,\"\u{c4}\":2}"),
            Err(ParseError::DuplicateKey("\u{c4}".into()))
        );
        assert!(matches!(
            parse(r#"{"decision":"allow","decision":"deny"}"#),
            Err(ParseError::DuplicateKey(_))
        ));
        // Nested objects are checked too.
        assert!(matches!(
            parse(r#"{"m":{"host":"a","host":"b"}}"#),
            Err(ParseError::DuplicateKey(_))
        ));
        // Distinct keys that merely look alike are fine.
        assert!(parse(r#"{"a":1,"A":2,"":3}"#).is_ok());
    }

    #[test]
    fn separates_truncation_from_corruption() {
        assert_eq!(parse(r#"{"a":1,"b":"unfinis"#), Err(ParseError::Truncated));
        assert_eq!(parse(r#"{"a":1,"#), Err(ParseError::Truncated));
        assert_eq!(parse(r#"{"a":tru"#), Err(ParseError::Truncated));
        assert_eq!(parse("[1,2"), Err(ParseError::Truncated));
        assert!(matches!(parse(r#"{"a":1}x"#), Err(ParseError::Invalid(_))));
        assert!(matches!(
            parse(r#"{"a":truX}"#),
            Err(ParseError::Invalid(_))
        ));
        assert!(matches!(parse(r#"{a:1}"#), Err(ParseError::Invalid(_))));
        assert!(matches!(
            parse("{\"a\":\"\t\"}"),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn decodes_keys_to_utf16_code_units() {
        // The spec's worked example table, key by key.
        assert_eq!(decode_string(r#""Zebra""#).unwrap()[0], 0x005a);
        assert_eq!(decode_string(r#""apple""#).unwrap()[0], 0x0061);
        assert_eq!(decode_string(r#""\u00c4""#).unwrap(), vec![0x00c4]);
        assert_eq!(decode_string("\"\u{c4}\"").unwrap(), vec![0x00c4]);
        assert_eq!(
            decode_string(r#""\ud835\udc00""#).unwrap(),
            vec![0xd835, 0xdc00]
        );
        assert_eq!(decode_string(r#""\uff21""#).unwrap(), vec![0xff21]);
        // The astral character written literally decodes to the same two units.
        assert_eq!(
            decode_string("\"\u{1d400}\"").unwrap(),
            vec![0xd835, 0xdc00]
        );
    }

    #[test]
    fn refuses_absurd_nesting_instead_of_overflowing_the_stack() {
        let deep = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
        assert!(matches!(parse(&deep), Err(ParseError::Invalid(_))));
    }
}
