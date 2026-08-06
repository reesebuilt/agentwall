//! Canonical form `cu1` and the record hash material.
//!
//! Straight from `docs/audit-format.md`, section "Canonicalization cu1":
//!
//! - scalars emit their source lexeme byte for byte;
//! - arrays emit `[`, items joined by `,`, `]`, in source order;
//! - objects sort members ascending by DECODED key and emit the ORIGINAL key lexeme.
//!
//! That last asymmetry is the whole game. The document says so explicitly: "sorting compares
//! DECODED keys, while emission uses the ORIGINAL key lexeme. Two keys written `"\u00c4"` and as
//! the raw two UTF-8 bytes of U+00C4 sort identically and emit differently, because each emits
//! the bytes its own line contained."
//!
//! Key order is by UTF-16 code unit, which `Vec<u16>`'s own `Ord` already is: element by
//! element numerically, with a proper prefix sorting first. No collation table, no locale.

use crate::hex::to_hex;
use crate::json::{Object, Value};
use crate::sha2::sha256;

pub fn canon(v: &Value<'_>, out: &mut String) {
    match v {
        Value::Scalar(lex) => out.push_str(lex),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon(item, out);
            }
            out.push(']');
        }
        Value::Object(o) => {
            let mut order: Vec<usize> = (0..o.members.len()).collect();
            order.sort_by(|&a, &b| o.members[a].key.cmp(&o.members[b].key));
            out.push('{');
            for (i, &idx) in order.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(o.members[idx].key_lexeme);
                out.push(':');
                canon(&o.members[idx].value, out);
            }
            out.push('}');
        }
    }
}

/// `canonicalPayload(R)`: `canon` of the record with its `integrity` member removed and every
/// other member left byte for byte as the line contains it.
pub fn canonical_payload(record: &Object<'_>) -> String {
    let mut order: Vec<usize> = (0..record.members.len())
        .filter(|&i| record.members[i].key != INTEGRITY_KEY_UNITS.to_vec())
        .collect();
    order.sort_by(|&a, &b| record.members[a].key.cmp(&record.members[b].key));

    let mut out = String::new();
    out.push('{');
    for (i, &idx) in order.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(record.members[idx].key_lexeme);
        out.push(':');
        canon(&record.members[idx].value, &mut out);
    }
    out.push('}');
    out
}

/// UTF-16 code units of "integrity".
const INTEGRITY_KEY_UNITS: [u16; 9] = [
    b'i' as u16,
    b'n' as u16,
    b't' as u16,
    b'e' as u16,
    b'g' as u16,
    b'r' as u16,
    b'i' as u16,
    b't' as u16,
    b'y' as u16,
];

/// Embed `payload` as a JSON string: an opening quote, the payload with `\` doubled and `"`
/// escaped and nothing else touched, then a closing quote.
///
/// "Only those two characters need escaping. `canonicalPayload` is itself JSON text, and JSON
/// text cannot contain an unescaped control character or an unpaired surrogate, so no other
/// escape can arise."
fn embed(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() + 2);
    out.push('"');
    for c in payload.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The exact bytes hashed for a record.
///
/// ```text
/// {"chainIndex":I,"previousHash":P,"algorithm":"sha256","payload":J}
/// ```
///
/// `index_lexeme` is `integrity.chainIndex` as written on the line, `previous_lexeme` is either
/// the four bytes `null` or `integrity.previousHash`'s lexeme with its quotes.
pub fn hash_material(index_lexeme: &str, previous_lexeme: &str, payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() + 128);
    out.push_str("{\"chainIndex\":");
    out.push_str(index_lexeme);
    out.push_str(",\"previousHash\":");
    out.push_str(previous_lexeme);
    out.push_str(",\"algorithm\":\"sha256\",\"payload\":");
    out.push_str(&embed(payload));
    out.push('}');
    out
}

/// The lowercase hex SHA-256 of a record's hash material.
pub fn record_hash(index_lexeme: &str, previous_lexeme: &str, record: &Object<'_>) -> String {
    let payload = canonical_payload(record);
    to_hex(&sha256(
        hash_material(index_lexeme, previous_lexeme, &payload).as_bytes(),
    ))
}

/// The format asserts `canonicalPayload` holds no byte below `0x20`, and permits a verifier to
/// check it. The parser already refuses unescaped control characters, so this is a cheap
/// restatement of that invariant rather than a second line of defence.
pub fn payload_is_clean(payload: &str) -> bool {
    !payload.bytes().any(|b| b < 0x20)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn canon_of(src: &str) -> String {
        let v = parse(src).unwrap();
        let mut out = String::new();
        canon(&v, &mut out);
        out
    }

    #[test]
    fn sorts_by_utf16_code_unit_not_code_point() {
        // docs/audit-format.md, "Key ordering". The astral key sorts BEFORE the fullwidth one
        // even though its code point is higher, because its first UTF-16 unit is a surrogate.
        let src = r#"{"\uff21":5,"apple":2,"\ud835\udc00":4,"Zebra":1,"\u00c4":3}"#;
        let want = r#"{"Zebra":1,"apple":2,"\u00c4":3,"\ud835\udc00":4,"\uff21":5}"#;
        assert_eq!(canon_of(src), want);
    }

    #[test]
    fn emits_the_original_key_lexeme_after_sorting_on_the_decoded_one() {
        // Both keys decode to characters that sort the same way, and each emits the bytes its
        // own line carried. A verifier that re-escaped, or that unescaped, would produce one
        // spelling for both and a different hash.
        let src = "{\"\u{c4}\":1,\"apple\":2}";
        assert_eq!(canon_of(src), "{\"apple\":2,\"\u{c4}\":1}");
        let src2 = r#"{"\u00c4":1,"apple":2}"#;
        assert_eq!(canon_of(src2), r#"{"apple":2,"\u00c4":1}"#);
    }

    #[test]
    fn never_reformats_numbers_or_strings() {
        assert_eq!(
            canon_of(r#"{"a":1e+21,"b":-0,"c":0.10,"d":"\u0041"}"#),
            r#"{"a":1e+21,"b":-0,"c":0.10,"d":"\u0041"}"#
        );
    }

    #[test]
    fn preserves_array_order_and_ignores_inter_token_whitespace() {
        assert_eq!(canon_of(r#"[3,1,2]"#), "[3,1,2]");
        assert_eq!(
            canon_of("{ \"b\" : 1 , \"a\" : [ 1 , 2 ] }"),
            r#"{"a":[1,2],"b":1}"#
        );
    }

    #[test]
    fn reproduces_the_spec_worked_example_record() {
        let line = r#"{"id":"01JQ8Z0MZ9V6QK9J0H7X4T2R5B","timestamp":"2026-01-01T00:00:00.000Z","agentId":"curl","plane":"network","action":"egress:https","decision":"allow","riskLevel":"low","matchedRules":[],"reasons":["monitor-first: observed, not gated"],"requiresApproval":false,"highRiskFlow":false,"metadata":{"host":"example.com","port":"443","durationMs":"378"},"integrity":{"chainIndex":0,"hash":"d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303","previousHash":null,"algorithm":"sha256","status":"chained-local","canon":"cu1"}}"#;
        let v = parse(line).unwrap();
        let record = v.as_object().unwrap();

        let payload = canonical_payload(record);
        assert_eq!(
            payload,
            r#"{"action":"egress:https","agentId":"curl","decision":"allow","highRiskFlow":false,"id":"01JQ8Z0MZ9V6QK9J0H7X4T2R5B","matchedRules":[],"metadata":{"durationMs":"378","host":"example.com","port":"443"},"plane":"network","reasons":["monitor-first: observed, not gated"],"requiresApproval":false,"riskLevel":"low","timestamp":"2026-01-01T00:00:00.000Z"}"#
        );
        assert!(payload_is_clean(&payload));

        let material = hash_material("0", "null", &payload);
        assert_eq!(material.len(), 471);
        assert_eq!(
            record_hash("0", "null", record),
            "d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303"
        );
    }

    #[test]
    fn reproduces_the_spec_second_chained_record() {
        let line = r#"{"id":"01JQ8Z0N2C4M8P1S6D3F9G7H2K","timestamp":"2026-01-01T00:00:01.000Z","agentId":"curl","plane":"network","action":"egress:https","decision":"allow","riskLevel":"low","matchedRules":[],"reasons":["monitor-first: observed, not gated"],"requiresApproval":false,"highRiskFlow":false,"metadata":{"host":"example.com","port":"443","durationMs":"412"},"integrity":{"chainIndex":1,"hash":"8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428","previousHash":"d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303","algorithm":"sha256","status":"chained-local","canon":"cu1"}}"#;
        let v = parse(line).unwrap();
        let record = v.as_object().unwrap();
        assert_eq!(
            record_hash(
                "1",
                r#""d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303""#,
                record
            ),
            "8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428"
        );
    }

    #[test]
    fn member_order_on_disk_does_not_change_the_hash() {
        // "member order on disk, and any whitespace a later tool may have introduced between
        // tokens, are both absorbed by canonicalization."
        let a = r#"{"b":2,"a":1,"integrity":{"chainIndex":0}}"#;
        let b = r#"{ "a" : 1 , "b" : 2 , "integrity" : { "chainIndex" : 0 } }"#;
        let va = parse(a).unwrap();
        let vb = parse(b).unwrap();
        assert_eq!(
            canonical_payload(va.as_object().unwrap()),
            canonical_payload(vb.as_object().unwrap())
        );
    }

    #[test]
    fn embeds_only_backslash_and_quote() {
        assert_eq!(embed(r#"{"a":"b\\c"}"#), r#""{\"a\":\"b\\\\c\"}""#);
        // A tab that survived into a payload would be embedded literally, which is why the
        // parser refuses one earlier rather than letting it reach here.
        assert!(!payload_is_clean("{\"a\":\"\t\"}"));
    }
}
