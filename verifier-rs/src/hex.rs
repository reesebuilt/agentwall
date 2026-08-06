//! Lowercase hex, and a strict decoder.
//!
//! The format requires lowercase hex for every stored digest so a verifier can compare byte
//! for byte against its own recomputation, so `to_hex` only ever emits lowercase and
//! comparisons in this crate are plain string equality rather than case-insensitive.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Decode hex. Accepts either case on input because a hex string arriving from a proof file or
/// a manifest is data, not a digest this verifier produced; the lowercase rule binds what the
/// writer stores in `integrity.hash`, which is checked separately by string comparison.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = nibble(b[i])?;
        let lo = nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// True when `s` is exactly 64 lowercase hex characters, the shape the format requires of
/// `integrity.hash`, `previousHash`, `finalHash`, `previousSegmentHash`, `entryHash`, and an
/// anchor `digest`.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(from_hex("000fff").unwrap(), vec![0x00, 0x0f, 0xff]);
        assert_eq!(from_hex("000FFF").unwrap(), vec![0x00, 0x0f, 0xff]);
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }

    #[test]
    fn sha256_hex_shape_rejects_uppercase_and_wrong_length() {
        let ok = "d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303";
        assert!(is_sha256_hex(ok));
        assert!(!is_sha256_hex(&ok.to_uppercase()));
        assert!(!is_sha256_hex(&ok[..63]));
    }
}
