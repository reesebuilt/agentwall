//! Strict RFC 4648 base64 decoding, standard alphabet, padding required.
//!
//! Checkpoints carry `signature` and `publicKey` as base64. A lenient decoder that skipped
//! stray characters would let two different strings decode to the same key, which matters
//! because pinning compares the base64 string while verification uses the decoded bytes: if
//! those two views can disagree, a pin can be satisfied by a string that decodes to something
//! else. So: no whitespace, no alternate alphabet, padding exact, and the unused bits of the
//! final group must be zero.

pub fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return None;
    }

    let mut pad = 0usize;
    if b[b.len() - 1] == b'=' {
        pad += 1;
        if b[b.len() - 2] == b'=' {
            pad += 1;
        }
    }

    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let groups = b.len() / 4;
    for g in 0..groups {
        let chunk = &b[g * 4..g * 4 + 4];
        let last = g == groups - 1;
        let mut acc: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' {
                // Padding is legal only in the final group, and only in the last two slots.
                if !last || i < 2 || (i == 2 && pad != 2) {
                    return None;
                }
                0
            } else {
                sextet(c)?
            };
            acc = (acc << 6) | u32::from(v);
        }
        let bytes = [(acc >> 16) as u8, (acc >> 8) as u8, acc as u8];
        let keep = if last { 3 - pad } else { 3 };
        // Bits covered by padding must be zero, or two distinct strings decode alike.
        for &dropped in &bytes[keep..] {
            if dropped != 0 {
                return None;
            }
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    Some(out)
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::to_hex;

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn rejects_sloppy_input() {
        assert!(decode("Zm9vYmFy\n").is_none());
        assert!(decode("Zm9v YmFy").is_none());
        assert!(decode("Zg").is_none());
        assert!(decode("Z===").is_none());
        // Non-zero bits under the padding.
        assert!(decode("Zh==").is_none());
        assert!(decode("").is_none());
    }

    #[test]
    fn decodes_the_spec_worked_example_key() {
        // docs/audit-format.md: "The `publicKey` decodes to 44 bytes of DER SPKI, of which the
        // last 32 are the raw Ed25519 public key."
        let der = decode("MCowBQYDK2VwAyEAvU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE=").unwrap();
        assert_eq!(der.len(), 44);
        assert_eq!(
            to_hex(&der[12..]),
            "bd4dc029d94f6d85e16e44b58b018cf6d0a346759f4cbee4104ac55edcaba271"
        );
        let sig = decode(
            "0Kt6u/CfbfxIdPm6Kgp6WpAzi8301ca8Zw7RpqOxoIq1BC4n6sOiY0eVOZTMfcOfo+eoTHH+CodhmYhYmh/ADg==",
        )
        .unwrap();
        assert_eq!(sig.len(), 64);
    }
}
