//! The OpenTimestamps proof grammar.
//!
//! The whole grammar is in `docs/audit-format.md` under "OpenTimestamps proof files", and this
//! is a direct reading of it. Two rules from that section are the point of the exercise and are
//! enforced below rather than described:
//!
//! - "A pending attestation is reported as pending, with its calendar URI, and MUST NOT be
//!   reported as proof."
//! - A Bitcoin attestation gives "the claimed Merkle root of the named block", and a verifier
//!   that reads only local files "MUST NOT report the attestation as confirming anything by
//!   itself."
//!
//! So this module never returns a boolean called "confirmed". It returns what the operations
//! actually reached, and the caller reports that.
//!
//! "A verifier operates on attacker-influenced input by definition, so it bounds what a proof
//! can make it do: a cap on the size of each operation argument, a cap on total work, and a cap
//! on fork depth. A proof exceeding a cap is reported as a parse error rather than being
//! followed." The caps are constants at the top.

use crate::hashes::{keccak256, ripemd160, sha1};
use crate::hex::to_hex;
use crate::sha2::sha256;

/// Largest varbytes argument a single operation may carry.
const MAX_ARG: usize = 8192;
/// Largest the running message may grow to.
const MAX_MESSAGE: usize = 65536;
/// Total operations applied across every branch.
const MAX_OPS: usize = 8192;
/// How deep forks may nest.
const MAX_FORK_DEPTH: usize = 64;
/// How many attestations one proof may yield.
const MAX_ATTESTATIONS: usize = 1024;

const MAGIC: [u8; 31] = [
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
    0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
];

const TAG_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const TAG_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    /// A calendar accepted a submission. That is all it records.
    Pending { uri: String, value: Vec<u8> },
    /// A value claimed to be the Merkle root of the named block, to be compared elsewhere.
    Bitcoin { height: u64, value: Vec<u8> },
    /// "An attestation tag a verifier does not recognize is skipped using its varbytes length
    /// ... Unknown attestations are neither proof nor failure."
    Unknown { tag: [u8; 8] },
}

impl Attestation {
    pub fn describe(&self) -> String {
        match self {
            Attestation::Pending { uri, .. } => {
                format!("pending at {uri}, which records that a calendar accepted a submission and nothing more")
            }
            Attestation::Bitcoin { height, value } => format!(
                "bitcoin block {height} claimed to have merkle root {}, which this verifier \
                 cannot confirm offline; compare it against any block source to finish the check",
                to_hex(value)
            ),
            Attestation::Unknown { tag } => {
                format!(
                    "an attestation of unrecognised type {} that is neither proof nor failure",
                    to_hex(tag)
                )
            }
        }
    }
}

pub struct Proof {
    pub attestations: Vec<Attestation>,
    /// True when the file carried the 31 magic bytes rather than being a bare calendar response.
    pub container: bool,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    ops: usize,
    attestations: usize,
}

type ParseResult<T> = Result<T, String>;

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> ParseResult<u8> {
        let b = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| format!("proof ends at offset {}", self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> ParseResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or("length overflow")?;
        if end > self.bytes.len() {
            return Err(format!(
                "proof claims {n} bytes at offset {} but only {} remain",
                self.pos,
                self.bytes.len() - self.pos
            ));
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// "Unsigned little-endian base 128. Each byte contributes 7 bits, least significant group
    /// first. The high bit set means another byte follows."
    fn varint(&mut self) -> ParseResult<u64> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            let part = u64::from(b & 0x7f);
            if shift >= 64 || (shift == 63 && part > 1) {
                return Err("varint wider than 64 bits".into());
            }
            value |= part << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn varbytes(&mut self) -> ParseResult<&'a [u8]> {
        let n = self.varint()? as usize;
        if n > MAX_ARG {
            return Err(format!(
                "operation argument of {n} bytes exceeds the {MAX_ARG} byte cap"
            ));
        }
        self.take(n)
    }
}

/// Parse a proof file and return every attestation it reaches, starting from `digest`.
pub fn parse_proof(bytes: &[u8], digest: &[u8]) -> ParseResult<Proof> {
    let mut c = Cursor {
        bytes,
        pos: 0,
        ops: 0,
        attestations: 0,
    };

    // "a verifier distinguishes them by looking for the magic bytes at offset 0 ... a file that
    // does not begin with the magic bytes is read as this form."
    let container = bytes.len() >= MAGIC.len() && bytes[..MAGIC.len()] == MAGIC;
    if container {
        c.pos = MAGIC.len();
        let _version = c.varint()?;
        let hash_tag = c.byte()?;
        let width = match hash_tag {
            0x02 | 0x03 => 20,
            0x08 | 0x67 => 32,
            other => return Err(format!("container names an unknown hash op {other:#04x}")),
        };
        let embedded = c.take(width)?;
        // The starting message is the anchor record's digest in both container forms, so a
        // container carrying a different one is a proof for some other submission.
        if embedded != digest {
            return Err(format!(
                "container is a proof for digest {} but the anchor record submitted {}",
                to_hex(embedded),
                to_hex(digest)
            ));
        }
    }

    let mut attestations = Vec::new();
    walk(&mut c, digest.to_vec(), 0, &mut attestations)?;
    if c.pos != bytes.len() {
        return Err(format!(
            "{} trailing byte(s) after the proof ends",
            bytes.len() - c.pos
        ));
    }
    Ok(Proof {
        attestations,
        container,
    })
}

/// One branch: apply operations to `message` until an attestation terminates it. A fork starts a
/// sub-branch from the message as it stands and then continues this one.
fn walk(
    c: &mut Cursor<'_>,
    mut message: Vec<u8>,
    depth: usize,
    out: &mut Vec<Attestation>,
) -> ParseResult<()> {
    if depth > MAX_FORK_DEPTH {
        return Err(format!("fork nesting deeper than the {MAX_FORK_DEPTH} cap"));
    }
    loop {
        c.ops += 1;
        if c.ops > MAX_OPS {
            return Err(format!(
                "proof applies more than the {MAX_OPS} operation cap"
            ));
        }
        let tag = c.byte()?;
        match tag {
            0x00 => {
                let tag_bytes = c.take(8)?;
                let mut t = [0u8; 8];
                t.copy_from_slice(tag_bytes);
                let payload = c.varbytes()?;
                c.attestations += 1;
                if c.attestations > MAX_ATTESTATIONS {
                    return Err(format!(
                        "proof carries more than the {MAX_ATTESTATIONS} attestation cap"
                    ));
                }
                out.push(read_attestation(t, payload, &message)?);
                return Ok(());
            }
            0xff => {
                walk(c, message.clone(), depth + 1, out)?;
            }
            0xf0 => {
                let arg = c.varbytes()?;
                grow(&message, arg.len())?;
                message.extend_from_slice(arg);
            }
            0xf1 => {
                let arg = c.varbytes()?;
                grow(&message, arg.len())?;
                let mut next = Vec::with_capacity(arg.len() + message.len());
                next.extend_from_slice(arg);
                next.extend_from_slice(&message);
                message = next;
            }
            0xf2 => message.reverse(),
            0xf3 => {
                grow(&message, message.len())?;
                message = to_hex(&message).into_bytes();
            }
            0x02 => message = sha1(&message).to_vec(),
            0x03 => message = ripemd160(&message).to_vec(),
            0x08 => message = sha256(&message).to_vec(),
            0x67 => message = keccak256(&message).to_vec(),
            other => {
                // Unlike an unknown ATTESTATION, which carries a length and can be skipped, an
                // unknown OPERATION has no length and the rest of the stream cannot be located.
                return Err(format!(
                    "unknown operation {other:#04x} at offset {}; the remaining bytes cannot be \
                     located without knowing its length",
                    c.pos - 1
                ));
            }
        }
    }
}

fn grow(message: &[u8], extra: usize) -> ParseResult<()> {
    if message.len() + extra > MAX_MESSAGE {
        return Err(format!(
            "proof grows the message past the {MAX_MESSAGE} byte cap"
        ));
    }
    Ok(())
}

fn read_attestation(tag: [u8; 8], payload: &[u8], message: &[u8]) -> ParseResult<Attestation> {
    if tag == TAG_PENDING {
        let mut inner = Cursor {
            bytes: payload,
            pos: 0,
            ops: 0,
            attestations: 0,
        };
        let uri_bytes = inner.varbytes()?;
        let uri = String::from_utf8(uri_bytes.to_vec())
            .map_err(|_| "pending attestation URI is not UTF-8".to_string())?;
        Ok(Attestation::Pending {
            uri,
            value: message.to_vec(),
        })
    } else if tag == TAG_BITCOIN {
        let mut inner = Cursor {
            bytes: payload,
            pos: 0,
            ops: 0,
            attestations: 0,
        };
        let height = inner.varint()?;
        Ok(Attestation::Bitcoin {
            height,
            value: message.to_vec(),
        })
    } else {
        Ok(Attestation::Unknown { tag })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::from_hex;

    const DIGEST: &str = "d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94";
    const REACHED: &str = "a422fc26d26edb0ea1b4a0b2b421d0d0e7e8d60c814db3d654a5fa2130c0ae00";

    #[test]
    fn the_spec_worked_example_pending_proof() {
        // docs/audit-format.md, "Worked example: a pending proof". The document states the
        // stream is 67 bytes and names the value the attestation covers.
        let stream = from_hex(concat!(
            "f0081122334455667788080083dfe30d2ef90c8e2e2d",
            "68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267"
        ))
        .unwrap();
        assert_eq!(stream.len(), 67);
        let digest = from_hex(DIGEST).unwrap();
        let proof = parse_proof(&stream, &digest).unwrap();
        assert!(!proof.container);
        assert_eq!(proof.attestations.len(), 1);
        match &proof.attestations[0] {
            Attestation::Pending { uri, value } => {
                assert_eq!(uri, "https://alice.btc.calendar.opentimestamps.org");
                assert_eq!(to_hex(value), REACHED);
            }
            other => panic!("expected a pending attestation, got {other:?}"),
        }
    }

    #[test]
    fn the_same_proof_inside_a_full_ots_container() {
        // "As a full .ots file the same proof is the 31 magic bytes, then version varint 01,
        // then hash-op tag 08, then the 32 digest bytes, then the same 67 operation bytes,
        // 132 bytes in all"
        let file = from_hex(concat!(
            "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294",
            "0108",
            "d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94",
            "f0081122334455667788080083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267"
        ))
        .unwrap();
        assert_eq!(file.len(), 132);
        let digest = from_hex(DIGEST).unwrap();
        let proof = parse_proof(&file, &digest).unwrap();
        assert!(proof.container);
        assert_eq!(proof.attestations.len(), 1);
    }

    #[test]
    fn a_container_for_another_digest_is_refused() {
        let mut file = from_hex(concat!(
            "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294",
            "0108",
            "d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94",
            "f0081122334455667788080083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267"
        ))
        .unwrap();
        file[33] ^= 0x01;
        let digest = from_hex(DIGEST).unwrap();
        assert!(parse_proof(&file, &digest).is_err());
    }

    #[test]
    fn the_spec_worked_example_bitcoin_attestation() {
        // "The same operations with a Bitcoin attestation for block height 850000 instead,
        // 24 bytes" and the payload varint decodes to 850000.
        let stream = from_hex(
            "f00811223344556677880800 0588960d73d71901 03 d0f033"
                .replace(' ', "")
                .as_str(),
        )
        .unwrap();
        assert_eq!(stream.len(), 24);
        let digest = from_hex(DIGEST).unwrap();
        let proof = parse_proof(&stream, &digest).unwrap();
        match &proof.attestations[0] {
            Attestation::Bitcoin { height, value } => {
                assert_eq!(*height, 850_000);
                assert_eq!(to_hex(value), REACHED);
            }
            other => panic!("expected a bitcoin attestation, got {other:?}"),
        }
        // The report must never call this confirmed.
        let text = proof.attestations[0].describe();
        assert!(text.contains("cannot confirm offline"));
    }

    #[test]
    fn a_truncated_stream_is_a_parse_error() {
        let mut stream = from_hex(concat!(
            "f0081122334455667788080083dfe30d2ef90c8e2e2d",
            "68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267"
        ))
        .unwrap();
        stream.truncate(stream.len() - 2);
        let digest = from_hex(DIGEST).unwrap();
        assert!(parse_proof(&stream, &digest).is_err());
    }

    #[test]
    fn a_fork_yields_both_branches() {
        // ff <branch: sha256 then pending> then <branch: pending on the unhashed message>
        let mut stream: Vec<u8> = vec![0xff];
        stream.push(0x08); // sha256 on the first branch
        stream.push(0x00);
        stream.extend_from_slice(&TAG_PENDING);
        stream.push(0x03);
        stream.push(0x02);
        stream.extend_from_slice(b"ab");
        // second branch, straight to an attestation
        stream.push(0x00);
        stream.extend_from_slice(&TAG_BITCOIN);
        stream.push(0x03);
        stream.extend_from_slice(&[0xd0, 0xf0, 0x33]);

        let digest = from_hex(DIGEST).unwrap();
        let proof = parse_proof(&stream, &digest).unwrap();
        assert_eq!(proof.attestations.len(), 2);
        match (&proof.attestations[0], &proof.attestations[1]) {
            (Attestation::Pending { uri, value }, Attestation::Bitcoin { height, value: v2 }) => {
                assert_eq!(uri, "ab");
                // The first branch hashed the digest; the second saw it untouched.
                assert_eq!(to_hex(value), to_hex(&sha256(&digest)));
                assert_eq!(to_hex(v2), DIGEST);
                assert_eq!(*height, 850_000);
            }
            other => panic!("unexpected attestations {other:?}"),
        }
    }

    #[test]
    fn an_unknown_attestation_is_skipped_by_its_length() {
        let mut stream: Vec<u8> = vec![0x00];
        stream.extend_from_slice(&[0xaa; 8]);
        stream.push(0x04);
        stream.extend_from_slice(&[1, 2, 3, 4]);
        let digest = from_hex(DIGEST).unwrap();
        let proof = parse_proof(&stream, &digest).unwrap();
        assert_eq!(proof.attestations.len(), 1);
        assert!(matches!(proof.attestations[0], Attestation::Unknown { .. }));
    }

    #[test]
    fn caps_refuse_a_hostile_proof_instead_of_following_it() {
        let digest = from_hex(DIGEST).unwrap();

        // An argument larger than the cap.
        let mut big: Vec<u8> = vec![0xf0];
        big.extend_from_slice(&[0x80, 0x80, 0x80, 0x01]); // varint 2097152
        big.extend_from_slice(&[0u8; 16]);
        assert!(parse_proof(&big, &digest).is_err());

        // A fork bomb: MAX_FORK_DEPTH + 2 nested forks and no attestation in sight.
        let bomb = vec![0xffu8; MAX_FORK_DEPTH + 2];
        assert!(parse_proof(&bomb, &digest).is_err());

        // Endless work: reverse repeated past the operation cap.
        let grind = vec![0xf2u8; MAX_OPS + 8];
        assert!(parse_proof(&grind, &digest).is_err());

        // A varint that never terminates.
        let runaway = vec![
            0xf0u8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        ];
        assert!(parse_proof(&runaway, &digest).is_err());
    }

    #[test]
    fn trailing_bytes_after_the_proof_are_refused() {
        let mut stream = from_hex(concat!(
            "f0081122334455667788080083dfe30d2ef90c8e2e2d",
            "68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267"
        ))
        .unwrap();
        stream.push(0xf2);
        let digest = from_hex(DIGEST).unwrap();
        assert!(parse_proof(&stream, &digest).is_err());
    }

    #[test]
    fn every_hash_operation_is_reachable() {
        // Each op applied to the digest, then a bare unknown attestation so the branch ends.
        for op in [0x02u8, 0x03, 0x08, 0x67, 0xf2, 0xf3] {
            let mut stream: Vec<u8> = vec![op, 0x00];
            stream.extend_from_slice(&[0xaa; 8]);
            stream.push(0x00);
            let digest = from_hex(DIGEST).unwrap();
            assert!(
                parse_proof(&stream, &digest).is_ok(),
                "operation {op:#04x} should be applicable"
            );
        }
    }
}
