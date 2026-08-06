//! The rotation manifest: the `linked` layer.
//!
//! Three self-checks plus one check against the bytes. The document is blunt about why the
//! fourth exists: a verifier that checks the manifest only against itself "can be handed a
//! segment rewritten from end to end, with its own per-record chain rebuilt so it verifies, and
//! will report the `linked` layer as passing."

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::hex::{is_sha256_hex, to_hex};
use crate::json::{self, Object};
use crate::records::FileScan;
use crate::report::Problem;
use crate::sha2::sha256;

pub struct Entry {
    /// `path` exactly as recorded, for messages.
    pub recorded_path: String,
    pub resolved: PathBuf,
    pub count: i64,
    pub first_index: i64,
    pub last_index: i64,
    pub final_hash: String,
}

pub struct Manifest {
    pub present: bool,
    pub entries: Vec<Entry>,
    pub problems: Vec<Problem>,
}

/// Rebuild an entry's hashed bytes from its members, in the order this document fixes, "which is
/// unrelated to the order the members happen to appear in on the line".
fn entry_material(o: &Object<'_>) -> Option<String> {
    let lex = |name: &str| o.get(name).and_then(|v| v.lexeme());
    Some(format!(
        r#"{{"path":{},"count":{},"firstIndex":{},"lastIndex":{},"finalHash":{},"previousSegmentHash":{},"sealedAt":{}}}"#,
        lex("path")?,
        lex("count")?,
        lex("firstIndex")?,
        lex("lastIndex")?,
        lex("finalHash")?,
        lex("previousSegmentHash")?,
        lex("sealedAt")?,
    ))
}

pub fn load(manifest_path: &Path) -> Manifest {
    let mut m = Manifest {
        present: false,
        entries: Vec::new(),
        problems: Vec::new(),
    };

    let bytes = match std::fs::read(manifest_path) {
        Ok(b) => b,
        Err(_) => return m,
    };
    m.present = true;

    // "A relative `path` resolves against the directory containing the manifest file ... A
    // verifier MUST NOT resolve a relative `path` against its own working directory: the same
    // evidence would then verify from one directory and fail from another."
    let base = manifest_path.parent().unwrap_or(Path::new("."));
    let name = manifest_path.display().to_string();

    let mut previous_final: Option<String> = None;

    for (i, chunk) in bytes.split(|&b| b == b'\n').enumerate() {
        if chunk.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let line_no = i + 1;
        let Ok(text) = std::str::from_utf8(chunk) else {
            m.problems.push(Problem::fatal(
                "manifest-line-unreadable",
                format!("{name}:{line_no} is not valid UTF-8"),
            ));
            continue;
        };
        let parsed = match json::parse(text) {
            Ok(v) => v,
            Err(e) => {
                m.problems.push(Problem::fatal(
                    "manifest-line-unreadable",
                    format!("{name}:{line_no} is not a readable manifest entry: {e}"),
                ));
                continue;
            }
        };
        let Some(o) = parsed.as_object() else {
            m.problems.push(Problem::fatal(
                "manifest-line-unreadable",
                format!("{name}:{line_no} is not a JSON object"),
            ));
            continue;
        };

        let (
            Some(recorded_path),
            Some(count),
            Some(first_index),
            Some(last_index),
            Some(final_hash),
            Some(entry_hash),
        ) = (
            o.get("path").and_then(|v| v.as_str()),
            o.get("count").and_then(|v| v.as_i64()),
            o.get("firstIndex").and_then(|v| v.as_i64()),
            o.get("lastIndex").and_then(|v| v.as_i64()),
            o.get("finalHash").and_then(|v| v.as_str()),
            o.get("entryHash").and_then(|v| v.as_str()),
        )
        else {
            m.problems.push(Problem::fatal(
                "manifest-entry-incomplete",
                format!("{name}:{line_no} is missing a member the format requires"),
            ));
            continue;
        };

        let previous_segment_hash = match o.get("previousSegmentHash") {
            None => {
                m.problems.push(Problem::fatal(
                    "manifest-entry-incomplete",
                    format!("{name}:{line_no} has no previousSegmentHash"),
                ));
                continue;
            }
            Some(v) if v.is_null() => None,
            Some(v) => v.as_str(),
        };

        match entry_material(o) {
            None => {
                m.problems.push(Problem::fatal(
                    "manifest-entry-incomplete",
                    format!("{name}:{line_no} cannot be rebuilt for hashing"),
                ));
                continue;
            }
            Some(material) => {
                let recomputed = to_hex(&sha256(material.as_bytes()));
                if recomputed != entry_hash {
                    m.problems.push(Problem::fatal(
                        "manifest-entry-edited",
                        format!(
                            "{name}:{line_no} carries entryHash {entry_hash} but its members \
                             hash to {recomputed}"
                        ),
                    ));
                }
            }
        }

        // Linkage. The first entry must open with null; every later entry must name the
        // previous entry's finalHash.
        match (&previous_final, &previous_segment_hash) {
            (None, Some(p)) => m.problems.push(Problem::fatal(
                "manifest-chain-broken",
                format!("{name}:{line_no} is the first entry but points back at {p}"),
            )),
            (Some(expected), None) => m.problems.push(Problem::fatal(
                "manifest-chain-broken",
                format!(
                    "{name}:{line_no} has a null previousSegmentHash mid-manifest; it should \
                     name {expected}"
                ),
            )),
            (Some(expected), Some(p)) if p != expected => m.problems.push(Problem::fatal(
                "manifest-chain-broken",
                format!(
                    "{name}:{line_no} points back at {p}, but the previous entry is {expected}"
                ),
            )),
            _ => {}
        }

        if !is_sha256_hex(&final_hash) {
            m.problems.push(Problem::fatal(
                "manifest-entry-incomplete",
                format!("{name}:{line_no} finalHash is not 64 lowercase hex characters"),
            ));
        }

        previous_final = Some(final_hash.clone());

        let candidate = Path::new(&recorded_path);
        let resolved = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            base.join(candidate)
        };

        m.entries.push(Entry {
            recorded_path,
            resolved,
            count,
            first_index,
            last_index,
            final_hash,
        });
    }

    m
}

/// Check every entry against the segment it names, and report rotated files that no entry
/// vouches for.
///
/// `lookup` returns the scan of a segment, or `None` when the file is not on disk.
pub fn check_against_disk<'a>(
    manifest: &Manifest,
    lookup: impl Fn(&Path) -> Option<&'a FileScan>,
    rotated_on_disk: &[PathBuf],
) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut vouched: HashSet<PathBuf> = HashSet::new();

    for entry in &manifest.entries {
        vouched.insert(entry.resolved.clone());
        let recorded = &entry.recorded_path;

        let Some(scan) = lookup(&entry.resolved) else {
            // "A segment the manifest names but that is absent from disk is a DIFFERENT
            // finding, reported as missing rather than as a content difference."
            problems.push(Problem::fatal(
                "segment-missing",
                format!(
                    "{recorded} is named by the manifest but is not on disk; absent evidence and \
                     contradicting evidence lead an operator to different places, so this is not \
                     reported as a content difference"
                ),
            ));
            continue;
        };

        // "A present file holding no readable record MUST be reported the same way. Truncating a
        // sealed segment to nothing leaves the file in place, so presence alone is not the test."
        let Some(last) = scan.records.last() else {
            problems.push(Problem::fatal(
                "segment-contradicts-manifest",
                format!("{recorded} is on disk but holds no readable record, while the manifest vouches for {} of them", entry.count),
            ));
            continue;
        };
        let first = &scan.records[0];

        if last.stored_hash != entry.final_hash {
            problems.push(Problem::fatal(
                "segment-contradicts-manifest",
                format!(
                    "{recorded} ends at {} but the manifest seals it at {}",
                    last.stored_hash, entry.final_hash
                ),
            ));
        }
        if scan.records.len() as i64 != entry.count {
            problems.push(Problem::fatal(
                "segment-contradicts-manifest",
                format!(
                    "{recorded} holds {} records but the manifest counts {}",
                    scan.records.len(),
                    entry.count
                ),
            ));
        }
        if first.chain_index != entry.first_index || last.chain_index != entry.last_index {
            problems.push(Problem::fatal(
                "segment-contradicts-manifest",
                format!(
                    "{recorded} spans indexes {}..{} but the manifest records {}..{}",
                    first.chain_index, last.chain_index, entry.first_index, entry.last_index
                ),
            ));
        }
    }

    // "Rotated files present on disk but absent from the manifest sit outside the anchor and are
    // reported."
    //
    // Reported, and NOT fatal. The document says "is a failure" where it means fatal, and here
    // says only "are reported". The checkpoint section settles it: at "Re-deriving what a
    // checkpoint committed" it names "closed segments still awaiting a seal" as an ELIGIBLE
    // source for a committed live tail, so that state is a normal moment between a rotation and
    // its seal. Failing the layer for it would cry wolf on a healthy deployment, which is the
    // reasoning the format itself uses to keep a torn tail non-fatal.
    for path in rotated_on_disk {
        if vouched.contains(path) {
            continue;
        }
        problems.push(Problem::note(
            "segment-unsealed",
            format!(
                "{} is a rotated file that no manifest entry vouches for, so it sits outside \
                 the anchor; this is the expected state between a rotation and its seal",
                path.display()
            ),
        ));
    }

    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuilds_the_spec_worked_example_entry_hash() {
        let line = r#"{"path":"audit.1.jsonl","count":2,"firstIndex":0,"lastIndex":1,"finalHash":"8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428","previousSegmentHash":null,"sealedAt":"2026-01-01T00:00:02.000Z"}"#;
        let v = json::parse(line).unwrap();
        let material = entry_material(v.as_object().unwrap()).unwrap();
        assert_eq!(material, line);
        assert_eq!(
            to_hex(&sha256(material.as_bytes())),
            "6172869bd41e220a1ee64372e9aea4a68d8b11e9bb675a6f11611a2890d5f861"
        );
    }

    #[test]
    fn entry_material_uses_the_documents_order_not_the_lines_order() {
        // Same members, shuffled on disk. The hashed bytes must be identical.
        let shuffled = r#"{"sealedAt":"2026-01-01T00:00:02.000Z","finalHash":"8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428","count":2,"path":"audit.1.jsonl","previousSegmentHash":null,"lastIndex":1,"firstIndex":0}"#;
        let v = json::parse(shuffled).unwrap();
        assert_eq!(
            to_hex(&sha256(
                entry_material(v.as_object().unwrap()).unwrap().as_bytes()
            )),
            "6172869bd41e220a1ee64372e9aea4a68d8b11e9bb675a6f11611a2890d5f861"
        );
    }
}
