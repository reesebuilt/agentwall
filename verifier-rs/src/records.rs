//! Walking one record file: the `chained` layer.
//!
//! "A verifier walks each record file independently, in file order, from the first line."
//!
//! Every rule below is from the "Chain rules" section, and the two that look like leniency are
//! not: a torn final line is reported without failing the layer because "a verifier that called
//! that tampering would cry wolf on every hard kill", and a gap declaration is reported without
//! excusing anything because "A verifier MUST NOT let a declaration excuse anything."

use std::path::{Path, PathBuf};

use crate::canon::{canonical_payload, hash_material, payload_is_clean};
use crate::hex::{is_sha256_hex, to_hex};
use crate::json::{self, ParseError};
use crate::report::Problem;
use crate::sha2::sha256;

/// One record that counted: it parsed, it had a well formed `integrity` block, and no duplicate
/// key. A record that failed any of those "counts toward NOTHING" and never reaches this struct.
#[derive(Debug, Clone)]
pub struct Record {
    pub line_no: usize,
    pub chain_index: i64,
    /// `integrity.hash` as stored on the line. The format's live-tail rebuild asks for "that
    /// record's `integrity.hash`", which names this member, so this is the value offered as a
    /// candidate there even when `hash_ok` is false.
    pub stored_hash: String,
    pub previous_hash: Option<String>,
    /// Whether the stored hash equals the recomputation under cu1.
    pub hash_ok: bool,
}

pub struct FileScan {
    pub path: PathBuf,
    pub records: Vec<Record>,
    pub problems: Vec<Problem>,
    /// Set when the file is not readable at all. The caller decides what that means: for the
    /// live audit file it is a usage error, for a manifest-named segment it is `segment-missing`
    /// on the `linked` layer.
    pub unreadable: bool,
}

pub fn scan_file(path: &Path) -> FileScan {
    let mut scan = FileScan {
        path: path.to_path_buf(),
        records: Vec::new(),
        problems: Vec::new(),
        unreadable: false,
    };

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            scan.unreadable = true;
            return scan;
        }
    };

    let name = path.display().to_string();
    // Split on LF. "A line that is empty or contains only whitespace is not a record and is
    // ignored", which is what makes the trailing LF of the final record harmless.
    let chunks: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    let last_content = chunks
        .iter()
        .rposition(|c| !c.iter().all(|b| b.is_ascii_whitespace()));

    let mut previous: Option<Record> = None;

    for (i, chunk) in chunks.iter().enumerate() {
        if chunk.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let line_no = i + 1;
        let is_final = Some(i) == last_content;

        let text = match std::str::from_utf8(chunk) {
            Ok(t) => t,
            Err(e) => {
                // An incomplete trailing UTF-8 sequence on the final line is the same kill that
                // produces a torn tail; anything else is a corrupt line.
                if is_final && e.error_len().is_none() {
                    scan.problems.push(torn(&name, line_no));
                } else {
                    scan.problems.push(Problem::fatal(
                        "line-not-utf8",
                        format!("{name}:{line_no} is not valid UTF-8"),
                    ));
                }
                continue;
            }
        };

        let parsed = match json::parse(text) {
            Ok(v) => v,
            Err(ParseError::Truncated) if is_final => {
                scan.problems.push(torn(&name, line_no));
                continue;
            }
            Err(ParseError::DuplicateKey(key)) => {
                scan.problems.push(Problem::fatal(
                    "shadowed-key",
                    format!(
                        "{name}:{line_no} has two members named {key:?} in one object, so what \
                         the record says depends on which parser reads it; it counts toward no \
                         chain link, no segment count and no committed live tail"
                    ),
                ));
                continue;
            }
            Err(e) => {
                scan.problems.push(Problem::fatal(
                    "line-not-json",
                    format!("{name}:{line_no} is not valid JSON: {e}"),
                ));
                continue;
            }
        };

        let Some(record) = parsed.as_object() else {
            scan.problems.push(Problem::fatal(
                "record-not-object",
                format!("{name}:{line_no} is not a JSON object"),
            ));
            continue;
        };

        let Some(integrity) = record.get("integrity").and_then(|v| v.as_object()) else {
            scan.problems.push(Problem::fatal(
                "no-integrity",
                format!("{name}:{line_no} has no integrity object"),
            ));
            continue;
        };

        // chainIndex, reusing the source lexeme for the hash material and the parsed value for
        // index arithmetic. The format guarantees a conforming writer emits a plain base-10
        // integer, so a lexeme that is not one has no defined hash material.
        let Some(index_value) = integrity.get("chainIndex") else {
            scan.problems.push(Problem::fatal(
                "no-chain-index",
                format!("{name}:{line_no} integrity has no chainIndex"),
            ));
            continue;
        };
        let (Some(index_lexeme), Some(chain_index)) = (index_value.lexeme(), index_value.as_i64())
        else {
            scan.problems.push(Problem::fatal(
                "chain-index-not-integer",
                format!("{name}:{line_no} chainIndex is not a plain base-10 integer"),
            ));
            continue;
        };
        if chain_index < 0 {
            scan.problems.push(Problem::fatal(
                "chain-index-negative",
                format!("{name}:{line_no} chainIndex {chain_index} is negative"),
            ));
            continue;
        }

        let stored_hash = match integrity.get("hash").and_then(|v| v.as_str()) {
            Some(h) if is_sha256_hex(&h) => h,
            _ => {
                scan.problems.push(Problem::fatal(
                    "hash-not-lowercase-hex",
                    format!("{name}:{line_no} integrity.hash is not 64 lowercase hex characters"),
                ));
                continue;
            }
        };

        let previous_value = integrity.get("previousHash");
        let (previous_lexeme, previous_hash) = match previous_value {
            None => {
                scan.problems.push(Problem::fatal(
                    "no-previous-hash",
                    format!("{name}:{line_no} integrity has no previousHash"),
                ));
                continue;
            }
            Some(v) if v.is_null() => ("null".to_string(), None),
            Some(v) => match v.as_str() {
                Some(h) if is_sha256_hex(&h) => (v.lexeme().unwrap_or("").to_string(), Some(h)),
                _ => {
                    scan.problems.push(Problem::fatal(
                        "previous-hash-malformed",
                        format!(
                            "{name}:{line_no} previousHash is neither null nor 64 lowercase hex"
                        ),
                    ));
                    continue;
                }
            },
        };

        // The literal "sha256" is spelled into the hash material by the format, so a record
        // naming another algorithm has no derivation at all rather than a different one.
        match integrity
            .get("algorithm")
            .and_then(|v| v.as_str())
            .as_deref()
        {
            Some("sha256") => {}
            other => {
                scan.problems.push(Problem::fatal(
                    "algorithm-unknown",
                    format!(
                        "{name}:{line_no} integrity.algorithm is {:?}, and this format defines \
                         a derivation only for sha256",
                        other.unwrap_or("absent")
                    ),
                ));
                continue;
            }
        }

        // canon absent is meaningful; canon present and not cu1 has no defined derivation.
        let canon_marker = integrity.get("canon").and_then(|v| v.as_str());
        match canon_marker.as_deref() {
            None | Some("cu1") => {}
            Some(other) => {
                scan.problems.push(Problem::fatal(
                    "canon-unknown",
                    format!(
                        "{name}:{line_no} integrity.canon is {other:?}, which this document \
                         does not define"
                    ),
                ));
                continue;
            }
        }

        let payload = canonical_payload(record);
        if !payload_is_clean(&payload) {
            scan.problems.push(Problem::fatal(
                "payload-has-control-byte",
                format!("{name}:{line_no} canonical payload holds a byte below 0x20"),
            ));
            continue;
        }
        let recomputed = to_hex(&sha256(
            hash_material(index_lexeme, &previous_lexeme, &payload).as_bytes(),
        ));
        let hash_ok = recomputed == stored_hash;
        if !hash_ok {
            if canon_marker.is_some() {
                scan.problems.push(Problem::fatal(
                    "hash-broken",
                    format!(
                        "{name}:{line_no} index {chain_index} carries {stored_hash} but cu1 \
                         derives {recomputed}"
                    ),
                ));
            } else {
                // "it reports that the record either was altered or predates cu1, without
                // claiming to know which, because from the file alone it cannot tell."
                scan.problems.push(Problem::fatal(
                    "hash-broken-or-pre-cu1",
                    format!(
                        "{name}:{line_no} index {chain_index} carries no canon marker and cu1 \
                         derives {recomputed}, not {stored_hash}; the record was either altered \
                         or written under the earlier collation-ordered form, and the file alone \
                         cannot say which"
                    ),
                ));
            }
        }

        // Linkage against the previous COUNTABLE record, so a malformed line between two good
        // records leaves them judged against each other.
        match &previous {
            None => {
                if previous_hash.is_none() && chain_index != 0 {
                    scan.problems.push(Problem::fatal(
                        "null-link-at-nonzero-index",
                        format!(
                            "{name}:{line_no} opens the file at index {chain_index} with a null \
                             previousHash; only index 0 may do that"
                        ),
                    ));
                }
            }
            Some(prev) => {
                if chain_index != prev.chain_index + 1 {
                    scan.problems.push(Problem::fatal(
                        "index-not-contiguous",
                        format!(
                            "{name}:{line_no} index {chain_index} follows index {}; the chain \
                             must advance by exactly one",
                            prev.chain_index
                        ),
                    ));
                }
                match &previous_hash {
                    Some(p) if *p == prev.stored_hash => {}
                    Some(p) => scan.problems.push(Problem::fatal(
                        "link-broken",
                        format!(
                            "{name}:{line_no} points back at {p} but the preceding record is {}",
                            prev.stored_hash
                        ),
                    )),
                    None => scan.problems.push(Problem::fatal(
                        "link-broken",
                        format!("{name}:{line_no} has a null previousHash mid-file"),
                    )),
                }
            }
        }

        // A declared gap is reported and excuses nothing: every check above already ran.
        if record.get("action").and_then(|v| v.as_str()).as_deref() == Some("audit:chain-gap") {
            let dropped = record
                .get("metadata")
                .and_then(|v| v.as_object())
                .and_then(|m| m.get("droppedRecords"))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| "an unstated number of".to_string());
            scan.problems.push(Problem::note(
                "chain-gap-declared",
                format!(
                    "{name}:{line_no} declares {dropped} record(s) produced and not stored; the \
                     chain stays contiguous across them, so this is the writer's account of a \
                     hole and not a licence to have one, and absence of such a record is not \
                     proof that nothing was lost"
                ),
            ));
        }

        let rec = Record {
            line_no,
            chain_index,
            stored_hash,
            previous_hash,
            hash_ok,
        };
        scan.records.push(rec.clone());
        previous = Some(rec);
    }

    // "Many records but few distinct indexes is the signature of two processes each keeping
    // their own chain state and appending to one file, not of an edit." Reported as its own
    // diagnosis alongside the contiguity failures those records already produced.
    let mut indexes: Vec<i64> = scan.records.iter().map(|r| r.chain_index).collect();
    indexes.sort_unstable();
    let distinct = {
        let mut d = indexes.clone();
        d.dedup();
        d.len()
    };
    if distinct < scan.records.len() {
        scan.problems.push(Problem::note(
            "index-reused",
            format!(
                "{name} holds {} records across {distinct} distinct indexes, which is the shape \
                 of two writers appending to one file rather than of an edit",
                scan.records.len()
            ),
        ));
    }

    scan
}

fn torn(name: &str, line_no: usize) -> Problem {
    Problem::note(
        "torn-tail",
        format!(
            "{name}:{line_no} ends mid-value; a process killed mid-append leaves exactly one \
             such line legitimately, and the records before it are complete and still chain"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_with(lines: &str) -> (tempdir::Dir, PathBuf) {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("audit.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(lines.as_bytes()).unwrap();
        (dir, path)
    }

    /// Minimal scratch directory helper, so the tests need no dev-dependency either.
    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                let base = std::env::temp_dir().join(format!(
                    "agentwall-rs-test-{}-{:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&base).unwrap();
                Dir(base)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    /// Build a record line whose hash is correct by construction.
    fn record(index: i64, previous: Option<&str>, marker: &str) -> String {
        let payload = format!(r#"{{"marker":"{marker}"}}"#);
        let prev_lex = match previous {
            None => "null".to_string(),
            Some(p) => format!("\"{p}\""),
        };
        let hash = to_hex(&sha256(
            hash_material(&index.to_string(), &prev_lex, &payload).as_bytes(),
        ));
        format!(
            r#"{{"marker":"{marker}","integrity":{{"chainIndex":{index},"hash":"{hash}","previousHash":{prev_lex},"algorithm":"sha256","status":"chained-local","canon":"cu1"}}}}"#
        )
    }

    fn hash_of(line: &str) -> String {
        let v = json::parse(line).unwrap();
        v.as_object()
            .unwrap()
            .get("integrity")
            .unwrap()
            .as_object()
            .unwrap()
            .get("hash")
            .unwrap()
            .as_str()
            .unwrap()
    }

    #[test]
    fn a_clean_chain_reports_nothing() {
        let a = record(0, None, "a");
        let b = record(1, Some(&hash_of(&a)), "b");
        let (_d, p) = temp_with(&format!("{a}\n{b}\n"));
        let scan = scan_file(&p);
        assert_eq!(scan.records.len(), 2);
        assert!(scan.problems.is_empty(), "{:?}", scan.problems);
        assert!(scan.records.iter().all(|r| r.hash_ok));
    }

    #[test]
    fn a_file_may_start_at_a_nonzero_index_when_it_links_back() {
        // "A file need not start at 0, because a chain that continues across a rotation starts
        // its next file at the index it had reached."
        let earlier = record(5, None, "x");
        let a = record(6, Some(&hash_of(&earlier)), "a");
        let (_d, p) = temp_with(&format!("{a}\n"));
        let scan = scan_file(&p);
        assert!(scan.problems.is_empty(), "{:?}", scan.problems);
    }

    #[test]
    fn a_nonzero_first_index_with_a_null_link_is_a_break() {
        let a = record(6, None, "a");
        let (_d, p) = temp_with(&format!("{a}\n"));
        let scan = scan_file(&p);
        assert!(scan
            .problems
            .iter()
            .any(|x| x.code == "null-link-at-nonzero-index" && x.fatal));
    }

    #[test]
    fn a_torn_final_line_is_reported_without_failing() {
        let a = record(0, None, "a");
        let (_d, p) = temp_with(&format!("{a}\n{{\"id\":\"half"));
        let scan = scan_file(&p);
        assert_eq!(scan.records.len(), 1);
        assert_eq!(scan.problems.len(), 1);
        assert_eq!(scan.problems[0].code, "torn-tail");
        assert!(!scan.problems[0].fatal);
    }

    #[test]
    fn a_broken_line_that_is_not_final_is_fatal() {
        let a = record(0, None, "a");
        let (_d, p) = temp_with(&format!("{a}\n{{\"id\":\"half\nsomething\n"));
        let scan = scan_file(&p);
        assert!(scan
            .problems
            .iter()
            .any(|x| x.code == "line-not-json" && x.fatal));
    }

    #[test]
    fn a_shadowed_key_counts_toward_nothing_and_neighbours_face_each_other() {
        let a = record(0, None, "a");
        let b = record(1, Some(&hash_of(&a)), "b");
        let c = record(2, Some(&hash_of(&b)), "c");
        let shadowed = b.replacen(r#""marker":"b""#, r#""marker":"b","marker":"b2""#, 1);
        let (_d, p) = temp_with(&format!("{a}\n{shadowed}\n{c}\n"));
        let scan = scan_file(&p);
        assert_eq!(scan.records.len(), 2, "the shadowed line must not count");
        assert!(scan
            .problems
            .iter()
            .any(|x| x.code == "shadowed-key" && x.fatal));
        // a and c are now judged against each other: 0 then 2 is not contiguous, and c points
        // back at b which no longer counts.
        assert!(scan
            .problems
            .iter()
            .any(|x| x.code == "index-not-contiguous"));
        assert!(scan.problems.iter().any(|x| x.code == "link-broken"));
    }

    #[test]
    fn a_gap_declaration_reports_but_excuses_nothing() {
        // The declaration sits on a contiguous, correctly linked chain: reported, not fatal.
        let a = record(0, None, "a");
        let payload = r#"{"action":"audit:chain-gap","metadata":{"droppedRecords":"4"}}"#;
        let prev = format!("\"{}\"", hash_of(&a));
        let hash = to_hex(&sha256(hash_material("1", &prev, payload).as_bytes()));
        let gap = format!(
            r#"{{"action":"audit:chain-gap","metadata":{{"droppedRecords":"4"}},"integrity":{{"chainIndex":1,"hash":"{hash}","previousHash":{prev},"algorithm":"sha256","status":"chained-local","canon":"cu1"}}}}"#
        );
        let (_d, p) = temp_with(&format!("{a}\n{gap}\n"));
        let scan = scan_file(&p);
        assert_eq!(scan.problems.len(), 1);
        assert_eq!(scan.problems[0].code, "chain-gap-declared");
        assert!(!scan.problems[0].fatal);
        assert!(scan.problems[0].text.contains('4'));
    }

    #[test]
    fn a_declaration_does_not_excuse_a_real_gap() {
        // Same declaration, but the index jumps. The gap is judged exactly as if the
        // declaration were absent.
        let a = record(0, None, "a");
        let payload = r#"{"action":"audit:chain-gap","metadata":{"droppedRecords":"4"}}"#;
        let prev = format!("\"{}\"", hash_of(&a));
        let hash = to_hex(&sha256(hash_material("7", &prev, payload).as_bytes()));
        let gap = format!(
            r#"{{"action":"audit:chain-gap","metadata":{{"droppedRecords":"4"}},"integrity":{{"chainIndex":7,"hash":"{hash}","previousHash":{prev},"algorithm":"sha256","status":"chained-local","canon":"cu1"}}}}"#
        );
        let (_d, p) = temp_with(&format!("{a}\n{gap}\n"));
        let scan = scan_file(&p);
        assert!(scan.problems.iter().any(|x| x.code == "chain-gap-declared"));
        assert!(
            scan.problems
                .iter()
                .any(|x| x.code == "index-not-contiguous" && x.fatal),
            "a declaration must not turn an index jump into an excused one"
        );
    }

    #[test]
    fn an_edited_field_breaks_the_hash_but_not_the_links() {
        // The forgery of b1: change a value, leave every stored hash alone.
        let a = record(0, None, "a");
        let b = record(1, Some(&hash_of(&a)), "b");
        let flipped = b.replacen(r#""marker":"b""#, r#""marker":"Z""#, 1);
        let (_d, p) = temp_with(&format!("{a}\n{flipped}\n"));
        let scan = scan_file(&p);
        assert!(scan
            .problems
            .iter()
            .any(|x| x.code == "hash-broken" && x.fatal));
        assert!(!scan.problems.iter().any(|x| x.code == "link-broken"));
        // The stored hash is still offered to the live-tail rebuild, which is what makes the
        // anchored layer independent of this failure.
        assert_eq!(scan.records.len(), 2);
        assert!(!scan.records[1].hash_ok);
        assert_eq!(scan.records[1].stored_hash, hash_of(&b));
    }

    #[test]
    fn a_record_without_a_canon_marker_is_reported_as_undecidable() {
        let a = record(0, None, "a");
        let legacy = a.replacen(r#","canon":"cu1""#, "", 1);
        // Recomputation still runs; here it happens to match, so nothing is reported.
        let (_d, p) = temp_with(&format!("{legacy}\n"));
        assert!(scan_file(&p).problems.is_empty());

        // When it does not match, the finding must not claim to know which cause it was.
        let broken = legacy.replacen(r#""marker":"a""#, r#""marker":"Z""#, 1);
        let (_d2, p2) = temp_with(&format!("{broken}\n"));
        let scan = scan_file(&p2);
        let found = scan
            .problems
            .iter()
            .find(|x| x.code == "hash-broken-or-pre-cu1")
            .expect("expected the undecidable diagnosis");
        assert!(found.fatal);
        assert!(found.text.contains("cannot say which"));
    }

    #[test]
    fn an_unknown_canon_marker_has_no_derivation() {
        let a = record(0, None, "a").replacen(r#""canon":"cu1""#, r#""canon":"cu2""#, 1);
        let (_d, p) = temp_with(&format!("{a}\n"));
        assert!(scan_file(&p)
            .problems
            .iter()
            .any(|x| x.code == "canon-unknown" && x.fatal));
    }

    #[test]
    fn a_wrong_algorithm_has_no_derivation() {
        let a =
            record(0, None, "a").replacen(r#""algorithm":"sha256""#, r#""algorithm":"sha512""#, 1);
        let (_d, p) = temp_with(&format!("{a}\n"));
        assert!(scan_file(&p)
            .problems
            .iter()
            .any(|x| x.code == "algorithm-unknown" && x.fatal));
    }

    #[test]
    fn a_writer_status_this_verifier_does_not_recognise_is_not_a_failure() {
        // "status is deliberately not verified ... It is not a verification result, and a
        // verifier MUST NOT treat it as one." Treating an unexpected value as fatal would be
        // treating it as one.
        let a = record(0, None, "a").replacen(
            r#""status":"chained-local""#,
            r#""status":"something-else""#,
            1,
        );
        let (_d, p) = temp_with(&format!("{a}\n"));
        assert!(scan_file(&p).problems.is_empty());
    }

    #[test]
    fn blank_lines_and_a_trailing_newline_are_not_records() {
        let a = record(0, None, "a");
        let b = record(1, Some(&hash_of(&a)), "b");
        let (_d, p) = temp_with(&format!("{a}\n\n   \n{b}\n"));
        let scan = scan_file(&p);
        assert_eq!(scan.records.len(), 2);
        assert!(scan.problems.is_empty(), "{:?}", scan.problems);
    }
}
