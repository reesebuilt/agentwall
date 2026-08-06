//! Checkpoints, the anchor log, and the `anchored` layer.
//!
//! Four things are checked per anchor record, and the document names each as a failure of this
//! layer: the record's `digest` must describe the checkpoint it carries, the signature must
//! verify against the key the checkpoint carries (and against an operator's pin when one is
//! given), the committed composite must be rebuildable from the evidence on disk, and the proof
//! the record points at must be present and parseable.
//!
//! The counters are a separate output from the verdict and are deliberately not derived from the
//! proof. `status` is the backend state the writer recorded, with exactly one override: "`error`
//! set means the submission never reached a calendar. Such a record counts as failed whatever
//! its `status` says." Nothing else in the document overrides it, and the conformance checklist
//! enumerates that one override alone.
//!
//! That is safe only because every attestation actually reached is reported alongside the
//! counts, which the document requires anyway: a reader who sees `confirmed: 1` sees, beside it,
//! that the proof reaches a pending attestation at a named calendar and nothing more.

use std::path::{Path, PathBuf};

use crate::base64;
use crate::ed25519;
use crate::hex::{from_hex, is_sha256_hex, to_hex};
use crate::json::{self, Object};
use crate::manifest::{Entry, Manifest};
use crate::ots;
use crate::records::FileScan;
use crate::report::Problem;
use crate::sha2::sha256;

pub struct Outcome {
    pub problems: Vec<Problem>,
    pub pending: usize,
    pub confirmed: usize,
    pub failed: usize,
    pub records: usize,
    /// Set when no pin was supplied, to be printed once rather than per record.
    pub unpinned: bool,
}

/// Everything a committed live tail could have been written to.
pub struct TailSources<'a> {
    pub live: &'a FileScan,
    /// Rotated files on disk that no manifest entry vouches for: "closed segments still awaiting
    /// a seal".
    pub unsealed: Vec<&'a FileScan>,
    /// Manifest entries paired with their segment scan when the file is present.
    pub sealed: Vec<(&'a Entry, Option<&'a FileScan>)>,
}

pub fn verify(
    anchors_path: &Path,
    proofs_dir: &Path,
    manifest: &Manifest,
    tails: &TailSources<'_>,
    pin: Option<&str>,
) -> Outcome {
    let mut out = Outcome {
        problems: Vec::new(),
        pending: 0,
        confirmed: 0,
        failed: 0,
        records: 0,
        unpinned: pin.is_none(),
    };

    let bytes = match std::fs::read(anchors_path) {
        Ok(b) => b,
        Err(_) => {
            out.problems.push(no_anchor_evidence(anchors_path));
            return out;
        }
    };

    let name = anchors_path.display().to_string();
    for (i, chunk) in bytes.split(|&b| b == b'\n').enumerate() {
        if chunk.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let line_no = i + 1;
        let Ok(text) = std::str::from_utf8(chunk) else {
            out.records += 1;
            out.failed += 1;
            out.problems.push(Problem::fatal(
                "anchor-line-unreadable",
                format!("{name}:{line_no} is not valid UTF-8"),
            ));
            continue;
        };
        let parsed = match json::parse(text) {
            Ok(v) => v,
            Err(e) => {
                out.records += 1;
                out.failed += 1;
                out.problems.push(Problem::fatal(
                    "anchor-line-unreadable",
                    format!("{name}:{line_no} is not a readable anchor record: {e}"),
                ));
                continue;
            }
        };
        let Some(record) = parsed.as_object() else {
            out.records += 1;
            out.failed += 1;
            out.problems.push(Problem::fatal(
                "anchor-line-unreadable",
                format!("{name}:{line_no} is not a JSON object"),
            ));
            continue;
        };
        out.records += 1;
        check_record(
            record, &name, line_no, proofs_dir, manifest, tails, pin, &mut out,
        );
    }

    if out.records == 0 {
        out.problems.push(no_anchor_evidence(anchors_path));
    }
    out
}

/// The document never states what `anchored` reports when there is no anchor at all. It is
/// resolved as a failure because the layer's evidence, per the table at the top of the format,
/// is "Signed checkpoint plus an off-box timestamp": with neither on disk the layer's question
/// has no answer, and reporting a pass would be the overclaim the format spends a whole section
/// warning against. Note this is NOT symmetric with an empty rotation manifest, which is a
/// vacuous pass: "was a whole rotated file removed" really is answerable as no when there are no
/// rotated files, while "was the entire local history rewritten" is not answerable from local
/// files alone. The corpus pins both readings; the document states neither.
fn no_anchor_evidence(path: &Path) -> Problem {
    Problem::fatal(
        "nothing-anchored",
        format!(
            "no anchor record at {}, so nothing here bounds when this history existed; the \
             record chain may verify perfectly and still have been written wholesale a moment ago",
            path.display()
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn check_record(
    record: &Object<'_>,
    name: &str,
    line_no: usize,
    proofs_dir: &Path,
    manifest: &Manifest,
    tails: &TailSources<'_>,
    pin: Option<&str>,
    out: &mut Outcome,
) {
    let where_ = format!("{name}:{line_no}");

    // Counters first, so a record that is malformed further down still lands in exactly one
    // bucket. "A verifier counts each record as exactly one of confirmed, pending, or failed."
    let error = record.get("error").and_then(|v| v.as_str());
    let status = record.get("status").and_then(|v| v.as_str());
    match (&error, status.as_deref()) {
        (Some(e), _) => {
            out.failed += 1;
            out.problems.push(Problem::fatal(
                "anchor-never-reached-a-calendar",
                format!(
                    "{where_} records an error, {e:?}, so the submission never reached a \
                     calendar; it counts as failed whatever its status says"
                ),
            ));
        }
        (None, Some("confirmed")) => out.confirmed += 1,
        (None, Some("pending")) => out.pending += 1,
        (None, other) => {
            // The format enumerates exactly two values for `status` and requires each record to
            // land in exactly one of three counters. A record with neither value has no bucket,
            // so it is counted failed and reported.
            out.failed += 1;
            out.problems.push(Problem::fatal(
                "anchor-status-unusable",
                format!(
                    "{where_} has status {:?}, and the format defines only pending and confirmed",
                    other.unwrap_or("absent")
                ),
            ));
        }
    }

    let Some(checkpoint) = record.get("checkpoint").and_then(|v| v.as_object()) else {
        out.problems.push(Problem::fatal(
            "anchor-has-no-checkpoint",
            format!("{where_} carries no checkpoint object"),
        ));
        return;
    };

    let lex = |field: &str| checkpoint.get(field).and_then(|v| v.lexeme());
    let (
        Some(index_lex),
        Some(hash_lex),
        Some(signed_at_lex),
        Some(signature_lex),
        Some(public_key_lex),
    ) = (
        lex("chainIndex"),
        lex("hash"),
        lex("signedAt"),
        lex("signature"),
        lex("publicKey"),
    )
    else {
        out.problems.push(Problem::fatal(
            "checkpoint-incomplete",
            format!("{where_} checkpoint is missing a member the format requires"),
        ));
        return;
    };

    // digest: note the two differences from the signed bytes, signature and publicKey are in and
    // algorithm is out. "A mismatch means the record does not describe the checkpoint it
    // carries, so the proof, whatever it attests to, does not attest to this checkpoint."
    let digest_material = format!(
        r#"{{"chainIndex":{index_lex},"hash":{hash_lex},"signedAt":{signed_at_lex},"signature":{signature_lex},"publicKey":{public_key_lex}}}"#
    );
    let digest_hex = to_hex(&sha256(digest_material.as_bytes()));
    let recorded_digest = record.get("digest").and_then(|v| v.as_str());
    match &recorded_digest {
        Some(d) if *d == digest_hex => {}
        Some(d) => out.problems.push(Problem::fatal(
            "digest-describes-another-checkpoint",
            format!(
                "{where_} submitted {d} but the checkpoint it carries hashes to {digest_hex}, so \
                 whatever the proof attests to, it does not attest to this checkpoint"
            ),
        )),
        None => out.problems.push(Problem::fatal(
            "digest-describes-another-checkpoint",
            format!("{where_} has no digest"),
        )),
    }

    // signature over exactly these bytes, no pre-hash.
    let signed = format!(
        r#"{{"chainIndex":{index_lex},"hash":{hash_lex},"signedAt":{signed_at_lex},"algorithm":"ed25519"}}"#
    );
    let public_key_b64 = checkpoint
        .get("publicKey")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let signature_b64 = checkpoint
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    match (raw_key(&public_key_b64), raw_signature(&signature_b64)) {
        (Some(key), Some(sig)) => {
            if !ed25519::verify(&key, signed.as_bytes(), &sig) {
                out.problems.push(Problem::fatal(
                    "checkpoint-signature-invalid",
                    format!("{where_} signature does not verify against the key it carries"),
                ));
            }
        }
        (None, _) => out.problems.push(Problem::fatal(
            "checkpoint-key-unusable",
            format!("{where_} publicKey is not a 44 byte base64 DER SPKI Ed25519 key"),
        )),
        (_, None) => out.problems.push(Problem::fatal(
            "checkpoint-signature-unusable",
            format!("{where_} signature is not 64 base64 bytes"),
        )),
    }

    if let Some(expected) = pin {
        if public_key_b64 != expected {
            out.problems.push(Problem::fatal(
                "checkpoint-key-is-not-the-pinned-one",
                format!(
                    "{where_} is signed by {public_key_b64}, not the pinned key; a signature \
                     checked only against the key the checkpoint carries proves internal \
                     consistency and nothing about who signed"
                ),
            ));
        }
    }

    // Rebuild the composite. A valid signature "says nothing about whether the composite still
    // describes anything on disk".
    let Some(segments) = checkpoint.get("chainIndex").and_then(|v| v.as_i64()) else {
        out.problems.push(Problem::fatal(
            "checkpoint-incomplete",
            format!("{where_} checkpoint chainIndex is not a plain integer"),
        ));
        return;
    };
    let committed_hash = checkpoint
        .get("hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    rebuild_composite(&where_, segments, &committed_hash, manifest, tails, out);

    // The proof.
    let proof_path = record.get("proofPath").and_then(|v| v.as_str());
    match locate_proof(proof_path.as_deref(), proofs_dir) {
        None => out.problems.push(Problem::fatal(
            "proof-not-found",
            format!(
                "{where_} points at {} and no such file is readable there or under {}; without \
                 the calendar's response this record is a claim that an HTTP request once happened",
                proof_path.as_deref().unwrap_or("no proof path"),
                proofs_dir.display()
            ),
        )),
        Some(found) => {
            let digest_bytes = recorded_digest
                .as_deref()
                .filter(|d| is_sha256_hex(d))
                .and_then(from_hex);
            match digest_bytes {
                None => out.problems.push(Problem::fatal(
                    "digest-describes-another-checkpoint",
                    format!("{where_} digest is not 64 lowercase hex characters"),
                )),
                Some(digest) => match std::fs::read(&found) {
                    Err(e) => out.problems.push(Problem::fatal(
                        "proof-not-found",
                        format!("{where_} proof at {} is unreadable: {e}", found.display()),
                    )),
                    Ok(raw) => match ots::parse_proof(&raw, &digest) {
                        Err(e) => out.problems.push(Problem::fatal(
                            "proof-unreadable",
                            format!("{where_} proof at {} does not parse: {e}", found.display()),
                        )),
                        Ok(proof) => {
                            if proof.attestations.is_empty() {
                                out.problems.push(Problem::fatal(
                                    "proof-attests-to-nothing",
                                    format!(
                                        "{where_} proof parses but reaches no attestation, so it \
                                         records no submission"
                                    ),
                                ));
                            }
                            for att in &proof.attestations {
                                out.problems.push(Problem::note(
                                    "attestation-reached",
                                    format!("{where_} proof reaches {}", att.describe()),
                                ));
                            }
                        }
                    },
                },
            }
        }
    }
}

/// "`manifestHead` is rebuilt from the checkpoint's own `chainIndex`: it is entry `chainIndex-1`'s
/// `finalHash`, or `null` when `chainIndex` is zero."
fn rebuild_composite(
    where_: &str,
    segments: i64,
    committed_hash: &str,
    manifest: &Manifest,
    tails: &TailSources<'_>,
    out: &mut Outcome,
) {
    let head = if segments == 0 {
        "null".to_string()
    } else {
        let idx = (segments - 1) as usize;
        match manifest.entries.get(idx) {
            Some(e) => format!("\"{}\"", e.final_hash),
            None => {
                // "A manifest now holding FEWER than chainIndex entries cannot supply it, and
                // MUST be reported: dropping the newest entries breaks no previousSegmentHash
                // link, because what remains still chains, and the checkpoint is the only thing
                // that notices."
                out.problems.push(Problem::fatal(
                    "manifest-shorter-than-the-checkpoint",
                    format!(
                        "{where_} commits {segments} sealed segment(s) but the manifest now holds \
                         {}; the newest entries were dropped, which breaks no link in the \
                         manifest and only the checkpoint notices",
                        manifest.entries.len()
                    ),
                ));
                return;
            }
        }
    };

    for tail in tail_candidates(tails, segments) {
        let composite = match &tail {
            None => format!(r#"{{"manifestHead":{head},"segments":{segments},"liveTail":null}}"#),
            Some((hash, count)) => format!(
                r#"{{"manifestHead":{head},"segments":{segments},"liveTail":{{"finalHash":"{hash}","count":{count}}}}}"#
            ),
        };
        if to_hex(&sha256(composite.as_bytes())) == committed_hash {
            return;
        }
    }

    out.problems.push(Problem::fatal(
        "committed-tail-is-gone",
        format!(
            "{where_} commits a composite that nothing on disk reproduces; the prefix it covers \
             was rewritten, truncated or reordered, since a live file that has only grown or \
             rotated still reproduces its own committed prefix"
        ),
    ));
}

/// Every (finalHash, count) pair the committed live tail could legitimately be.
///
/// "for each eligible segment file, each prefix of `c` records offers the pair (that record's
/// `integrity.hash`, `c`)". That names the STORED member, not a recomputation: whether a record
/// verifies is the `chained` layer's question, and folding it in here would make this layer fail
/// for a reason another layer already owns.
fn tail_candidates(tails: &TailSources<'_>, segments: i64) -> Vec<Option<(String, usize)>> {
    // "the whole liveTail value is null when the live file holds no complete record"
    let mut out: Vec<Option<(String, usize)>> = vec![None];

    let push_prefixes = |scan: &FileScan, out: &mut Vec<Option<(String, usize)>>| {
        for (i, record) in scan.records.iter().enumerate() {
            out.push(Some((record.stored_hash.clone(), i + 1)));
        }
    };

    push_prefixes(tails.live, &mut out);
    for scan in &tails.unsealed {
        push_prefixes(scan, &mut out);
    }

    // "Eligible files are the live file, closed segments still awaiting a seal, and manifest
    // entries from index chainIndex onward, which is exactly the set that closed after this
    // checkpoint was signed. A segment already sealed when the checkpoint was signed is NOT
    // eligible."
    for (i, (entry, scan)) in tails.sealed.iter().enumerate() {
        if (i as i64) < segments {
            continue;
        }
        if let Some(scan) = scan {
            push_prefixes(scan, &mut out);
        }
        // "each eligible manifest entry's own (finalHash, count) are candidates too, the latter
        // covering a rotated segment whose file is gone".
        if entry.count >= 0 {
            out.push(Some((entry.final_hash.clone(), entry.count as usize)));
        }
    }

    out
}

/// "`proofPath` carries whatever the producer wrote ... What a verifier can rely on is the
/// recorded base name inside the proof directory it was given, and that is where it looks when
/// the recorded path itself does not resolve."
///
/// The recorded path stays authoritative and is tried first. Deriving the name from the digest
/// is explicitly forbidden, so it is never attempted.
fn locate_proof(recorded: Option<&str>, proofs_dir: &Path) -> Option<PathBuf> {
    let recorded = recorded?;
    if recorded.is_empty() {
        return None;
    }
    let as_written = PathBuf::from(recorded);
    if as_written.is_file() {
        return Some(as_written);
    }
    let base = as_written.file_name()?;
    let beside = proofs_dir.join(base);
    if beside.is_file() {
        return Some(beside);
    }
    None
}

/// "The `publicKey` decodes to 44 bytes of DER SPKI, of which the last 32 are the raw Ed25519
/// public key."
fn raw_key(b64: &str) -> Option<[u8; 32]> {
    let der = base64::decode(b64)?;
    if der.len() != 44 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&der[12..]);
    Some(out)
}

fn raw_signature(b64: &str) -> Option<[u8; 64]> {
    let raw = base64::decode(b64)?;
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw);
    Some(out)
}

/// The sentence an operator needs when no pin was supplied.
pub const UNPINNED_NOTE: &str =
    "No public key was pinned, so each checkpoint signature was checked only against the key the \
     checkpoint itself carries. That is internal consistency: anyone who can write these files \
     can generate a key, sign their own version, and produce a set that verifies perfectly. Pass \
     --pubkey or --pubkey-file with a key recorded independently to make a signature evidence \
     about who signed.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuilds_the_spec_worked_example_composite_and_digest() {
        // docs/audit-format.md, "Worked example: a checkpoint".
        let composite = concat!(
            r#"{"manifestHead":"8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428","#,
            r#""segments":1,"liveTail":{"finalHash":"bd5cb6e6d98cc93e166c79b0945889642a3c2e7fdad1892bab83044b76c51348","count":1}}"#
        );
        assert_eq!(
            to_hex(&sha256(composite.as_bytes())),
            "fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0"
        );

        // "Worked example: an anchor record".
        let digest_material = concat!(
            r#"{"chainIndex":1,"hash":"fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0","#,
            r#""signedAt":"2026-01-01T00:00:03.000Z","#,
            r#""signature":"0Kt6u/CfbfxIdPm6Kgp6WpAzi8301ca8Zw7RpqOxoIq1BC4n6sOiY0eVOZTMfcOfo+eoTHH+CodhmYhYmh/ADg==","#,
            r#""publicKey":"MCowBQYDK2VwAyEAvU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE="}"#
        );
        assert_eq!(
            to_hex(&sha256(digest_material.as_bytes())),
            "d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94"
        );
    }

    #[test]
    fn a_key_must_be_a_44_byte_spki() {
        assert!(raw_key("MCowBQYDK2VwAyEAvU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE=").is_some());
        // 32 raw bytes base64: right key, wrong wrapper, and the format says SPKI.
        assert!(raw_key("vU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE=").is_none());
        assert!(raw_key("not base64!").is_none());
    }
}
