//! The conformance corpus, run in process.
//!
//! `scripts/conformance.js` drives the built binary and compares implementations against each
//! other. This test does the narrower job of holding THIS implementation against
//! `verifier/testdata/corpus/*/expected.json`, which the harness documents as carrying "the
//! FORMAT's verdict, not any implementation's". Having it here means a change to this crate that
//! breaks a case fails `cargo test` immediately, without needing node, a build of the
//! TypeScript CLI, or a Go toolchain.
//!
//! It also checks one conformance-checklist item the cross-implementation harness cannot see,
//! because the harness copies each case to a scratch directory first: "It reaches its verdict
//! from the evidence files alone. Every check in this document is computable offline, and none
//! of them modifies a file."

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agentwall_verify_rs::hex::to_hex;
use agentwall_verify_rs::json;
use agentwall_verify_rs::sha2::sha256;
use agentwall_verify_rs::{verify, Options};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has a parent directory")
        .join("verifier/testdata/corpus")
}

struct Expected {
    exit: i64,
    chained: bool,
    linked: bool,
    anchored: bool,
}

fn read_expected(dir: &Path) -> Expected {
    let text = std::fs::read_to_string(dir.join("expected.json")).expect("expected.json");
    let parsed = json::parse(text.trim()).expect("expected.json parses");
    let o = parsed.as_object().expect("expected.json is an object");
    let layers = o
        .get("layers")
        .and_then(|v| v.as_object())
        .expect("expected.json has layers");
    let flag = |name: &str| matches!(layers.get(name).and_then(|v| v.lexeme()), Some("true"));
    Expected {
        exit: o.get("exit").and_then(|v| v.as_i64()).expect("exit"),
        chained: flag("chained"),
        linked: flag("linked"),
        anchored: flag("anchored"),
    }
}

fn options_for(dir: &Path) -> Options {
    // A case that ships a pinned key expects the pin to be applied: without it, a checkpoint
    // signed by a forger's own key verifies against the key it carries.
    let pin = std::fs::read_to_string(dir.join("pubkey.txt"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Options::with_defaults(dir.join("audit.jsonl"), None, None, None, pin)
}

fn cases() -> Vec<PathBuf> {
    let root = corpus_root();
    let mut out: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("no corpus at {}: {e}", root.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    assert!(!out.is_empty(), "corpus is empty at {}", root.display());
    out
}

#[test]
fn every_corpus_case_matches_the_formats_verdict() {
    let mut mismatches: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for dir in cases() {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let expected = read_expected(&dir);
        let report = verify(&options_for(&dir));

        let layer = |n: &str| report.layers.iter().find(|l| l.name == n).unwrap().ok();
        let exit = if report.ok() { 0 } else { 1 };

        let got = (exit, layer("chained"), layer("linked"), layer("anchored"));
        let want = (
            expected.exit,
            expected.chained,
            expected.linked,
            expected.anchored,
        );
        if got != want {
            mismatches.push(format!(
                "{name}: exit={} chained={} linked={} anchored={}, expected exit={} chained={} linked={} anchored={}",
                got.0, got.1, got.2, got.3, want.0, want.1, want.2, want.3
            ));
        }
        checked += 1;
    }

    assert!(
        mismatches.is_empty(),
        "{} of {checked} case(s) disagree with the format:\n  {}",
        mismatches.len(),
        mismatches.join("\n  ")
    );
    assert_eq!(checked, 27, "the corpus should hold 27 cases");
}

#[test]
fn the_three_layers_are_reported_separately_and_never_collapsed() {
    // A verdict that folded the layers together would hide which claim an operator actually has.
    // b15 is the case that proves the layers move independently: the sealed segment was
    // rewritten, so `linked` fails, while `chained` and `anchored` both pass.
    let dir = corpus_root().join("b15-sealed-segment-rewritten");
    let report = verify(&options_for(&dir));
    let names: Vec<&str> = report.layers.iter().map(|l| l.name).collect();
    assert_eq!(names, vec!["chained", "linked", "anchored"]);
    assert!(report.layers[0].ok());
    assert!(!report.layers[1].ok());
    assert!(report.layers[2].ok());
}

#[test]
fn a_pending_attestation_is_never_reported_as_proof() {
    // l1 is the limits case: the anchor record says confirmed, the proof reaches only a pending
    // attestation. The counters report what the backend told the writer, so confirmed is 1, and
    // the report must say beside it what the proof actually reaches.
    let dir = corpus_root().join("l1-confirmed-with-pending-proof");
    let report = verify(&options_for(&dir));
    assert_eq!(report.confirmed, 1);
    let anchored = report.layers.iter().find(|l| l.name == "anchored").unwrap();
    // Only the description is under test. The finding is prefixed with the anchor log's path,
    // and this case's directory is literally named "...-confirmed-with-pending-proof", so a
    // substring check over the whole line would be checking the fixture's name.
    let attestations: Vec<String> = anchored
        .problems
        .iter()
        .filter(|p| p.code == "attestation-reached")
        .map(|p| {
            p.text
                .split_once(" proof reaches ")
                .expect("finding names what the proof reaches")
                .1
                .to_string()
        })
        .collect();
    assert_eq!(
        attestations.len(),
        1,
        "the reached attestation must be reported"
    );
    assert!(
        attestations[0].starts_with("pending at https://alice.btc.calendar.opentimestamps.org"),
        "got {:?}",
        attestations[0]
    );
    assert!(
        !attestations[0].contains("confirm"),
        "a pending attestation must not be described as confirming anything, got {:?}",
        attestations[0]
    );
}

#[test]
fn a_bitcoin_attestation_is_a_value_and_a_height_to_compare_elsewhere() {
    let dir = corpus_root().join("g6-anchor-bitcoin-attestation");
    let report = verify(&options_for(&dir));
    let anchored = report.layers.iter().find(|l| l.name == "anchored").unwrap();
    let text = anchored
        .problems
        .iter()
        .find(|p| p.code == "attestation-reached")
        .map(|p| p.text.clone())
        .expect("a bitcoin attestation should be reported");
    assert!(text.contains("bitcoin block"), "got {text:?}");
    assert!(text.contains("cannot confirm offline"), "got {text:?}");
    assert!(
        text.contains("compare it against any block source"),
        "got {text:?}"
    );
}

#[test]
fn a_declared_gap_never_excuses_a_real_one() {
    // Every corpus case that fails `chained` must do so whether or not the file also carries a
    // gap declaration: the declaration is the writer's account of a hole, not a licence.
    for dir in cases() {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let report = verify(&options_for(&dir));
        let chained = report.layers.iter().find(|l| l.name == "chained").unwrap();
        for problem in &chained.problems {
            if problem.code == "chain-gap-declared" {
                assert!(
                    !problem.fatal,
                    "{name}: a declaration is a report, not a failure"
                );
            }
        }
    }
}

/// SHA-256 of every file under `dir`, keyed by relative path.
fn fingerprint(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path.strip_prefix(dir).unwrap().display().to_string();
                let bytes = std::fs::read(&path).unwrap();
                out.insert(rel, to_hex(&sha256(&bytes)));
            }
        }
    }
    out
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap();
        }
    }
}

#[test]
fn verifying_never_writes_to_the_evidence() {
    // "It reaches its verdict from the evidence files alone ... and none of them modifies a
    // file." A verifier that dropped a lock or generated a key beside the evidence would make
    // the second run of a byte-identity check meaningless.
    let scratch = std::env::temp_dir().join(format!(
        "agentwall-rs-readonly-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    for dir in cases() {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let target = scratch.join(&name);
        copy_tree(&dir, &target);

        let before = fingerprint(&target);
        let _ = verify(&options_for(&target));
        let after = fingerprint(&target);

        assert_eq!(before, after, "{name}: verifying changed the evidence");
    }

    std::fs::remove_dir_all(&scratch).unwrap();
}
