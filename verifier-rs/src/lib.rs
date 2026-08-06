//! An independent verifier for the Agentwall audit evidence format, written in Rust.
//!
//! This implementation was written from `docs/audit-format.md` alone. It is deliberately not a
//! translation of either bundled verifier: a third implementation that was ported from a second
//! one agrees with it for reasons that have nothing to do with the format, and the conformance
//! harness that compares them then measures nothing. Where this verifier and the others agree,
//! that agreement is evidence about the document. Where they disagree, the disagreement is the
//! point and belongs in the harness's divergence table.
//!
//! Zero dependencies, no `unsafe`. Every hash, the signature check, the JSON reader and the
//! proof grammar are in this crate, checked against published vectors and against the worked
//! examples the format itself carries.

#![forbid(unsafe_code)]

pub mod anchors;
pub mod base64;
pub mod canon;
pub mod ed25519;
pub mod hashes;
pub mod hex;
pub mod json;
pub mod manifest;
pub mod ots;
pub mod records;
pub mod report;
pub mod sha2;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use records::FileScan;
use report::{Layer, Problem, Report};

pub const VERIFIER_NAME: &str = "agentwall-verify-rs";
pub const VERIFIER_VERSION: &str = "0.2.0";

pub struct Options {
    pub audit: PathBuf,
    pub manifest: PathBuf,
    pub anchors: PathBuf,
    pub proofs: PathBuf,
    pub pin: Option<String>,
}

impl Options {
    /// Defaults resolve beside the audit file, which the format names as the anchor for every
    /// other path.
    pub fn with_defaults(
        audit: PathBuf,
        manifest: Option<PathBuf>,
        anchors: Option<PathBuf>,
        proofs: Option<PathBuf>,
        pin: Option<String>,
    ) -> Self {
        let dir = audit.parent().unwrap_or(Path::new(".")).to_path_buf();
        Options {
            manifest: manifest.unwrap_or_else(|| dir.join("segments.jsonl")),
            anchors: anchors.unwrap_or_else(|| dir.join("anchors.jsonl")),
            proofs: proofs.unwrap_or_else(|| dir.join("proofs")),
            audit,
            pin,
        }
    }
}

/// Rotated segments sitting beside the audit file.
///
/// The format leaves rotated file names operator-configurable, listing `<audit>.1`, `<audit>.2`
/// "or a date-suffixed variant", so discovery is by prefix rather than by a fixed pattern. This
/// finds them for two purposes: the `chained` layer walks "each record file", and the `linked`
/// layer reports rotated files the manifest does not vouch for.
fn discover_rotated(audit: &Path) -> Vec<PathBuf> {
    let Some(stem) = audit.file_name().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    let dir = audit.parent().unwrap_or(Path::new("."));
    let prefix = format!("{stem}.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: BTreeSet<PathBuf> = BTreeSet::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // `.lock` is the writer's single-writer lock, not a segment. It sits beside the chain
        // for the whole life of every live deployment, so a verifier that walks it reports
        // `chained` FAIL on a healthy host: the pid inside is not a record. The bundled
        // TypeScript verifier (src/audit/rotation.ts) and the Go verifier (verifier/manifest.go)
        // both exclude it. Omitting it here meant an auditor running this binary against a live
        // directory was told the evidence had been edited when nothing had touched it.
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.starts_with(&prefix) && !n.ends_with(".lock"))
        {
            found.insert(path);
        }
    }
    found.into_iter().collect()
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

pub fn verify(opts: &Options) -> Report {
    let manifest = manifest::load(&opts.manifest);
    let rotated = discover_rotated(&opts.audit);

    // Every record file, walked once. Manifest order first because that is the historical order,
    // then anything rotated that no entry vouches for, then the live file.
    let mut to_scan: Vec<PathBuf> = Vec::new();
    for entry in &manifest.entries {
        if !to_scan.iter().any(|p| same_file(p, &entry.resolved)) {
            to_scan.push(entry.resolved.clone());
        }
    }
    for path in &rotated {
        if !to_scan.iter().any(|p| same_file(p, path)) {
            to_scan.push(path.clone());
        }
    }
    if !to_scan.iter().any(|p| same_file(p, &opts.audit)) {
        to_scan.push(opts.audit.clone());
    }

    let scans: Vec<FileScan> = to_scan.iter().map(|p| records::scan_file(p)).collect();
    let find = |path: &Path| -> Option<&FileScan> {
        scans
            .iter()
            .find(|s| same_file(&s.path, path) && !s.unreadable)
    };

    // Layer 1, chained. A segment the manifest names but that is not on disk is the linked
    // layer's finding, so the chain walk skips what it cannot read rather than reporting it
    // twice under two names.
    let mut chain_problems: Vec<Problem> = Vec::new();
    let mut records_seen = 0usize;
    let mut files_walked = 0usize;
    for scan in &scans {
        if scan.unreadable {
            continue;
        }
        files_walked += 1;
        records_seen += scan.records.len();
        chain_problems.extend(scan.problems.iter().cloned());
    }
    if find(&opts.audit).is_none() {
        chain_problems.push(Problem::fatal(
            "audit-file-unreadable",
            format!("{} could not be read", opts.audit.display()),
        ));
    }
    let chained = Layer::new(
        "chained",
        format!("{records_seen} record(s) across {files_walked} file(s)"),
        chain_problems,
    );

    // Layer 2, linked.
    let mut link_problems = manifest.problems.clone();
    if manifest.present {
        link_problems.extend(manifest::check_against_disk(&manifest, find, &rotated));
    } else if !rotated.is_empty() {
        for path in &rotated {
            link_problems.push(Problem::note(
                "segment-unsealed",
                format!(
                    "{} is a rotated file and there is no manifest at {}, so nothing vouches for \
                     it",
                    path.display(),
                    opts.manifest.display()
                ),
            ));
        }
    }
    let link_detail = if manifest.present {
        format!("{} sealed segment(s)", manifest.entries.len())
    } else {
        format!("no rotation manifest at {}", opts.manifest.display())
    };
    let linked = Layer::new("linked", link_detail, link_problems);

    // Layer 3, anchored.
    let empty = FileScan {
        path: opts.audit.clone(),
        records: Vec::new(),
        problems: Vec::new(),
        unreadable: true,
    };
    let live = find(&opts.audit).unwrap_or(&empty);
    let sealed: Vec<(&manifest::Entry, Option<&FileScan>)> = manifest
        .entries
        .iter()
        .map(|e| (e, find(&e.resolved)))
        .collect();
    let unsealed: Vec<&FileScan> = rotated
        .iter()
        .filter(|p| !manifest.entries.iter().any(|e| same_file(&e.resolved, p)))
        .filter_map(|p| find(p))
        .collect();

    let tails = anchors::TailSources {
        live,
        unsealed,
        sealed,
    };
    let outcome = anchors::verify(
        &opts.anchors,
        &opts.proofs,
        &manifest,
        &tails,
        opts.pin.as_deref(),
    );

    let anchored = Layer::new(
        "anchored",
        format!(
            "{} anchor record(s): {} confirmed, {} pending, {} failed",
            outcome.records, outcome.confirmed, outcome.pending, outcome.failed
        ),
        outcome.problems,
    );

    Report {
        layers: vec![chained, linked, anchored],
        pending: outcome.pending,
        confirmed: outcome.confirmed,
        failed: outcome.failed,
        note: if outcome.unpinned && outcome.records > 0 {
            Some(anchors::UNPINNED_NOTE.to_string())
        } else {
            None
        },
    }
}
