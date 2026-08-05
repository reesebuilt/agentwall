import { createHash } from "crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "fs";
import { basename, dirname, isAbsolute, join, resolve } from "path";
import { findDuplicateKey } from "./chain";
import type { AuditEvent } from "../types";

/**
 * Chain continuity across rotation.
 *
 * THE GAP THIS CLOSES
 *
 * Rotating the audit file started a fresh chain at index 0 with previousHash null, and
 * nothing tied it to the file that came before. Each segment verified on its own, so
 * everything looked healthy, but the seam between them was unprotected: an entire
 * segment could be deleted, replaced, or reordered relative to its neighbours and every
 * per-file check would still pass.
 *
 * Concretely: an archived segment ending at index 72 and a live file starting again at
 * index 0 with no link back. Anchoring the live head says nothing whatsoever about the
 * archived records behind it.
 *
 * THE FIX
 *
 * A rotation manifest: an append-only record of every segment, each carrying the hash of
 * the previous segment's final record. That makes the SEQUENCE OF SEGMENTS itself a hash
 * chain, one level up from the per-record chain. Anchoring the manifest head then covers
 * all history rather than only the current file.
 *
 * WHAT BINDS AN ENTRY TO ITS SEGMENT
 *
 * An entry checked only against itself and its neighbours says nothing about the file it
 * names. Without reading that file, a sealed segment can be rewritten wholesale and
 * relinked so its own per-record chain is valid again, and every manifest check still
 * passes. The anchor then binds a manifest that binds only itself, which destroys the one
 * property the manifest exists to provide. Verification therefore opens each segment and
 * requires its actual shape to equal what the entry recorded.
 *
 * WHAT IT STILL DOES NOT DO
 *
 * The manifest lives on the same host as the segments, so an adversary with write access
 * can rewrite both. It converts "delete a whole segment invisibly" into "rewrite every
 * subsequent manifest entry too", which is the same order of improvement the per-record
 * chain gives within a file. Binding still comes from the off-box anchor, not from here.
 */

export interface SegmentRecord {
	/** Path as it was at seal time. Advisory: files get moved. */
	path: string;
	/** Records in the segment. */
	count: number;
	/** chainIndex of the first and last record. */
	firstIndex: number;
	lastIndex: number;
	/** Hash of the final record. The value the next segment must reference. */
	finalHash: string;
	/** Final hash of the PREVIOUS segment. Null only for the first segment ever. */
	previousSegmentHash: string | null;
	sealedAt: string;
	/** Hash over this entry's own fields, so manifest lines are themselves tamper-evident. */
	entryHash: string;
}

export interface SegmentSummary {
	count: number;
	firstIndex: number;
	lastIndex: number;
	finalHash: string;
}

/** Read a segment's shape without holding the whole file in memory as objects. */
export function summarizeSegment(path: string): SegmentSummary | null {
	if (!existsSync(path)) return null;
	const lines = readFileSync(path, "utf8").split("\n").filter((l) => l.trim() !== "");
	if (lines.length === 0) return null;

	let first: AuditEvent | undefined;
	let last: AuditEvent | undefined;
	let count = 0;
	for (const line of lines) {
		// A duplicate member makes the record malformed, so it is not part of the segment's
		// shape. Counting it would let an attacker pad a count, and it has to be caught on
		// the raw line because parsing collapses the duplicate out of existence.
		if (findDuplicateKey(line) !== null) continue;
		let ev: AuditEvent;
		try {
			ev = JSON.parse(line) as AuditEvent;
		} catch {
			// A torn tail is recoverable and normal after a hard kill; skip it rather than
			// refusing to summarize an otherwise good segment.
			continue;
		}
		if (!ev.integrity) continue;
		if (!first) first = ev;
		last = ev;
		count++;
	}
	if (!first || !last) return null;
	return {
		count,
		firstIndex: first.integrity.chainIndex,
		lastIndex: last.integrity.chainIndex,
		finalHash: last.integrity.hash,
	};
}

function hashEntry(e: Omit<SegmentRecord, "entryHash">): string {
	return createHash("sha256")
		.update(
			JSON.stringify({
				path: e.path,
				count: e.count,
				firstIndex: e.firstIndex,
				lastIndex: e.lastIndex,
				finalHash: e.finalHash,
				previousSegmentHash: e.previousSegmentHash,
				sealedAt: e.sealedAt,
			}),
		)
		.digest("hex");
}

export function readManifest(manifestPath: string): SegmentRecord[] {
	if (!existsSync(manifestPath)) return [];
	const out: SegmentRecord[] = [];
	for (const line of readFileSync(manifestPath, "utf8").split("\n")) {
		if (!line.trim()) continue;
		try {
			out.push(JSON.parse(line) as SegmentRecord);
		} catch {
			continue;
		}
	}
	return out;
}

/**
 * Resolve an entry's segment path against the manifest's own directory.
 *
 * A relative entry path resolved against the process working directory makes verification
 * depend on where the operator happens to stand, so the same evidence passes from one
 * shell and fails from another. The manifest directory is the only stable reference the
 * evidence carries, and it keeps a whole evidence directory portable when it is copied.
 * Every caller resolves through here so the layers cannot disagree about which file an
 * entry names.
 */
export function resolveSegmentPath(manifestPath: string, entryPath: string): string {
	return isAbsolute(entryPath) ? entryPath : resolve(dirname(manifestPath), entryPath);
}

/**
 * Seal a segment into the manifest.
 *
 * Idempotent on finalHash: re-sealing the same segment is a no-op rather than a
 * duplicate entry, because a retried rotation should not corrupt the segment chain.
 */
export function sealSegment(
	segmentPath: string,
	manifestPath: string,
	now: () => Date = () => new Date(),
): SegmentRecord | null {
	const summary = summarizeSegment(segmentPath);
	if (!summary) return null;

	const existing = readManifest(manifestPath);
	const already = existing.find((e) => e.finalHash === summary.finalHash);
	if (already) return already;

	const previousSegmentHash = existing.length ? existing[existing.length - 1].finalHash : null;
	const base: Omit<SegmentRecord, "entryHash"> = {
		path: segmentPath,
		count: summary.count,
		firstIndex: summary.firstIndex,
		lastIndex: summary.lastIndex,
		finalHash: summary.finalHash,
		previousSegmentHash,
		sealedAt: now().toISOString(),
	};
	const record: SegmentRecord = { ...base, entryHash: hashEntry(base) };
	writeFileSync(manifestPath, existing.map((e) => JSON.stringify(e)).concat(JSON.stringify(record)).join("\n") + "\n", {
		mode: 0o600,
	});
	return record;
}

export interface ManifestVerification {
	ok: boolean;
	segments: number;
	/** Total records across every sealed segment. */
	records: number;
	problems: string[];
	/** Final hash of the newest segment. This is what should be anchored off-box. */
	head: string | null;
}

/**
 * Verify the segment chain: every entry's own hash, every link between segments, and
 * every entry against the bytes of the segment it names.
 *
 * The content check is what makes the manifest evidence about the segments rather than
 * about itself. An entry records a segment's final record hash, and that hash folds in
 * every record before it, so requiring the file to still produce it detects any rewrite
 * of the sealed segment even when the attacker relinks the file's own chain. Count and
 * span are checked alongside it so a truncation or an extension is named directly rather
 * than surfacing only as a hash difference.
 *
 * A segment the manifest names but that is absent from disk is NOT reported here. It is
 * already reported as missing by the per-record layer, and the two diagnoses are
 * different: absent evidence is not the same finding as evidence that contradicts its
 * seal, and an operator needs to be able to tell them apart.
 *
 * Reports ALL problems rather than stopping at the first, because an operator
 * investigating tampering needs the shape of the damage, not just its earliest point.
 */
export function verifyManifest(manifestPath: string): ManifestVerification {
	const entries = readManifest(manifestPath);
	const problems: string[] = [];
	let records = 0;
	let expectedPrev: string | null = null;

	entries.forEach((e, i) => {
		records += e.count;
		const { entryHash, ...rest } = e;
		if (hashEntry(rest) !== entryHash) {
			problems.push(`segment ${i} (${e.path}): entry hash mismatch, manifest line was altered`);
		}
		if (e.previousSegmentHash !== expectedPrev) {

			problems.push(
				`segment ${i} (${e.path}): expected previousSegmentHash ${expectedPrev ?? "null"}, found ${e.previousSegmentHash ?? "null"} — a segment may have been removed or reordered`,
			);
		}

		const resolved = resolveSegmentPath(manifestPath, e.path);
		if (existsSync(resolved)) {
			const actual = summarizeSegment(resolved);
			const differences: string[] = [];
			if (!actual) {
				// The file is there and holds nothing a verifier can read. Truncating a sealed
				// segment to zero bytes erases its records while leaving every other check
				// green, so presence is judged on content, not on the directory entry.
				differences.push(`count ${e.count} sealed, no readable records on disk`);
			} else {
				if (actual.finalHash !== e.finalHash) {
					differences.push(`finalHash ${e.finalHash} sealed, ${actual.finalHash} on disk`);
				}
				if (actual.count !== e.count) differences.push(`count ${e.count} sealed, ${actual.count} on disk`);
				if (actual.firstIndex !== e.firstIndex) {
					differences.push(`firstIndex ${e.firstIndex} sealed, ${actual.firstIndex} on disk`);
				}
				if (actual.lastIndex !== e.lastIndex) {
					differences.push(`lastIndex ${e.lastIndex} sealed, ${actual.lastIndex} on disk`);
				}
			}
			if (differences.length > 0) {
				problems.push(
					`segment ${i} (${e.path}): segment-content-mismatch, the file no longer matches its seal — ` +
						differences.join("; "),
				);
			}
		}

		expectedPrev = e.finalHash;
	});

	return {
		ok: problems.length === 0,
		segments: entries.length,
		records,
		problems,
		head: entries.length ? entries[entries.length - 1].finalHash : null,
	};
}

/**
 * Adopt segments that predate the manifest.
 *
 * Backfill is honest about what it proves: sealing an existing file records the hash it
 * has NOW, not the hash it had when written. For already-rotated files this establishes
 * continuity going forward and cannot retroactively attest to the past. Recorded as a
 * distinct operation so a reviewer can tell adopted history from history that was sealed
 * as it happened.
 */
export function adoptExistingSegments(
	segmentPaths: readonly string[],
	manifestPath: string,
	now: () => Date = () => new Date(),
): SegmentRecord[] {
	const sealed: SegmentRecord[] = [];
	for (const p of segmentPaths) {
		const rec = sealSegment(p, manifestPath, now);
		if (rec) sealed.push(rec);
	}
	return sealed;
}

/**
 * Find CLOSED segments beside a live audit file.
 *
 * Closed means rotated out: `audit.jsonl.1`, `audit.jsonl.2`, `audit.jsonl.2026-08-04`.
 * The live file itself is deliberately excluded, because sealing a file that is still
 * being appended to records a hash that is stale the moment it is written, and re-sealing
 * it every pass inflates the manifest with duplicate entries for one file.
 *
 * ORDERING IS BEST EFFORT AND THE LIMIT IS REAL. Each segment restarts its own chain at
 * index 0, so nothing inside the files establishes which came first. Ordering by mtime is
 * the most defensible signal available, and it is a heuristic: an adversary who can
 * rewrite segments can also set timestamps. Segments sealed AS THEY ROTATE carry a
 * genuine link; segments adopted retroactively carry an assumed one. Adoption exists to
 * start the chain from wherever a deployment already is, not to prove its past.
 */
export function discoverClosedSegments(auditPath: string): string[] {
	const dir = dirname(auditPath);
	const base = basename(auditPath);
	if (!existsSync(dir)) return [];
	return readdirSync(dir)
		.filter((f) => f.startsWith(base + ".") && !f.endsWith(".lock"))
		.map((f) => join(dir, f))
		.filter((p) => summarizeSegment(p) !== null)
		.map((p) => ({ p, t: statSync(p).mtimeMs }))
		.sort((a, b) => a.t - b.t)
		.map((x) => x.p);
}
