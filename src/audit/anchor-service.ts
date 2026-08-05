import { createHash } from "crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "fs";
import { dirname, join } from "path";
import { anchorToOpenTimestamps, fetchPoster, type AnchorRecord } from "./anchor";
import { verifyChainFile } from "./file-sink";
import { chainAuditEvent } from "./chain";
import { loadOrCreateKeys, signCheckpoint, verifyCheckpoint, type Checkpoint } from "./signing";
import {
	adoptExistingSegments,
	discoverClosedSegments,
	readManifest,
	summarizeSegment,
	verifyManifest,
} from "./rotation";
import type { AuditEvent } from "../types";

/**
 * The anchor path, wired end to end.
 *
 * Signing and anchoring existed as tested library code with no production caller, which
 * meant the capability was real and the CONTROL was not. A security feature nothing
 * invokes is documentation, not defence. This module is the caller: it is what the CLI
 * drives and what the scheduler runs.
 *
 * WHAT ONE ANCHOR PASS DOES
 *
 *   1. Seal the current audit segment into the rotation manifest, so segment-to-segment
 *      linkage covers history rather than only the live file.
 *   2. Sign an Ed25519 checkpoint over the manifest head.
 *   3. Submit the checkpoint digest to OpenTimestamps.
 *
 * Order matters. Anchoring the live file alone leaves rotated segments unprotected, so
 * the manifest is sealed FIRST and the checkpoint covers the manifest head, not the
 * per-file head.
 */

export interface AnchorPaths {
	/** Live audit file. */
	auditPath: string;
	/** Segment chain. Defaults beside the audit file. */
	manifestPath?: string;
	/** Ed25519 private key. Created on first use at 0600. */
	keyPath?: string;
	/** Where checkpoint records and OTS proofs are written. */
	anchorLogPath?: string;
	proofDir?: string;
}

export interface ResolvedPaths {
	auditPath: string;
	manifestPath: string;
	keyPath: string;
	anchorLogPath: string;
	proofDir: string;
}

export function resolvePaths(p: AnchorPaths): ResolvedPaths {
	const dir = dirname(p.auditPath);
	return {
		auditPath: p.auditPath,
		manifestPath: p.manifestPath ?? join(dir, "segments.jsonl"),
		keyPath: p.keyPath ?? join(dir, "checkpoint-key.pem"),
		anchorLogPath: p.anchorLogPath ?? join(dir, "anchors.jsonl"),
		proofDir: p.proofDir ?? join(dir, "proofs"),
	};
}

export interface AnchorPassResult {
	/** False when there is nothing to anchor. Not an error. */
	anchored: boolean;
	reason?: string;
	checkpoint?: Checkpoint;
	records?: AnchorRecord[];
	/** Records covered: sealed segments plus the live tail. Counted once each. */
	covered?: number;
	/** Sealed (closed) segments. The live file is not one of these. */
	segments?: number;
	/** Records in the live file at the moment of anchoring. */
	liveRecords?: number;
}

/**
 * Run one anchor pass.
 *
 * Never throws on a calendar being unreachable: an anchor failure is recorded and
 * reported, because a monitoring tool that dies when a third party is down is worse
 * than one that tells you it could not reach them.
 */
export async function runAnchorPass(
	paths: AnchorPaths,
	now: () => Date = () => new Date(),
	poster = fetchPoster,
): Promise<AnchorPassResult> {
	const r = resolvePaths(paths);

	if (!existsSync(r.auditPath)) {
		return { anchored: false, reason: "no audit file yet" };
	}

	// Seal only CLOSED segments. The live file is deliberately NOT sealed: it grows
	// between passes, so each pass would append another manifest entry for the same
	// path and the record count would inflate without bound. Its current state is
	// carried in the checkpoint as a live tail instead.
	adoptExistingSegments(discoverClosedSegments(r.auditPath), r.manifestPath, now);

	const manifest = verifyManifest(r.manifestPath);
	const live = summarizeSegment(r.auditPath);
	if (!live && !manifest.head) {
		return { anchored: false, reason: "no complete records to anchor" };
	}

	// The checkpoint commits to BOTH sealed history and the live tail, so one anchor
	// covers everything on disk rather than only the rotated part.
	const composite = createHash("sha256")
		.update(
			JSON.stringify({
				manifestHead: manifest.head,
				segments: manifest.segments,
				liveTail: live ? { finalHash: live.finalHash, count: live.count } : null,
			}),
		)
		.digest("hex");

	const keys = loadOrCreateKeys(r.keyPath);
	const checkpoint = signCheckpoint(manifest.segments, composite, keys, now);

	const records = [await anchorToOpenTimestamps(checkpoint, poster, now, r.proofDir)];

	mkdirSync(dirname(r.anchorLogPath), { recursive: true });
	for (const rec of records) {
		appendFileSync(r.anchorLogPath, JSON.stringify({ ...rec, checkpoint }) + "\n", {
			encoding: "utf8",
			mode: 0o600,
		});
	}

	return {
		anchored: true,
		checkpoint,
		records,
		covered: manifest.records + (live?.count ?? 0),
		segments: manifest.segments,
		liveRecords: live?.count ?? 0,
	};
}

/** Problems shown per segment before summarizing. */
const PROBLEM_SAMPLE = 3;

/**
 * Distinguish concurrent writers from a targeted edit.
 *
 * A tampered record breaks one link. Two processes appending with independent chain
 * state reuse the same indexes over and over. Telling an operator WHICH they are looking
 * at is the difference between a useful report and a wall of text.
 */
function countIndexReuse(path: string): { distinct: number; worst: number } | null {
	try {
		const seen = new Map<number, number>();
		for (const line of readFileSync(path, "utf8").split("\n")) {
			if (!line.trim()) continue;
			const ev = JSON.parse(line) as AuditEvent;
			if (!ev.integrity) continue;
			seen.set(ev.integrity.chainIndex, (seen.get(ev.integrity.chainIndex) ?? 0) + 1);
		}
		const worst = Math.max(...seen.values());
		return worst > 1 ? { distinct: seen.size, worst } : null;
	} catch {
		return null;
	}
}

export interface LayerVerdict {
	name: string;
	ok: boolean;
	detail: string;
	problems: string[];
}

export interface VerifyReport {
	ok: boolean;
	layers: LayerVerdict[];
	/** Anchors submitted and waiting on a Bitcoin block. */
	pending: number;
	/** Anchors confirmed by a block. */
	confirmed: number;
	/** Submissions that never reached a calendar. Never counted as pending. */
	failed: number;
}

/**
 * Verify all three layers independently and report each.
 *
 * Reported separately on purpose. They are different properties and collapsing them
 * into one green tick is exactly the overclaiming this project exists to avoid:
 *
 *   chained  - records link, so an edit inside a segment is detectable
 *   linked   - segments link, so removing a whole segment is detectable
 *   anchored - a hash exists off-box, so rewriting everything locally is detectable
 *
 * A pending anchor is reported as pending, never as verified. OpenTimestamps needs a
 * Bitcoin block, typically one to six hours.
 */
export function runVerify(paths: AnchorPaths): VerifyReport {
	const r = resolvePaths(paths);
	const layers: LayerVerdict[] = [];

	const rehash = (event: AuditEvent): string => {
		const { integrity, ...rest } = event;
		return chainAuditEvent(rest as Omit<AuditEvent, "integrity">, {
			chainIndex: integrity.chainIndex,
			previousHash: integrity.previousHash,
		}).integrity.hash;
	};

	// Layer 1: per-record chain, for every segment the manifest knows plus the live file.
	const segPaths = new Set<string>(readManifest(r.manifestPath).map((e) => e.path));
	segPaths.add(r.auditPath);
	const chainProblems: string[] = [];
	let totalRecords = 0;
	for (const p of segPaths) {
		if (!existsSync(p)) {
			chainProblems.push(`${p}: sealed in the manifest but missing from disk`);
			continue;
		}
		const v = verifyChainFile(p, rehash);
		totalRecords += v.records;
		// A broken segment produces one problem PER RECORD. A file damaged by concurrent
		// writers yields hundreds of near-identical lines, which buries the finding it is
		// meant to surface. Summarize per segment: the shape and the scale, then a few
		// examples. An operator needs to know what happened, not read it once per record.
		if (v.problems.length > PROBLEM_SAMPLE) {
			const reuse = countIndexReuse(p);
			chainProblems.push(
				`${p}: ${v.problems.length} problems across ${v.records} records` +
					(reuse
						? ` — ${v.records} records but only ${reuse.distinct} distinct chain indexes ` +
							`(one index reused up to ${reuse.worst} times), which is the signature of ` +
							`CONCURRENT WRITERS each keeping their own chain state, not of a single edit`
						: ""),
			);
			for (const problem of v.problems.slice(0, PROBLEM_SAMPLE)) {
				chainProblems.push(`${p}:   e.g. ${problem}`);
			}
			chainProblems.push(`${p}:   ... and ${v.problems.length - PROBLEM_SAMPLE} more`);
		} else {
			for (const problem of v.problems) chainProblems.push(`${p}: ${problem}`);
		}
	}
	layers.push({
		name: "chained",
		ok: chainProblems.length === 0,
		detail: `${totalRecords} records across ${segPaths.size} segment(s)`,
		problems: chainProblems,
	});

	// Layer 2: segment linkage.
	//
	// An empty manifest is only a failure if there is something it SHOULD contain. On a
	// deployment that has never rotated there are no segments to link, and reporting
	// that as FAIL would tell a new user the tool is broken on first run and hand them a
	// remedy that cannot clear it: `anchor` seals closed segments, and there are none.
	// Nothing to link is a vacuous pass. Rotated files sitting unsealed is a real one.
	const m = verifyManifest(r.manifestPath);
	const unsealed = discoverClosedSegments(r.auditPath).filter(
		(p) => !readManifest(r.manifestPath).some((e) => e.path === p),
	);
	const linkedProblems = [...m.problems];
	if (unsealed.length > 0) {
		linkedProblems.push(
			`${unsealed.length} rotated segment(s) on disk are not sealed into the manifest, ` +
				"so they sit outside the anchor. Run `agentwall anchor` to seal them.",
		);
	}
	layers.push({
		name: "linked",
		ok: m.ok && linkedProblems.length === 0,
		detail:
			m.segments === 0
				? unsealed.length > 0
					? `${unsealed.length} rotated segment(s) found, none sealed yet`
					: "no rotations yet, nothing to link"
				: `${m.segments} segment(s) linked, head ${m.head?.slice(0, 16)}` +
					(unsealed.length > 0 ? `, ${unsealed.length} unsealed` : ""),
		problems: linkedProblems,
	});

	// Layer 3: checkpoint signatures and anchor state.
	const anchorProblems: string[] = [];
	let pending = 0;
	let confirmed = 0;
	let failed = 0;
	if (existsSync(r.anchorLogPath) && existsSync(r.keyPath)) {
		const keys = loadOrCreateKeys(r.keyPath);
		for (const line of readFileSync(r.anchorLogPath, "utf8").split("\n")) {
			if (!line.trim()) continue;
			let rec: AnchorRecord & { checkpoint?: Checkpoint };
			try {
				rec = JSON.parse(line);
			} catch {
				anchorProblems.push("anchor log has an unparseable line");
				continue;
			}
			if (rec.checkpoint) {
				const v = verifyCheckpoint(rec.checkpoint, keys.publicKey.export({ type: "spki", format: "der" }).toString("base64"));
				if (!v.ok) anchorProblems.push(`checkpoint ${rec.checkpoint.chainIndex}: ${v.problem}`);
			}
			// A total submission failure is recorded as status "pending" WITH an error,
			// because the record is written either way. Counting that as pending would
			// report a failed anchor as merely waiting on a Bitcoin block, which is the
			// exact overclaim this layer exists to prevent. Error wins over status.
			if (rec.error) failed++;
			else if (rec.status === "confirmed") confirmed++;
			else if (rec.status === "pending") pending++;
		}
	}
	const attempted = confirmed + pending + failed;
	layers.push({
		name: "anchored",
		ok: anchorProblems.length === 0 && confirmed + pending > 0,
		detail:
			attempted === 0
				? "nothing anchored off-box yet"
				: `${confirmed} confirmed, ${pending} pending a Bitcoin block` +
					(failed ? `, ${failed} FAILED to reach a calendar` : ""),
		problems: anchorProblems,
	});

	return { ok: layers.every((l) => l.ok), layers, pending, confirmed, failed };
}

/**
 * Periodic anchoring for the running service.
 *
 * unref'd so a scheduled anchor never holds the process open during shutdown. Failures
 * are surfaced through onError rather than thrown, since an unreachable calendar must
 * not take the firewall down with it.
 */
export function startAnchorSchedule(
	paths: AnchorPaths,
	intervalMs: number,
	onResult: (r: AnchorPassResult) => void = () => {},
	onError: (e: unknown) => void = () => {},
): { stop: () => void } {
	const tick = () => {
		runAnchorPass(paths).then(onResult).catch(onError);
	};
	const timer = setInterval(tick, intervalMs);
	timer.unref?.();
	return { stop: () => clearInterval(timer) };
}

/** Stable digest of a checkpoint, for display. */
export function shortDigest(cp: Checkpoint): string {
	return createHash("sha256").update(cp.hash).digest("hex").slice(0, 12);
}
