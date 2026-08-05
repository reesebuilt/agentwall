import { createHash } from "crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "fs";
import { dirname, join, resolve } from "path";
import { anchorToOpenTimestamps, fetchPoster, type AnchorRecord } from "./anchor";
import { verifyChainFile } from "./file-sink";
import { chainAuditEvent, findDuplicateKey } from "./chain";
import { loadOrCreateKeys, signCheckpoint, verifyCheckpoint, type Checkpoint } from "./signing";
import {
	adoptExistingSegments,
	discoverClosedSegments,
	readManifest,
	resolveSegmentPath,
	summarizeSegment,
	verifyManifest,
	type SegmentRecord,
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
	const composite = compositeDigest(
		manifest.head,
		manifest.segments,
		live ? { finalHash: live.finalHash, count: live.count } : null,
	);

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

/** What a checkpoint says the live file held at signing time. */
interface LiveTail {
	finalHash: string;
	count: number;
}

/**
 * The exact bytes a checkpoint commits to.
 *
 * Signing and verification share this function so the two cannot drift. If they computed
 * the composite separately, a change to one side would make every existing checkpoint
 * look tampered with, and the check meant to detect tampering would report nothing else.
 */
function compositeDigest(manifestHead: string | null, segments: number, liveTail: LiveTail | null): string {
	return createHash("sha256").update(JSON.stringify({ manifestHead, segments, liveTail })).digest("hex");
}

/**
 * Every live tail a checkpoint that sealed `segments` could honestly have committed, read
 * from disk now.
 *
 * The composite is a hash, so the committed finalHash and count are not readable from the
 * checkpoint. Re-deriving them means reconstructing candidates from the evidence and
 * asking whether any of them reproduces the signed composite.
 *
 * WHY GROWTH IS NOT TAMPERING. A checkpoint commits the live file's first `count` records
 * and the hash that ends them. That hash folds in every record before it, so it is a
 * commitment to a PREFIX, not to the file's length. Appending after the checkpoint leaves
 * that prefix byte for byte identical, so the commitment still reproduces and a growing
 * file stays silent. Every prefix of the live file is offered for exactly this reason: a
 * healthy deployment anchors on a timer and appends continuously, and a check that
 * compared against the file's CURRENT end would fail on every pass but the last.
 *
 * WHY ROTATION IS NOT TAMPERING EITHER. Rotation moves that prefix into a closed segment
 * and starts a new live file, so a checkpoint older than the last rotation reproduces
 * from a rotated file rather than from the live one.
 *
 * WHICH FILES ARE ELIGIBLE. Only the ones the committed tail can legitimately be in: the
 * current live file, and segments that closed AFTER this checkpoint. A segment already
 * sealed when the checkpoint was signed was not the live file at that moment, so letting
 * it excuse a tail would widen the check for nothing. The manifest is append-only, so
 * "sealed after" is exactly the entries from index `segments` onward, and closed segments
 * still awaiting a seal are eligible too, since verification runs between anchor passes.
 * Each eligible entry also offers its recorded pair, which covers a rotated segment whose
 * file is gone: that absence is already reported as missing, and reporting it a second
 * time under a tampering code would tell an operator the wrong thing.
 *
 * WHAT IS LEFT IS THE ATTACK. A prefix that was rewritten, truncated, or reordered
 * produces a different hash at that count and reproduces from nothing eligible. That is
 * the only condition this reports.
 */
function liveTailCandidates(
	r: ResolvedPaths,
	entries: readonly SegmentRecord[],
	segments: number,
): LiveTail[] {
	const alreadyClosed = new Set<string>(
		entries.slice(0, segments).map((e) => resolveSegmentPath(r.manifestPath, e.path)),
	);
	const eligible = new Set<string>([resolve(r.auditPath)]);
	for (const p of discoverClosedSegments(r.auditPath)) {
		const full = resolve(p);
		if (!alreadyClosed.has(full)) eligible.add(full);
	}
	for (const e of entries.slice(segments)) eligible.add(resolveSegmentPath(r.manifestPath, e.path));

	const seen = new Set<string>();
	const out: LiveTail[] = [];
	const offer = (t: LiveTail): void => {
		const key = `${t.count}:${t.finalHash}`;
		if (seen.has(key)) return;
		seen.add(key);
		out.push(t);
	};

	for (const file of eligible) {
		if (!existsSync(file)) continue;
		let count = 0;
		for (const line of readFileSync(file, "utf8").split("\n")) {
			if (!line.trim()) continue;
			// Skipped exactly as summarizeSegment skips them, because the count a checkpoint
			// committed came from there. A malformed record counts toward no live tail, so a
			// duplicate member smuggled into a committed prefix stops that prefix reproducing.
			if (findDuplicateKey(line) !== null) continue;
			let ev: AuditEvent;
			try {
				ev = JSON.parse(line) as AuditEvent;
			} catch {
				// summarizeSegment skips a torn tail rather than refusing the file, and the
				// counts a checkpoint committed came from it, so skip identically here.
				continue;
			}
			if (!ev.integrity) continue;
			count++;
			offer({ finalHash: ev.integrity.hash, count });
		}
	}
	for (const e of entries.slice(segments)) offer({ finalHash: e.finalHash, count: e.count });
	return out;
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
 *   linked   - segments link and match their entries, so removing or replacing a whole
 *              segment is detectable
 *   anchored - a hash exists off-box and still describes what is here, so rewriting
 *              everything locally is detectable
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
	// Entry paths resolve against the manifest's directory, so the same evidence verifies
	// identically whatever directory the operator runs from.
	const segPaths = new Set<string>(
		readManifest(r.manifestPath).map((e) => resolveSegmentPath(r.manifestPath, e.path)),
	);
	segPaths.add(resolve(r.auditPath));
	const chainProblems: string[] = [];
	let totalRecords = 0;
	let walked = 0;
	for (const p of segPaths) {
		// A file that is not there is accounted for by the manifest layer, which is what
		// names it. Reporting its absence here as well would put segment accountability on
		// two layers at once and let `linked` pass while a segment it vouches for is gone,
		// which is the same "manifest binds only itself" hole the content check closes.
		if (!existsSync(p)) continue;
		walked++;
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
						? `; ${v.records} records but only ${reuse.distinct} distinct chain indexes ` +
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
		detail: `${totalRecords} records across ${walked} segment(s)`,
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
	const sealedPaths = new Set<string>(
		readManifest(r.manifestPath).map((e) => resolveSegmentPath(r.manifestPath, e.path)),
	);
	const unsealed = discoverClosedSegments(r.auditPath).filter((p) => !sealedPaths.has(resolve(p)));
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

	// Layer 3: checkpoint signatures, the state each checkpoint committed, and anchor
	// state. A signature only says the composite was signed by the key. Re-deriving the
	// composite from disk is what makes the off-box anchor describe the evidence rather
	// than describe a number.
	const anchorProblems: string[] = [];
	let pending = 0;
	let confirmed = 0;
	let failed = 0;
	if (existsSync(r.anchorLogPath) && existsSync(r.keyPath)) {
		const manifestEntries = readManifest(r.manifestPath);
		// One composite set per distinct sealed-segment count. An anchor log holds many
		// checkpoints and every one signed between two rotations shares that count, so the
		// eligible files and their prefixes are read once per rotation, not once per anchor.
		const compositesBySegmentCount = new Map<number, Set<string>>();
		const compositesFor = (segments: number): Set<string> | null => {
			if (segments > manifestEntries.length) return null;
			const cached = compositesBySegmentCount.get(segments);
			if (cached) return cached;
			const head = segments === 0 ? null : manifestEntries[segments - 1].finalHash;
			const set = new Set<string>([compositeDigest(head, segments, null)]);
			for (const c of liveTailCandidates(r, manifestEntries, segments)) {
				set.add(compositeDigest(head, segments, c));
			}
			compositesBySegmentCount.set(segments, set);
			return set;
		};

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
				const composites = compositesFor(rec.checkpoint.chainIndex);
				if (!composites) {
					anchorProblems.push(
						`checkpoint ${rec.checkpoint.chainIndex}: live-tail-mismatch, it committed ` +
							`${rec.checkpoint.chainIndex} sealed segment(s) and the manifest now holds ` +
							`${manifestEntries.length}, so the state it anchored cannot be rebuilt`,
					);
				} else if (!composites.has(rec.checkpoint.hash)) {
					anchorProblems.push(
						`checkpoint ${rec.checkpoint.chainIndex}: live-tail-mismatch, the live tail it signed ` +
							"reproduces from no segment it could have been written to, so the anchored value " +
							"no longer describes the evidence on disk",
					);
				}
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
