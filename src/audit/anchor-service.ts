import { createHash } from "crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync } from "fs";
import { basename, dirname, isAbsolute, join, resolve } from "path";
import { anchorDigest, anchorToOpenTimestamps, fetchPoster, type AnchorRecord } from "./anchor";
import { verifyChainFile } from "./file-sink";
import { chainAuditEvent, findDuplicateKey } from "./chain";
import { OtsParseError, parseOtsProofFile } from "./ots-proof";
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
interface LiveTailCandidate {
	/** Exactly the members the composite is computed over. Nothing may be added here. */
	tail: LiveTail;
	/**
	 * Highest record chainIndex the tail reaches, or null when the candidate came from a
	 * manifest entry whose file is gone. Carried alongside rather than inside `tail`
	 * because `tail` is hashed: an extra member there would change every composite ever
	 * signed and report every honest checkpoint as tampered.
	 */
	reachIndex: number | null;
}

function liveTailCandidates(
	r: ResolvedPaths,
	entries: readonly SegmentRecord[],
	segments: number,
): LiveTailCandidate[] {
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
	const out: LiveTailCandidate[] = [];
	const offer = (tail: LiveTail, reachIndex: number | null): void => {
		const key = `${tail.count}:${tail.finalHash}`;
		if (seen.has(key)) return;
		seen.add(key);
		out.push({ tail, reachIndex });
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
			offer({ finalHash: ev.integrity.hash, count }, ev.integrity.chainIndex);
		}
	}
	for (const e of entries.slice(segments)) offer({ finalHash: e.finalHash, count: e.count }, e.lastIndex);
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

/**
 * Find the proof file an anchor record names.
 *
 * `proofPath` holds whatever the producer wrote, relative to a working directory this
 * verifier neither knows nor needs to share, because an evidence directory gets copied
 * between hosts. So a short fixed candidate list is tried and the first file that exists
 * wins. Deriving the name from the digest instead is refused: naming a proof after its
 * digest is a writer convention rather than a rule of the format, and the recorded path
 * is the only thing that finds a proof named any other way. Nothing here writes.
 */
function resolveProofPath(proofPath: string, r: ResolvedPaths): string | null {
	const candidates = isAbsolute(proofPath) ? [proofPath] : [];
	candidates.push(
		join(r.proofDir, proofPath),
		join(r.proofDir, basename(proofPath)),
		join(dirname(r.anchorLogPath), proofPath),
	);
	return candidates.find((c) => existsSync(c)) ?? null;
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
	// Kept apart from the problems so a torn tail is surfaced to the operator without
	// deciding the verdict. What fails the layer is evidence of an edit, and a partial
	// trailing line is not that.
	const chainNotes: string[] = [];
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
		for (const note of v.notes) chainNotes.push(`${p}: ${note}`);
	}
	layers.push({
		name: "chained",
		ok: chainProblems.length === 0,
		detail: `${totalRecords} records across ${walked} segment(s)`,
		problems: [...chainProblems, ...chainNotes],
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
	let calendarAttestations = 0;
	let bitcoinAttestations = 0;
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
				set.add(compositeDigest(head, segments, c.tail));
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
				// Recompute the digest from the checkpoint the record carries, rather than
				// reporting the one the record states. Taken on trust, `digest` lets a forger
				// point a record at a checkpoint its proof never covered: the proof still
				// parses, because nothing tied the two together. Recomputing is what makes an
				// off-box timestamp attest to THIS checkpoint.
				const submitted = anchorDigest(rec.checkpoint);
				if (rec.digest !== submitted) {
					anchorProblems.push(
						`checkpoint ${rec.checkpoint.chainIndex}: digest-mismatch, the record says it submitted ` +
							`${String(rec.digest).slice(0, 16)} and the checkpoint it embeds hashes to ` +
							`${submitted.slice(0, 16)}, so the proof does not attest to this checkpoint`,
					);
				}
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
			} else {
				anchorProblems.push(
					"digest-mismatch, an anchor record embeds no checkpoint, so there is nothing to " +
						"recompute its digest from and nothing for its proof to be about",
				);
			}
			// A total submission failure is recorded as status "pending" WITH an error,
			// because the record is written either way. Counting that as pending would
			// report a failed anchor as merely waiting on a Bitcoin block, which is the
			// exact overclaim this layer exists to prevent. Error wins over status.
			if (rec.error) failed++;
			else if (rec.status === "confirmed") confirmed++;
			else if (rec.status === "pending") pending++;

			// `status` is what the record says about itself, and a record is exactly as
			// trustworthy as the host that wrote it. The calendar's response IS the proof, so
			// an anchor that reached a calendar has proof bytes behind it and one that did not
			// carries `error` and is already counted failed. Without this, "confirmed" with an
			// empty proof directory verifies, which is the overclaim this layer exists to
			// refuse: it would report Bitcoin-grade evidence for a line of JSON.
			if (!rec.error) {
				const named = typeof rec.proofPath === "string" ? rec.proofPath : "";
				const found = named ? resolveProofPath(named, r) : null;
				if (!found || statSync(found).size === 0) {
					anchorProblems.push(
						`anchor ${rec.chainIndex}: proof-missing, it records status "${rec.status}" and ` +
							(named
								? `the proof it names (${basename(named)}) is absent or empty`
								: "names no proof file") +
							", so no off-box bytes stand behind the claim",
					);
					continue;
				}
				// Parse it. Unopened, a proof is a file name: truncate the bytes and the anchor
				// still counts, which reduces the whole layer to trusting that an HTTP request
				// once happened.
				let parseProblem: string | null = null;
				try {
					const attestations = parseOtsProofFile(found, Buffer.from(String(rec.digest), "hex"));
					if (attestations.length === 0) parseProblem = "it parses but reaches no attestation";
					for (const a of attestations) {
						if (a.kind === "pending") calendarAttestations++;
						else bitcoinAttestations++;
					}
				} catch (err) {
					parseProblem =
						err instanceof OtsParseError ? err.message : `unreadable: ${(err as Error).message}`;
				}
				if (parseProblem) {
					anchorProblems.push(
						`anchor ${rec.chainIndex}: proof-parse-error, ${basename(found)} ${parseProblem}, ` +
							"so the bytes on disk are not the timestamp the record claims",
					);
				}
			}
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
					(failed ? `, ${failed} FAILED to reach a calendar` : "") +
					`; proofs carry ${calendarAttestations} calendar and ${bitcoinAttestations} ` +
					"bitcoin attestation(s), neither kind confirmation on its own",
		problems: anchorProblems,
	});

	return { ok: layers.every((l) => l.ok), layers, pending, confirmed, failed };
}

/**
 * One anchor log line, reduced to the facts a reader needs and nothing more.
 *
 * Deliberately verdict-free. runVerify() is the verdict, and a second function phrasing
 * its own PASS/FAIL over the same bytes is how two readers of one evidence set end up
 * disagreeing on screen. Everything here is copied from the record, counted out of the
 * proof bytes, or re-derived from disk, so a caller can present it beside the layer verdict
 * without contradicting it.
 */
export interface AnchorReach {
	/** 1-based line in the anchor log. */
	line: number;
	/** Sealed segments the checkpoint committed. NOT a record index. */
	segments: number | null;
	submittedAt: string | null;
	/** Calendar the submission reached. Empty when none did. */
	reference: string;
	/** What the record says about itself. Not a verification result. */
	statusClaimed: string;
	/** Set when the submission never reached a calendar. */
	error: string | null;
	/** Whether the submitted digest recomputes from the checkpoint the record embeds. */
	digestMatchesCheckpoint: boolean;
	/**
	 * Highest record chainIndex this anchor demonstrably commits to, re-derived from disk.
	 *
	 * A checkpoint commits a manifest head plus a live tail, and the tail is inside a hash,
	 * so the reach is not readable off the record. It is recovered by finding which candidate
	 * reproduces the signed composite. null means none did, which is the same condition
	 * runVerify reports as live-tail-mismatch, and it means the reach is UNKNOWN rather than
	 * zero: naming the sealed span alone would claim coverage the bytes no longer support.
	 */
	coveredThroughIndex: number | null;
	proofPath: string | null;
	proofBytes: number;
	/** The parser's own message, or null when the proof parsed. */
	proofProblem: string | null;
	/** Attestation kinds the proof bytes actually carry, not what the record claims. */
	pendingAttestations: number;
	bitcoinAttestations: number;
	pendingUris: string[];
	bitcoinHeights: number[];
}

/**
 * Project the anchor log into per-anchor reach, for a reader that has to say which records
 * an off-box timestamp actually covers.
 *
 * Exists because the layer verdict is file-wide while a reviewer asks something narrower:
 * are THESE records anchored, and is that anchor in a block or still waiting for one. The
 * re-derivation is shared with runVerify through liveTailCandidates and compositeDigest, so
 * the two cannot drift apart about what a checkpoint committed.
 */
export function anchorReach(paths: AnchorPaths): AnchorReach[] {
	const r = resolvePaths(paths);
	if (!existsSync(r.anchorLogPath)) return [];
	const entries = readManifest(r.manifestPath);

	// Same per-rotation cache runVerify keeps, for the same reason: every checkpoint signed
	// between two rotations shares a sealed-segment count, so the eligible files are read
	// once per count rather than once per anchor.
	const candidatesBySegmentCount = new Map<number, LiveTailCandidate[]>();
	const candidatesFor = (segments: number): LiveTailCandidate[] => {
		const cached = candidatesBySegmentCount.get(segments);
		if (cached) return cached;
		const fresh = liveTailCandidates(r, entries, segments);
		candidatesBySegmentCount.set(segments, fresh);
		return fresh;
	};

	const out: AnchorReach[] = [];
	let line = 0;
	for (const raw of readFileSync(r.anchorLogPath, "utf8").split("\n")) {
		line++;
		if (!raw.trim()) continue;
		let rec: AnchorRecord & { checkpoint?: Checkpoint };
		try {
			rec = JSON.parse(raw) as AnchorRecord & { checkpoint?: Checkpoint };
		} catch {
			// Already a problem on the anchored layer. Carried here so a reader sees that the
			// line exists rather than a silently shorter timeline.
			out.push({
				line,
				segments: null,
				submittedAt: null,
				reference: "",
				statusClaimed: "unparseable",
				error: "this anchor log line does not parse",
				digestMatchesCheckpoint: false,
				coveredThroughIndex: null,
				proofPath: null,
				proofBytes: 0,
				proofProblem: null,
				pendingAttestations: 0,
				bitcoinAttestations: 0,
				pendingUris: [],
				bitcoinHeights: [],
			});
			continue;
		}

		const cp = rec.checkpoint;
		const segments = cp ? cp.chainIndex : null;
		const digestMatchesCheckpoint = cp ? rec.digest === anchorDigest(cp) : false;

		let coveredThroughIndex: number | null = null;
		if (cp && segments !== null && segments <= entries.length) {
			const head = segments === 0 ? null : entries[segments - 1].finalHash;
			// The sealed part of the reach is readable straight off the manifest.
			const sealedThrough = segments === 0 ? null : entries[segments - 1].lastIndex;
			if (compositeDigest(head, segments, null) === cp.hash) {
				// It committed no live tail, so the sealed span is the whole reach.
				coveredThroughIndex = sealedThrough;
			} else {
				const match = candidatesFor(segments).find(
					(c) => compositeDigest(head, segments, c.tail) === cp.hash,
				);
				const reaches = match
					? [sealedThrough, match.reachIndex].filter((v): v is number => v !== null)
					: [];
				coveredThroughIndex = reaches.length ? Math.max(...reaches) : null;
			}
		}

		out.push(reachRecord(line, rec, segments, digestMatchesCheckpoint, coveredThroughIndex, r));
	}
	return out;
}

/** Read the proof bytes an anchor names and count what they lead to. */
function reachRecord(
	line: number,
	rec: AnchorRecord & { checkpoint?: Checkpoint },
	segments: number | null,
	digestMatchesCheckpoint: boolean,
	coveredThroughIndex: number | null,
	r: ResolvedPaths,
): AnchorReach {
	const named = typeof rec.proofPath === "string" ? rec.proofPath : "";
	const found = named ? resolveProofPath(named, r) : null;
	let proofBytes = 0;
	let proofProblem: string | null = null;
	const pendingUris: string[] = [];
	const bitcoinHeights: number[] = [];
	let pendingAttestations = 0;
	let bitcoinAttestations = 0;

	if (rec.error) {
		// A submission that never reached a calendar has no proof to point at, so naming the
		// proof missing as well would report two faults for one event.
		proofProblem = null;
	} else if (!found) {
		proofProblem = named
			? `the proof it names (${basename(named)}) is not on disk`
			: "it names no proof file";
	} else {
		proofBytes = statSync(found).size;
		if (proofBytes === 0) {
			proofProblem = "the proof file is empty";
		} else {
			try {
				const attestations = parseOtsProofFile(found, Buffer.from(String(rec.digest), "hex"));
				if (attestations.length === 0) proofProblem = "it parses but reaches no attestation";
				for (const a of attestations) {
					if (a.kind === "pending") {
						pendingAttestations++;
						pendingUris.push(a.uri);
					} else {
						bitcoinAttestations++;
						bitcoinHeights.push(a.height);
					}
				}
			} catch (err) {
				proofProblem =
					err instanceof OtsParseError ? err.message : `unreadable: ${(err as Error).message}`;
			}
		}
	}

	return {
		line,
		segments,
		submittedAt: typeof rec.submittedAt === "string" ? rec.submittedAt : null,
		reference: typeof rec.reference === "string" ? rec.reference : "",
		statusClaimed: typeof rec.status === "string" ? rec.status : "unstated",
		error: rec.error ?? null,
		digestMatchesCheckpoint,
		coveredThroughIndex,
		proofPath: found,
		proofBytes,
		proofProblem,
		pendingAttestations,
		bitcoinAttestations,
		pendingUris,
		bitcoinHeights,
	};
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
