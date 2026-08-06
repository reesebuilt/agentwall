import { existsSync, readFileSync, statSync } from "fs";
import { resolve } from "path";
import { AUDIT_CHAIN_GAP_ACTION, chainAuditEvent, findDuplicateKey } from "../audit/chain";
import { resolvePaths, type AnchorPaths, type ResolvedPaths } from "../audit/anchor-service";
import { discoverClosedSegments, readManifest, resolveSegmentPath, type SegmentRecord } from "../audit/rotation";
import type { AuditEvent } from "../types";

/**
 * Read the evidence files into a structure a reviewer can be shown.
 *
 * WHAT THIS IS NOT. It is not a second verifier. `runVerify()` in src/audit/anchor-service.ts
 * owns the verdict, and this module never contradicts it: the per-record annotations below
 * are computed with the same rehash `runVerify` uses, over the same files, in the same order,
 * so a record marked faulty here is a record the layer verdict is already failing on. The
 * reason to walk the files a second time is shape rather than judgement. `verifyChainFile()`
 * returns problem strings suitable for a terminal; a viewer needs to say WHICH record, in
 * which file, belonging to which session, so it can put a break next to the decision it
 * belongs to.
 *
 * READ ONLY, structurally. Nothing in this module opens a file for writing, and it imports
 * nothing that does. Evidence a viewer can edit is not evidence.
 */

/** What is wrong with one record. Empty means the record reproduced and linked. */
export type RecordFault =
	| "altered"
	| "unmarked-canon"
	| "link-broken"
	| "index-break"
	| "dup-key"
	| "unparseable"
	| "torn-tail"
	| "no-integrity";

/**
 * Why each fault means what it means, in the words a reviewer needs. Kept beside the codes
 * so the page cannot describe a fault differently from the code that raised it.
 */
export const FAULT_MEANING: Record<RecordFault, string> = {
	altered: "the record does not reproduce its own hash, which is what an edit after write looks like",
	"unmarked-canon":
		"the record does not reproduce its hash AND names no canonical form, so it cannot be told apart from an edit; records written before the cu1 marker land here",
	"link-broken": "previousHash does not point at the preceding record in this file",
	"index-break": "chainIndex is not one past its predecessor, which is what a removed record or a second writer looks like",
	"dup-key": "two members share one name, so what this record says depends on which parser reads it",
	unparseable: "the line is not JSON and is not the torn final line a hard kill leaves",
	"torn-tail": "the final line has no terminator and does not parse, which is what a hard kill mid-append leaves; the records before it are complete",
	"no-integrity": "the line carries no integrity block, so there is nothing to check it against",
};

/** Whether a fault is evidence of an edit, or only of an interrupted write. */
export const FAULT_CONDEMNS: Record<RecordFault, boolean> = {
	altered: true,
	"unmarked-canon": true,
	"link-broken": true,
	"index-break": true,
	"dup-key": true,
	unparseable: true,
	"torn-tail": false,
	"no-integrity": true,
};

export type FileRole = "live" | "sealed" | "unsealed";

/**
 * The fleet attribution a record carries, read back from the named metadata keys
 * `src/index.ts` and `src/runtime/enforcement.ts` write.
 *
 * Named keys, never the metadata block. The block holds agent-supplied strings and grows
 * whenever anything upstream adds a field, so carrying it whole would put unreviewed content
 * into every view that reads a record. What a reviewer needs from it is a short fixed list,
 * and a short fixed list is what this is.
 *
 * `null` on the whole object means the record names no agent at all. That is the honest
 * answer for a record written before any egress resolution ran, and it is different from an
 * agent whose signals resolved to nothing.
 */
export interface RecordAgent {
	label: string | null;
	/** `credential`, `uid`, `comm`, or a combination. What the identity claim actually rests on. */
	matchedOn: string | null;
	/** Whether a declared fleet agent claimed this connection, or it fell through. */
	declared: boolean | null;
	/** `global`, or `agent:<id>`. Which allowlist judged it. */
	allowlistSource: string | null;
}

/**
 * What one proxied connection's record says about how much of it was readable.
 *
 * Present only on records the proxy record path wrote, which is what `bodyVisibility`
 * identifies: every forward and transparent record carries it and nothing else does. A
 * `/evaluate` decision has no body and no destination, so it gets `null` rather than a row
 * of empty strings that would read like a connection nobody looked at.
 */
export interface RecordEgress {
	host: string | null;
	port: string | null;
	scheme: string | null;
	/** `monitor`, `guarded`, or `strict`. An "allow" under monitor blocked nothing. */
	enforcementMode: string | null;
	/** `forward` or `transparent`. The transparent path resolves no fleet identity. */
	transportMode: string | null;
	/** `tunneled`, `unread`, `bypassed`, `stream`, `partial`, `plaintext`, or `intercepted`. */
	bodyVisibility: string | null;
	/** True when either direction was read only to the inspection cap. */
	contentTruncated: boolean;
	/**
	 * Classes of secret the content scan named, both directions, deduplicated. Never a value:
	 * the writer records the class and the offset and nothing else, and a reader that
	 * reconstituted more than the writer stored would be inventing evidence.
	 */
	secretTypes: string[];
}

export interface EvidenceRecord {
	/** Absolute path of the file the record was read from. */
	file: string;
	fileRole: FileRole;
	/** 1-based line within that file. */
	line: number;
	chainIndex: number | null;
	hash: string | null;
	previousHash: string | null;
	/** The canonical form the record names, or null when it names none. */
	canon: string | null;
	id: string | null;
	timestamp: string | null;
	agentId: string | null;
	sessionId: string | null;
	plane: string | null;
	action: string | null;
	decision: string | null;
	riskLevel: string | null;
	matchedRules: string[];
	reasons: string[];
	detections: { id: string; name: string; severity: string }[];
	requiresApproval: boolean;
	highRiskFlow: boolean;
	/** True on the writer's own declaration that records it produced could not be stored. */
	chainGapDeclared: boolean;
	/** How many records the writer said were lost at this point, when it said. */
	droppedRecords: string | null;
	/** Null when the record names no fleet agent. */
	agent: RecordAgent | null;
	/** Null when the record is not a proxied connection. */
	egress: RecordEgress | null;
	faults: RecordFault[];
}

export interface EvidenceFile {
	path: string;
	role: FileRole;
	exists: boolean;
	bytes: number;
	records: number;
	firstIndex: number | null;
	lastIndex: number | null;
	/** The manifest entry that seals this file, when one does. */
	sealedAs: { count: number; firstIndex: number; lastIndex: number; finalHash: string } | null;
	/** Set when the file was not read. The CLI is then the only complete reader of it. */
	skipped: string | null;
}

export interface EvidenceCollection {
	paths: ResolvedPaths;
	files: EvidenceFile[];
	records: EvidenceRecord[];
	/**
	 * True when a cap stopped the walk. A viewer that silently shows a prefix of the
	 * evidence is worse than one that says it is showing a prefix.
	 */
	truncated: boolean;
	/** Limits that actually bit on this read, in the words the page shows. */
	notes: string[];
}

/**
 * Caps on one read.
 *
 * A route that reads and rehashes an unbounded file is a route an operator can hang by
 * pointing it at a large chain, and the audit path is operator-supplied with no default
 * size. Both caps are stated on the page when they bite, and neither changes a verdict:
 * `runVerify()` still walks everything, and the CLI is what a reviewer runs to see the rest.
 */
export const READ_LIMITS = {
	/** Per file. Rotation keeps segments far below this in any configured deployment. */
	fileBytes: 64 * 1024 * 1024,
	/** Across all files in one read. */
	records: 100_000,
} as const;

/**
 * The files that make up the record evidence, in the order a verifier walks them: sealed
 * segments in manifest order, then rotated segments not yet sealed, then the live file.
 *
 * Order is part of what the page shows. A reviewer reading a break needs to know whether it
 * sits in history that has been sealed and anchored or in the tail that has not.
 */
function recordFiles(r: ResolvedPaths): { path: string; role: FileRole; sealedAs: SegmentRecord | null }[] {
	const out: { path: string; role: FileRole; sealedAs: SegmentRecord | null }[] = [];
	const seen = new Set<string>();
	const add = (path: string, role: FileRole, sealedAs: SegmentRecord | null): void => {
		const full = resolve(path);
		if (seen.has(full)) return;
		seen.add(full);
		out.push({ path: full, role, sealedAs });
	};

	for (const entry of readManifest(r.manifestPath)) {
		add(resolveSegmentPath(r.manifestPath, entry.path), "sealed", entry);
	}
	for (const path of discoverClosedSegments(r.auditPath)) {
		add(path, "unsealed", null);
	}
	add(r.auditPath, "live", null);
	return out;
}

/** The rehash `runVerify()` uses. Shared so an annotation cannot disagree with a verdict. */
function rehash(event: AuditEvent): string {
	const { integrity, ...rest } = event;
	return chainAuditEvent(rest as Omit<AuditEvent, "integrity">, {
		chainIndex: integrity.chainIndex,
		previousHash: integrity.previousHash,
	}).integrity.hash;
}

/**
 * Read one member as an array of strings.
 *
 * A record is JSON off disk rather than a value this process produced, so a member that
 * should be an array of rule ids may be anything at all. Coerced in one place because a
 * viewer that throws on a malformed record cannot show the reviewer the malformed record.
 */
function asStringArray(value: unknown): string[] {
	return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function asDetections(value: unknown): { id: string; name: string; severity: string }[] {
	if (!Array.isArray(value)) return [];
	const out: { id: string; name: string; severity: string }[] = [];
	for (const item of value) {
		if (!item || typeof item !== "object") continue;
		const d = item as Record<string, unknown>;
		out.push({
			id: typeof d.id === "string" ? d.id : "(unnamed)",
			name: typeof d.name === "string" ? d.name : "(unnamed)",
			severity: typeof d.severity === "string" ? d.severity : "unstated",
		});
	}
	return out;
}

function asString(value: unknown): string | null {
	return typeof value === "string" ? value : null;
}

/**
 * The fleet keys the writers actually emit, in one place.
 *
 * A reader that spelled a key differently from the writer reports "no agent" for every
 * record forever and looks exactly like a fleet nobody declared. Naming them once here is
 * what lets a test hold the reader against the writer instead of against itself.
 */
export const AGENT_KEYS = {
	label: "agentLabel",
	matchedOn: "agentMatchedOn",
	declared: "agentDeclared",
	allowlistSource: "egressAllowlistSource",
} as const;

/**
 * Content keys arrive under two spellings and a reader that knows only one reports the other
 * path as clean.
 *
 * The plaintext proxy folds a request pass and a response pass into one record, so
 * `VerdictLedger.absorb` prefixes each key with the direction it describes: `contentTruncated`
 * from the request pass lands as `requestContentTruncated`. The TLS interception path files one
 * record PER inner exchange, so it never folds two passes together and never prefixes: its
 * `finalise` copies the verdict's metadata verbatim and the key stays `contentTruncated`.
 *
 * Both spellings are read here. Interception is the one mode in which an https body IS
 * decrypted and scanned, so a reader that missed its keys would report the mode with the most
 * visibility as the mode with the least, which inverts the meaning of the coverage section
 * these counters feed.
 */
export const EGRESS_KEYS = {
	host: "host",
	port: "port",
	scheme: "scheme",
	enforcementMode: "enforcementMode",
	transportMode: "transportMode",
	/** Present on every proxy record and on nothing else, so it is what identifies one. */
	bodyVisibility: "bodyVisibility",
	truncated: ["contentTruncated", "requestContentTruncated", "responseContentTruncated"],
	secretTypes: ["contentSecretTypes", "requestContentSecretTypes", "responseContentSecretTypes"],
} as const;

function agentOf(metadata: Record<string, unknown>): RecordAgent | null {
	const label = asString(metadata[AGENT_KEYS.label]);
	const matchedOn = asString(metadata[AGENT_KEYS.matchedOn]);
	const declared = asString(metadata[AGENT_KEYS.declared]);
	const allowlistSource = asString(metadata[AGENT_KEYS.allowlistSource]);
	if (label === null && matchedOn === null && declared === null && allowlistSource === null) return null;
	return {
		label,
		matchedOn,
		// Tri-state on purpose. `null` is "the record does not say", which is a different fact
		// from "no declared agent claimed this" and must not collapse into false.
		declared: declared === null ? null : declared === "true",
		allowlistSource,
	};
}

function egressOf(metadata: Record<string, unknown>): RecordEgress | null {
	const bodyVisibility = asString(metadata[EGRESS_KEYS.bodyVisibility]);
	if (bodyVisibility === null) return null;
	const secretTypes = new Set<string>();
	for (const key of EGRESS_KEYS.secretTypes) {
		for (const type of (asString(metadata[key]) ?? "").split(",")) {
			if (type.trim() !== "") secretTypes.add(type.trim());
		}
	}
	return {
		host: asString(metadata[EGRESS_KEYS.host]),
		port: asString(metadata[EGRESS_KEYS.port]),
		scheme: asString(metadata[EGRESS_KEYS.scheme]),
		enforcementMode: asString(metadata[EGRESS_KEYS.enforcementMode]),
		transportMode: asString(metadata[EGRESS_KEYS.transportMode]),
		bodyVisibility,
		contentTruncated: EGRESS_KEYS.truncated.some((key) => asString(metadata[key]) === "true"),
		secretTypes: [...secretTypes].sort(),
	};
}

export function collectEvidence(paths: AnchorPaths): EvidenceCollection {
	const r = resolvePaths(paths);
	const files: EvidenceFile[] = [];
	const records: EvidenceRecord[] = [];
	const notes: string[] = [];
	let truncated = false;

	for (const { path, role, sealedAs } of recordFiles(r)) {
		const sealed = sealedAs
			? {
					count: sealedAs.count,
					firstIndex: sealedAs.firstIndex,
					lastIndex: sealedAs.lastIndex,
					finalHash: sealedAs.finalHash,
				}
			: null;

		if (!existsSync(path)) {
			// Reported rather than dropped. A sealed segment the manifest names and disk does
			// not have is exactly the finding the linked layer exists to make, and a file list
			// that quietly omits it hides it.
			files.push({
				path,
				role,
				exists: false,
				bytes: 0,
				records: 0,
				firstIndex: null,
				lastIndex: null,
				sealedAs: sealed,
				skipped: "not on disk",
			});
			continue;
		}

		const bytes = statSync(path).size;
		if (bytes > READ_LIMITS.fileBytes) {
			truncated = true;
			notes.push(
				`${path} is ${bytes} bytes, above this view's ${READ_LIMITS.fileBytes} byte per-file cap, so it was not read here. ` +
					"The layer verdicts above still cover it, and the offline command below reads all of it.",
			);
			files.push({
				path,
				role,
				exists: true,
				bytes,
				records: 0,
				firstIndex: null,
				lastIndex: null,
				sealedAs: sealed,
				skipped: "above the per-file read cap",
			});
			continue;
		}

		if (records.length >= READ_LIMITS.records) {
			truncated = true;
			files.push({
				path,
				role,
				exists: true,
				bytes,
				records: 0,
				firstIndex: null,
				lastIndex: null,
				sealedAs: sealed,
				skipped: "the record cap was already reached",
			});
			continue;
		}

		const raw = readFileSync(path, "utf8");
		// Whether the file ends with its terminator is the whole distinction between a hard
		// kill and an edit, so it is read off the raw bytes before anything is filtered. Only
		// the trailing chunk can be unterminated: every earlier one was followed by an LF.
		const chunks = raw.split("\n");
		const unterminated = raw.endsWith("\n") ? -1 : chunks.length - 1;
		const lines: { text: string; torn: boolean }[] = [];
		chunks.forEach((text, i) => {
			if (text.trim() === "") return;
			lines.push({ text, torn: i === unterminated });
		});

		let expectedIndex: number | null = null;
		let expectedPrev: string | null = null;
		let fileRecords = 0;
		let firstIndex: number | null = null;
		let lastIndex: number | null = null;

		for (let i = 0; i < lines.length; i++) {
			if (records.length >= READ_LIMITS.records) {
				// Pushed once however many files are left, because the reviewer needs the fact
				// that the view is a prefix, not the fact repeated per remaining file.
				if (!truncated) {
					notes.push(
						`This view stopped at ${READ_LIMITS.records} records. Later records exist and are not shown. ` +
							"The layer verdicts above cover the whole chain, and the offline command below reads all of it.",
					);
				}
				truncated = true;
				break;
			}
			const { text: line, torn } = lines[i];
			const base = {
				file: path,
				fileRole: role,
				line: i + 1,
				chainIndex: null,
				hash: null,
				previousHash: null,
				canon: null,
				id: null,
				timestamp: null,
				agentId: null,
				sessionId: null,
				plane: null,
				action: null,
				decision: null,
				riskLevel: null,
				matchedRules: [] as string[],
				reasons: [] as string[],
				detections: [] as { id: string; name: string; severity: string }[],
				requiresApproval: false,
				highRiskFlow: false,
				chainGapDeclared: false,
				droppedRecords: null,
				agent: null as RecordAgent | null,
				egress: null as RecordEgress | null,
			};

			// Checked on the raw bytes, because JSON.parse collapses a duplicate member and the
			// evidence of it is gone the moment the line is parsed. Such a record advances
			// neither the expected index nor the expected link, exactly as the verifier does it.
			if (findDuplicateKey(line) !== null) {
				records.push({ ...base, faults: ["dup-key"] });
				fileRecords++;
				continue;
			}

			let ev: AuditEvent;
			try {
				ev = JSON.parse(line) as AuditEvent;
			} catch {
				records.push({ ...base, faults: [torn ? "torn-tail" : "unparseable"] });
				fileRecords++;
				continue;
			}

			const integrity = ev?.integrity;
			if (!integrity || typeof integrity.chainIndex !== "number" || typeof integrity.hash !== "string") {
				records.push({ ...base, faults: ["no-integrity"] });
				fileRecords++;
				continue;
			}

			const faults: RecordFault[] = [];
			if (expectedIndex !== null && integrity.chainIndex !== expectedIndex) faults.push("index-break");
			if (expectedPrev !== null && integrity.previousHash !== expectedPrev) faults.push("link-broken");
			if (rehash(ev) !== integrity.hash) {
				// A record with no canon marker cannot be recomputed here at all: the pre-marker
				// key order needs collation tables this verifier does not carry. Reporting it as
				// tampered would be a different and stronger statement than the evidence supports,
				// so it gets its own code. It still fails the layer, exactly as the verifier fails
				// it, because unverifiable and untouched are indistinguishable from outside.
				faults.push(integrity.canon === "cu1" ? "altered" : "unmarked-canon");
			}

			const metadata = (ev.metadata ?? {}) as Record<string, unknown>;
			records.push({
				...base,
				chainIndex: integrity.chainIndex,
				hash: integrity.hash,
				previousHash: typeof integrity.previousHash === "string" ? integrity.previousHash : null,
				canon: asString(integrity.canon),
				id: asString(ev.id),
				timestamp: asString(ev.timestamp),
				agentId: asString(ev.agentId),
				sessionId: asString(ev.sessionId),
				plane: asString(ev.plane),
				action: asString(ev.action),
				decision: asString(ev.decision),
				riskLevel: asString(ev.riskLevel),
				matchedRules: asStringArray(ev.matchedRules),
				reasons: asStringArray(ev.reasons),
				detections: asDetections(ev.detections),
				requiresApproval: ev.requiresApproval === true,
				highRiskFlow: ev.highRiskFlow === true,
				chainGapDeclared: ev.action === AUDIT_CHAIN_GAP_ACTION,
				droppedRecords: asString(metadata.droppedRecords),
				agent: agentOf(metadata),
				egress: egressOf(metadata),
				faults,
			});
			fileRecords++;
			if (firstIndex === null) firstIndex = integrity.chainIndex;
			lastIndex = integrity.chainIndex;

			expectedIndex = integrity.chainIndex + 1;
			expectedPrev = integrity.hash;
		}

		files.push({
			path,
			role,
			exists: true,
			bytes,
			records: fileRecords,
			firstIndex,
			lastIndex,
			sealedAs: sealed,
			skipped: null,
		});
	}

	return { paths: r, files, records, truncated, notes };
}
