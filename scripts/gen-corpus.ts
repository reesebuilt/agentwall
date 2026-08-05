/**
 * Conformance corpus generator.
 *
 * The corpus is what separates a verifier that is honest from one that is merely green.
 * Every case is written by the PRODUCTION writers in src/audit, so the corpus cannot drift
 * into a private idea of the format, and every forgery is a byte edit applied on top of a
 * case that passes. A verifier is measured by which of these it refuses.
 *
 * Determinism is a hard requirement of the corpus contract: the clock is injected and fixed,
 * the signing keys are committed fixtures rather than generated, paths inside a case are
 * relative, and the tree is wiped before it is written. Re-running the generator produces a
 * byte-identical tree, which is what makes an unexpected diff mean something.
 *
 * A case directory holds audit.jsonl, optionally segments.jsonl, anchors.jsonl, proofs/,
 * checkpoint-key.pem and pubkey.txt, plus expected.json carrying the exit code and the three
 * layer verdicts a conforming verifier reports. Harnesses copy a case to a temp directory
 * before running it, because a verifier may leave key or lock side effects behind and the
 * corpus in git is immutable.
 *
 * CASE CATALOGUE. The second line of each entry is what a naive implementation gets wrong.
 *
 *   g1  one record, nothing else.
 *       Nothing. It is the floor: a verifier that fails g1 is broken, not strict.
 *   g2  twelve records carrying detections, provenance, actor and flow.
 *       Reserializes parsed values instead of reusing the source lexemes, and cannot
 *       reproduce the writer's bytes once a record nests anything.
 *   g3  three sealed segments plus a live file and a manifest.
 *       Reads a chain that resumes in a new file as a gap, or resolves a manifest path
 *       against its own working directory instead of the manifest's.
 *   g4  g3 plus a signed checkpoint and an anchor record with a pending OTS proof.
 *       Reports a pending attestation as proof of inclusion in a Bitcoin block.
 *   g5  unicode, escapes, mixed-case and non-ASCII keys, large and fractional numbers.
 *       Sorts keys by locale collation or reformats numbers, then calls an untouched record
 *       tampered.
 *   g6  g4 with a Bitcoin attestation in the proof and a confirmed anchor.
 *       Cannot walk past the pending attestation tag it hardcoded.
 *   g7  two anchor passes over a growing live file.
 *       Assumes one anchor per log, or overwrites the first pass's proof with the second.
 *
 *   b1  one decision flipped from deny to allow, hash left alone.
 *       Trusts the hash field the record carries instead of recomputing it.
 *   b2  a record removed, then the whole tail relinked and rehashed, indexes untouched.
 *       Checks previousHash links only. Every link here is perfect; the index sequence and
 *       the prefix the checkpoint committed to are what survive the edit.
 *   b3  a record removed and nothing else touched.
 *       Stops at the first problem, so it reports one broken link and never reports that the
 *       index sequence lost a step.
 *   b4  a second writer's records appended with indexes already used.
 *       Reports each reused index as a separate tampering event, which buries the finding
 *       that two processes are writing one chain.
 *   b5  a manifest entry's record count edited.
 *       Verifies segment-to-segment linkage and never recomputes an entry's own hash.
 *   b6  the middle manifest entry removed.
 *       Accepts a manifest that is internally consistent after the removal, because the
 *       surviving entries do link, just not to the segment that vanished, and never asks the
 *       checkpoint how many segments it was signed over.
 *   b7  one bit flipped in the checkpoint signature.
 *       Reads the checkpoint's fields and never verifies the signature over them.
 *   b8  the checkpoint re-signed by a different key, self-consistently.
 *       Verifies the signature against the key carried inside the record, which any forger
 *       controls. Only a pinned key catches this one.
 *   b9  the anchor record's digest field altered.
 *       Reports what the record claims was submitted instead of recomputing the digest from
 *       the checkpoint the record embeds.
 *   b10 the OTS proof truncated inside a varbytes length.
 *       Never opens the proof, or reads the fields it wants and ignores the rest.
 *   b11 a torn final line, as a hard kill leaves behind.
 *       Condemns the whole chain over one partial write, which teaches an operator to ignore
 *       the verifier.
 *   b12 a duplicate key smuggled in ahead of the real one.
 *       Parses with last-key-wins, sees the original value, recomputes the original hash and
 *       passes the record, while a first-key-wins reader downstream sees allow where the
 *       audit trail says deny. A record two implementations read differently is malformed,
 *       so it also cannot count toward what the checkpoint committed to.
 *   b13 an anchor claiming confirmed with its proof file deleted.
 *       Counts the status field. Confirmed is a claim; the proof bytes are the evidence.
 *   b14 a submission that never reached a calendar, recorded with status pending.
 *       Counts it as pending and reports the chain as anchored off-box when nothing ever
 *       left the machine.
 *
 *   b15 a sealed segment rewritten end to end and internally relinked, manifest untouched.
 *       Checks the manifest against itself and never against the bytes it names, so the
 *       anchor ends up binding a manifest that binds only itself.
 *   b16 the live file's last record rewritten and rehashed after the checkpoint was signed.
 *       Checks the signature and stops, so it never asks whether the composite still
 *       describes anything on disk.
 *
 * LIMIT CASES. These pass. They are in the corpus because the format binds less than a
 * reader assumes, and a limit pinned by a case is a limit that cannot be quietly forgotten.
 *
 *   l1  an anchor claiming confirmed whose proof carries only a pending attestation.
 *       Nothing compares the status claim against the attestations in the proof.
 *   l2  records hashed under the pre-marker locale-collated form, with no canon marker.
 *       Treats every hash it cannot reproduce as tampering. A record written before the
 *       canonical form was named is unverifiable here, which is a different statement.
 */

import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { join, resolve } from "path";
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "crypto";
import {
	canonicalizeAuditPayloadLocaleLegacy,
	chainAuditEvent,
	type AuditChainState,
} from "../src/audit/chain";
import { sealSegment } from "../src/audit/rotation";
import { runAnchorPass } from "../src/audit/anchor-service";
import type { HttpPoster } from "../src/audit/anchor";
import type { AuditEvent } from "../src/types";

const REPO = resolve(__dirname, "..");
const CORPUS = join(REPO, "verifier", "testdata", "corpus");
/**
 * Conformance fixture keys, committed rather than generated. A fresh keypair per run would
 * change every signature and every anchor digest, and the corpus would stop being
 * reproducible, which is the property that makes an unexpected diff evidence. They sign
 * synthetic corpus data and secure nothing.
 */
const KEY = join(REPO, "verifier", "testdata", "keys", "checkpoint-key.pem");
const FORGER_KEY = join(REPO, "verifier", "testdata", "keys", "forger-checkpoint-key.pem");

/** Layout of a case's expected.json. Exit code and layer verdicts are the contract. */
interface Expected {
	exit: number;
	layers: { chained: boolean; linked: boolean; anchored: boolean };
	go_codes_include?: string[];
}

type Event = Omit<AuditEvent, "integrity">;
type Clock = () => Date;

/**
 * One clock per case, threaded through every writer in it. Time only moves forward, so no
 * two records and no two checkpoints in a case share a timestamp. That matters beyond
 * realism: an anchor digest covers the checkpoint's signedAt, and two passes at one clock
 * value collapse into a single proof file, which would silently turn a two-anchor case into
 * a one-anchor case.
 */
function clock(stepMs = 1000): Clock {
	let t = Date.parse("2026-01-01T00:00:00.000Z");
	return () => {
		const at = new Date(t);
		t += stepMs;
		return at;
	};
}

const PLANES = ["network", "tool", "content", "browser", "identity", "governance"] as const;

/** One synthetic decision. Shape follows AuditEvent, so the production writers take it. */
function event(n: number, at: Date): Event {
	const deny = n % 5 === 4;
	return {
		id: `evt-${String(n).padStart(4, "0")}`,
		timestamp: at.toISOString(),
		agentId: "corpus-agent",
		sessionId: `sess-${Math.floor(n / 6)}`,
		plane: PLANES[n % PLANES.length],
		action: deny ? "network.egress" : "tool.call",
		decision: deny ? "deny" : "allow",
		riskLevel: deny ? "high" : "low",
		matchedRules: deny ? ["egress-allowlist"] : [],
		reasons: deny ? ["destination is not on the allowlist"] : [],
		requiresApproval: false,
		highRiskFlow: deny,
		metadata: { tool: "http.post", host: `svc-${n % 3}.internal` },
	};
}

/** g2 carries every optional member, so nesting and arrays are exercised end to end. */
function richEvent(n: number, at: Date): Event {
	return {
		...event(n, at),
		detections: [
			{
				id: `det-${n}`,
				ruleId: "secret-material",
				name: "credential in tool output",
				description: 'looks like a token: "sk-test-1234567890"',
				severity: "critical",
				mitreAttack: { tactic: "credential-access", technique: "unsecured credentials", techniqueId: "T1552" },
			},
		],
		provenance: [
			{ source: "tool_output", trustLabel: "untrusted", labels: ["secret_material", "pii"] },
			{ source: "user", trustLabel: "trusted", derivedFrom: ["memory", "web"], justification: "operator typed it" },
		],
		flow: {
			direction: "egress",
			channel: "https",
			target: "api.example.com",
			labels: ["external_egress"],
			crossesBoundary: true,
			highRisk: true,
		},
		actor: { channelId: "chan-7", userId: "u-42", roleIds: ["admin", "auditor"] },
	};
}

/**
 * g5. Every member here exists to break a verifier that reserializes instead of reusing the
 * lexemes it read, or that orders keys by anything other than UTF-16 code units. The typed
 * record shape has no numeric payload members, and canonicalization is defined over JSON
 * values rather than over this project's types, so the case states the JSON directly.
 */
function tortureEvent(at: Date): Event {
	const torture = {
		id: "evt-torture",
		timestamp: at.toISOString(),
		agentId: "corpus-agent",
		plane: "content",
		action: "content.inspect",
		decision: "redact",
		riskLevel: "medium",
		matchedRules: ["pii-detector"],
		reasons: ['quote " backslash \\ tab \t newline \n', "\u0007 control", "emoji \u{1f512} and \u00e9\u00e8\u00ea"],
		requiresApproval: true,
		highRiskFlow: false,
		metadata: {
			// Mixed case and punctuation are the pairs where locale collation and code unit
			// order disagree, which is the entire reason the canonical form names a comparator.
			Zebra: "uppercase sorts first under code units",
			apple: "lowercase sorts after",
			"aws-key": "hyphen",
			aws_key: "underscore",
			"\u00e9cole": "non-ASCII key",
			"\u65e5\u672c\u8a9e": "CJK key",
			"": "empty key",
			'key with "quote"': "quoted",
			// These two are the trap that UTF-16 code unit order sets for a verifier sorting by
			// codepoint or by UTF-8 bytes. The astral key encodes as a leading surrogate
			// (U+D83D), which is BELOW U+FF21, while its codepoint (U+1F511) is above it, so the
			// two orderings put this pair in opposite order.
			"\u{1f511}": "astral key, leading surrogate U+D83D",
			"\uff21": "fullwidth key, U+FF21",
		},
		// A conforming verifier carries these through as source lexemes. One that parses them
		// into a float and prints them back produces a different payload and a different hash.
		numbers: { large: 9007199254740991, negative: -1234567890, fraction: 0.1, exponent: 1e21, zero: 0 },
		nested: [[1, 2, [3, ["deep", { inner: true, Inner: false }]]], [], {}],
	};
	return torture as unknown as Event;
}

function chainLines(events: Event[], state: AuditChainState): { lines: string[]; state: AuditChainState } {
	const lines: string[] = [];
	let cursor = state;
	for (const e of events) {
		const chained = chainAuditEvent(e, cursor);
		lines.push(JSON.stringify(chained));
		cursor = { chainIndex: chained.integrity.chainIndex + 1, previousHash: chained.integrity.hash };
	}
	return { lines, state: cursor };
}

/**
 * Records in the shape a deployment carries from before the canonical form was named: hashed
 * over locale-collated keys and marked with nothing. The skeleton is assembled here because
 * production no longer writes this shape, and the corpus needs it to stay a real deployment
 * shape rather than a hypothesis.
 */
function legacyLines(events: Event[]): string[] {
	let state: AuditChainState = { chainIndex: 0, previousHash: null };
	return events.map((e) => {
		const hash = createHash("sha256")
			.update(
				JSON.stringify({
					chainIndex: state.chainIndex,
					previousHash: state.previousHash,
					algorithm: "sha256",
					payload: canonicalizeAuditPayloadLocaleLegacy(e),
				}),
			)
			.digest("hex");
		const record = {
			...e,
			integrity: {
				chainIndex: state.chainIndex,
				hash,
				previousHash: state.previousHash,
				algorithm: "sha256",
				status: "chained-local",
			},
		};
		state = { chainIndex: state.chainIndex + 1, previousHash: hash };
		return JSON.stringify(record);
	});
}

function readLines(path: string): string[] {
	return readFileSync(path, "utf8").split("\n").filter((l) => l !== "");
}

function writeLines(path: string, lines: string[]): void {
	writeFileSync(path, lines.join("\n") + "\n");
}

/**
 * Byte edits are the whole point of the bad cases, so a substitution that matches nothing is
 * a corpus bug that would ship a forgery case containing no forgery.
 */
function mustReplace(line: string, from: string, to: string): string {
	const edited = line.replace(from, to);
	if (edited === line) throw new Error(`edit matched nothing: ${from}`);
	return edited;
}

function mustFind(lines: string[], needle: string): number {
	const index = lines.findIndex((l) => l.includes(needle));
	if (index < 0) throw new Error(`no line contains ${needle}`);
	return index;
}

/**
 * Rehash a file's records so a forgery is internally perfect. This is what makes the bad
 * cases worth having: a verifier catches them through a property the forger could not
 * recompute, never through a link the forger forgot to fix.
 */
function relink(lines: string[], first: AuditChainState, keepIndexes: boolean): string[] {
	let cursor = first;
	return lines.map((line) => {
		const { integrity, ...rest } = JSON.parse(line) as AuditEvent;
		const chained = chainAuditEvent(rest as Event, {
			chainIndex: keepIndexes ? integrity.chainIndex : cursor.chainIndex,
			previousHash: cursor.previousHash,
		});
		cursor = { chainIndex: chained.integrity.chainIndex + 1, previousHash: chained.integrity.hash };
		return JSON.stringify(chained);
	});
}

// --- OpenTimestamps proof synthesis --------------------------------------------------
//
// A calendar answers a submission with an ops stream that begins where the submitted digest
// ends. These are the smallest streams that exercise each container the format allows.

function varint(value: number): Buffer {
	const out: number[] = [];
	let v = value;
	do {
		let b = v % 128;
		v = Math.floor(v / 128);
		if (v > 0) b |= 0x80;
		out.push(b);
	} while (v > 0);
	return Buffer.from(out);
}

function varbytes(payload: Buffer): Buffer {
	return Buffer.concat([varint(payload.length), payload]);
}

const OP_APPEND = 0xf0;
const OP_SHA256 = 0x08;
const ATTESTATION = 0x00;
const SALT = Buffer.from("a1b2c3d4e5f60708", "hex");
const PENDING_TAG = Buffer.from("83dfe30d2ef90c8e", "hex");
const BITCOIN_TAG = Buffer.from("0588960d73d71901", "hex");

/** What a calendar returns before a block confirms: aggregate, hash, promise to publish. */
function pendingProof(uri: string): Buffer {
	return Buffer.concat([
		Buffer.from([OP_APPEND]),
		varbytes(SALT),
		Buffer.from([OP_SHA256]),
		Buffer.from([ATTESTATION]),
		PENDING_TAG,
		varbytes(varbytes(Buffer.from(uri, "utf8"))),
	]);
}

/** The same stream after an upgrade, attesting to a block height. */
function bitcoinProof(height: number): Buffer {
	return Buffer.concat([
		Buffer.from([OP_APPEND]),
		varbytes(SALT),
		Buffer.from([OP_SHA256]),
		Buffer.from([ATTESTATION]),
		BITCOIN_TAG,
		varbytes(varint(height)),
	]);
}

/** Injected transport. The corpus never touches the network. */
function poster(body: Buffer): HttpPoster {
	return {
		async post() {
			return { status: 200, body };
		},
	};
}

// --- case construction ---------------------------------------------------------------

const LIVE = "audit.jsonl";
const MANIFEST = "segments.jsonl";
const ANCHORS = "anchors.jsonl";
const PROOFS = "proofs";
const CASE_KEY = "checkpoint-key.pem";
const CALENDAR = "https://alice.btc.calendar.opentimestamps.org";
const SEGMENTS = [`${LIVE}.1`, `${LIVE}.2`, `${LIVE}.3`];

/** Three sealed segments plus a live file: what a rotating deployment looks like on disk. */
function writeRotatedChain(at: Clock): void {
	let state: AuditChainState = { chainIndex: 0, previousHash: null };
	let n = 0;
	for (const segment of [...SEGMENTS, LIVE]) {
		const chained = chainLines(
			Array.from({ length: 6 }, () => event(n++, at())),
			state,
		);
		writeLines(segment, chained.lines);
		state = chained.state;
	}
	// Sealed in rotation order rather than through discovery, whose ordering comes from mtime
	// and is therefore not reproducible from a git checkout.
	for (const segment of SEGMENTS) sealSegment(segment, MANIFEST, at);
}

/** Sign a checkpoint over the manifest head and anchor it against a synthetic calendar. */
async function anchor(proof: Buffer, at: Clock): Promise<void> {
	copyFileSync(KEY, CASE_KEY);
	const result = await runAnchorPass(
		{ auditPath: LIVE, manifestPath: MANIFEST, keyPath: CASE_KEY, anchorLogPath: ANCHORS, proofDir: PROOFS },
		at,
		poster(proof),
	);
	if (!result.anchored) throw new Error(`anchor pass did nothing: ${result.reason}`);
}

/** The baseline every forgery is cut from: three segments, a live file, one pending anchor. */
async function baseline(at: Clock): Promise<void> {
	writeRotatedChain(at);
	await anchor(pendingProof(`${CALENDAR}/timestamp`), at);
}

function anchorRecords(): Record<string, unknown>[] {
	return readLines(ANCHORS).map((l) => JSON.parse(l) as Record<string, unknown>);
}

function writeAnchorRecords(records: Record<string, unknown>[]): void {
	writeLines(ANCHORS, records.map((r) => JSON.stringify(r)));
}

function proofPath(record: Record<string, unknown>): string {
	const path = record.proofPath;
	if (typeof path !== "string") throw new Error("anchor record carries no proof path");
	return path;
}

async function buildCase(name: string, build: (at: Clock) => Promise<Expected> | Expected): Promise<void> {
	const dir = join(CORPUS, name);
	mkdirSync(dir, { recursive: true });
	const previous = process.cwd();
	// Built from inside the case directory so every recorded path is relative and the case
	// still verifies after a harness copies it somewhere else.
	process.chdir(dir);
	let expected: Expected;
	try {
		expected = await build(clock());
	} finally {
		process.chdir(previous);
	}
	// The exit code is a function of the three layers, never an independent claim: a verifier
	// exits 0 only when all three verify. An expectation that says otherwise is unreachable,
	// and it would fail whichever verifier is right.
	const allVerified = Object.values(expected.layers).every(Boolean);
	if ((expected.exit === 0) !== allVerified) {
		throw new Error(`${name}: exit ${expected.exit} contradicts layers ${JSON.stringify(expected.layers)}`);
	}
	writeFileSync(join(dir, "expected.json"), JSON.stringify(expected, null, 2) + "\n");
	process.stdout.write(`${name}\n`);
}

const UNANCHORED: Expected = { exit: 1, layers: { chained: true, linked: true, anchored: false } };
const ANCHORED_OK: Expected = { exit: 0, layers: { chained: true, linked: true, anchored: true } };

async function main(): Promise<void> {
	// Wiped rather than merged: a case that is renamed or dropped has to disappear from the
	// tree, or the corpus accumulates entries no generator produces.
	rmSync(CORPUS, { recursive: true, force: true });
	mkdirSync(CORPUS, { recursive: true });

	await buildCase("g1-single-record", (at) => {
		writeLines(LIVE, chainLines([event(0, at())], { chainIndex: 0, previousHash: null }).lines);
		return UNANCHORED;
	});

	await buildCase("g2-nested-records", (at) => {
		const events = Array.from({ length: 12 }, (_, i) => (i % 3 === 0 ? richEvent(i, at()) : event(i, at())));
		writeLines(LIVE, chainLines(events, { chainIndex: 0, previousHash: null }).lines);
		return UNANCHORED;
	});

	await buildCase("g3-rotated-segments", (at) => {
		writeRotatedChain(at);
		return UNANCHORED;
	});

	await buildCase("g4-anchored-pending", async (at) => {
		await baseline(at);
		return ANCHORED_OK;
	});

	await buildCase("g5-canonicalization-torture", (at) => {
		const events = [event(0, at()), tortureEvent(at()), event(2, at())];
		writeLines(LIVE, chainLines(events, { chainIndex: 0, previousHash: null }).lines);
		return UNANCHORED;
	});

	await buildCase("g6-anchor-bitcoin-attestation", async (at) => {
		writeRotatedChain(at);
		await anchor(bitcoinProof(850000), at);
		// An upgraded proof carries a block attestation, so the record's status catches up with
		// its evidence. Production has no upgrade path, so the corpus states the shape directly.
		writeAnchorRecords(anchorRecords().map((r) => ({ ...r, status: "confirmed" })));
		return ANCHORED_OK;
	});

	await buildCase("g7-two-anchor-passes", async (at) => {
		await baseline(at);
		// The live file keeps growing between passes, which is the normal shape: each pass
		// covers more records than the last and each proof stands on its own.
		const grown = chainLines([event(24, at())], {
			chainIndex: 24,
			previousHash: (JSON.parse(readLines(LIVE)[5]) as AuditEvent).integrity.hash,
		});
		writeLines(LIVE, [...readLines(LIVE), ...grown.lines]);
		await anchor(pendingProof(`${CALENDAR}/timestamp`), at);
		if (anchorRecords().length !== 2) throw new Error("second anchor pass wrote no record");
		return ANCHORED_OK;
	});

	await buildCase("b1-decision-flipped", async (at) => {
		await baseline(at);
		const lines = readLines(LIVE);
		const target = mustFind(lines, '"decision":"deny"');
		lines[target] = mustReplace(lines[target], '"decision":"deny"', '"decision":"allow"');
		writeLines(LIVE, lines);
		return { exit: 1, layers: { chained: false, linked: true, anchored: true }, go_codes_include: ["hash-mismatch"] };
	});

	await buildCase("b2-record-removed-tail-relinked", async (at) => {
		await baseline(at);
		const lines = readLines(LIVE);
		const head = lines.slice(0, 3);
		const previousHash = (JSON.parse(head[2]) as AuditEvent).integrity.hash;
		// Indexes are kept, so the tail links and hashes perfectly and the gap in the index
		// sequence is the only evidence left that a record was taken out.
		writeLines(LIVE, [...head, ...relink(lines.slice(4), { chainIndex: 0, previousHash }, true)]);
		// The live file is a record shorter than the prefix the checkpoint committed to, and no
		// other eligible file carries that prefix, so the anchored layer loses its footing too.
		return {
			exit: 1,
			layers: { chained: false, linked: true, anchored: false },
			go_codes_include: ["index-gap"],
		};
	});

	await buildCase("b3-record-removed", async (at) => {
		await baseline(at);
		const lines = readLines(LIVE);
		writeLines(LIVE, [...lines.slice(0, 3), ...lines.slice(4)]);
		return {
			exit: 1,
			layers: { chained: false, linked: true, anchored: false },
			go_codes_include: ["index-gap", "link-break"],
		};
	});

	await buildCase("b4-index-reuse-concurrent-writers", async (at) => {
		await baseline(at);
		const lines = readLines(LIVE);
		const stale = JSON.parse(lines[1]) as AuditEvent;
		// A second writer that resumed from a stale read keeps its own chain state, so both
		// writers issue the same indexes. Every record it writes is internally valid.
		const second = chainLines(
			Array.from({ length: 4 }, (_, i) => event(100 + i, at())),
			{ chainIndex: stale.integrity.chainIndex + 1, previousHash: stale.integrity.hash },
		);
		writeLines(LIVE, [...lines, ...second.lines]);
		return {
			exit: 1,
			layers: { chained: false, linked: true, anchored: true },
			go_codes_include: ["index-gap", "link-break"],
		};
	});

	await buildCase("b5-manifest-count-edited", async (at) => {
		await baseline(at);
		const entries = readLines(MANIFEST);
		entries[0] = mustReplace(entries[0], '"count":6', '"count":4');
		writeLines(MANIFEST, entries);
		return {
			exit: 1,
			layers: { chained: true, linked: false, anchored: true },
			go_codes_include: ["manifest-entry-hash"],
		};
	});

	await buildCase("b6-manifest-middle-entry-removed", async (at) => {
		await baseline(at);
		const entries = readLines(MANIFEST);
		writeLines(MANIFEST, [entries[0], entries[2]]);
		// The checkpoint was signed over three sealed segments, so a manifest now holding two
		// cannot supply the head it committed to. Dropping the newest entries breaks no
		// previousSegmentHash link, because what remains still chains, and the checkpoint is the
		// only thing that notices.
		return {
			exit: 1,
			layers: { chained: true, linked: false, anchored: false },
			go_codes_include: ["manifest-link-break"],
		};
	});

	await buildCase("b7-checkpoint-signature-flipped", async (at) => {
		await baseline(at);
		const [record] = anchorRecords();
		const checkpoint = record.checkpoint as Record<string, unknown>;
		const signature = Buffer.from(String(checkpoint.signature), "base64");
		signature[0] ^= 0x01;
		writeAnchorRecords([{ ...record, checkpoint: { ...checkpoint, signature: signature.toString("base64") } }]);
		return {
			exit: 1,
			layers: { chained: true, linked: true, anchored: false },
			go_codes_include: ["checkpoint-bad-signature"],
		};
	});

	await buildCase("b8-checkpoint-foreign-key", async (at) => {
		await baseline(at);
		const [record] = anchorRecords();
		const checkpoint = record.checkpoint as Record<string, unknown>;
		const forger = createPrivateKey(readFileSync(FORGER_KEY, "utf8"));
		const payload = Buffer.from(
			JSON.stringify({
				chainIndex: checkpoint.chainIndex,
				hash: checkpoint.hash,
				signedAt: checkpoint.signedAt,
				algorithm: "ed25519",
			}),
			"utf8",
		);
		// Re-signed, not corrupted. The checkpoint verifies perfectly against the key it
		// carries, and the anchor digest is recomputed to match, so every internal check
		// passes. Only a verifier holding the key it expects can tell this from the real one.
		const forged: Record<string, unknown> = {
			...checkpoint,
			signature: edSign(null, payload, forger).toString("base64"),
			publicKey: createPublicKey(forger).export({ type: "spki", format: "der" }).toString("base64"),
		};
		const digest = createHash("sha256")
			.update(
				JSON.stringify({
					chainIndex: forged.chainIndex,
					hash: forged.hash,
					signedAt: forged.signedAt,
					signature: forged.signature,
					publicKey: forged.publicKey,
				}),
				"utf8",
			)
			.digest("hex");
		writeAnchorRecords([{ ...record, digest, checkpoint: forged }]);
		const expectedKey = createPublicKey(createPrivateKey(readFileSync(KEY, "utf8")))
			.export({ type: "spki", format: "der" })
			.toString("base64");
		writeFileSync("pubkey.txt", `${expectedKey}\n`);
		return {
			exit: 1,
			layers: { chained: true, linked: true, anchored: false },
			go_codes_include: ["checkpoint-key-mismatch"],
		};
	});

	await buildCase("b9-anchor-digest-altered", async (at) => {
		await baseline(at);
		const [record] = anchorRecords();
		const digest = String(record.digest);
		writeAnchorRecords([{ ...record, digest: (digest[0] === "0" ? "1" : "0") + digest.slice(1) }]);
		return {
			exit: 1,
			layers: { chained: true, linked: true, anchored: false },
			go_codes_include: ["digest-mismatch"],
		};
	});

	await buildCase("b10-proof-truncated", async (at) => {
		await baseline(at);
		const path = proofPath(anchorRecords()[0]);
		const proof = readFileSync(path);
		// Cut inside the attestation payload, so a length prefix promises bytes the file does
		// not contain.
		writeFileSync(path, proof.subarray(0, proof.length - 12));
		return {
			exit: 1,
			layers: { chained: true, linked: true, anchored: false },
			go_codes_include: ["proof-parse-error"],
		};
	});

	await buildCase("b11-torn-tail", (at) => {
		writeRotatedChain(at);
		const lines = readLines(LIVE);
		// A hard kill during a write leaves a partial line with no terminator. It is damage
		// rather than forgery, and the format reports it as its own condition rather than as a
		// broken chain. Left unanchored so the exit code still carries a failure to report.
		writeFileSync(LIVE, `${lines.join("\n")}\n${lines[lines.length - 1].slice(0, 64)}`);
		return {
			exit: 1,
			layers: { chained: true, linked: true, anchored: false },
			go_codes_include: ["torn-tail"],
		};
	});

	await buildCase("b12-duplicate-key-shadowed", async (at) => {
		await baseline(at);
		const lines = readLines(LIVE);
		const target = mustFind(lines, '"decision":"deny"');
		// The duplicate goes FIRST so a last-key-wins parser reads the original value and
		// recomputes the original hash. The forger is aiming at whatever reads this file with
		// first-key-wins semantics.
		lines[target] = `{"decision":"allow",${lines[target].slice(1)}`;
		writeLines(LIVE, lines);
		// A record two implementations can read differently is not evidence, so the format calls
		// it malformed. It therefore cannot count toward the prefix the checkpoint committed to
		// either, and the anchored layer loses the record it needs to reproduce that prefix.
		return {
			exit: 1,
			layers: { chained: false, linked: true, anchored: false },
			go_codes_include: ["dup-key"],
		};
	});

	await buildCase("b13-confirmed-without-proof", async (at) => {
		await baseline(at);
		const [record] = anchorRecords();
		rmSync(proofPath(record));
		writeAnchorRecords([{ ...record, status: "confirmed" }]);
		return {
			exit: 1,
			layers: { chained: true, linked: true, anchored: false },
			go_codes_include: ["proof-missing"],
		};
	});

	await buildCase("b14-submission-never-reached-calendar", async (at) => {
		await baseline(at);
		const [record] = anchorRecords();
		rmSync(proofPath(record));
		delete record.proofPath;
		// The record is written either way, because silence about a failed submission is worse
		// than the failure. It is not an anchor and must never be counted as one.
		writeAnchorRecords([{ ...record, reference: "", error: "all calendars failed: connection refused" }]);
		return {
			exit: 1,
			layers: { chained: true, linked: true, anchored: false },
			go_codes_include: ["anchor-failed"],
		};
	});

	await buildCase("b15-sealed-segment-rewritten", async (at) => {
		await baseline(at);
		const segment = SEGMENTS[1];
		const lines = readLines(segment);
		const first = JSON.parse(lines[0]) as AuditEvent;
		const target = mustFind(lines, '"decision":"deny"');
		lines[target] = mustReplace(lines[target], '"decision":"deny"', '"decision":"allow"');
		// Rewritten end to end and relinked, so the segment's own chain verifies and every
		// manifest rule that looks only at the manifest still passes. What catches it is the
		// entry's finalHash, which folds in every record in the file it names.
		writeLines(
			segment,
			relink(lines, { chainIndex: first.integrity.chainIndex, previousHash: first.integrity.previousHash }, false),
		);
		return {
			exit: 1,
			layers: { chained: true, linked: false, anchored: true },
			go_codes_include: ["segment-content-mismatch"],
		};
	});

	await buildCase("b16-live-tail-rewritten-after-checkpoint", async (at) => {
		await baseline(at);
		const lines = readLines(LIVE);
		const last = JSON.parse(lines[lines.length - 1]) as AuditEvent;
		lines[lines.length - 1] = mustReplace(
			lines[lines.length - 1],
			`"host":"${last.metadata?.host}"`,
			'"host":"attacker.example"',
		);
		// Rehashed, so the live file's own chain verifies. The checkpoint committed to a prefix
		// of this file, and a rewritten prefix produces a different hash at that count and
		// reproduces from nothing else eligible.
		writeLines(LIVE, [
			...lines.slice(0, -1),
			...relink(lines.slice(-1), { chainIndex: last.integrity.chainIndex, previousHash: last.integrity.previousHash }, true),
		]);
		return {
			exit: 1,
			layers: { chained: true, linked: true, anchored: false },
			go_codes_include: ["live-tail-mismatch"],
		};
	});

	await buildCase("l1-confirmed-with-pending-proof", async (at) => {
		await baseline(at);
		writeAnchorRecords(anchorRecords().map((r) => ({ ...r, status: "confirmed" })));
		return ANCHORED_OK;
	});

	await buildCase("l2-legacy-canon-unmarked", () => {
		const legacyClock = clock();
		writeLines(
			LIVE,
			legacyLines([
				event(0, legacyClock()),
				tortureEvent(legacyClock()),
				event(2, legacyClock()),
			]),
		);
		return {
			exit: 1,
			layers: { chained: false, linked: true, anchored: false },
			go_codes_include: ["hash-mismatch-or-legacy-canon"],
		};
	});
}

main().catch((err) => {
	process.stderr.write(`${(err as Error).stack ?? String(err)}\n`);
	process.exit(1);
});
