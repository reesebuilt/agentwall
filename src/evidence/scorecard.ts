import { basename } from "path";
import { anchorReach, runVerify, type AnchorPaths, type AnchorReach, type VerifyReport } from "../audit/anchor-service";
import { verifyManifest } from "../audit/rotation";
import {
	collectEvidence,
	FAULT_CONDEMNS,
	type EvidenceCollection,
	type EvidenceRecord,
	type RecordFault,
} from "./collect";

/**
 * The per-session scorecard and the layer states a page shows.
 *
 * ONE RULE GOVERNS THIS FILE. The layer verdicts come from `runVerify()` and are reproduced
 * verbatim, including the PASS or FAIL a reviewer will see if they run the command the page
 * prints. Anything this module derives on top of that is scoped, labelled as scoped, and
 * carries the CLI verdict beside it, because a viewer that quietly disagrees with the
 * verifier is worse than no viewer: the reviewer then has two verdicts and no way to choose.
 *
 * The one place the viewer says something the layer counter does not is the anchored state,
 * and it says LESS rather than more. `runVerify()` counts an anchor as confirmed when the
 * record says "confirmed"; nothing compares that claim against the attestations inside the
 * proof, which is the limit corpus case `l1-confirmed-with-pending-proof` pins. This view
 * derives the state from the proof bytes instead, so an anchor whose proof carries only a
 * calendar attestation renders as pending. Rendering pending as verified is the overclaim
 * this whole product exists not to make.
 */

/**
 * What a layer can be, from a reader's point of view.
 *
 * `pending` and `absent` exist because a two-state chip forces one of two lies. Calling a
 * submitted-but-unconfirmed anchor a pass claims a Bitcoin block that does not exist yet;
 * calling it a failure tells an operator something is broken when nothing is.
 */
export type LayerState = "pass" | "fail" | "pending" | "absent";

export const LAYER_MEANING: Record<string, string> = {
	chained: "records link within each segment, so an edit inside one is detectable",
	linked: "segments link and match their files, so removing or replacing one is detectable",
	anchored: "a fingerprint exists off-box and still matches what is here, so a local rewrite shows",
};

export const LAYER_STATE_MEANING: Record<LayerState, string> = {
	pass: "checked and holds",
	fail: "checked and does not hold",
	pending: "submitted off-box and waiting on a Bitcoin block; pending is not proof",
	absent: "no evidence of this property exists for this span, so nothing was checked",
};

export interface EvidenceLayer {
	name: string;
	/** What this view says, which may be narrower than the CLI verdict. Never wider. */
	state: LayerState;
	/** Exactly what `agentwall verify` prints for this layer, so the two cannot be confused. */
	cliVerdict: "PASS" | "FAIL";
	detail: string;
	problems: string[];
	/** Set when `state` and `cliVerdict` differ, naming why. */
	divergence: string | null;
}

/** One anchor as a reviewer reads it: a receipt with a state derived from its proof bytes. */
export interface AnchorReceipt extends AnchorReach {
	/**
	 * confirmed: the proof reaches a Bitcoin attestation.
	 * pending:   a calendar accepted it and no block has been reached.
	 * failed:    the submission never reached a calendar.
	 * unproven:  it claims a calendar answered and no usable proof stands behind that.
	 */
	state: "confirmed" | "pending" | "failed" | "unproven";
	/** True when the record's own status claims more than its proof bytes carry. */
	overclaimsStatus: boolean;
}

export interface SessionScorecard {
	/** null is the bucket for records that carry no session. */
	sessionId: string | null;
	agentIds: string[];
	records: number;
	firstSeen: string | null;
	lastSeen: string | null;
	firstIndex: number | null;
	lastIndex: number | null;
	files: string[];
	/** Counts keyed by the decision the record carries. */
	decisions: { decision: string; count: number }[];
	planes: { plane: string; count: number }[];
	actions: { action: string; count: number }[];
	riskLevels: { riskLevel: string; count: number }[];
	approvalsRequired: number;
	highRiskFlows: number;
	detections: { id: string; name: string; severity: string; count: number }[];
	matchedRules: { ruleId: string; count: number }[];
	/** Records that reproduced their own hash and linked to their predecessor. */
	intact: number;
	faulty: { file: string; line: number; chainIndex: number | null; faults: RecordFault[] }[];
	/** Records the writer declared it could not store, inside this session's span. */
	declaredGaps: number;
	/**
	 * The session's own records, in the order the files hold them.
	 *
	 * Carried on the scorecard rather than looked up again by the caller, because the rule for
	 * which bucket a record belongs to lives in one place. A second implementation of that rule
	 * in a route would eventually disagree with this one, and a reviewer would be reading a
	 * record list that does not match the counts above it.
	 */
	chainRecords: EvidenceRecord[];
	layers: EvidenceLayer[];
}

export interface EvidenceReport {
	paths: EvidenceCollection["paths"];
	files: EvidenceCollection["files"];
	/** The verifier's own three-layer verdict, reproduced. */
	verify: VerifyReport;
	/** The same three layers with a reader-facing state beside the CLI verdict. */
	layers: EvidenceLayer[];
	anchors: AnchorReceipt[];
	sessions: SessionScorecard[];
	totals: {
		records: number;
		intact: number;
		faulty: number;
		declaredGaps: number;
		sessions: number;
	};
	truncated: boolean;
	notes: string[];
	/** Commands that reproduce the verdict above without trusting this page. */
	offline: OfflineCommands;
}

export interface OfflineCommands {
	/** The bundled TypeScript verifier. */
	bundled: string;
	/** Machine-readable form of the same run. */
	bundledJson: string;
	/** The independent Go verifier, which shares no code with the writer. */
	independent: string;
	/** Binding checkpoints to a key supplied from outside the evidence. */
	pinned: string;
	/** Reading one session's records straight out of the JSONL. */
	session: (sessionId: string | null) => string;
}

/** Order the counts by weight, then by name, so the same evidence renders the same way twice. */
function ranked(counts: Map<string, number>): { key: string; count: number }[] {
	return [...counts.entries()]
		.map(([key, count]) => ({ key, count }))
		.sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

function bump(counts: Map<string, number>, key: string | null): void {
	if (key === null) return;
	counts.set(key, (counts.get(key) ?? 0) + 1);
}

/**
 * Turn one anchor's facts into the state a reviewer reads.
 *
 * The order is the point. An error beats every other signal, because a submission that never
 * reached a calendar has nothing behind it whatever its status field says. Then proof
 * problems, then the attestations the bytes actually carry. The record's own `status` is
 * never consulted for the state; it is only compared against the state, so a claim larger
 * than the evidence becomes visible instead of becoming the verdict.
 */
function receiptFor(reach: AnchorReach): AnchorReceipt {
	let state: AnchorReceipt["state"];
	if (reach.error) state = "failed";
	else if (reach.proofProblem !== null || !reach.digestMatchesCheckpoint) state = "unproven";
	else if (reach.bitcoinAttestations > 0) state = "confirmed";
	else if (reach.pendingAttestations > 0) state = "pending";
	else state = "unproven";

	return {
		...reach,
		state,
		overclaimsStatus: reach.statusClaimed === "confirmed" && state !== "confirmed",
	};
}

/**
 * Anchors whose proof stands up and whose reach is known. Only these can support a claim
 * that some record is anchored; the rest are shown so their failure is visible, never used
 * to cover anything.
 */
function usableAnchors(anchors: readonly AnchorReceipt[]): AnchorReceipt[] {
	return anchors.filter(
		(a) => (a.state === "confirmed" || a.state === "pending") && a.coveredThroughIndex !== null,
	);
}

/**
 * The anchored state for a span of record indexes.
 *
 * `throughIndex` is the highest record index the span contains. An anchor covers the span
 * only when it demonstrably commits to at least that index: an anchor taken before a
 * session's last record says nothing about that record, and reporting it as covered would be
 * the difference between evidence and decoration.
 */
function anchoredStateFor(
	anchors: readonly AnchorReceipt[],
	throughIndex: number | null,
): { state: LayerState; detail: string; problems: string[] } {
	if (anchors.length === 0) {
		return { state: "absent", detail: "nothing anchored off-box yet", problems: [] };
	}
	if (throughIndex === null) {
		return {
			state: "absent",
			detail: "no record in this span carries a chain index, so no anchor can be matched to it",
			problems: [],
		};
	}

	const usable = usableAnchors(anchors);
	const covering = usable.filter((a) => (a.coveredThroughIndex as number) >= throughIndex);
	const broken = anchors.filter((a) => a.state === "failed" || a.state === "unproven");
	const problems: string[] = [];
	for (const a of broken) {
		problems.push(
			`anchor on line ${a.line}: ${a.error ?? a.proofProblem ?? "the digest does not recompute from the checkpoint it embeds"}`,
		);
	}

	const confirmed = covering.filter((a) => a.state === "confirmed");
	if (confirmed.length > 0) {
		const heights = confirmed.flatMap((a) => a.bitcoinHeights);
		return {
			state: "pass",
			detail:
				`${confirmed.length} anchor(s) reach a Bitcoin attestation and commit through record ` +
				`${Math.max(...confirmed.map((a) => a.coveredThroughIndex as number))}` +
				(heights.length ? `, block height(s) ${heights.join(", ")}` : ""),
			problems,
		};
	}

	const pending = covering.filter((a) => a.state === "pending");
	if (pending.length > 0) {
		return {
			state: "pending",
			detail:
				`${pending.length} anchor(s) commit through record ` +
				`${Math.max(...pending.map((a) => a.coveredThroughIndex as number))} and are waiting on a ` +
				"Bitcoin block. A calendar accepted the submission; no block has included it yet",
			problems,
		};
	}

	if (broken.length > 0 && usable.length === 0) {
		return {
			state: "fail",
			detail: `${broken.length} anchor(s) exist and none has usable proof behind it`,
			problems,
		};
	}

	const furthest = usable.reduce<number | null>(
		(max, a) => (max === null || (a.coveredThroughIndex as number) > max ? (a.coveredThroughIndex as number) : max),
		null,
	);
	return {
		state: "absent",
		detail:
			furthest === null
				? `no anchor's reach could be rebuilt from disk, so nothing here is shown as anchored`
				: `the furthest usable anchor commits through record ${furthest}; this span runs to ${throughIndex}, ` +
					"so the records past that rest on local controls alone",
		problems,
	};
}

/**
 * The three layers as the page shows them: the verifier's verdict, plus a reader state that
 * splits pending out of the anchored pass.
 */
function globalLayers(verify: VerifyReport, anchors: readonly AnchorReceipt[]): EvidenceLayer[] {
	return verify.layers.map((layer) => {
		const cliVerdict = layer.ok ? "PASS" : "FAIL";
		if (layer.name !== "anchored") {
			return {
				name: layer.name,
				state: layer.ok ? "pass" : "fail",
				cliVerdict,
				detail: layer.detail,
				problems: layer.problems,
				divergence: null,
			} satisfies EvidenceLayer;
		}

		const usable = usableAnchors(anchors);
		const anyBitcoin = usable.some((a) => a.state === "confirmed");
		const anyPending = usable.some((a) => a.state === "pending");
		let state: LayerState;
		if (!layer.ok) state = "fail";
		else if (anyBitcoin) state = "pass";
		else if (anyPending) state = "pending";
		else state = "absent";

		return {
			name: layer.name,
			state,
			cliVerdict,
			detail: layer.detail,
			problems: layer.problems,
			divergence:
				state === "pending" && cliVerdict === "PASS"
					? "agentwall verify passes this layer with a pending anchor and prints that pending is not proof. " +
						"This view carries that caveat in the state itself, so no reader can skim past it. Same evidence, same exit code."
					: state === "absent" && cliVerdict === "PASS"
						? "agentwall verify passes this layer and no anchor here has a proof this view can stand behind."
						: null,
		} satisfies EvidenceLayer;
	});
}

/**
 * The chained state for one session.
 *
 * Two questions, deliberately kept apart. Do this session's own records reproduce their own
 * hashes, and is the chain across the span they occupy unbroken. They are not the same
 * question: a chain holds one global sequence, so a session's records are interleaved with
 * other sessions', and an edit to somebody else's record between two of these leaves these
 * reproducing perfectly while the ORDER around them is no longer vouched for. A scorecard
 * that reported only the first would tell a reviewer this session is clean inside a file that
 * is not.
 */
function chainedStateFor(
	mine: readonly EvidenceRecord[],
	all: readonly EvidenceRecord[],
): { state: LayerState; detail: string; problems: string[] } {
	const problems: string[] = [];
	const ownFaults = mine.filter((rec) => rec.faults.some((f) => FAULT_CONDEMNS[f]));
	for (const rec of ownFaults) {
		problems.push(
			`${rec.file} line ${rec.line}${rec.chainIndex === null ? "" : ` (record ${rec.chainIndex})`}: ${rec.faults.join(", ")}`,
		);
	}

	const indexes = mine.map((rec) => rec.chainIndex).filter((v): v is number => v !== null);
	if (indexes.length === 0) {
		return {
			state: ownFaults.length > 0 ? "fail" : "absent",
			detail: "no record in this session carries a chain index",
			problems,
		};
	}
	const low = Math.min(...indexes);
	const high = Math.max(...indexes);

	// Every record inside the span, whoever it belongs to. A break anywhere in here is a
	// break in the ordering this session's records depend on.
	const mineKeys = new Set(mine.map((rec) => `${rec.file}:${rec.line}`));
	const neighbourFaults = all.filter(
		(rec) =>
			!mineKeys.has(`${rec.file}:${rec.line}`) &&
			rec.chainIndex !== null &&
			rec.chainIndex >= low &&
			rec.chainIndex <= high &&
			rec.faults.some((f) => FAULT_CONDEMNS[f]),
	);
	for (const rec of neighbourFaults) {
		problems.push(
			`${rec.file} line ${rec.line} (record ${rec.chainIndex}, another session): ${rec.faults.join(", ")}, ` +
				"so the ordering around this session's records is not vouched for",
		);
	}

	const files = new Set(mine.map((rec) => rec.file)).size;
	return {
		state: ownFaults.length + neighbourFaults.length > 0 ? "fail" : "pass",
		detail:
			`${mine.length} record(s), chain index ${low} to ${high}, in ${files} file(s)` +
			(ownFaults.length === 0 && neighbourFaults.length === 0
				? "; every one reproduces its own hash and links to its predecessor"
				: ""),
		problems,
	};
}

/**
 * The linked state for one session.
 *
 * A session whose records are all still in the live file is NOT covered by the manifest, and
 * saying pass there would vouch for a property nothing has established. The manifest seals
 * closed segments; the live file is deliberately left out of it because it is still growing.
 */
function linkedStateFor(
	mine: readonly EvidenceRecord[],
	report: EvidenceReport["files"],
	manifestProblems: readonly string[],
): { state: LayerState; detail: string; problems: string[] } {
	const paths = new Set(mine.map((rec) => rec.file));
	const containing = report.filter((f) => paths.has(f.path));
	const sealed = containing.filter((f) => f.role === "sealed");
	const unsealed = containing.filter((f) => f.role === "unsealed");
	const live = containing.filter((f) => f.role === "live");

	const problems: string[] = [];
	for (const f of unsealed) {
		problems.push(
			`${f.path} holds records from this session, is a closed segment, and is not sealed into the manifest, ` +
				"so it sits outside every anchor. Run `agentwall anchor` to seal it.",
		);
	}
	// Only the manifest findings that name a file this session's records are in. A manifest
	// problem about some other segment is real and belongs on the file-wide layer above, not
	// on this session's row.
	//
	// Matched on the file name rather than the full path because a manifest entry records the
	// path the writer was given, which may be relative, while the file list here is resolved.
	// Segment names are unique within one evidence directory, which is what makes the short
	// name sufficient.
	for (const problem of manifestProblems) {
		if (sealed.some((f) => problem.includes(basename(f.path)))) {
			problems.push(problem);
		}
	}

	if (sealed.length === 0) {
		return {
			state: unsealed.length > 0 ? "fail" : "absent",
			detail:
				unsealed.length > 0
					? `${unsealed.length} closed segment(s) hold this session and none is sealed`
					: `all ${live.length ? "records are in the live file" : "records are outside any sealed segment"}, ` +
						"which no manifest entry covers until it rotates and is sealed",
			problems,
		};
	}

	return {
		state: problems.length === 0 ? "pass" : "fail",
		detail:
			`${sealed.length} sealed segment(s) hold this session` +
			(live.length ? `, plus the live file, which no manifest entry covers yet` : "") +
			(unsealed.length ? `, plus ${unsealed.length} unsealed segment(s)` : ""),
		problems,
	};
}

function scorecardFor(
	sessionId: string | null,
	mine: readonly EvidenceRecord[],
	all: readonly EvidenceRecord[],
	files: EvidenceReport["files"],
	manifestProblems: readonly string[],
	anchors: readonly AnchorReceipt[],
	verify: VerifyReport,
): SessionScorecard {
	const decisions = new Map<string, number>();
	const planes = new Map<string, number>();
	const actions = new Map<string, number>();
	const riskLevels = new Map<string, number>();
	const rules = new Map<string, number>();
	const agents = new Set<string>();
	const detections = new Map<string, { id: string; name: string; severity: string; count: number }>();
	let approvalsRequired = 0;
	let highRiskFlows = 0;
	let declaredGaps = 0;
	let firstSeen: string | null = null;
	let lastSeen: string | null = null;

	for (const rec of mine) {
		bump(decisions, rec.decision);
		bump(planes, rec.plane);
		bump(actions, rec.action);
		bump(riskLevels, rec.riskLevel);
		for (const ruleId of rec.matchedRules) bump(rules, ruleId);
		if (rec.agentId !== null) agents.add(rec.agentId);
		if (rec.requiresApproval) approvalsRequired++;
		if (rec.highRiskFlow) highRiskFlows++;
		if (rec.chainGapDeclared) declaredGaps++;
		for (const d of rec.detections) {
			const seen = detections.get(d.id);
			if (seen) seen.count++;
			else detections.set(d.id, { ...d, count: 1 });
		}
		if (rec.timestamp !== null) {
			if (firstSeen === null || rec.timestamp < firstSeen) firstSeen = rec.timestamp;
			if (lastSeen === null || rec.timestamp > lastSeen) lastSeen = rec.timestamp;
		}
	}

	const indexes = mine.map((rec) => rec.chainIndex).filter((v): v is number => v !== null);
	const chained = chainedStateFor(mine, all);
	const linked = linkedStateFor(mine, files, manifestProblems);
	const anchored = anchoredStateFor(anchors, indexes.length ? Math.max(...indexes) : null);
	const cliFor = (name: string): "PASS" | "FAIL" =>
		verify.layers.find((l) => l.name === name)?.ok ? "PASS" : "FAIL";

	return {
		sessionId,
		agentIds: [...agents].sort(),
		records: mine.length,
		firstSeen,
		lastSeen,
		firstIndex: indexes.length ? Math.min(...indexes) : null,
		lastIndex: indexes.length ? Math.max(...indexes) : null,
		files: [...new Set(mine.map((rec) => rec.file))],
		decisions: ranked(decisions).map((r) => ({ decision: r.key, count: r.count })),
		planes: ranked(planes).map((r) => ({ plane: r.key, count: r.count })),
		actions: ranked(actions).map((r) => ({ action: r.key, count: r.count })),
		riskLevels: ranked(riskLevels).map((r) => ({ riskLevel: r.key, count: r.count })),
		approvalsRequired,
		highRiskFlows,
		detections: [...detections.values()].sort((a, b) => b.count - a.count || a.id.localeCompare(b.id)),
		matchedRules: ranked(rules).map((r) => ({ ruleId: r.key, count: r.count })),
		intact: mine.filter((rec) => !rec.faults.some((f) => FAULT_CONDEMNS[f])).length,
		faulty: mine
			.filter((rec) => rec.faults.length > 0)
			.map((rec) => ({ file: rec.file, line: rec.line, chainIndex: rec.chainIndex, faults: rec.faults })),
		declaredGaps,
		chainRecords: [...mine],
		layers: [
			{
				name: "chained",
				state: chained.state,
				cliVerdict: cliFor("chained"),
				detail: chained.detail,
				problems: chained.problems,
				divergence: null,
			},
			{
				name: "linked",
				state: linked.state,
				cliVerdict: cliFor("linked"),
				detail: linked.detail,
				problems: linked.problems,
				divergence: null,
			},
			{
				name: "anchored",
				state: anchored.state,
				cliVerdict: cliFor("anchored"),
				detail: anchored.detail,
				problems: anchored.problems,
				divergence: null,
			},
		],
	};
}

/**
 * Shell-quote a path for the commands the page prints.
 *
 * The audit path is operator-supplied, so it may hold a space or a quote. A command a
 * reviewer cannot paste is a command that makes this page the root of trust, which is the
 * one thing it must not be.
 */
function shellQuote(value: string): string {
	return /^[A-Za-z0-9_./:@%+=-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

export function offlineCommandsFor(auditPath: string, files: readonly { path: string }[]): OfflineCommands {
	const audit = shellQuote(auditPath);
	const jsonlFiles = files.map((f) => shellQuote(f.path)).join(" ");
	return {
		bundled: `node dist/cli.js verify --audit ${audit}`,
		bundledJson: `node dist/cli.js verify --audit ${audit} --json`,
		independent: `cd verifier && go build -o agentwall-verify . && ./agentwall-verify --audit ${audit}`,
		pinned: `./agentwall-verify --audit ${audit} --pubkey-file <the key you expect>`,
		session: (sessionId) =>
			sessionId === null
				? `cat ${jsonlFiles} | jq -c 'select(has("sessionId") | not)'`
				: `cat ${jsonlFiles} | jq -c 'select(.sessionId == ${JSON.stringify(sessionId)})'`,
	};
}

/**
 * Build the whole report a reviewer reads.
 *
 * `runVerify()` runs first and its output is carried through untouched, because everything
 * else on the page is a projection of the same bytes and the verdict has to be the one the
 * printed command reproduces.
 */
export function buildEvidenceReport(paths: AnchorPaths): EvidenceReport {
	const collection = collectEvidence(paths);
	const verify = runVerify(paths);
	const anchors = anchorReach(paths).map(receiptFor);
	const manifestProblems = verifyManifest(collection.paths.manifestPath).problems;

	const bySession = new Map<string | null, EvidenceRecord[]>();
	for (const rec of collection.records) {
		// A record with no chain index carries no session either: it did not parse, or it
		// carries a duplicate member so what it says depends on the parser. It stays visible
		// in the file inventory and the fault list rather than being attributed to a session
		// it might not belong to.
		const key = rec.chainIndex === null ? null : rec.sessionId;
		const bucket = bySession.get(key);
		if (bucket) bucket.push(rec);
		else bySession.set(key, [rec]);
	}

	const sessions = [...bySession.entries()]
		.map(([sessionId, mine]) =>
			scorecardFor(sessionId, mine, collection.records, collection.files, manifestProblems, anchors, verify),
		)
		.sort((a, b) => {
			// Newest activity first, which is what a reviewer opening the page is looking for.
			// Nulls last: the unattributed bucket is a diagnostic, not a session.
			if (a.sessionId === null) return 1;
			if (b.sessionId === null) return -1;
			return (b.lastSeen ?? "").localeCompare(a.lastSeen ?? "") || a.sessionId.localeCompare(b.sessionId);
		});

	const faulty = collection.records.filter((rec) => rec.faults.some((f) => FAULT_CONDEMNS[f])).length;
	return {
		paths: collection.paths,
		files: collection.files,
		verify,
		layers: globalLayers(verify, anchors),
		anchors,
		sessions,
		totals: {
			records: collection.records.length,
			intact: collection.records.length - faulty,
			faulty,
			declaredGaps: collection.records.filter((rec) => rec.chainGapDeclared).length,
			sessions: sessions.filter((s) => s.sessionId !== null).length,
		},
		truncated: collection.truncated,
		notes: collection.notes,
		offline: offlineCommandsFor(collection.paths.auditPath, collection.files),
	};
}
