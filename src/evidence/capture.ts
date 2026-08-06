import { closeSync, existsSync, openSync, readFileSync, readSync, statSync } from "fs";
import { resolvePaths, type AnchorPaths, type ResolvedPaths } from "../audit/anchor-service";
import { READ_LIMITS, recordFiles } from "./collect";
import {
	UNDECLARED_AGENT_ID,
	compareBindingTier,
	strongestBindingTier,
	weakestBindingTier,
	type AgentMatchSignal,
	type RegisteredAgent,
} from "../fleet/registry";

/**
 * Is every agent on this host still being captured, and is anything getting out that no
 * declared agent claims?
 *
 * WHY THIS IS NOT A COLLECTOR. Nothing here subscribes, samples, or keeps state between
 * calls. It reads the chain the proxy already wrote, over the same file list the evidence
 * viewer walks, and answers a different question about it. A background collector would be
 * a second account of what happened, and the first thing an operator would have to do in an
 * incident is work out which of the two to believe.
 *
 * WHY IT IS NOT THE BUDGET LEDGER. `AgentBudgetLedger` lives in the serving process and
 * dies with it. `agentwall doctor` is a different process, usually run precisely when the
 * serving one is suspect, so it cannot read those counters and must not pretend to. The
 * window totals below are recounted from the chain; the ceilings come from the declaration
 * in the config. Declaration supplies the limit, the chain supplies the observations, and
 * neither is derived from the other.
 *
 * WHAT THE RECOUNT IS AND IS NOT. A record is written when a connection CLOSES, so a
 * connection is counted in the window it finished in, not the one it started in. For a
 * long-lived model stream those differ. The ledger inside the server attributes bytes back
 * to the row that admitted the connection and does not have that skew; this does, and says
 * so, because a number that quietly disagrees with the one the server enforced on is worse
 * than a number with a stated shape.
 *
 * READ ONLY, structurally, exactly like collect.ts. The watermark that makes "since the last
 * run" mean anything is passed in and handed back, never written here.
 */

/** Doctor's bookmark in the chain. */
export interface CaptureWatermark {
	/** Highest chain index the previous run had already accounted for. */
	chainIndex: number;
	/** When that run happened. */
	at: string;
}

/**
 * How long a window to count over for an agent that declares no budget.
 *
 * There is no right answer for an agent with no ceiling, and the honest options are "do not
 * report counts at all" or "report counts over a stated span". An hour is short enough that
 * an agent which stopped an hour ago reads as idle rather than busy, and the row says the
 * window is an observation rather than a budget so nobody reads a limit into it.
 */
export const DEFAULT_OBSERVATION_WINDOW_SECONDS = 3600;

export interface AgentCaptureRow {
	agentId: string;
	label: string;
	/** The best proof this declaration can ever produce. */
	strongestTier: AgentMatchSignal;
	/**
	 * The proof it can be satisfied with, which is what it is actually worth. Weaker than
	 * `strongestTier` when the declaration names a credential AND a uid or comm.
	 */
	weakestTier: AgentMatchSignal;
	/** Null when no egress record in the chain claims this agent. Not the same as zero. */
	lastSeen: { at: string; tier: AgentMatchSignal } | null;
	/** Tiers this agent was actually bound at in the records read, weakest first. */
	observedTiers: AgentMatchSignal[];
	/** The span the counts below cover. */
	windowSeconds: number;
	/** True when that span is the agent's declared budget window rather than the default. */
	windowIsBudget: boolean;
	requests: number;
	bytes: number;
	maxRequests: number | null;
	maxBytes: number | null;
	/** Egress the chain shows was refused for this agent inside the window. */
	denied: number;
}

/** Egress no declared agent claimed. The reason this module exists. */
export interface UndeclaredCapture {
	/** Every undeclared egress record in what was read. */
	total: number;
	/** Records past the previous watermark. Equals `total` when there was no previous run. */
	sinceLastRun: number;
	/** Of those, the ones that actually reached the network. */
	allowedSinceLastRun: number;
	/** Of those, the ones enforcement refused. Containment working, not an escape. */
	deniedSinceLastRun: number;
	/**
	 * Allowed undeclared egress that policy said to REFUSE and that got out anyway:
	 * `fleet.unmatched: deny` under an enforcing mode. This is the only number that means
	 * "something escaped", and through the forward proxy it should be unreachable, because
	 * that combination is exactly what src/runtime/enforcement.ts refuses before opening an
	 * upstream socket. Seeing it above zero means something reached the network without
	 * passing that gate.
	 */
	escapedSinceLastRun: number;
	/**
	 * Allowed undeclared egress the configuration told AgentWall to allow, and the reason
	 * why, most common first. `fleet.unmatched: global` hands undeclared traffic to the
	 * global allowlist by design; `enforcement.mode: monitor` gates nothing by design.
	 *
	 * These are NOT escapes and must never be reported as one. They are also not proof of
	 * innocence: an undeclared agent talking to an allowlisted host produces exactly this
	 * record, and nothing here can tell the two apart. That is what makes the verdict
	 * inconclusive rather than clean, and the remedy names the setting to change so the
	 * next run can be conclusive.
	 */
	permittedByConfigSinceLastRun: { reason: string; count: number }[];
	bytesSinceLastRun: number;
	/** Oldest and newest of the records counted in `sinceLastRun`. */
	firstAt: string | null;
	lastAt: string | null;
	/**
	 * Broken out by the identity the record did carry, commonest first. The
	 * `UNDECLARED_AGENT_ID` bucket is traffic with no recoverable identity at all; every
	 * other bucket is a process comm that matched no declaration.
	 */
	byIdentity: { id: string; count: number }[];
	/** Where it went, commonest first. Somewhere to start looking. */
	topHosts: { host: string; count: number }[];
	/**
	 * Undeclared records written before this version began stamping attribution. Counted so
	 * an operator who just upgraded can tell inherited history from new escapes.
	 */
	predatingAttribution: number;
}

export interface CaptureHealth {
	auditPath: string;
	/** False when there is no chain on disk. Nothing below means anything when it is false. */
	chainPresent: boolean;
	/** Egress records read. Non-egress records advance the chain and are not counted here. */
	egressRecords: number;
	readAt: string;
	/** The previous run's bookmark, or null on the first run. */
	since: CaptureWatermark | null;
	/** Why the previous bookmark was discarded, when it was. */
	watermarkReset: string | null;
	/** The bookmark to persist for the next run. Null when the chain held nothing readable. */
	watermark: CaptureWatermark | null;
	fleetDeclared: boolean;
	agents: AgentCaptureRow[];
	undeclared: UndeclaredCapture;
	/** The weakest binding any declared agent can be satisfied by, and who. */
	weakestBinding: { tier: AgentMatchSignal; agentIds: string[] } | null;
	/** True when a cap stopped the walk, so "never seen" softens to "not in what was read". */
	truncated: boolean;
	notes: string[];
}

/** One egress record, reduced to the fields this question needs. */
interface EgressSighting {
	chainIndex: number;
	atMs: number;
	at: string;
	agentId: string;
	/** Absent on records written before attribution was stamped. */
	declared: boolean | null;
	tier: AgentMatchSignal;
	host: string;
	bytes: number;
	denied: boolean;
	/**
	 * The fleet posture and the enforcement mode in force when this connection was judged,
	 * as the record states them. Null when the record predates the field, in which case the
	 * caller's current configuration is the only thing left to judge by, and the report says
	 * it is doing that.
	 */
	unmatched: "global" | "deny" | null;
	mode: string | null;
}

/**
 * An index-signature view of a value already proven to be a non-null object.
 *
 * The single place this module reaches past the type system, and safe by construction:
 * every JS object can be read by string key, and the members come back as `unknown`, so
 * nothing downstream inherits a type the file did not check for itself.
 */
function fields(value: unknown): Record<string, unknown> | null {
	return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
}

function asTier(value: unknown): AgentMatchSignal {
	switch (value) {
		case "credential":
		case "uid+comm":
		case "uid":
		case "comm":
			return value;
		default:
			return "none";
	}
}

/** Byte counters are written as strings and may be anything at all once on disk. */
function asCount(value: unknown): number {
	const n = typeof value === "string" ? Number(value) : typeof value === "number" ? value : Number.NaN;
	return Number.isFinite(n) && n > 0 ? n : 0;
}

/** The chain index a parsed line claims, or -1 when it claims none. */
function chainIndexOf(parsed: unknown): number {
	const integrity = fields(fields(parsed)?.integrity);
	return typeof integrity?.chainIndex === "number" ? integrity.chainIndex : -1;
}

/**
 * Reduce one parsed chain line to a sighting, or null when it is not egress.
 *
 * Deliberately tolerant. These are JSON objects off disk, not values this process produced,
 * and a doctor that throws on one malformed line tells the operator nothing about the other
 * ten thousand.
 */
function toSighting(parsed: unknown): EgressSighting | null {
	const record = fields(parsed);
	const action = record?.action;
	if (typeof action !== "string" || !action.startsWith("egress:")) return null;

	const timestamp = typeof record?.timestamp === "string" ? record.timestamp : null;
	const atMs = timestamp === null ? Number.NaN : Date.parse(timestamp);
	const metadata = fields(record?.metadata) ?? {};
	const declaredMarker = metadata.agentDeclared;

	return {
		chainIndex: chainIndexOf(parsed),
		atMs: Number.isFinite(atMs) ? atMs : Number.NaN,
		at: timestamp ?? "unknown",
		agentId: typeof record?.agentId === "string" ? record.agentId : UNDECLARED_AGENT_ID,
		declared: typeof declaredMarker === "string" ? declaredMarker === "true" : null,
		tier: asTier(metadata.agentMatchedOn),
		host: typeof metadata.host === "string" ? metadata.host : "unknown",
		bytes: asCount(metadata.bytesUp) + asCount(metadata.bytesDown),
		denied: record?.decision === "deny",
		unmatched: metadata.fleetUnmatched === "deny" ? "deny" : metadata.fleetUnmatched === "global" ? "global" : null,
		mode: typeof metadata.enforcementMode === "string" ? metadata.enforcementMode : null,
	};
}

/**
 * The tail of a file, capped, with any partial leading record removed.
 *
 * The evidence viewer SKIPS a file above its cap, which is right for a viewer showing a
 * chain from its start. Skipping here would be a silent pass of the worst kind: the live
 * file is the one that holds today's records, so a busy host with an unrotated chain would
 * get a capture section that read only sealed history, found nothing new, reported zero
 * undeclared egress, and kept doing that forever. Reading the tail answers the question the
 * section actually asks, at the same bounded cost.
 *
 * Exported as a test seam. The behaviour that matters here only shows up on a file larger
 * than the cap, and the real cap is 64 MB, which is not a thing to write in a unit test.
 */
export function readTail(path: string, size: number, cap: number): { text: string; truncated: boolean } {
	if (size <= cap) return { text: readFileSync(path, "utf8"), truncated: false };
	const fd = openSync(path, "r");
	try {
		const buffer = Buffer.allocUnsafe(cap);
		readSync(fd, buffer, 0, cap, size - cap);
		const text = buffer.toString("utf8");
		// The read began at a byte offset, so it almost certainly began mid-record. That
		// fragment is not a torn record and must not be counted as one; it also may split a
		// multi-byte character, which dropping everything up to the first newline removes.
		const firstBreak = text.indexOf("\n");
		return { text: firstBreak === -1 ? "" : text.slice(firstBreak + 1), truncated: true };
	} finally {
		closeSync(fd);
	}
}

/**
 * Walk the chain newest first and collect every egress sighting.
 *
 * Newest first is the whole difference between this and `collectEvidence`, which reads
 * oldest first because it is showing a chain from its start. This one is answering "what is
 * happening now", so when a cap bites it has to drop the OLDEST records: a capture report
 * truncated at the recent end would report an escaping agent as never seen.
 */
function readSightings(r: ResolvedPaths): {
	sightings: EgressSighting[];
	maxChainIndex: number;
	truncated: boolean;
	unreadable: number;
	notes: string[];
	chainPresent: boolean;
} {
	const sightings: EgressSighting[] = [];
	const notes: string[] = [];
	let maxChainIndex = -1;
	let truncated = false;
	let unreadable = 0;
	let chainPresent = false;

	for (const { path } of recordFiles(r).reverse()) {
		if (!existsSync(path)) continue;
		chainPresent = true;

		if (sightings.length >= READ_LIMITS.records) {
			truncated = true;
			continue;
		}

		const size = statSync(path).size;
		const tail = readTail(path, size, READ_LIMITS.fileBytes);
		if (tail.truncated) {
			truncated = true;
			notes.push(
				`${path} is ${size} bytes, so only its last ${READ_LIMITS.fileBytes} were read. Records older ` +
					"than that in this file were not counted.",
			);
		}

		const lines = tail.text.split("\n");
		for (let i = lines.length - 1; i >= 0; i--) {
			if (sightings.length >= READ_LIMITS.records) {
				if (!truncated) {
					notes.push(
						`This read stopped at ${READ_LIMITS.records} egress records, newest first. Older records exist ` +
							"and were not counted, so a long-idle agent may read as never seen.",
					);
				}
				truncated = true;
				break;
			}
			const line = lines[i];
			if (line.trim() === "") continue;

			let parsed: unknown;
			try {
				parsed = JSON.parse(line);
			} catch {
				// A torn tail is one line at the end of the live file and is the ordinary shape
				// of a hard kill. Counted, not diagnosed: `agentwall verify` owns that verdict.
				unreadable += 1;
				continue;
			}

			// Read off every record, not just egress ones: approvals and MCP decisions advance
			// the same chain, and a bookmark that ignored them would replay them as new work.
			const index = chainIndexOf(parsed);
			if (index > maxChainIndex) maxChainIndex = index;

			const sighting = toSighting(parsed);
			if (sighting !== null) sightings.push(sighting);
		}
	}

	return { sightings, maxChainIndex, truncated, unreadable, notes, chainPresent };
}

export interface CaptureReadOptions {
	/** The declared fleet. Empty means no fleet is declared, which is a different report. */
	agents: readonly RegisteredAgent[];
	/**
	 * The posture the CALLER's configuration declares now, used only for records written
	 * before the posture was stamped into the chain. Records that carry their own are judged
	 * by that, so an operator who tightened the config yesterday still sees yesterday's
	 * traffic judged by yesterday's rules rather than convicted by today's.
	 */
	unmatched: "global" | "deny";
	/** The previous run's bookmark. */
	since: CaptureWatermark | null;
	/** Injected so a test can pin the window without sleeping. */
	now?: number;
}

/** Enforcement modes that actually gate. `monitor` evaluates fully and refuses nothing. */
const ENFORCING_MODES: Record<string, true> = { guarded: true, strict: true };

/**
 * Read the chain and answer, per declared agent, whether it is still being captured.
 */
export function readCaptureHealth(paths: AnchorPaths, options: CaptureReadOptions): CaptureHealth {
	const now = options.now ?? Date.now();
	const readAt = new Date(now).toISOString();
	const resolved = resolvePaths(paths);
	const { sightings, maxChainIndex, truncated, unreadable, notes, chainPresent } = readSightings(resolved);

	if (unreadable > 0) {
		notes.push(
			`${unreadable} line(s) in the chain did not parse and were not counted. ` +
				"Run `agentwall verify` to find out whether that is a torn tail or an edit.",
		);
	}

	// A bookmark ahead of the chain is a bookmark for a different chain: the file was rotated
	// away, replaced, or restarted at zero. Counting "since" against it would report nothing
	// new forever, which is the exact silent-pass failure this section exists to prevent.
	let watermarkReset: string | null = null;
	let since = options.since;
	if (since !== null && maxChainIndex >= 0 && maxChainIndex < since.chainIndex) {
		watermarkReset =
			`the last run recorded chain index ${since.chainIndex} but the chain now ends at ${maxChainIndex}, ` +
			"so it was replaced or rotated away. Everything readable is being counted as new.";
		notes.push(`Previous run's bookmark discarded: ${watermarkReset}`);
		since = null;
	}
	const floor = since?.chainIndex ?? -1;

	const declared = new Map<string, RegisteredAgent>();
	for (const agent of options.agents) declared.set(agent.id, agent);
	const fleetDeclared = declared.size > 0;

	const rows: AgentCaptureRow[] = options.agents.map((agent) => ({
		agentId: agent.id,
		label: agent.label,
		strongestTier: strongestBindingTier(agent),
		weakestTier: weakestBindingTier(agent),
		lastSeen: null,
		observedTiers: [],
		windowSeconds: agent.budget?.windowSeconds ?? DEFAULT_OBSERVATION_WINDOW_SECONDS,
		windowIsBudget: agent.budget !== undefined,
		requests: 0,
		bytes: 0,
		maxRequests: agent.budget?.maxRequests ?? null,
		maxBytes: agent.budget?.maxBytes ?? null,
		denied: 0,
	}));
	const rowById = new Map(rows.map((row) => [row.agentId, row]));
	const tiersById = new Map<string, Set<AgentMatchSignal>>();

	const undeclared: UndeclaredCapture = {
		total: 0,
		sinceLastRun: 0,
		allowedSinceLastRun: 0,
		deniedSinceLastRun: 0,
		escapedSinceLastRun: 0,
		permittedByConfigSinceLastRun: [],
		bytesSinceLastRun: 0,
		firstAt: null,
		lastAt: null,
		byIdentity: [],
		topHosts: [],
		predatingAttribution: 0,
	};
	const identityCounts = new Map<string, number>();
	const hostCounts = new Map<string, number>();
	const permitCounts = new Map<string, number>();
	let spoofedIds = 0;
	let judgedByCurrentConfig = 0;

	for (const sighting of sightings) {
		// With no fleet declared nothing can be attributed by construction, and every record
		// carries `declared: false`. Calling all of it undeclared would be technically true
		// and operationally useless: it would alarm on a correct single-agent install forever.
		const isUndeclared = fleetDeclared && sighting.declared !== true;

		if (isUndeclared) {
			undeclared.total += 1;
			if (sighting.declared === null) undeclared.predatingAttribution += 1;
			if (declared.has(sighting.agentId)) spoofedIds += 1;
			if (sighting.chainIndex > floor) {
				undeclared.sinceLastRun += 1;
				if (sighting.denied) {
					undeclared.deniedSinceLastRun += 1;
				} else {
					undeclared.allowedSinceLastRun += 1;
					// Why was undeclared traffic allowed out? Only one of these answers is an
					// escape, and reporting the others as one would accuse an operator of a
					// breach their own configuration prescribes.
					const posture = sighting.unmatched ?? options.unmatched;
					if (sighting.unmatched === null) judgedByCurrentConfig += 1;
					// A record with no mode marker cannot be shown to have been gated, and
					// "unproven" must not round up to "escaped".
					const enforcing = sighting.mode !== null && ENFORCING_MODES[sighting.mode] === true;
					const reason =
						posture === "global"
							? 'fleet.unmatched: global (the global allowlist judges undeclared traffic, by design)'
							: !enforcing
								? `enforcement.mode: ${sighting.mode ?? "not recorded"} (gates nothing, by design)`
								: null;
					if (reason === null) undeclared.escapedSinceLastRun += 1;
					else permitCounts.set(reason, (permitCounts.get(reason) ?? 0) + 1);
				}
				undeclared.bytesSinceLastRun += sighting.bytes;
				identityCounts.set(sighting.agentId, (identityCounts.get(sighting.agentId) ?? 0) + 1);
				hostCounts.set(sighting.host, (hostCounts.get(sighting.host) ?? 0) + 1);
				// Sightings arrive newest first, so the first one seen is the latest and the
				// last one seen is the earliest.
				undeclared.lastAt ??= sighting.at;
				undeclared.firstAt = sighting.at;
			}
			continue;
		}

		const row = rowById.get(sighting.agentId);
		if (row === undefined) continue;

		// Newest first, so the first sighting for an agent is its last one.
		row.lastSeen ??= { at: sighting.at, tier: sighting.tier };
		let tiers = tiersById.get(row.agentId);
		if (tiers === undefined) {
			tiers = new Set();
			tiersById.set(row.agentId, tiers);
		}
		tiers.add(sighting.tier);

		if (Number.isFinite(sighting.atMs) && sighting.atMs > now - row.windowSeconds * 1000) {
			row.requests += 1;
			row.bytes += sighting.bytes;
			if (sighting.denied) row.denied += 1;
		}
	}

	for (const row of rows) {
		row.observedTiers = [...(tiersById.get(row.agentId) ?? [])].sort(compareBindingTier);
	}

	undeclared.byIdentity = [...identityCounts.entries()]
		.map(([id, count]) => ({ id, count }))
		.sort((left, right) => right.count - left.count || left.id.localeCompare(right.id));
	undeclared.topHosts = [...hostCounts.entries()]
		.map(([host, count]) => ({ host, count }))
		.sort((left, right) => right.count - left.count || left.host.localeCompare(right.host))
		.slice(0, 5);
	undeclared.permittedByConfigSinceLastRun = [...permitCounts.entries()]
		.map(([reason, count]) => ({ reason, count }))
		.sort((left, right) => right.count - left.count || left.reason.localeCompare(right.reason));

	if (judgedByCurrentConfig > 0) {
		notes.push(
			`${judgedByCurrentConfig} allowed undeclared record(s) do not state the fleet posture in force when ` +
				`they were written, so they were judged against the posture this config declares now ` +
				`("${options.unmatched}"). An older build wrote them; records from this version carry their own.`,
		);
	}

	if (spoofedIds > 0) {
		notes.push(
			`${spoofedIds} undeclared record(s) carried the id of a declared agent. A process is claiming that ` +
				"name without satisfying its declaration, which is what a comm-only match looks like when it is abused.",
		);
	}

	let weakestBinding: { tier: AgentMatchSignal; agentIds: string[] } | null = null;
	for (const row of rows) {
		if (weakestBinding === null || compareBindingTier(row.weakestTier, weakestBinding.tier) < 0) {
			weakestBinding = { tier: row.weakestTier, agentIds: [row.agentId] };
		} else if (row.weakestTier === weakestBinding.tier) {
			weakestBinding.agentIds.push(row.agentId);
		}
	}

	return {
		auditPath: resolved.auditPath,
		chainPresent,
		egressRecords: sightings.length,
		readAt,
		since,
		watermarkReset,
		watermark: maxChainIndex >= 0 ? { chainIndex: maxChainIndex, at: readAt } : null,
		fleetDeclared,
		agents: rows,
		undeclared,
		weakestBinding,
		truncated,
		notes,
	};
}
