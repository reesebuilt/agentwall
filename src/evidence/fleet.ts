import { existsSync, readFileSync, statSync } from "fs";
import { basename, dirname, resolve } from "path";
import { load as parseYaml } from "js-yaml";
import { z } from "zod";
import { resolvePaths } from "../audit/anchor-service";
// The cap the proxy actually enforces. Read rather than retyped: a number in prose beside a
// control is a claim about that control, and prose does not change when the constant does.
import { CONTENT_SCAN_MAX_BYTES } from "../proxy/forward-proxy";
import { buildEvidenceReport, type EvidenceReport } from "./scorecard";
import { FAULT_CONDEMNS, type EvidenceRecord } from "./collect";

/**
 * Read-only evidence aggregation across several hosts.
 *
 * WHAT THIS IS. N hosts produce N chains. This reads all of them, verifies each one
 * independently with the same `runVerify()` the single-host viewer uses, and puts the
 * verdicts side by side. It is the single-host viewer's shape, one level up.
 *
 * WHAT IT IS NOT, and the distinction is the whole design:
 *
 *   1. It is NOT a control plane. Nothing here is on an egress path. If this process is down,
 *      every host keeps enforcing and keeps writing its own chain; what is lost is visibility,
 *      never enforcement. A management outage that becomes an agent outage is the failure mode
 *      that makes people turn the security tool off.
 *   2. It does NOT merge the chains. Merging N chains into one ordered ledger needs a total
 *      order across hosts, which needs a single writer or agreed clocks. Neither exists and
 *      neither is needed: what an auditor asks is answered by N verdicts side by side, and a
 *      merged chain would be a distributed systems problem taken on for presentation.
 *   3. It is NOT an authority. It re-derives every hash from the bytes on disk. It never asks
 *      a host for a verdict, so a compromised host cannot report itself clean here, and an
 *      auditor can reproduce any row with the commands the page prints. Four independent
 *      verifier implementations exist; the page names all four per host.
 *
 * HOW THE BYTES GET HERE. Each host's evidence directory is delivered to this box by whatever
 * transport the operator already runs: rsync over ssh, an object-store sync, a read-only
 * mount. This module reads a path. It opens no socket, so an agent host needs no inbound
 * listener and this process needs no credential on any host.
 *
 * The cost of that choice is stated rather than hidden: "unreachable" here means THE EVIDENCE
 * COULD NOT BE READ AT THIS PATH. It does not distinguish a host that is down from a transport
 * that is down, and it must not be read as either.
 *
 * READ ONLY, structurally. Nothing in this module opens a file for writing and it imports
 * nothing that does.
 */

/**
 * One host's evidence, as the operator declares where it landed.
 *
 * The path fields mirror `AnchorPaths` so a host directory copied whole verifies with no
 * further configuration: the manifest, anchor log, key and proofs all default beside the audit
 * file exactly as the CLI resolves them.
 */
export const FleetEvidenceHostSchema = z
	.object({
		/** Stable across restarts and reinstalls. It is what a reviewer cites. */
		id: z
			.string()
			.trim()
			.min(1)
			// URL-safe, because it appears in a path segment. Rejected at load rather than
			// escaped at render: an id that needs escaping is an id somebody will mistype into
			// a bug report.
			.regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, "must be alphanumeric with dots, dashes or underscores"),
		label: z.string().trim().min(1).optional(),
		auditPath: z.string().trim().min(1),
		manifestPath: z.string().trim().min(1).optional(),
		keyPath: z.string().trim().min(1).optional(),
		anchorLogPath: z.string().trim().min(1).optional(),
		proofDir: z.string().trim().min(1).optional(),
	})
	.strict();

export const FleetEvidenceSourcesSchema = z
	.object({
		/**
		 * How old the newest record may be before this host is reported stale.
		 *
		 * There is no safe default that is also silent. A host whose sync broke three days ago
		 * still renders every old verdict as a pass, and without a freshness bound that page is
		 * decoration. So the field is required, and picking it is the operator stating how often
		 * they expect evidence to arrive.
		 */
		staleAfterSeconds: z.number().int().positive(),
		hosts: z.array(FleetEvidenceHostSchema).min(1),
	})
	.strict();

export type FleetEvidenceHost = z.infer<typeof FleetEvidenceHostSchema>;
export type FleetEvidenceSources = z.infer<typeof FleetEvidenceSourcesSchema>;

/**
 * Load and validate the sources file.
 *
 * A malformed file is a hard failure, never a partial load. An aggregator that quietly drops
 * the host with the typo shows a green fleet that is missing a member, which is the worst
 * possible output from a tool whose entire job is saying what it could not see.
 */
export function loadFleetEvidenceSources(path: string): FleetEvidenceSources {
	let raw: unknown;
	try {
		raw = parseYaml(readFileSync(path, "utf8"));
	} catch (err) {
		throw new Error(`agentwall: cannot read the fleet evidence sources at ${path}. ${(err as Error).message}`);
	}
	const parsed = FleetEvidenceSourcesSchema.safeParse(raw);
	if (!parsed.success) {
		const detail = parsed.error.issues
			.map((issue) => `${issue.path.length > 0 ? issue.path.join(".") : "(root)"}: ${issue.message}`)
			.join("; ");
		throw new Error(`agentwall: invalid fleet evidence sources in ${path}. ${detail}`);
	}
	const seen = new Set<string>();
	for (const host of parsed.data.hosts) {
		if (seen.has(host.id)) {
			throw new Error(
				`agentwall: fleet evidence sources in ${path} declare host id "${host.id}" twice. ` +
					"Two rows under one id would render as one host and hide whichever the iteration order lost.",
			);
		}
		seen.add(host.id);
	}
	// Relative paths resolve against the sources file, not the working directory, for the same
	// reason segment paths resolve against the manifest: otherwise the same file verifies from
	// one shell and reports every host unreachable from another.
	const base = dirname(resolve(path));
	return {
		staleAfterSeconds: parsed.data.staleAfterSeconds,
		hosts: parsed.data.hosts.map((host) => ({
			...host,
			auditPath: resolve(base, host.auditPath),
			...(host.manifestPath === undefined ? {} : { manifestPath: resolve(base, host.manifestPath) }),
			...(host.keyPath === undefined ? {} : { keyPath: resolve(base, host.keyPath) }),
			...(host.anchorLogPath === undefined ? {} : { anchorLogPath: resolve(base, host.anchorLogPath) }),
			...(host.proofDir === undefined ? {} : { proofDir: resolve(base, host.proofDir) }),
		})),
	};
}

/**
 * One host's headline, and the six states exist because fewer force a lie.
 *
 * `unreachable` and `empty` are the two that matter most day to day. A host whose evidence
 * could not be read and a host that recorded nothing both produce zero findings, and rendering
 * either as a clean host is the difference between evidence and decoration. `stale` is the
 * third: evidence that arrived once and stopped arriving reads exactly like a quiet host.
 *
 * `inconclusive` is the one that keeps this surface honest in the other direction. A check that
 * cannot tell "the evidence was edited" from "my own reading of it is confused by how the files
 * were arranged" will eventually accuse an operator who did nothing wrong, and a security tool
 * that cries wolf once gets its alarms filtered out forever. Where the file set cannot describe
 * one history, that is said, rather than passed off as a verdict about the records.
 */
export type HostState = "verified" | "broken" | "inconclusive" | "stale" | "empty" | "unreachable";

export const HOST_STATE_MEANING: Record<HostState, string> = {
	verified: "every layer this aggregator could check holds, on evidence fresh enough to be current",
	broken: "a layer fails on this host's own chain; the finding is local to this host",
	inconclusive:
		"the files in this host's evidence directory cannot describe one history, so no verdict about the records can be reached until that is fixed; this is not a finding of tampering",
	stale: "the chain verifies, and the newest record is older than the freshness bound, so this is history rather than current state",
	empty: "the evidence was read and holds no records; nothing was recorded here, which is not the same as nothing happened",
	unreachable: "the evidence could not be read at the path given, so nothing about this host was checked",
};

/** The four independent implementations, per host. */
export interface HostReproduce {
	/** The bundled TypeScript verifier. */
	bundled: string;
	/** Go. Shares no code with the writer. */
	go: string;
	/** Rust. No dependencies and no unsafe. */
	rust: string;
	/** Python. RFC 8032 implemented directly rather than through OpenSSL. */
	python: string;
	/** Binding the checkpoint signature to a key supplied from outside the evidence. */
	pinned: string;
}

/**
 * How far off-box evidence reaches over a set of hosts.
 *
 * Supplied to `coverageFor` because the anchoring gap is the one limit that is a property of a
 * HOST rather than of a record, and leaving it out of the table would put the most consequential
 * fleet limit in prose while the smaller ones got a row each.
 */
export interface OffBoxReach {
	/** Hosts the reach was evaluated over. */
	hosts: number;
	/** Of those, how many have submitted no anchor at all. */
	unanchored: number;
}

/**
 * A limit on what the evidence can say, stated beside the evidence rather than in a footnote.
 *
 * Three separate things, and conflating any two of them is how a gap table turns into
 * reassurance:
 *
 *   `limit`      a property of the controls, true whatever any chain contains.
 *   `measurable` whether a record could ever land in this gap in a way a reader can count.
 *                Three of these are permanently unmeasurable and say so; counting them as
 *                zero would report the evasions as absent.
 *   `observed`   how many records in THIS evidence landed in it. `null` on a measurable gap
 *                means there was no population to count, which is not the same as zero.
 */
export interface CoverageGap {
	id: string;
	title: string;
	/** What is not covered. True regardless of what was recorded. */
	limit: string;
	/** False when no evidence of any kind could ever populate this row. */
	measurable: boolean;
	/** Records in this evidence that fell in the gap. Null when there was nothing to count. */
	observed: number | null;
	/** What the count means, or why there is none. */
	measurement: string;
	reference: string;
}

export interface HostEvidence {
	id: string;
	label: string;
	state: HostState;
	/** The state in this host's own particulars. */
	detail: string;
	/** Where the evidence was read from, whether or not it was there. */
	auditPath: string;
	/**
	 * The full single-host report, or null when unreachable.
	 *
	 * Identical in shape to what `/api/evidence` serves for a local chain, because it is the
	 * same function over a different path. A reviewer who learned the single-host page already
	 * knows how to read a host row here.
	 */
	report: EvidenceReport | null;
	/** Newest record timestamp, or the newest evidence file mtime when no record carries one. */
	lastSeen: string | null;
	lastSeenSource: "record" | "file-mtime" | null;
	/** Age of `lastSeen` in seconds at the moment the report was built. */
	ageSeconds: number | null;
	/** Set only when unreachable, naming what was tried and what came back. */
	unreachable: { path: string; reason: string } | null;
	/** First record timestamp seen on this host, so a reviewer can state the window. */
	firstSeen: string | null;
	agents: HostAgentRollup[];
	coverage: CoverageGap[];
	reproduce: HostReproduce;
}

/**
 * One agent as an auditor asks about it: what it was permitted, what it attempted, what was
 * refused, and on what evidence the identity claim rests.
 */
export interface HostAgentRollup {
	agentId: string;
	label: string | null;
	/**
	 * What the identity claim rests on: `credential`, `uid`, `comm`, or a combination.
	 *
	 * Carried because "this was agent X" means something different depending on the signal. A
	 * credential survives a host boundary; a `comm` is a label the process chose and is worth
	 * nothing against one that lies. See docs/fleet.md.
	 */
	matchedOn: string[];
	/** Whether a declared fleet agent claimed these connections, or they fell through. */
	declared: boolean | null;
	/** `global`, or `agent:<id>`. Which allowlist judged it. */
	allowlistSources: string[];
	sessions: number;
	records: number;
	allowed: number;
	denied: number;
	/** Sent to a human. */
	approvals: number;
	/** Content the DLP plane rewrote before it was returned. */
	redactions: number;
	firstSeen: string | null;
	lastSeen: string | null;
	/** Destinations attempted, most attempts first. Capped for display; the count is exact. */
	destinations: { host: string; attempts: number; denied: number }[];
	distinctDestinations: number;
	/** Rules that refused something this agent attempted. */
	refusedBy: { ruleId: string; count: number }[];
	/** Classes of secret the content scan named in this agent's traffic. Never a value. */
	secretTypes: string[];
	/** Records written while the instance was in monitor mode, where an allow blocked nothing. */
	monitorRecords: number;
}

export interface FleetEvidenceReport {
	generatedAt: string;
	staleAfterSeconds: number;
	hosts: HostEvidence[];
	/** The span the evidence actually covers, across every host that could be read. */
	window: { from: string | null; to: string | null };
	totals: {
		hosts: number;
		verified: number;
		broken: number;
		/** File set cannot describe one history, so no verdict about the records was reached. */
		inconclusive: number;
		stale: number;
		empty: number;
		unreachable: number;
		records: number;
		faulty: number;
		sessions: number;
		agents: number;
	};
	/**
	 * The aggregate, and it is deliberately unable to say "clean" while anything is unread.
	 */
	verdict: {
		state: "verified" | "broken" | "incomplete";
		headline: string;
		/** What the aggregate does and does not establish, in the words the page shows. */
		detail: string;
	};
	/** Fleet-wide gaps, summed over the hosts that could be read. */
	coverage: CoverageGap[];
	notes: string[];
}

/** Records the writer could not store, and records that do not reproduce. */
function faultyCount(records: readonly EvidenceRecord[]): number {
	return records.filter((rec) => rec.faults.some((f) => FAULT_CONDEMNS[f])).length;
}

function shellQuote(value: string): string {
	return /^[A-Za-z0-9_./:@%+=-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * The four commands that reproduce one host's verdict without trusting this page.
 *
 * All four, always, rather than one with the rest in the docs. Four implementations written
 * from the format document and agreeing on 27 conformance cases is the strongest property this
 * project has, and it is worth strictly more in a fleet than on one laptop: an auditor
 * reproduces the aggregator's verdict without trusting the aggregator, in a language of their
 * choosing, from a checkout that shares no code with the writer.
 */
export function reproduceFor(auditPath: string): HostReproduce {
	const audit = shellQuote(auditPath);
	// Every line runs from the repository root and leaves you there. The obvious spelling,
	// `cd verifier && go build ...`, is a bug in a block meant to be pasted whole: it changes
	// the working directory, so the next line looks for verifier-rs inside verifier and fails.
	// A snippet that cannot execute is a defect shipped into somebody else's terminal, so each
	// toolchain line is a subshell. Checked with `bash -n` in tests/fleet-evidence.test.ts.
	return {
		bundled: `node dist/cli.js verify --audit ${audit}`,
		go: `(cd verifier && go build -o agentwall-verify . && ./agentwall-verify --audit ${audit})`,
		rust: `(cd verifier-rs && cargo build --release && ./target/release/agentwall-verify --audit ${audit})`,
		python: `python3 verifier-py/agentwall-verify-py --audit ${audit}`,
		// Named in full rather than as a bare `./agentwall-verify`, which would depend on which
		// of the lines above you happened to run last and which directory it left you in.
		pinned: `(cd verifier && ./agentwall-verify --audit ${audit} --pubkey-file <the key you expect>)`,
	};
}

/**
 * Newest mtime across the evidence files a host directory would hold.
 *
 * Used only when no record carries a timestamp, which is the case for a directory that was
 * created and never filled. It is a weaker fact than a record timestamp and is labelled as
 * one wherever it is shown, because a file mtime says when something touched the file and not
 * when a decision was made.
 */
function newestMtime(paths: readonly string[]): number | null {
	let newest: number | null = null;
	for (const path of paths) {
		if (!existsSync(path)) continue;
		try {
			const ms = statSync(path).mtimeMs;
			if (newest === null || ms > newest) newest = ms;
		} catch {
			// A file that exists and cannot be stat'd contributes nothing rather than throwing.
			// The reachability decision above already covers the audit file itself.
		}
	}
	return newest;
}

/** Sort a count map into a stable ranked list. */
function ranked<T extends string>(counts: Map<T, number>): { key: T; count: number }[] {
	return [...counts.entries()]
		.map(([key, count]) => ({ key, count }))
		.sort((a, b) => b.count - a.count || String(a.key).localeCompare(String(b.key)));
}

/** How many destinations a host row lists before it stops. The distinct count stays exact. */
const DESTINATIONS_SHOWN = 12;

/**
 * Roll one host's records up per agent.
 *
 * Keyed on the record's own `agentId`, which is the identity the decision was actually
 * enforced against. Re-resolving it here from the uid and comm on the record would risk
 * disagreeing with the identity that was gated, and a rollup whose agent was computed by a
 * different code path than the allow cannot answer "which agent did this".
 */
function agentRollups(records: readonly EvidenceRecord[]): HostAgentRollup[] {
	interface Accumulator {
		label: string | null;
		matchedOn: Set<string>;
		declared: Set<boolean>;
		allowlistSources: Set<string>;
		sessions: Set<string>;
		records: number;
		allowed: number;
		denied: number;
		approvals: number;
		redactions: number;
		firstSeen: string | null;
		lastSeen: string | null;
		destinations: Map<string, { attempts: number; denied: number }>;
		refusedBy: Map<string, number>;
		secretTypes: Set<string>;
		monitorRecords: number;
	}
	const byAgent = new Map<string, Accumulator>();

	for (const rec of records) {
		if (rec.agentId === null) continue;
		let acc = byAgent.get(rec.agentId);
		if (!acc) {
			acc = {
				label: null,
				matchedOn: new Set(),
				declared: new Set(),
				allowlistSources: new Set(),
				sessions: new Set(),
				records: 0,
				allowed: 0,
				denied: 0,
				approvals: 0,
				redactions: 0,
				firstSeen: null,
				lastSeen: null,
				destinations: new Map(),
				refusedBy: new Map(),
				secretTypes: new Set(),
				monitorRecords: 0,
			};
			byAgent.set(rec.agentId, acc);
		}
		acc.records++;
		if (rec.sessionId !== null) acc.sessions.add(rec.sessionId);
		if (rec.decision === "allow") acc.allowed++;
		if (rec.decision === "deny") acc.denied++;
		if (rec.decision === "approve") acc.approvals++;
		if (rec.decision === "redact") acc.redactions++;
		if (rec.timestamp !== null) {
			if (acc.firstSeen === null || rec.timestamp < acc.firstSeen) acc.firstSeen = rec.timestamp;
			if (acc.lastSeen === null || rec.timestamp > acc.lastSeen) acc.lastSeen = rec.timestamp;
		}
		if (rec.decision === "deny") {
			for (const ruleId of rec.matchedRules) acc.refusedBy.set(ruleId, (acc.refusedBy.get(ruleId) ?? 0) + 1);
		}
		if (rec.agent) {
			if (rec.agent.label !== null) acc.label = rec.agent.label;
			if (rec.agent.matchedOn !== null) acc.matchedOn.add(rec.agent.matchedOn);
			if (rec.agent.declared !== null) acc.declared.add(rec.agent.declared);
			if (rec.agent.allowlistSource !== null) acc.allowlistSources.add(rec.agent.allowlistSource);
		}
		if (rec.egress) {
			if (rec.egress.host !== null) {
				const dest = acc.destinations.get(rec.egress.host) ?? { attempts: 0, denied: 0 };
				dest.attempts++;
				if (rec.decision === "deny") dest.denied++;
				acc.destinations.set(rec.egress.host, dest);
			}
			for (const type of rec.egress.secretTypes) acc.secretTypes.add(type);
			if (rec.egress.enforcementMode === "monitor") acc.monitorRecords++;
		}
	}

	return [...byAgent.entries()]
		.map(([agentId, acc]) => ({
			agentId,
			label: acc.label,
			matchedOn: [...acc.matchedOn].sort(),
			// Only a single consistent answer is asserted. An agent whose records disagree about
			// whether it was declared gets `null` and the reviewer is not told a resolved fact
			// that the evidence does not hold.
			declared: acc.declared.size === 1 ? [...acc.declared][0] : null,
			allowlistSources: [...acc.allowlistSources].sort(),
			sessions: acc.sessions.size,
			records: acc.records,
			allowed: acc.allowed,
			denied: acc.denied,
			approvals: acc.approvals,
			redactions: acc.redactions,
			firstSeen: acc.firstSeen,
			lastSeen: acc.lastSeen,
			destinations: [...acc.destinations.entries()]
				.map(([host, d]) => ({ host, attempts: d.attempts, denied: d.denied }))
				.sort((a, b) => b.attempts - a.attempts || a.host.localeCompare(b.host))
				.slice(0, DESTINATIONS_SHOWN),
			distinctDestinations: acc.destinations.size,
			refusedBy: ranked(acc.refusedBy).map((r) => ({ ruleId: r.key, count: r.count })),
			secretTypes: [...acc.secretTypes].sort(),
			monitorRecords: acc.monitorRecords,
		}))
		.sort((a, b) => b.records - a.records || a.agentId.localeCompare(b.agentId));
}

/**
 * The gaps, measured against one host's records.
 *
 * Order is deliberate: the four the threat model names first, because they are the ones an
 * audit answer most often omits, and an audit answer that omits its own gaps is the overclaim
 * pattern that ends up in a suit.
 *
 * A gap whose `observed` is `null` is not an absent gap. Two here are permanently unmeasurable
 * from this evidence and say so, because a table where every unmeasurable row silently reads
 * zero is a table that has replaced its gaps with reassurance.
 */
export function coverageFor(records: readonly EvidenceRecord[], offBox: OffBoxReach | null = null): CoverageGap[] {
	const egress = records.filter((rec) => rec.egress !== null);
	const visibility = (...states: string[]): number =>
		egress.filter((rec) => states.includes(rec.egress?.bodyVisibility ?? "")).length;
	const noEgress = egress.length === 0;
	/** Same sentence wherever a counter has no population, so it cannot drift between rows. */
	const unpopulated =
		"No proxied connection appears in this evidence, so this is unmeasured here. Unmeasured is not zero: " +
		"a host whose agents never went through the proxy produces the same empty count as a host that was never watched.";

	const truncated = egress.filter((rec) => rec.egress?.contentTruncated === true).length;
	const withSecrets = egress.filter((rec) => (rec.egress?.secretTypes.length ?? 0) > 0).length;
	const monitor = egress.filter((rec) => rec.egress?.enforcementMode === "monitor").length;
	const transparent = egress.filter((rec) => rec.egress?.transportMode === "transparent").length;

	return [
		{
			id: "https-body-unread",
			title: "https bodies are not read unless interception is switched on",
			limit:
				"A CONNECT tunnel is decided from the destination host and port before anything is opened upstream. " +
				"The body is ciphertext and is never scanned. TLS interception exists and is opt-in per destination; " +
				"where it is off, every DLP and injection finding for that connection is absent rather than negative.",
			measurable: true,
			observed: noEgress ? null : visibility("tunneled"),
			measurement: noEgress
				? unpopulated
				: "Records whose body was relayed as ciphertext. Nothing was inspected inside any of them.",
			reference: "docs/tls-interception.md",
		},
		{
			id: "inspection-cap",
			title: `content inspection stops at ${CONTENT_SCAN_MAX_BYTES >> 10} KiB`,
			limit:
				`A plaintext or intercepted body is buffered to ${CONTENT_SCAN_MAX_BYTES} bytes, scanned, and the remainder is forwarded ` +
				"uninspected. The exchange is not refused, because refusing every response over a quarter-megabyte " +
				"breaks ordinary agent traffic. The record says `partial` and carries the byte count.",
			measurable: true,
			observed: noEgress ? null : truncated,
			measurement: noEgress
				? unpopulated
				: "Records where at least one direction was read only to the cap. A clean scan on any of these covers a prefix, not a body.",
			reference: "docs/enforcement.md",
		},
		{
			id: "padding-evasion",
			title: "the inspection cap is evadable by padding, and the evasion is invisible here",
			limit:
				`Anything placed past ${CONTENT_SCAN_MAX_BYTES} bytes is forwarded unread. An agent that pads a body and puts the payload ` +
				"after the cap produces a scan that finds nothing, which is indistinguishable from a body that " +
				"contained nothing. The cap is a deliberate trade, not an oversight.",
			// Unmeasurable by construction: the evasion's signature IS a clean scan. Reporting
			// zero here would be the exact overclaim the row exists to refuse.
			measurable: false,
			observed: null,
			measurement:
				"Not measurable from this evidence, by construction: a successful padding evasion produces a clean " +
				"scan and a partial read, which is exactly what an innocent large body produces. The population where " +
				"it could have happened is the capped record(s) in the row above, " +
				`${noEgress ? "and that row is itself unmeasured here." : `of which there are ${truncated}.`}`,
			reference: "docs/enforcement.md",
		},
		{
			id: "dns-channel",
			title: "DNS to a named resolver never reaches the proxy or the chain",
			limit:
				"An agent resolves a name before it connects, so port 53 must be open for anything to work. The " +
				"perimeter narrows that to one resolver address; omitting the resolver denies DNS outright and with " +
				"it most agents' ability to function. A named resolver is a working bidirectional channel to an " +
				"external host: a payload has been carried off a host inside a query name and an answer returned, " +
				"measured rather than theorised.",
			// Nothing to count. A DNS query produces no record anywhere in this format.
			measurable: false,
			observed: null,
			measurement:
				"Not measurable from this evidence at all. A DNS query never reaches the proxy, so no record of one " +
				"exists in any chain. The absence of DNS rows here is the absence of a record type, not the absence " +
				"of DNS traffic.",
			reference: "docs/perimeter.md",
		},
		{
			id: "stream-uninspected",
			title: "event streams are passed through without inspection",
			limit:
				"An event stream cannot be buffered whole without hanging it, so it is relayed uninspected on both " +
				"schemes. No finding may be claimed for a streamed body in either direction.",
			measurable: true,
			observed: noEgress ? null : visibility("stream"),
			measurement: noEgress ? unpopulated : "Records whose body was a stream. None of them was scanned.",
			reference: "docs/enforcement.md",
		},
		{
			id: "interception-bypassed",
			title: "some destinations are relayed opaque on purpose",
			limit:
				"A destination on the interception bypass list is tunnelled without decryption even where " +
				"interception is on. That is deliberate opacity and a different claim from incidental opacity, " +
				"which is why the record distinguishes the two.",
			measurable: true,
			observed: noEgress ? null : visibility("bypassed"),
			measurement: noEgress ? unpopulated : "Records the operator configured not to look inside.",
			reference: "docs/tls-interception.md",
		},
		{
			id: "no-redaction-in-flight",
			title: "credential material found in a proxied body is recorded, never removed",
			limit:
				"A proxied body is not rewritten. Rewriting one in flight means recomputing Content-Length and " +
				"re-encoding whatever transfer or content encoding it arrived under, and getting that wrong corrupts " +
				"a live response over a finding that may be a false positive. In guarded and strict the connection is " +
				"refused; in monitor it completes. Redaction happens on the /evaluate plane, where AgentWall returns " +
				"the content, and not on the wire.",
			measurable: true,
			observed: noEgress ? null : withSecrets,
			measurement: noEgress
				? unpopulated
				: "Proxied records where the scan named a class of secret. The class and offset are recorded; the value never is. " +
					"Whether the connection was refused is the decision on the record, not this count.",
			reference: "docs/enforcement.md",
		},
		{
			id: "monitor-mode",
			title: "an allow written in monitor mode blocked nothing",
			limit:
				"Monitor records every destination and refuses none. An `allow` decision from a monitor-mode " +
				"instance is an observation, not a permission granted after a check the agent could have failed. " +
				"Reading a monitor chain as an enforcement record is the most common way to misread one.",
			measurable: true,
			observed: noEgress ? null : monitor,
			measurement: noEgress
				? unpopulated
				: "Proxied records written while the instance was in monitor mode. What guarded or strict would have done is in each record's reasons.",
			reference: "docs/enforcement.md",
		},
		{
			id: "transparent-no-identity",
			title: "the transparent path carries no fleet identity",
			limit:
				"A kernel-redirected connection is not a proxy request: there is no Proxy-Authorization, no comm and " +
				"no uid to resolve, so it lands on the undeclared agent. Per-agent allowlists and budgets do not bind " +
				"to it.",
			measurable: true,
			observed: noEgress ? null : transparent,
			measurement: noEgress
				? unpopulated
				: "Records that arrived through kernel redirection. Any agent attribution on them is the fallback, not a resolved identity.",
			reference: "docs/perimeter.md",
		},
		{
			id: "completeness",
			title: "an intact chain does not show that everything was recorded",
			limit:
				"Verification shows that what was written was not altered afterwards. It cannot show that everything " +
				"which should have been written was. A decision that was never recorded leaves nothing to detect, " +
				"here or in any verifier, on one host or a thousand.",
			measurable: false,
			observed: null,
			measurement:
				"Not measurable from evidence, by definition. The writer declares gaps it knows about and those are " +
				"counted per host; a decision that never reached the writer declares nothing.",
			reference: "docs/audit-format.md",
		},
		{
			id: "no-off-box-anchor",
			title: "a chain with no off-box anchor is only checked against itself",
			limit:
				"The chained and linked layers detect an edit made to part of a history. They cannot detect a history " +
				"rewritten whole and consistently, which is what somebody with root on the host and the writer's key " +
				"can produce. Only an off-box anchor makes that visible, by committing a fingerprint somewhere the " +
				"host cannot reach back into. A host with no anchor is not tampered with; it is unfalsifiable from " +
				"outside, and in a fleet that is the difference between one compromised host being caught and one " +
				"compromised host reporting itself clean.",
			measurable: true,
			observed: offBox === null ? null : offBox.unanchored,
			measurement:
				offBox === null
					? "Not evaluated at this level."
					: offBox.hosts === 1
						? offBox.unanchored === 0
							? "This host has submitted at least one anchor. What each anchor actually reaches is in its own receipt, and pending is not proof."
							: "This host has submitted no anchor. Its history rests on local controls alone."
						: `${offBox.unanchored} of ${offBox.hosts} readable host(s) have submitted no anchor at all.`,
			reference: "docs/verification.md",
		},
	];
}

/**
 * Sum the per-host gaps into one fleet table, keeping the unmeasurable rows unmeasurable.
 *
 * A host that could not be read contributes nothing, and its nothing is not a zero. That is
 * why the summed rows carry how many hosts they were summed over: a fleet-wide "0 capped
 * bodies" over three of twelve hosts is a different statement from the same number over all
 * twelve, and only one of them is reassuring.
 */
function foldCoverage(hosts: readonly HostEvidence[]): CoverageGap[] {
	const reachable = hosts.filter((h) => h.report !== null);
	const template = coverageFor([], {
		hosts: reachable.length,
		unanchored: reachable.filter((h) => (h.report?.anchors.length ?? 0) === 0).length,
	});
	return template.map((gap) => {
		// The anchoring row is already a per-host count and is carried through rather than
		// summed again: summing a per-host row over hosts would count each host twice.
		if (gap.id === "no-off-box-anchor") return gap;
		const contributions = reachable
			.map((host) => host.coverage.find((g) => g.id === gap.id)?.observed ?? null)
			.filter((n): n is number => n !== null);
		return {
			...gap,
			observed: contributions.length === 0 ? null : contributions.reduce((sum, n) => sum + n, 0),
			measurement:
				contributions.length === 0
					? gap.measurement
					: `Summed over ${contributions.length} of ${hosts.length} host(s). Hosts that could not be read contribute nothing to this count and are not zeroes.`,
		};
	});
}

/**
 * Read one host and decide what it is.
 *
 * Reachability is decided on the audit file alone and before anything else, because every
 * other question is downstream of whether there were bytes to ask it about. `runVerify()` over
 * a missing file returns a verdict, and that verdict must never reach a page: a FAIL for a
 * host whose transport is broken would send an operator hunting for tampering.
 */
function readHost(host: FleetEvidenceHost, staleAfterSeconds: number, nowMs: number): HostEvidence {
	const label = host.label ?? host.id;
	const reproduce = reproduceFor(host.auditPath);
	const unreachable = (reason: string): HostEvidence => {
		// The audit file is gone, so the only remaining trace of when this host last delivered
		// anything is the siblings beside it. Resolved the way the CLI resolves them, so a host
		// directory copied whole reports the same last-seen here as it would there.
		const siblings = resolvePaths(host);
		const mtime = newestMtime([siblings.manifestPath, siblings.anchorLogPath, dirname(siblings.auditPath)]);
		return {
			id: host.id,
			label,
			state: "unreachable",
			detail:
				`The evidence could not be read at ${host.auditPath}. ${reason} ` +
				"This says the aggregator could not look. It does not say the host is down, and it must not be " +
				"read as a clean host or as a host with no findings.",
			auditPath: host.auditPath,
			report: null,
			lastSeen: mtime === null ? null : new Date(mtime).toISOString(),
			lastSeenSource: mtime === null ? null : "file-mtime",
			ageSeconds: mtime === null ? null : Math.max(0, Math.round((nowMs - mtime) / 1000)),
			unreachable: { path: host.auditPath, reason },
			firstSeen: null,
			agents: [],
			coverage: coverageFor([]),
			reproduce,
		};
	};

	if (!existsSync(host.auditPath)) return unreachable("No file is there.");

	let report: EvidenceReport;
	try {
		report = buildEvidenceReport(host);
	} catch (err) {
		// A read that throws is a transport or permission problem, not a verdict about the
		// evidence. Rendering it as a failed chain would report tampering on an NFS mount.
		return unreachable(`Reading it raised: ${(err as Error).message}`);
	}

	const records = report.sessions.flatMap((s) => s.chainRecords);
	const stamps = records.map((rec) => rec.timestamp).filter((t): t is string => t !== null);
	stamps.sort();
	const firstSeen = stamps[0] ?? null;
	const recordSeen = stamps.length > 0 ? stamps[stamps.length - 1] : null;
	const mtime = recordSeen === null ? newestMtime(report.files.map((f) => f.path)) : null;
	const lastSeen = recordSeen ?? (mtime === null ? null : new Date(mtime).toISOString());
	const lastSeenSource = recordSeen !== null ? "record" : mtime === null ? null : "file-mtime";
	const lastSeenMs = lastSeen === null ? null : Date.parse(lastSeen);
	const ageSeconds =
		lastSeenMs === null || Number.isNaN(lastSeenMs) ? null : Math.max(0, Math.round((nowMs - lastSeenMs) / 1000));

	/**
	 * Files in this host's directory whose chain-index ranges overlap.
	 *
	 * THE FAILURE THIS EXISTS TO REFUSE. Segment discovery takes any file named `<audit>.<x>`
	 * that parses as a chain, which is right for `audit.jsonl.1` and wrong for
	 * `audit.jsonl.orig`. This feature's whole operating model is that operators COPY evidence
	 * directories between machines, so a `cp` before an rsync is not an exotic mistake, it is
	 * the expected workflow with one extra step. The copy is then walked as if it were a
	 * rotated segment, the indexes restart, and both the chained and linked layers fail. The
	 * tool has just accused an operator of tampering for taking a backup.
	 *
	 * WHY OVERLAP IS THE RIGHT TEST. Rotation produces strictly increasing, contiguous index
	 * ranges: the writer cannot emit two files covering index 4. So an overlap is not a claim
	 * about the records at all, it is proof that the FILE SET does not describe one history.
	 * The honest answer to "was this evidence edited" over such a set is that it cannot be
	 * determined yet, which is a third outcome and a better one than a confident answer in
	 * either direction.
	 *
	 * THE ADVERSARIAL TRADE-OFF, STATED RATHER THAN GLOSSED. Someone who can write to the
	 * evidence directory can drop a copy and turn a broken host into an inconclusive one. They
	 * could equally delete the directory and turn it into an unreachable one. Neither renders
	 * as clean, and that is the property that matters: this is a finding that demands action,
	 * never an absence of findings.
	 */
	const spans = report.files
		.filter((f) => f.exists && f.skipped === null && f.firstIndex !== null && f.lastIndex !== null)
		.map((f) => ({ path: f.path, first: f.firstIndex as number, last: f.lastIndex as number }));
	const overlaps: string[] = [];
	for (let i = 0; i < spans.length; i++) {
		for (let j = i + 1; j < spans.length; j++) {
			const a = spans[i];
			const b = spans[j];
			if (a.first <= b.last && b.first <= a.last) {
				overlaps.push(
					`${basename(a.path)} covers chain index ${a.first} to ${a.last} and ${basename(b.path)} covers ` +
						`${b.first} to ${b.last}; the writer cannot produce two files over one index, so one of these is a copy ` +
						"rather than a rotated segment",
				);
			}
		}
	}

	/**
	 * Whether ANY off-box anchor has ever been submitted for this host.
	 *
	 * `runVerify()` reports the anchored layer as FAIL on a chain nobody has anchored, with the
	 * detail "nothing anchored off-box yet". That is correct for a layer counter and wrong as a
	 * host verdict: an absence of external evidence is not a contradiction of it, and treating
	 * it as a break would paint every unanchored deployment as tampered with, which is how a
	 * fleet console teaches an operator to ignore red.
	 *
	 * So the failure is reclassified here, not hidden. The layer table still shows FAIL beside
	 * the CLI's FAIL, verbatim, because this view must never quietly disagree with the verifier.
	 * What changes is where the fact is filed: as a coverage gap, counted, with its consequence
	 * spelled out. An anchor that EXISTS and does not reproduce is a different matter and still
	 * condemns the host.
	 */
	const anchorEvidence = report.anchors.length > 0;
	const broken = report.layers.filter(
		(layer) => layer.state === "fail" && !(layer.name === "anchored" && !anchorEvidence),
	);
	const unanchoredNote = anchorEvidence
		? ""
		: " Nothing here has been anchored off-box, so the whole local history could be rewritten consistently and " +
			"nothing outside this host would contradict it. That is counted as a coverage gap rather than as a break, " +
			"and the anchored layer still reports FAIL beside the CLI's FAIL above.";
	const stale = ageSeconds !== null && ageSeconds > staleAfterSeconds;

	// Order matters and IS the honesty of this view.
	//
	// `inconclusive` outranks everything, because the layers below it were computed over a file
	// set that cannot describe one history, so their verdict is not about the records. Ranking
	// it under `broken` would leave the false tampering alarm on screen with an explanation
	// beneath it, which is the same alarm.
	//
	// Then a broken chain beats a stale one, because tampering is the finding and freshness is
	// context. An empty chain beats a stale one for the opposite reason: "nothing was recorded"
	// is what the reviewer needs to hear first, and it is never a pass.
	let state: HostState;
	let detail: string;
	if (overlaps.length > 0) {
		state = "inconclusive";
		detail =
			`No verdict about this host's records can be reached from the files as they stand. ${overlaps.join(". ")}. ` +
			"Until the extra file is out of the evidence directory, every layer below is being computed over a file " +
			"set that does not describe one history, and any FAIL it shows is about the arrangement of the files " +
			"rather than about the records. THIS IS NOT A FINDING OF TAMPERING. The usual cause is an ordinary " +
			"backup taken beside the chain, because segment discovery accepts any file named after the audit file " +
			"that parses as one. Move it elsewhere and re-read. Read this as a demand for action rather than as an " +
			"absence of findings: somebody who can write to this directory could produce this state deliberately to " +
			"mask a real break, exactly as they could delete the directory to produce an unreachable one.";
	} else if (broken.length > 0) {
		state = "broken";
		detail =
			`${broken.map((l) => l.name).join(" and ")} ${broken.length === 1 ? "fails" : "fail"} on this host's own chain. ` +
			"The finding is local: every other host's chain is anchored separately and is unaffected by it.";
	} else if (report.totals.records === 0) {
		state = "empty";
		detail =
			"The evidence was read and holds no records. Nothing was recorded on this host in what arrived here. " +
			"That is not the same as nothing happening: a decision that was never written leaves nothing to detect.";
	} else if (stale) {
		state = "stale";
		detail =
			`Every layer that could be checked holds, and the newest ${lastSeenSource === "record" ? "record" : "evidence file"} is ` +
			`${ageSeconds} seconds old against a bound of ${staleAfterSeconds}. Read this as history. Whatever this ` +
			`host has done since is not here, and the verdict above does not cover it.${unanchoredNote}`;
	} else {
		state = "verified";
		detail =
			`Every layer that could be checked holds over ${report.totals.records} record(s), on evidence ` +
			`${ageSeconds ?? "an unknown number of"} seconds old. The verdict is this aggregator re-deriving every ` +
			`hash from the bytes, not a claim the host made about itself.${unanchoredNote}`;
	}

	return {
		id: host.id,
		label,
		state,
		detail,
		auditPath: host.auditPath,
		report,
		lastSeen,
		lastSeenSource,
		ageSeconds,
		unreachable: null,
		firstSeen,
		agents: agentRollups(records),
		coverage: coverageFor(records, { hosts: 1, unanchored: anchorEvidence ? 0 : 1 }),
		reproduce,
	};
}

/**
 * Build the fleet report.
 *
 * Each host is read and verified on its own. Nothing about one host's chain is consulted while
 * judging another's, which is what makes a tampered record on one host a finding there and
 * only there. The aggregate below is arithmetic over independent verdicts, never a fourth
 * verdict of its own.
 */
export function buildFleetEvidenceReport(sources: FleetEvidenceSources, now: Date = new Date()): FleetEvidenceReport {
	const nowMs = now.getTime();
	const hosts = sources.hosts.map((host) => readHost(host, sources.staleAfterSeconds, nowMs));

	const count = (state: HostState): number => hosts.filter((h) => h.state === state).length;
	const readable = hosts.filter((h) => h.report !== null);
	// Record timestamps only. A file mtime says when something touched a file, not when a
	// decision was made, so letting one widen the window would state a span of activity the
	// evidence does not support. `firstSeen` is record-derived by construction; `lastSeen`
	// falls back to an mtime and is admitted here only when it did not have to.
	const stamps: string[] = [];
	for (const host of readable) {
		if (host.firstSeen !== null) stamps.push(host.firstSeen);
		if (host.lastSeenSource === "record" && host.lastSeen !== null) stamps.push(host.lastSeen);
	}
	stamps.sort();

	const agents = new Set<string>();
	for (const host of hosts) for (const agent of host.agents) agents.add(`${host.id}/${agent.agentId}`);

	const unreachable = count("unreachable");
	const broken = count("broken");
	const inconclusive = count("inconclusive");
	const stale = count("stale");
	const empty = count("empty");

	// Three states, and "incomplete" is the one that carries the design. An aggregate that
	// reported PASS while a host was unread would be exactly the decoration this whole surface
	// exists to refuse: a fleet answer is only as good as the hosts it could actually read.
	let verdictState: FleetEvidenceReport["verdict"]["state"];
	let headline: string;
	if (broken > 0) {
		verdictState = "broken";
		headline =
			`${broken} of ${hosts.length} host(s) fail their own chain verification` +
			`${inconclusive > 0 ? `, and ${inconclusive} could not be judged from the files as they stand` : ""}.`;
	} else if (unreachable + inconclusive + stale + empty > 0) {
		verdictState = "incomplete";
		headline =
			`Every chain that could be read verifies. ${unreachable} host(s) could not be read, ` +
			`${inconclusive} could not be judged from the files as they stand, ${stale} are stale and ` +
			`${empty} recorded nothing, so this is not a clean fleet answer.`;
	} else {
		verdictState = "verified";
		headline = `All ${hosts.length} host(s) verify independently on fresh evidence.`;
	}

	return {
		generatedAt: now.toISOString(),
		staleAfterSeconds: sources.staleAfterSeconds,
		hosts,
		window: { from: stamps[0] ?? null, to: stamps[stamps.length - 1] ?? null },
		totals: {
			hosts: hosts.length,
			verified: count("verified"),
			broken,
			inconclusive,
			stale,
			empty,
			unreachable,
			records: readable.reduce((sum, h) => sum + (h.report?.totals.records ?? 0), 0),
			faulty: readable.reduce((sum, h) => sum + faultyCount(h.report?.sessions.flatMap((s) => s.chainRecords) ?? []), 0),
			sessions: readable.reduce((sum, h) => sum + (h.report?.totals.sessions ?? 0), 0),
			agents: agents.size,
		},
		verdict: {
			state: verdictState,
			headline,
			detail:
				"What this establishes: each chain listed below was re-derived from its own bytes by this process and " +
				"holds or does not hold on its own. The chains are NOT merged and no ordering between hosts is " +
				"claimed; that would need a total order across hosts, which needs a single writer or agreed clocks, " +
				"and neither exists. What it does not establish: anything about a host absent from the sources file, " +
				"anything about a host that could not be read, and completeness on any host at all. Every verdict " +
				"here is reproducible with the commands on each host's page, in four independent implementations, " +
				"without trusting this process.",
		},
		coverage: foldCoverage(hosts),
		notes: readable.flatMap((h) => (h.report?.notes ?? []).map((note) => `${h.id}: ${note}`)),
	};
}
