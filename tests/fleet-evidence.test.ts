import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "@jest/globals";
import { spawnSync } from "child_process";
import { createServer, request as httpRequest } from "http";
import type { IncomingMessage, Server as HttpServer, ServerResponse } from "http";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import type { AddressInfo, Server as NetServer } from "net";
import { tmpdir } from "os";
import { join } from "path";
import type { FastifyInstance } from "fastify";
import { emit, resetAuditChain } from "../src/audit/logger";
import { runVerify } from "../src/audit/anchor-service";
import type { AgentwallConfig } from "../src/config";
import { buildServer } from "../src/server";
import { buildFleetEvidenceReport, coverageFor, loadFleetEvidenceSources } from "../src/evidence/fleet";
import { collectEvidence } from "../src/evidence/collect";
import { createForwardProxy } from "../src/proxy/forward-proxy";
import type { ProxyRecord } from "../src/proxy/forward-proxy";
import { PolicyEngine } from "../src/policy/engine";
import { builtinRules } from "../src/policy/rules";
import { detectionsForRules } from "../src/policy/detections";
import { decideEgress, setEgressPolicy } from "../src/runtime/enforcement";

/**
 * Read-only evidence aggregation across several hosts.
 *
 * Every chain here is written by the production writers through a running server, exactly as
 * the single-host suite does it, because a viewer asserted against strings some test wrote is
 * a test of the test. Each simulated host is a separate server instance with its own audit
 * file, closed before the next starts, which is what a real fleet's evidence looks like once it
 * has been copied to one box: N directories, N independently anchored chains, no shared writer.
 *
 * The four properties the feature rests on, each with a case below:
 *
 *   1. Two real chains from two hosts render in one view, each verified on its own bytes.
 *   2. A tampered record on ONE host is flagged there and does not touch the other's verdict.
 *   3. A host that could not be read renders as unreachable, distinctly from a clean one and
 *      distinctly from one that recorded nothing.
 *   4. The gaps in what any of this can see are on the page, counted where they are countable
 *      and named as unmeasurable where they are not.
 */

const dirs: string[] = [];
function tmp(): string {
	const d = mkdtempSync(join(tmpdir(), "aw-fleet-evidence-"));
	dirs.push(d);
	return d;
}

const config: AgentwallConfig = {
	port: 0,
	host: "127.0.0.1",
	logLevel: "silent",
	dashboard: {},
	approval: { mode: "auto", timeoutMs: 5_000, backend: "memory" },
	// allow, so the recorded decisions are the ones the rules actually reached rather than a
	// wall of identical defaults. A fleet view that cannot tell allow from deny shows nothing.
	policy: { defaultDecision: "allow" },
	dlp: { enabled: true, redactSecrets: true },
	egress: {
		enabled: true,
		defaultDeny: false,
		allowPrivateRanges: false,
		allowedHosts: ["api.github.com"],
		allowedSchemes: ["https"],
		allowedPorts: [443],
	},
	manifestIntegrity: { enabled: true },
	watchdog: { enabled: true, staleAfterMs: 15_000, timeoutMs: 30_000, killSwitchMode: "deny_all" },
};

interface Traffic {
	sessionId: string;
	agentId: string;
	plane: string;
	action: string;
	payload: Record<string, unknown>;
	flow?: unknown;
}

/** The build host: a shell runner and a researcher, one of them reaching for metadata. */
const TRAFFIC_A: Traffic[] = [
	{ sessionId: "build-1", agentId: "builder", plane: "tool", action: "shell.exec", payload: { command: "npm run build" } },
	{
		sessionId: "build-1",
		agentId: "builder",
		plane: "network",
		action: "network.egress",
		payload: { url: "https://api.github.com/repos/repsecure/agentwall" },
	},
	{
		sessionId: "build-2",
		agentId: "researcher",
		plane: "network",
		action: "network.egress",
		payload: { url: "http://169.254.169.254/latest/meta-data/" },
	},
];

/** The support host: a different agent, a credential in flight on the evaluate plane. */
const TRAFFIC_B: Traffic[] = [
	{
		sessionId: "support-1",
		agentId: "assistant",
		plane: "tool",
		action: "tool.call",
		payload: { tool: "http.get", url: "https://api.github.com/meta" },
	},
	{
		sessionId: "support-1",
		agentId: "assistant",
		plane: "content",
		action: "content.egress",
		payload: { text: "the key is AKIAIOSFODNN7EXAMPLE" },
		flow: { direction: "egress", labels: ["secret_material"] },
	},
	{ sessionId: "support-2", agentId: "assistant", plane: "network", action: "network.egress", payload: { url: "http://10.0.0.7:8080/admin" } },
];

const apps: FastifyInstance[] = [];
let savedAuditPath: string | undefined;
let savedSources: string | undefined;

/**
 * Write one host's chain, through a real server and the real file sink, then shut it down.
 *
 * Sequential rather than concurrent on purpose: the audit sinks are module state and the file
 * sink takes an exclusive per-path writer lock, so two servers alive at once would be the
 * two-writer interleave the lock exists to refuse. A fleet's hosts never share a process
 * anyway, so running them one at a time here reproduces that faithfully.
 */
async function writeHostChain(traffic: readonly Traffic[]): Promise<{ dir: string; auditPath: string }> {
	const dir = tmp();
	const auditPath = join(dir, "audit.jsonl");
	process.env.AGENTWALL_AUDIT_FILE = auditPath;
	resetAuditChain();

	const { app } = await buildServer(config);
	try {
		for (const t of traffic) {
			const res = await app.inject({ method: "POST", url: "/evaluate", payload: t });
			expect(res.statusCode).toBe(200);
		}
	} finally {
		await app.close();
		resetAuditChain();
	}
	return { dir, auditPath };
}

/** The aggregator: a server with no chain of its own, pointed at a sources file. */
async function aggregator(sourcesPath: string | undefined): Promise<FastifyInstance> {
	delete process.env.AGENTWALL_AUDIT_FILE;
	if (sourcesPath === undefined) delete process.env.AGENTWALL_FLEET_EVIDENCE;
	else process.env.AGENTWALL_FLEET_EVIDENCE = sourcesPath;
	resetAuditChain();
	const { app } = await buildServer(config);
	apps.push(app);
	return app;
}

/** A sources file, written where the test can point the aggregator at it. */
function writeSources(hosts: { id: string; label?: string; auditPath: string }[], staleAfterSeconds = 86_400): string {
	const path = join(tmp(), "fleet-evidence.yaml");
	const body = [
		`staleAfterSeconds: ${staleAfterSeconds}`,
		"hosts:",
		...hosts.flatMap((h) => [
			`  - id: ${h.id}`,
			...(h.label === undefined ? [] : [`    label: ${JSON.stringify(h.label)}`]),
			`    auditPath: ${JSON.stringify(h.auditPath)}`,
		]),
	].join("\n");
	writeFileSync(path, `${body}\n`);
	return path;
}

beforeEach(() => {
	savedAuditPath = process.env.AGENTWALL_AUDIT_FILE;
	savedSources = process.env.AGENTWALL_FLEET_EVIDENCE;
});

afterEach(async () => {
	if (savedAuditPath === undefined) delete process.env.AGENTWALL_AUDIT_FILE;
	else process.env.AGENTWALL_AUDIT_FILE = savedAuditPath;
	if (savedSources === undefined) delete process.env.AGENTWALL_FLEET_EVIDENCE;
	else process.env.AGENTWALL_FLEET_EVIDENCE = savedSources;
	resetAuditChain();
	while (apps.length) await (apps.pop() as FastifyInstance).close();
	while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

describe("fleet evidence, two real chains from two hosts", () => {
	it("renders both, verifies each on its own bytes, and matches the CLI per host", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const b = await writeHostChain(TRAFFIC_B);
		const app = await aggregator(
			writeSources([
				{ id: "build-01", label: "Build runner", auditPath: a.auditPath },
				{ id: "support-01", label: "Support box", auditPath: b.auditPath },
			]),
		);

		const res = await app.inject({ method: "GET", url: "/api/evidence/fleet" });
		expect(res.statusCode).toBe(200);
		const report = res.json();

		expect(report.totals.hosts).toBe(2);
		expect(report.totals.verified).toBe(2);
		expect(report.verdict.state).toBe("verified");
		expect(report.totals.records).toBe(TRAFFIC_A.length + TRAFFIC_B.length);

		// Each host's verdict is the verifier's own over that host's own files. Asserted against
		// a separate runVerify per path, because the claim under test is that the chains were
		// checked separately and not folded into one.
		for (const [id, auditPath, expected] of [
			["build-01", a.auditPath, TRAFFIC_A.length],
			["support-01", b.auditPath, TRAFFIC_B.length],
		] as const) {
			const host = report.hosts.find((h: { id: string }) => h.id === id);
			expect(host.state).toBe("verified");
			expect(host.verify.totals.records).toBe(expected);
			const cli = runVerify({ auditPath });
			for (const layer of host.verify.layers) {
				const own = cli.layers.find((l) => l.name === layer.name);
				expect(layer.cliVerdict).toBe(own?.ok ? "PASS" : "FAIL");
				expect(layer.detail).toBe(own?.detail);
			}
		}

		// One host's records never appear under the other. A merged view would be the failure.
		const buildHost = report.hosts.find((h: { id: string }) => h.id === "build-01");
		const supportHost = report.hosts.find((h: { id: string }) => h.id === "support-01");
		expect(buildHost.agents.map((x: { agentId: string }) => x.agentId).sort()).toEqual(["builder", "researcher"]);
		expect(supportHost.agents.map((x: { agentId: string }) => x.agentId)).toEqual(["assistant"]);

		const html = await app.inject({ method: "GET", url: "/evidence/fleet" });
		expect(html.statusCode).toBe(200);
		expect(html.headers["content-type"]).toContain("text/html");
		expect(html.body).toContain("Build runner");
		expect(html.body).toContain("Support box");
		expect(html.body).toContain("Read only");
		// A page that cannot run code cannot mutate anything, so the absence is asserted.
		expect(html.body).not.toContain("<script");

		const hostPage = await app.inject({ method: "GET", url: "/evidence/fleet/host/build-01" });
		expect(hostPage.statusCode).toBe(200);
		expect(hostPage.body).toContain("builder");
		expect(hostPage.body).toContain("net:block-metadata-endpoint");
		expect(hostPage.body).not.toContain("<script");
	});

	it("answers what an auditor asks: which agent, what it attempted, what refused it, in which window", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const app = await aggregator(writeSources([{ id: "build-01", auditPath: a.auditPath }]));

		const host = (await app.inject({ method: "GET", url: "/api/evidence/fleet/host/build-01" })).json();
		const researcher = host.agents.find((x: { agentId: string }) => x.agentId === "researcher");
		expect(researcher.records).toBe(1);
		expect(researcher.denied).toBe(1);
		expect(researcher.allowed).toBe(0);
		// The rule that refused it, by id, so the answer names the control rather than a mood.
		expect(researcher.refusedBy.map((r: { ruleId: string }) => r.ruleId)).toContain("net:block-metadata-endpoint");
		expect(researcher.firstSeen).not.toBeNull();
		expect(researcher.lastSeen).not.toBeNull();

		const builder = host.agents.find((x: { agentId: string }) => x.agentId === "builder");
		expect(builder.records).toBe(2);
		expect(builder.sessions).toBe(1);

		// The window is a span of decisions, and it is stated rather than implied.
		const index = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		expect(index.window.from).not.toBeNull();
		expect(index.window.to).not.toBeNull();
		expect(Date.parse(index.window.from)).toBeLessThanOrEqual(Date.parse(index.window.to));
	});

	it("prints four independent verifier commands per host, each naming that host's own file", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const b = await writeHostChain(TRAFFIC_B);
		const app = await aggregator(
			writeSources([
				{ id: "build-01", auditPath: a.auditPath },
				{ id: "support-01", auditPath: b.auditPath },
			]),
		);

		const report = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		const build = report.hosts.find((h: { id: string }) => h.id === "build-01");
		const support = report.hosts.find((h: { id: string }) => h.id === "support-01");

		for (const [name, command] of Object.entries(build.reproduce) as [string, string][]) {
			// The pinned form names the key to bind to, not a chain, so it is checked separately.
			if (name === "pinned") continue;
			expect(command).toContain(a.auditPath);
			expect(command).not.toContain(b.auditPath);
		}
		expect(build.reproduce.bundled).toContain("node dist/cli.js verify");
		expect(build.reproduce.go).toContain("go build");
		expect(build.reproduce.rust).toContain("cargo build");
		expect(build.reproduce.python).toContain("verifier-py/agentwall-verify-py");
		expect(build.reproduce.pinned).toContain("--pubkey-file");
		expect(support.reproduce.bundled).toContain(b.auditPath);

		const page = await app.inject({ method: "GET", url: "/evidence/fleet/host/build-01" });
		expect(page.body).toContain(a.auditPath);
		expect(page.body).toContain("cargo build");
		expect(page.body).toContain("agentwall-verify-py");
	});
});

describe("fleet evidence, a break on one host stays on that host", () => {
	it("flags the altered record where it is, leaves the other host verified, and clears on restore", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const b = await writeHostChain(TRAFFIC_B);
		const app = await aggregator(
			writeSources([
				{ id: "build-01", auditPath: a.auditPath },
				{ id: "support-01", auditPath: b.auditPath },
			]),
		);

		const clean = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		expect(clean.verdict.state).toBe("verified");
		expect(clean.totals.faulty).toBe(0);

		// One byte, in a record the chain already covers, on ONE host. "deny" and "alow" are the
		// same length, so the file size, the record count and the index span are all unchanged
		// and only the hash reveals it. This is the shape a real edit takes.
		const original = readFileSync(a.auditPath, "utf8");
		const lines = original.split("\n");
		const target = lines.findIndex((l) => l.includes(`"decision":"deny"`));
		expect(target).toBeGreaterThanOrEqual(0);
		lines[target] = lines[target].replace(`"decision":"deny"`, `"decision":"alow"`);
		const tampered = lines.join("\n");
		expect(tampered.length).toBe(original.length);
		const untouchedOther = readFileSync(b.auditPath, "utf8");
		writeFileSync(a.auditPath, tampered);

		const broken = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		expect(broken.verdict.state).toBe("broken");
		expect(broken.totals.broken).toBe(1);
		expect(broken.totals.verified).toBe(1);

		const hurt = broken.hosts.find((h: { id: string }) => h.id === "build-01");
		expect(hurt.state).toBe("broken");
		expect(hurt.verify.layers.find((l: { name: string }) => l.name === "chained").state).toBe("fail");
		expect(hurt.verify.layers.find((l: { name: string }) => l.name === "chained").cliVerdict).toBe("FAIL");
		expect(hurt.verify.totals.faulty).toBe(1);
		expect(hurt.detail).toContain("local");

		// The other host is untouched, in its bytes and in its verdict. Nothing in its chain
		// links to the first one's, which is the whole reason the chains are not merged.
		//
		// Asserted as an EQUALITY against the verdict this host had before the edit rather than
		// as a list of passes. A list of passes would have to encode which layers happen to hold
		// in this fixture, and the claim being made is stronger and simpler than that: tampering
		// with one host changed nothing whatsoever about the other's verdict.
		const fine = broken.hosts.find((h: { id: string }) => h.id === "support-01");
		const before = clean.hosts.find((h: { id: string }) => h.id === "support-01");
		expect(fine.state).toBe("verified");
		expect(fine.verify.layers).toEqual(before.verify.layers);
		expect(fine.verify.totals.faulty).toBe(0);
		expect(fine.verify.layers.find((l: { name: string }) => l.name === "chained").state).toBe("pass");
		expect(fine.verify.layers.find((l: { name: string }) => l.name === "linked").state).toBe("pass");
		expect(readFileSync(b.auditPath, "utf8")).toBe(untouchedOther);
		// And the CLI, run against that host alone, agrees on the two layers the edit could have
		// touched. Its anchored layer fails on both hosts for want of an anchor, before and after.
		const cli = runVerify({ auditPath: b.auditPath });
		expect(cli.layers.find((l) => l.name === "chained")?.ok).toBe(true);
		expect(cli.layers.find((l) => l.name === "linked")?.ok).toBe(true);

		// The break is on the page, attributed to the host it belongs to.
		const page = await app.inject({ method: "GET", url: "/evidence/fleet/host/build-01" });
		expect(page.body).toContain("BROKEN");
		expect(page.body).toContain("hash mismatch");

		// Restore, and the fleet goes clean again. A view that latched the failure would make
		// the next honest read look tampered.
		writeFileSync(a.auditPath, original);
		const healed = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		expect(healed.verdict.state).toBe("verified");
		expect(healed.totals.broken).toBe(0);
		expect(healed.totals.verified).toBe(2);
		expect(healed.totals.faulty).toBe(0);
	});
});

describe("fleet evidence, failure semantics", () => {
	it("renders a host it could not read as unreachable, never as clean and never as zero", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const missing = join(tmp(), "never-delivered", "audit.jsonl");
		const app = await aggregator(
			writeSources([
				{ id: "build-01", auditPath: a.auditPath },
				{ id: "offline-01", label: "Offline box", auditPath: missing },
			]),
		);

		const report = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		const gone = report.hosts.find((h: { id: string }) => h.id === "offline-01");
		expect(gone.state).toBe("unreachable");
		// No verdict at all, rather than a passing one over an absent file. A verdict here would
		// be invented, and an invented verdict is either a false clean or a false alarm.
		expect(gone.verify).toBeNull();
		expect(gone.unreachable.path).toBe(missing);
		expect(gone.detail).toContain("could not look");
		expect(gone.agents).toEqual([]);

		// It is distinct from a verified host in the aggregate, and the aggregate refuses to
		// call the fleet clean while a member is unread.
		expect(report.verdict.state).toBe("incomplete");
		expect(report.totals.unreachable).toBe(1);
		expect(report.totals.verified).toBe(1);

		const html = await app.inject({ method: "GET", url: "/evidence/fleet" });
		expect(html.body).toContain("unreachable");
		expect(html.body).toContain("could not look");
		expect(html.body).toContain("INCOMPLETE");

		const page = await app.inject({ method: "GET", url: "/evidence/fleet/host/offline-01" });
		expect(page.body).toContain("Nothing was checked");
		// The page lists the candidate causes and picks none of them. A console that named a
		// cause it did not check would be guessing during an incident, and the two causes people
		// assume, a dead host and a dead transport, are only two of five.
		expect(page.body).toContain("the cause is not stated here");
		expect(page.body).toContain("a host that is down");
		expect(page.body).toContain("a path that does not match");
	});

	it("distinguishes a host that recorded nothing from a host that could not be read", async () => {
		const emptyPath = join(tmp(), "audit.jsonl");
		writeFileSync(emptyPath, "");
		const app = await aggregator(
			writeSources([
				{ id: "quiet-01", auditPath: emptyPath },
				{ id: "offline-01", auditPath: join(tmp(), "gone", "audit.jsonl") },
			]),
		);

		const report = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		const quiet = report.hosts.find((h: { id: string }) => h.id === "quiet-01");
		const gone = report.hosts.find((h: { id: string }) => h.id === "offline-01");

		// Both produce zero findings. They are different answers and the view says which.
		expect(quiet.state).toBe("empty");
		expect(gone.state).toBe("unreachable");
		expect(quiet.verify).not.toBeNull();
		expect(gone.verify).toBeNull();
		expect(quiet.detail).toContain("not the same as nothing happening");
		expect(report.totals.empty).toBe(1);
		expect(report.totals.unreachable).toBe(1);
		expect(report.totals.verified).toBe(0);
		expect(report.verdict.state).toBe("incomplete");
	});

	it("renders a host whose evidence stopped arriving as stale, with its age", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		// One second of tolerance, read an hour later. The clock is supplied rather than waited
		// on, so the case measures the rule and not the test runner's speed.
		const sources = loadFleetEvidenceSources(writeSources([{ id: "build-01", auditPath: a.auditPath }], 1));
		const report = buildFleetEvidenceReport(sources, new Date(Date.now() + 3_600_000));

		const host = report.hosts[0];
		expect(host.state).toBe("stale");
		expect(host.lastSeenSource).toBe("record");
		expect(host.ageSeconds).toBeGreaterThan(3_000);
		expect(host.detail).toContain("Read this as history");
		// Stale is not broken: the chain still verifies and the page must not cry tampering.
		expect(host.report?.layers.find((l) => l.name === "chained")?.state).toBe("pass");
		expect(report.verdict.state).toBe("incomplete");
		expect(report.totals.stale).toBe(1);
		expect(report.totals.verified).toBe(0);
	});

	it("renders a backup left beside the chain as inconclusive, not as tampering", async () => {
		// Segment discovery takes any file named after the audit file that parses as a chain,
		// which is right for audit.jsonl.1 and wrong for audit.jsonl.orig. This feature's whole
		// operating model is that operators copy evidence directories between machines, so a cp
		// before an rsync is the expected workflow with one extra step. Walked as a rotated
		// segment the copy restarts the indexes and both chain layers fail, and the tool has
		// accused somebody of tampering for taking a backup.
		const a = await writeHostChain(TRAFFIC_A);
		copyFileSync(a.auditPath, `${a.auditPath}.orig`);
		const app = await aggregator(writeSources([{ id: "build-01", auditPath: a.auditPath }]));

		const report = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		const host = report.hosts[0];
		expect(host.state).toBe("inconclusive");
		// The layers really did fail. The point is that the host verdict does not repeat that as
		// a claim about the records, because the file set it was computed over is not one history.
		expect(host.verify.layers.some((l: { state: string }) => l.state === "fail")).toBe(true);
		expect(host.detail).toContain("audit.jsonl.orig");
		expect(host.detail).toContain("THIS IS NOT A FINDING OF TAMPERING");
		// Ranked above broken, or the false alarm is still the headline with a footnote under it.
		expect(report.totals.broken).toBe(0);
		expect(report.totals.inconclusive).toBe(1);
		// And never as clean. The adversarial reading is that somebody with write access could
		// force this state to mask a real break, which is why it is a finding demanding action.
		expect(report.verdict.state).toBe("incomplete");
		expect(report.totals.verified).toBe(0);

		const html = await app.inject({ method: "GET", url: "/evidence/fleet" });
		expect(html.body).toContain("inconclusive");
		expect(html.body).toContain("not judgeable");

		// Move the backup out and the host is judgeable again, with no residue.
		rmSync(`${a.auditPath}.orig`);
		const healed = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		expect(healed.hosts[0].state).toBe("verified");
		expect(healed.totals.inconclusive).toBe(0);
	});

	it("makes no network request while building a report", async () => {
		// The page tells an operator this surface makes no network request and holds no
		// credential on any agent host. That is a claim about behaviour, so it is measured
		// rather than asserted: a fetch from this path would throw and fail the case.
		const a = await writeHostChain(TRAFFIC_A);
		const sources = loadFleetEvidenceSources(writeSources([{ id: "build-01", auditPath: a.auditPath }]));
		const realFetch = globalThis.fetch;
		globalThis.fetch = (() => {
			throw new Error("the fleet evidence path must not reach the network");
		}) as typeof fetch;
		try {
			expect(buildFleetEvidenceReport(sources).hosts[0].state).toBe("verified");
		} finally {
			globalThis.fetch = realFetch;
		}
	});

	it("refuses to render a partial fleet when the sources file does not parse", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const path = join(tmp(), "fleet-evidence.yaml");
		writeFileSync(
			path,
			`staleAfterSeconds: 900\nhosts:\n  - id: build-01\n    auditPath: ${JSON.stringify(a.auditPath)}\n  - label: no id here\n`,
		);
		const app = await aggregator(path);

		const api = await app.inject({ method: "GET", url: "/api/evidence/fleet" });
		expect(api.statusCode).toBe(503);
		expect(api.json().detail).toContain("hosts.1.id");

		const html = await app.inject({ method: "GET", url: "/evidence/fleet" });
		expect(html.statusCode).toBe(503);
		// Not one host is shown. A green page missing a member is the worst possible output from
		// a tool whose whole job is saying what it could not see.
		expect(html.body).not.toContain("build-01");
		expect(html.body).toContain("No host is shown");
	});

	it("rejects two hosts declared under one id rather than silently dropping one", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const path = join(tmp(), "fleet-evidence.yaml");
		writeFileSync(
			path,
			`staleAfterSeconds: 900\nhosts:\n  - id: dup\n    auditPath: ${JSON.stringify(a.auditPath)}\n  - id: dup\n    auditPath: ${JSON.stringify(a.auditPath)}\n`,
		);
		expect(() => loadFleetEvidenceSources(path)).toThrow(/declare host id "dup" twice/);
	});

	it("resolves a relative audit path against the sources file, not the working directory", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const sourcesDir = tmp();
		mkdirSync(join(sourcesDir, "hosts"), { recursive: true });
		const nested = join(sourcesDir, "hosts", "audit.jsonl");
		writeFileSync(nested, readFileSync(a.auditPath, "utf8"));
		const path = join(sourcesDir, "fleet-evidence.yaml");
		writeFileSync(path, "staleAfterSeconds: 900\nhosts:\n  - id: rel-01\n    auditPath: hosts/audit.jsonl\n");

		const sources = loadFleetEvidenceSources(path);
		expect(sources.hosts[0].auditPath).toBe(nested);
		expect(buildFleetEvidenceReport(sources).hosts[0].state).toBe("verified");
	});
});

describe("fleet evidence, the gaps are on the page", () => {
	it("names every gap, counts the countable ones, and refuses to render the rest as zero", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const app = await aggregator(writeSources([{ id: "build-01", auditPath: a.auditPath }]));

		const report = (await app.inject({ method: "GET", url: "/api/evidence/fleet" })).json();
		const ids = report.coverage.map((g: { id: string }) => g.id);
		// The four the threat model names, plus the ones a fleet reader most needs.
		for (const id of [
			"https-body-unread",
			"inspection-cap",
			"padding-evasion",
			"dns-channel",
			"stream-uninspected",
			"interception-bypassed",
			"monitor-mode",
			"transparent-no-identity",
			"no-redaction-in-flight",
			"no-off-box-anchor",
			"completeness",
		]) {
			expect(ids).toContain(id);
		}

		// Three of them are unmeasurable by construction and say so instead of reading zero,
		// which is the difference between stating a gap and papering over it.
		const padding = report.coverage.find((g: { id: string }) => g.id === "padding-evasion");
		const dns = report.coverage.find((g: { id: string }) => g.id === "dns-channel");
		for (const gap of [padding, dns, report.coverage.find((g: { id: string }) => g.id === "completeness")]) {
			expect(gap.measurable).toBe(false);
			expect(gap.observed).toBeNull();
		}
		expect(dns.measurement).toContain("not the absence");

		// This host's chain holds no proxied connection, so the countable gaps are UNMEASURED
		// here. Unmeasured, unmeasurable and zero are three different claims and the row says
		// which one it is rather than collapsing them onto an empty cell.
		const https = report.coverage.find((g: { id: string }) => g.id === "https-body-unread");
		expect(https.measurable).toBe(true);
		expect(https.observed).toBeNull();
		expect(https.measurement).toContain("Unmeasured is not zero");

		// A chain nobody anchored is a gap, not a break: the host still reads verified and the
		// consequence is counted here instead.
		const anchor = report.coverage.find((g: { id: string }) => g.id === "no-off-box-anchor");
		expect(anchor.observed).toBe(1);
		expect(report.hosts[0].state).toBe("verified");
		expect(report.hosts[0].verify.layers.find((l: { name: string }) => l.name === "anchored").cliVerdict).toBe("FAIL");
		expect(report.hosts[0].detail).toContain("counted as a coverage gap rather than as a break");

		const html = await app.inject({ method: "GET", url: "/evidence/fleet" });
		expect(html.body).toContain("https bodies are not read unless interception is switched on");
		expect(html.body).toContain("content inspection stops at 256 KiB");
		expect(html.body).toContain("DNS to a named resolver never reaches the proxy or the chain");
		expect(html.body).toContain("the inspection cap is evadable by padding");
		expect(html.body).toContain("a chain with no off-box anchor is only checked against itself");
		expect(html.body).toContain("not measurable");
		expect(html.body).toContain("unmeasured");
	});
});

describe("fleet evidence, the commands the page prints are commands", () => {
	/**
	 * A snippet emitted for a human to paste is a thing this project ships into somebody else's
	 * terminal, and one that cannot execute is a defect there rather than a cosmetic one.
	 *
	 * The specific bug this pins: the obvious spelling of the reproduce block is four lines
	 * beginning `cd verifier && ...`, `cd verifier-rs && ...`. Pasted whole, the second `cd`
	 * runs from inside `verifier/` and fails, and so does everything after it. Each toolchain
	 * line is a subshell instead, and this asserts the block still parses and still leaves the
	 * shell where it started.
	 */
	it("parses under bash and does not move the shell out from under the next line", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const app = await aggregator(writeSources([{ id: "build-01", auditPath: a.auditPath }]));
		const host = (await app.inject({ method: "GET", url: "/api/evidence/fleet/host/build-01" })).json();

		const commands: string[] = [host.reproduce.bundled, host.reproduce.go, host.reproduce.rust, host.reproduce.python];
		for (const command of commands) {
			// `bash -n` parses without executing, so a quoting or subshell error is caught here
			// rather than by the reviewer who pasted it.
			expect(spawnSync("bash", ["-n", "-c", command], { encoding: "utf8" }).status).toBe(0);
		}
		// Pasted as one block, the shell must end where it began. Run in a subshell with the
		// toolchains stubbed out, because go and cargo are not present on every machine and what
		// is under test is the block's shape, not whether a compiler is installed.
		const probe = spawnSync(
			"bash",
			[
				"-c",
				["go() { :; }", "cargo() { :; }", "node() { :; }", "python3() { :; }", ...commands, "pwd"].join("\n"),
			],
			{ cwd: process.cwd(), encoding: "utf8" },
		);
		expect(probe.status).toBe(0);
		// The final line, not the whole of stdout. Stubbing `go` and `cargo` neutralises the
		// compilers but not the binaries a previous build already left behind: both toolchain
		// lines invoke their output by relative path (`./agentwall-verify`,
		// `./target/release/agentwall-verify`), so on a machine that has built the verifiers
		// those run for real and print their verdicts. Asserting on all of stdout made this
		// test pass only on a checkout where the verifiers had never been built, which is a
		// property of the machine rather than of the block. Where the shell ENDS is the
		// claim under test, and a stray `cd` still fails it.
		const printed = probe.stdout.trim().split("\n");
		expect(printed[printed.length - 1]).toBe(process.cwd());
	});

	/**
	 * The two verifiers this machine can actually run are run, against a real chain, and their
	 * verdicts are compared with the page's. The Go and Rust lines are parsed above but not
	 * executed here: neither toolchain is present, and claiming a run that did not happen is
	 * the exact failure this suite exists to prevent. tests/conformance drives all four.
	 */
	it("the bundled and python commands it prints reproduce the verdict it shows", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const app = await aggregator(writeSources([{ id: "build-01", auditPath: a.auditPath }]));
		const host = (await app.inject({ method: "GET", url: "/api/evidence/fleet/host/build-01" })).json();
		const chained = host.layers.find((l: { name: string }) => l.name === "chained");
		expect(chained.cliVerdict).toBe("PASS");

		const bundled = spawnSync("bash", ["-c", `${host.reproduce.bundled} --json`], {
			cwd: process.cwd(),
			encoding: "utf8",
		});
		expect(bundled.error).toBeUndefined();
		const parsed = JSON.parse(bundled.stdout) as { layers: { name: string; ok: boolean }[] };
		expect(parsed.layers.find((l) => l.name === "chained")?.ok).toBe(true);
		// And the divergence the host page documents is real rather than theoretical: this host
		// reads `verified` while the command it prints exits 1, because the anchored layer fails
		// for want of an anchor. If the page hid that, a reviewer running the command would find
		// a nonzero exit the console gave them no reason to expect.
		expect(bundled.status).toBe(1);
		expect(parsed.layers.find((l) => l.name === "anchored")?.ok).toBe(false);
		expect(host.state).toBe("verified");

		// Python is in the base image; the verifier has no dependencies by design, so there is
		// no install step to skip and nothing to mock. It runs and answers.
		const python = spawnSync("bash", ["-c", `${host.reproduce.python} --json`], {
			cwd: process.cwd(),
			encoding: "utf8",
		});
		expect(python.error).toBeUndefined();
		expect(() => JSON.parse(python.stdout)).not.toThrow();
	});

	/**
	 * The writer's lock file must not be mistaken for a rotated segment, in any implementation.
	 *
	 * The durable file sink writes `<audit>.lock` beside the chain and holds it for the life of
	 * the writer, so it is present in every live deployment and in any evidence directory copied
	 * wholesale. Segment discovery in the bundled and Go verifiers excluded it; the Python and
	 * Rust ones did not, so both walked the lock file, failed to parse the pid inside it, and
	 * reported the `chained` layer FAIL on a completely healthy chain.
	 *
	 * That is not a cosmetic divergence. This page is the first surface in the product to hand an
	 * auditor the Python command, and unqualified it would have told them a clean host had been
	 * tampered with, using the product's own lock file as the evidence. Both discovery rules now
	 * exclude it and this holds them to it.
	 *
	 * Python is exercised directly because it is in the base image and has no install step. Rust
	 * and Go are not built here, so no claim is made about running them: their exclusions live in
	 * verifier-rs/src/lib.rs and verifier/manifest.go and the conformance harness drives both.
	 */
	it("does not mistake the writer's lock file for a segment, in the implementations it can run", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		writeFileSync(`${a.auditPath}.lock`, `${process.pid}\n`);

		const run = (command: string): { ok: boolean; problems: string[] } => {
			const out = spawnSync("bash", ["-c", command], { cwd: process.cwd(), encoding: "utf8" });
			expect(out.error).toBeUndefined();
			return (JSON.parse(out.stdout) as { layers: { name: string; ok: boolean; problems: string[] }[] }).layers.find(
				(l) => l.name === "chained",
			) as { ok: boolean; problems: string[] };
		};

		const bundled = run(`node dist/cli.js verify --audit ${a.auditPath} --json`);
		const python = run(`python3 verifier-py/agentwall-verify-py --audit ${a.auditPath} --json`);
		expect(bundled.ok).toBe(true);
		expect(python.ok).toBe(true);
		expect(python.problems.join(" ")).not.toContain(".lock");
	});

	it("ships an example sources file that the real loader accepts", async () => {
		// A shipped example that the shipped parser rejects is a startup failure handed to
		// whoever followed it. Parsed with the production loader, not with a YAML reader.
		const sources = loadFleetEvidenceSources(join(process.cwd(), "examples", "fleet-evidence.yaml"));
		expect(sources.hosts.map((h) => h.id)).toEqual(["build-01", "support-01", "edge-07"]);
		expect(sources.staleAfterSeconds).toBeGreaterThan(0);
		// Relative entries resolved against the example itself rather than the working directory.
		expect(sources.hosts[0].auditPath).toBe(join(process.cwd(), "examples", "hosts", "build-01", "audit.jsonl"));
	});
});

describe("fleet evidence, read only and behind the operator token", () => {
	it("answers 405 to every mutating method and leaves every chain byte identical", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const b = await writeHostChain(TRAFFIC_B);
		const app = await aggregator(
			writeSources([
				{ id: "build-01", auditPath: a.auditPath },
				{ id: "support-01", auditPath: b.auditPath },
			]),
		);
		const before = [readFileSync(a.auditPath, "utf8"), readFileSync(b.auditPath, "utf8")];

		for (const method of ["POST", "PUT", "PATCH", "DELETE"] as const) {
			for (const url of [
				"/evidence/fleet",
				"/evidence/fleet/host/build-01",
				"/api/evidence/fleet",
				"/api/evidence/fleet/host/build-01",
			]) {
				const res = await app.inject({ method, url, payload: { decision: "allow" } });
				expect(res.statusCode).toBe(405);
				expect(res.json().error).toMatch(/read only/i);
			}
		}
		// Not merely status codes: the evidence is byte identical after every refusal.
		expect([readFileSync(a.auditPath, "utf8"), readFileSync(b.auditPath, "utf8")]).toEqual(before);
	});

	it("401s without a credential, on the operator token scheme and no second one", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const saved = process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
		delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
		try {
			const app = await aggregator(writeSources([{ id: "build-01", auditPath: a.auditPath }]));
			for (const url of ["/evidence/fleet", "/api/evidence/fleet", "/evidence/fleet/host/build-01"]) {
				expect((await app.inject({ method: "GET", url })).statusCode).toBe(401);
			}
		} finally {
			if (saved === undefined) delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
			else process.env.AGENTWALL_ALLOW_LOOPBACK_DEV = saved;
		}
	});

	it("says so, rather than 404ing, when no sources file is configured", async () => {
		const app = await aggregator(undefined);
		const html = await app.inject({ method: "GET", url: "/evidence/fleet" });
		expect(html.statusCode).toBe(503);
		expect(html.body).toContain("AGENTWALL_FLEET_EVIDENCE");
		const api = await app.inject({ method: "GET", url: "/api/evidence/fleet" });
		expect(api.statusCode).toBe(503);
		expect(api.json().error).toMatch(/no fleet evidence sources/i);
	});

	it("reports a host id nobody declared as absent from the sources, not as a broken host", async () => {
		const a = await writeHostChain(TRAFFIC_A);
		const app = await aggregator(writeSources([{ id: "build-01", auditPath: a.auditPath }]));
		const api = await app.inject({ method: "GET", url: "/api/evidence/fleet/host/build-02" });
		expect(api.statusCode).toBe(404);
		const html = await app.inject({ method: "GET", url: "/evidence/fleet/host/build-02" });
		expect(html.statusCode).toBe(404);
		expect(html.body).toContain("reads exactly where it is told to look");
	});

	it("escapes agent-supplied markup and operator-supplied labels rather than rendering them", async () => {
		const auditPath = join(tmp(), "audit.jsonl");
		process.env.AGENTWALL_AUDIT_FILE = auditPath;
		resetAuditChain();
		const { app: host } = await buildServer(config);
		try {
			// A record carries strings the audited agent chose. An evidence viewer that executes
			// what it is reviewing is the last place that should happen.
			const res = await host.inject({
				method: "POST",
				url: "/evaluate",
				payload: {
					agentId: `agent-<img src=x onerror=alert(1)>`,
					sessionId: "sess-x",
					plane: "tool",
					action: `tool.call<script>alert(2)</script>`,
					payload: { tool: "x" },
				},
			});
			expect(res.statusCode).toBe(200);
		} finally {
			await host.close();
			resetAuditChain();
		}

		const app = await aggregator(writeSources([{ id: "hostile-01", label: `Box <script>alert(3)</script>`, auditPath }]));
		const index = await app.inject({ method: "GET", url: "/evidence/fleet" });
		expect(index.body).not.toContain("<script>alert");
		expect(index.body).toContain("&lt;script&gt;alert(3)&lt;/script&gt;");
		const page = await app.inject({ method: "GET", url: "/evidence/fleet/host/hostile-01" });
		expect(page.body).not.toContain("<img src=x");
		expect(page.body).toContain("&lt;img src=x onerror=alert(1)&gt;");
	});
});

/**
 * The coverage counters, over records the production code actually produced.
 *
 * The counters read named metadata keys, and the one way they can be wrong while every other
 * test stays green is a key name that drifts from what the writers emit. Two spellings exist
 * and both are exercised here from real production output rather than from a literal:
 *
 *   - the PREFIXED one, from a real client speaking HTTP to a real forward proxy, which folds
 *     a request pass and a response pass into one record and so namespaces the content keys;
 *   - the UNPREFIXED one, from `decideEgress` directly, which is exactly what the TLS
 *     interception path copies onto its records verbatim because it files one record per inner
 *     exchange and never folds two passes together.
 *
 * A reader that knew only the prefixed spelling would report every intercepted body as carrying
 * no findings, which inverts the meaning of the coverage section: interception is the one mode
 * in which an https body IS decrypted and scanned.
 *
 * What the first case assembles is the audit metadata AROUND the proxy's content keys,
 * mirroring `src/index.ts`'s recordEgress, because that function lives inside a `main()`
 * bootstrap with no export and starting the whole process here would drag in config loading and
 * a listening admin port for no additional signal. The chain it lands in is the production one:
 * the production `emit()`, through the production file sink, into a real file the aggregator
 * then reads back.
 */
describe("fleet evidence, coverage counted from real proxy output", () => {
	/** AWS's own documentation key. Synthetic, allowlisted in .gitleaks.toml, detected as `aws-access-key`. */
	const FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
	/** Both match on the destination hostname, and the upstream here is necessarily loopback. */
	const HOST_RULES = new Set(["net:block-ssrf-private", "net:block-metadata-endpoint"]);

	let upstream: HttpServer;
	let upstreamPort = 0;
	let proxy: NetServer;
	let proxyPort = 0;
	let engine: PolicyEngine;
	let waiters: Array<(record: ProxyRecord) => void> = [];

	beforeAll(async () => {
		upstream = createServer((_req: IncomingMessage, res: ServerResponse) =>
			res.writeHead(200, { "content-type": "text/plain" }).end("ok\n"),
		);
		await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
		upstreamPort = (upstream.address() as AddressInfo).port;

		proxy = createForwardProxy({
			port: 0,
			host: "127.0.0.1",
			decide: (event) => {
				const verdict = decideEgress(
					{
						host: event.host,
						port: event.port,
						scheme: event.scheme,
						method: event.method,
						comm: event.client.comm,
						pid: event.client.pid,
						path: event.path,
						headers: event.headers,
						body: event.body,
					},
					"guarded",
					engine,
				);
				// The same narrowing src/index.ts performs, reproduced rather than imported,
				// because the boot path is not what is under test.
				return {
					decision: verdict.decision === "allow" ? "allow" : "deny",
					reasons: verdict.reasons,
					matchedRules: verdict.matchedRules,
					riskLevel: verdict.riskLevel,
					metadata: verdict.metadata,
				};
			},
			record: (record) => waiters.shift()?.(record),
			onError: () => {},
		});
		await new Promise<void>((resolve) => proxy.once("listening", resolve));
		proxyPort = (proxy.address() as AddressInfo).port;
	});

	afterAll(async () => {
		await new Promise<void>((resolve) => proxy.close(() => resolve()));
		await new Promise<void>((resolve) => upstream.close(() => resolve()));
	});

	beforeEach(() => {
		engine = new PolicyEngine(builtinRules.filter((rule) => !HOST_RULES.has(rule.id)));
		setEgressPolicy({ hosts: ["127.0.0.1"], ports: [upstreamPort] });
		waiters = [];
	});

	/** One plaintext POST through the real proxy, resolved on the record the proxy files. */
	function proxied(body: string): Promise<ProxyRecord> {
		const filed = new Promise<ProxyRecord>((resolve) => waiters.push(resolve));
		return new Promise<void>((resolve, reject) => {
			const req = httpRequest(
				{
					host: "127.0.0.1",
					port: proxyPort,
					method: "POST",
					path: `http://127.0.0.1:${upstreamPort}/upload`,
					headers: { "content-type": "text/plain", "content-length": String(Buffer.byteLength(body)) },
				},
				(res) => {
					res.resume();
					res.on("end", () => resolve());
				},
			);
			req.on("error", reject);
			req.end(body);
		}).then(() => filed);
	}

	it("reads a real forward-proxy record's visibility and secret classes, and moves the counters", async () => {
		const record = await proxied(`the deploy key is ${FAKE_AWS_KEY}\n`);
		// The shipped scanner read a real body and named a real class. Nothing here invented it,
		// and the prefix is the shipped proxy's own.
		expect(record.bodyVisibility).toBe("plaintext");
		expect(record.metadata?.requestContentSecretTypes).toContain("aws-access-key");

		const auditPath = join(tmp(), "audit.jsonl");
		process.env.AGENTWALL_AUDIT_FILE = auditPath;
		resetAuditChain();
		const { app: hostApp } = await buildServer(config);
		try {
			const matchedRules = [...record.matchedRules];
			emit(
				{
					agentId: "proxy-agent",
					plane: "network",
					action: `egress:${record.scheme}`,
					metadata: {
						host: record.host,
						port: String(record.port),
						scheme: record.scheme,
						enforcementMode: "monitor",
						transportMode: "forward",
						bodyVisibility: record.bodyVisibility,
						...(record.metadata ?? {}),
						agentLabel: "Proxy agent",
						agentMatchedOn: "credential",
						agentDeclared: "true",
						egressAllowlistSource: "agent:proxy-agent",
					},
					payload: {},
				},
				{
					decision: record.decision,
					riskLevel: record.riskLevel ?? "low",
					matchedRules,
					reasons: [...record.reasons],
					requiresApproval: false,
					highRiskFlow: false,
					detections: detectionsForRules(matchedRules),
				},
			);
		} finally {
			await hostApp.close();
			resetAuditChain();
		}

		const app = await aggregator(writeSources([{ id: "proxy-01", auditPath }]));
		const host = (await app.inject({ method: "GET", url: "/api/evidence/fleet/host/proxy-01" })).json();

		// The identity claim and what it rests on, both read back off the record.
		const agent = host.agents.find((x: { agentId: string }) => x.agentId === "proxy-agent");
		expect(agent.matchedOn).toEqual(["credential"]);
		expect(agent.declared).toBe(true);
		expect(agent.allowlistSources).toEqual(["agent:proxy-agent"]);
		expect(agent.destinations[0].host).toBe("127.0.0.1");
		// Credential material seen in flight, named by class and never by value.
		expect(agent.secretTypes).toContain("aws-access-key");
		expect(agent.monitorRecords).toBe(1);

		expect(host.coverage.find((g: { id: string }) => g.id === "no-redaction-in-flight").observed).toBe(1);
		expect(host.coverage.find((g: { id: string }) => g.id === "monitor-mode").observed).toBe(1);
		// A gap this connection did not fall into now reads zero rather than unmeasured, because
		// there is finally a population to count against.
		expect(host.coverage.find((g: { id: string }) => g.id === "https-body-unread").observed).toBe(0);

		const page = await app.inject({ method: "GET", url: "/evidence/fleet/host/proxy-01" });
		expect(page.body).toContain("aws-access-key");
		expect(page.body).toContain("monitor mode");
		// The class is on the page. The value the scan matched never is.
		expect(page.body).not.toContain(FAKE_AWS_KEY);
	});

	it("reads the unprefixed spelling the interception path writes, so a scanned https body is not reported clean", async () => {
		// The metadata an intercepted record carries, taken from the production decision function
		// rather than written out here. `tls-intercept.ts` files one record per inner exchange and
		// copies `verdict.metadata` onto it verbatim, so these ARE the keys on such a record: no
		// direction prefix is ever applied on that path.
		const verdict = decideEgress(
			{
				host: "127.0.0.1",
				port: upstreamPort,
				scheme: "https",
				method: "POST",
				path: "/upload",
				headers: { "content-type": "text/plain" },
				body: {
					direction: "request",
					text: `the deploy key is ${FAKE_AWS_KEY}\n`,
					truncated: true,
					bytes: 256 * 1024,
				},
			},
			"guarded",
			engine,
		);
		expect(verdict.metadata?.contentSecretTypes).toContain("aws-access-key");
		expect(verdict.metadata?.contentTruncated).toBe("true");
		// The prefixed spelling is absent, which is exactly why the reader has to know both.
		expect(verdict.metadata?.requestContentSecretTypes).toBeUndefined();

		const auditPath = join(tmp(), "audit.jsonl");
		process.env.AGENTWALL_AUDIT_FILE = auditPath;
		resetAuditChain();
		const { app: hostApp } = await buildServer(config);
		try {
			emit(
				{
					agentId: "intercepted-agent",
					plane: "network",
					action: "egress:https",
					metadata: {
						host: "127.0.0.1",
						port: String(upstreamPort),
						scheme: "https",
						enforcementMode: "guarded",
						transportMode: "forward",
						// What an intercepted body reads as: TLS was terminated and the whole body
						// was decrypted, so this is the mode with the MOST visibility.
						bodyVisibility: "intercepted",
						...(verdict.metadata ?? {}),
					},
					payload: {},
				},
				{
					decision: "deny",
					riskLevel: "high",
					matchedRules: [...verdict.matchedRules],
					reasons: [...verdict.reasons],
					requiresApproval: false,
					highRiskFlow: true,
					detections: detectionsForRules([...verdict.matchedRules]),
				},
			);
		} finally {
			await hostApp.close();
			resetAuditChain();
		}

		const records = collectEvidence({ auditPath }).records;
		const intercepted = records.find((r) => r.egress?.bodyVisibility === "intercepted");
		expect(intercepted).toBeDefined();
		// Without the unprefixed spelling both of these would be empty and the coverage row would
		// report a decrypted, scanned, capped body as carrying nothing.
		expect(intercepted?.egress?.secretTypes).toContain("aws-access-key");
		expect(intercepted?.egress?.contentTruncated).toBe(true);

		const gaps = coverageFor(records);
		expect(gaps.find((g) => g.id === "inspection-cap")?.observed).toBe(1);
		expect(gaps.find((g) => g.id === "no-redaction-in-flight")?.observed).toBe(1);
		// An intercepted body was read, so it is not an unread https body. The two rows must not
		// double count the same record.
		expect(gaps.find((g) => g.id === "https-body-unread")?.observed).toBe(0);
	});
});
