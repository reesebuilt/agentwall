import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { cpSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import type { FastifyInstance } from "fastify";
import { resetAuditChain } from "../src/audit/logger";
import { runAnchorPass, runVerify } from "../src/audit/anchor-service";
import type { HttpPoster } from "../src/audit/anchor";
import type { AgentwallConfig } from "../src/config";
import { buildServer } from "../src/server";
import { buildEvidenceReport } from "../src/evidence/scorecard";
import { bitcoinProof, otsContainer, pendingProof } from "./ots-fixtures";

/**
 * The operator evidence viewer.
 *
 * Every chain under test here is written by the production writers through the running server,
 * not by a hand-assembled fixture. That distinction is the whole point of the suite: a viewer
 * asserted against strings some test wrote is a test of the test, and it would pass while the
 * page misread anything the real file sink actually produces. So each case drives real requests
 * through /evaluate, lets the file sink append, and then reads the view over that file.
 *
 * Three properties carry the feature and each has a case below:
 *
 *   1. A real chain renders, with the decisions and detections attributed to the right session.
 *   2. A single altered byte is visibly flagged, and restoring it clears the flag.
 *   3. A pending anchor renders as pending. Never as verified, whatever the record claims.
 */

const dirs: string[] = [];
function tmp(): string {
	const d = mkdtempSync(join(tmpdir(), "aw-evidence-"));
	dirs.push(d);
	return d;
}

const CORPUS = join(__dirname, "..", "verifier", "testdata", "corpus");

/** Copy a conformance corpus case out of git so nothing under test can alter what it checks. */
function corpusCase(name: string): string {
	const dir = tmp();
	cpSync(join(CORPUS, name), dir, { recursive: true });
	return dir;
}

const config: AgentwallConfig = {
	port: 0,
	host: "127.0.0.1",
	logLevel: "silent",
	dashboard: {},
	approval: { mode: "auto", timeoutMs: 5_000, backend: "memory" },
	// allow, so the recorded decisions are the ones the rules actually reached rather than a
	// wall of identical defaults. A scorecard that cannot tell allow from deny shows nothing.
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
	watchdog: {
		enabled: true,
		staleAfterMs: 15_000,
		timeoutMs: 30_000,
		killSwitchMode: "deny_all",
	},
};

/** The requests every case records. Two sessions, so the chain interleaves them as a host does. */
const TRAFFIC: { sessionId: string; agentId: string; plane: string; action: string; payload: Record<string, unknown>; flow?: unknown }[] = [
	{ sessionId: "sess-a", agentId: "researcher-1", plane: "tool", action: "tool.call", payload: { tool: "http.get", url: "https://api.github.com/meta" } },
	{ sessionId: "sess-b", agentId: "builder-2", plane: "tool", action: "shell.exec", payload: { command: "npm run build" } },
	{ sessionId: "sess-a", agentId: "researcher-1", plane: "network", action: "network.egress", payload: { url: "http://169.254.169.254/latest/meta-data/" } },
	{ sessionId: "sess-b", agentId: "builder-2", plane: "network", action: "network.egress", payload: { url: "https://api.github.com/repos/repsecure/agentwall" } },
	{
		sessionId: "sess-a",
		agentId: "researcher-1",
		plane: "content",
		action: "content.egress",
		payload: { text: "the key is AKIAIOSFODNN7EXAMPLE" },
		flow: { direction: "egress", labels: ["secret_material"] },
	},
	{ sessionId: "sess-a", agentId: "researcher-1", plane: "network", action: "network.egress", payload: { url: "http://10.0.0.7:8080/admin" } },
];

interface Harness {
	app: FastifyInstance;
	auditPath: string;
	dir: string;
}

let savedAuditPath: string | undefined;
/**
 * Every server this suite builds, so each is closed afterwards.
 *
 * buildServer installs process-level handlers for the emergency stop, so a suite that leaves
 * a dozen instances open trips Node's listener ceiling and the warning it prints looks like a
 * leak in the product rather than housekeeping in a test.
 */
const apps: FastifyInstance[] = [];

/** Boot a server whose chain lands in a fresh directory, then record real decisions into it. */
async function harness(): Promise<Harness> {
	const dir = tmp();
	const auditPath = join(dir, "audit.jsonl");
	process.env.AGENTWALL_AUDIT_FILE = auditPath;
	// Sinks are module state, so a suite that builds several servers would otherwise stack a
	// second file sink against the first server's path and append every record twice.
	resetAuditChain();

	const { app } = await buildServer(config);
	apps.push(app);
	for (const t of TRAFFIC) {
		const res = await app.inject({ method: "POST", url: "/evaluate", payload: t });
		expect(res.statusCode).toBe(200);
	}
	return { app, auditPath, dir };
}

beforeEach(() => {
	savedAuditPath = process.env.AGENTWALL_AUDIT_FILE;
});

afterEach(async () => {
	if (savedAuditPath === undefined) delete process.env.AGENTWALL_AUDIT_FILE;
	else process.env.AGENTWALL_AUDIT_FILE = savedAuditPath;
	resetAuditChain();
	while (apps.length) await (apps.pop() as FastifyInstance).close();
	while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

describe("evidence viewer, over a chain a real run produced", () => {
	it("renders the layer verdicts, the file inventory, and one card per session", async () => {
		const { app, auditPath } = await harness();

		const api = await app.inject({ method: "GET", url: "/api/evidence" });
		expect(api.statusCode).toBe(200);
		const report = api.json();

		// The verdict on the page is the verifier's own, not a second opinion.
		expect(report.layers.map((l: { name: string }) => l.name)).toEqual(["chained", "linked", "anchored"]);
		const cli = runVerify({ auditPath });
		for (const layer of report.layers) {
			const own = cli.layers.find((l) => l.name === layer.name);
			expect(layer.cliVerdict).toBe(own?.ok ? "PASS" : "FAIL");
			expect(layer.detail).toBe(own?.detail);
		}
		expect(report.layers[0].state).toBe("pass");
		expect(report.totals.records).toBe(TRAFFIC.length);
		expect(report.totals.faulty).toBe(0);

		// Attribution: each session's own decisions, not the file's.
		const a = report.sessions.find((s: { sessionId: string }) => s.sessionId === "sess-a");
		const b = report.sessions.find((s: { sessionId: string }) => s.sessionId === "sess-b");
		expect(a.records).toBe(4);
		expect(b.records).toBe(2);
		expect(a.agentIds).toEqual(["researcher-1"]);
		const denied = a.decisions.find((d: { decision: string }) => d.decision === "deny");
		expect(denied.count).toBeGreaterThanOrEqual(2);
		expect(a.detections.map((d: { id: string }) => d.id)).toContain("det.net.metadata.access");
		expect(b.detections).toEqual([]);
		expect(a.matchedRules.map((r: { ruleId: string }) => r.ruleId)).toContain("net:block-metadata-endpoint");

		// A session card must not inherit another session's records or its verdict.
		expect(b.intact).toBe(2);
		expect(b.layers.find((l: { name: string }) => l.name === "chained").state).toBe("pass");

		const html = await app.inject({ method: "GET", url: "/evidence" });
		expect(html.statusCode).toBe(200);
		expect(html.headers["content-type"]).toContain("text/html");
		expect(html.body).toContain("sess-a");
		expect(html.body).toContain("Read only");
		// A page that cannot run code cannot mutate anything. The absence of a script tag is
		// the mechanism, so it is asserted rather than assumed.
		expect(html.body).not.toContain("<script");

		const page = await app.inject({ method: "GET", url: "/evidence/session/sess-a" });
		expect(page.statusCode).toBe(200);
		expect(page.body).toContain("det.net.metadata.access");
		expect(page.body).toContain("network.egress");
		// The offline command is on the page, because the page must not be the root of trust.
		expect(page.body).toContain(`verify --audit ${auditPath}`);
		expect(page.body).not.toContain("<script");
	});

	it("shows the offline verify command for the audit file it is actually reading", async () => {
		const { app, auditPath } = await harness();
		const report = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		expect(report.offline.bundled).toBe(`node dist/cli.js verify --audit ${auditPath}`);
		expect(report.offline.independent).toContain(`--audit ${auditPath}`);
		// The pin matters: an unpinned checkpoint signature verifies against the key the
		// checkpoint carries, so the page has to name the stronger command as well.
		expect(report.offline.pinned).toContain("--pubkey-file");

		const scoped = (await app.inject({ method: "GET", url: "/api/evidence/session/sess-a" })).json();
		// Selects by member rather than by text, so the command does not depend on the order
		// the writer happened to serialize keys in.
		expect(scoped.offline).toContain(`select(.sessionId == "sess-a")`);
	});

	it("refuses every mutating method against the viewer", async () => {
		const { app, auditPath } = await harness();
		const before = readFileSync(auditPath, "utf8");

		for (const method of ["POST", "PUT", "PATCH", "DELETE"] as const) {
			for (const url of ["/evidence", "/evidence/session/sess-a", "/api/evidence", "/api/evidence/session/sess-a"]) {
				const res = await app.inject({ method, url, payload: { decision: "allow" } });
				expect(res.statusCode).toBe(405);
				expect(res.json().error).toMatch(/read only/i);
			}
		}
		// The refusals are not merely status codes: the evidence is byte identical after them.
		expect(readFileSync(auditPath, "utf8")).toBe(before);
	});

	it("401s without a credential, using the operator token scheme and no second one", async () => {
		await harness();
		const saved = process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
		delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
		try {
			// A fresh instance, because the auth config is read when the guard is registered.
			const { app: guarded } = await buildServer(config);
			apps.push(guarded);
			for (const url of ["/evidence", "/api/evidence", "/evidence/session/sess-a"]) {
				expect((await guarded.inject({ method: "GET", url })).statusCode).toBe(401);
			}
		} finally {
			if (saved === undefined) delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
			else process.env.AGENTWALL_ALLOW_LOOPBACK_DEV = saved;
		}
	});

	it("says so, rather than 404ing, when no durable audit file is configured", async () => {
		delete process.env.AGENTWALL_AUDIT_FILE;
		resetAuditChain();
		const { app } = await buildServer(config);
		apps.push(app);
		const html = await app.inject({ method: "GET", url: "/evidence" });
		expect(html.statusCode).toBe(503);
		expect(html.body).toContain("AGENTWALL_AUDIT_FILE");
		const api = await app.inject({ method: "GET", url: "/api/evidence" });
		expect(api.statusCode).toBe(503);
		expect(api.json().error).toMatch(/no durable audit evidence/i);
	});

	it("reports a session id that no record carries as absent from the chain", async () => {
		const { app } = await harness();
		const res = await app.inject({ method: "GET", url: "/api/evidence/session/sess-a-typo" });
		expect(res.statusCode).toBe(404);
		const html = await app.inject({ method: "GET", url: "/evidence/session/sess-a-typo" });
		expect(html.statusCode).toBe(404);
		expect(html.body).toContain("never recorded");
	});

	it("escapes agent-supplied markup rather than rendering it", async () => {
		const { app } = await harness();
		// A record carries strings the audited agent chose: a URL, a tool argument, a session id
		// it named itself. An evidence viewer that executes what it is reviewing is the last
		// place that should happen, and the reviewer is an operator with a live session.
		const hostileSession = `sess-"><script>alert(1)</script>`;
		const res = await app.inject({
			method: "POST",
			url: "/evaluate",
			payload: {
				agentId: `agent-<img src=x onerror=alert(1)>`,
				sessionId: hostileSession,
				plane: "tool",
				action: `tool.call<script>alert(2)</script>`,
				payload: { tool: "x" },
			},
		});
		expect(res.statusCode).toBe(200);

		const index = await app.inject({ method: "GET", url: "/evidence" });
		expect(index.body).not.toContain("<script>alert");
		expect(index.body).not.toContain("<img src=x");
		expect(index.body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
		// The id also lands in a URL, so it is percent-encoded there rather than escaped.
		expect(index.body).toContain(`href="/evidence/session/${encodeURIComponent(hostileSession)}"`);

		const page = await app.inject({ method: "GET", url: `/evidence/session/${encodeURIComponent(hostileSession)}` });
		expect(page.statusCode).toBe(200);
		expect(page.body).not.toContain("<script>alert");
		expect(page.body).not.toContain("<img src=x");
		expect(page.body).toContain("&lt;img src=x onerror=alert(1)&gt;");
	});
});

describe("evidence viewer, tamper detection", () => {
	it("flags a single altered byte, names the record, and clears when it is restored", async () => {
		const { app, auditPath } = await harness();

		const clean = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		expect(clean.layers[0].state).toBe("pass");
		expect(clean.totals.faulty).toBe(0);

		// One byte, in a record the chain already covers. "deny" and "alow" are the same
		// length, so the file size, the record count and the index span are all unchanged and
		// only the hash reveals it. This is the shape a real edit takes.
		const original = readFileSync(auditPath, "utf8");
		const lines = original.split("\n");
		const target = lines.findIndex((l) => l.includes(`"decision":"deny"`));
		expect(target).toBeGreaterThanOrEqual(0);
		lines[target] = lines[target].replace(`"decision":"deny"`, `"decision":"alow"`);
		const tampered = lines.join("\n");
		expect(tampered.length).toBe(original.length);
		writeFileSync(auditPath, tampered);

		const broken = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		const chained = broken.layers.find((l: { name: string }) => l.name === "chained");
		expect(chained.state).toBe("fail");
		expect(chained.cliVerdict).toBe("FAIL");
		expect(chained.problems.join(" ")).toContain("hash mismatch");
		expect(broken.totals.faulty).toBe(1);

		// The break is attributed to the session whose record it is, and to that record's own
		// position, which is the difference between a viewer and a red banner.
		const owner = broken.sessions.find((s: { faulty: unknown[] }) => s.faulty.length > 0);
		expect(owner.faulty[0].chainIndex).toBeGreaterThanOrEqual(0);
		expect(owner.faulty[0].faults).toEqual(["altered"]);
		expect(owner.layers.find((l: { name: string }) => l.name === "chained").state).toBe("fail");

		const html = await app.inject({ method: "GET", url: `/evidence/session/${owner.sessionId}` });
		expect(html.body).toContain("altered");
		expect(html.body).toContain("does not reproduce its own hash");
		expect(html.body).toContain("class=\"broken\"");

		// Restore, and the view goes clean again. A viewer that latches a failure would make
		// the next honest read look tampered.
		writeFileSync(auditPath, original);
		const healed = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		expect(healed.layers[0].state).toBe("pass");
		expect(healed.totals.faulty).toBe(0);
	});

	it("tells a session its ordering is not vouched for when the break is another session's record", async () => {
		const { app, auditPath } = await harness();

		// sess-b's records sit between sess-a's, so breaking a sess-b record leaves every
		// sess-a record reproducing its own hash inside a span whose order is now unproven.
		// A scorecard reporting only "your records are fine" would be true and misleading.
		const lines = readFileSync(auditPath, "utf8").split("\n");
		const target = lines.findIndex((l) => l.includes(`"sessionId":"sess-b"`) && l.includes(`"action":"shell.exec"`));
		expect(target).toBeGreaterThanOrEqual(0);
		lines[target] = lines[target].replace(`"action":"shell.exec"`, `"action":"shell.exeC"`);
		writeFileSync(auditPath, lines.join("\n"));

		const report = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		const a = report.sessions.find((s: { sessionId: string }) => s.sessionId === "sess-a");
		expect(a.faulty).toEqual([]);
		const chained = a.layers.find((l: { name: string }) => l.name === "chained");
		expect(chained.state).toBe("fail");
		expect(chained.problems.join(" ")).toContain("another session");
		expect(chained.problems.join(" ")).toContain("not vouched for");
	});

	it("flags a rewritten sealed segment on the layer that vouched for it", async () => {
		const { app, auditPath } = await harness();
		const dir = join(auditPath, "..");

		// A real rotation: the closed segment moves aside while the writer keeps its chain
		// state, so the live file continues at the next index.
		renameSync(auditPath, join(dir, "audit.jsonl.1"));
		const res = await app.inject({
			method: "POST",
			url: "/evaluate",
			payload: { agentId: "builder-2", sessionId: "sess-b", plane: "tool", action: "tool.call", payload: { tool: "http.get", url: "https://api.github.com/rate_limit" } },
		});
		expect(res.statusCode).toBe(200);
		await runAnchorPass({ auditPath }, () => new Date(), {
			post: async () => ({ status: 200, body: pendingProof("https://calendar.example.com") }),
		} as HttpPoster);

		const sealedOk = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		expect(sealedOk.layers.find((l: { name: string }) => l.name === "linked").state).toBe("pass");
		expect(sealedOk.files.some((f: { role: string }) => f.role === "sealed")).toBe(true);

		// Truncate the sealed segment. Its own per-record chain stays valid; the manifest
		// entry bound to its bytes is what exposes it.
		const segment = join(dir, "audit.jsonl.1");
		const kept = readFileSync(segment, "utf8").split("\n").filter(Boolean).slice(0, 3);
		writeFileSync(segment, kept.join("\n") + "\n");

		const report = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		const linked = report.layers.find((l: { name: string }) => l.name === "linked");
		expect(linked.state).toBe("fail");
		expect(linked.problems.join(" ")).toContain("segment-content-mismatch");
		// Attributed to the sessions that live in that segment, not to every session.
		const affected = report.sessions.filter(
			(s: { layers: { name: string; state: string }[] }) =>
				s.layers.find((l) => l.name === "linked")?.state === "fail",
		);
		expect(affected.length).toBeGreaterThan(0);
	});
});

describe("evidence viewer, anchor state", () => {
	it("renders a submitted anchor as pending, never as verified", async () => {
		const { app, auditPath } = await harness();
		renameSync(auditPath, join(auditPath, "..", "audit.jsonl.1"));
		await app.inject({
			method: "POST",
			url: "/evaluate",
			payload: { agentId: "builder-2", sessionId: "sess-b", plane: "tool", action: "tool.call", payload: { tool: "http.get", url: "https://api.github.com/rate_limit" } },
		});
		await runAnchorPass({ auditPath }, () => new Date(), {
			post: async () => ({ status: 200, body: pendingProof("https://alice.calendar.example.com") }),
		} as HttpPoster);

		const report = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		const anchored = report.layers.find((l: { name: string }) => l.name === "anchored");
		expect(anchored.state).toBe("pending");
		// The verifier passes the layer with a pending anchor. The page shows both, so the
		// reviewer sees a caveat rather than a contradiction.
		expect(anchored.cliVerdict).toBe("PASS");
		expect(anchored.divergence).toMatch(/pending is not proof/);

		expect(report.anchors).toHaveLength(1);
		const receipt = report.anchors[0];
		expect(receipt.state).toBe("pending");
		expect(receipt.pendingAttestations).toBe(1);
		expect(receipt.bitcoinAttestations).toBe(0);
		expect(receipt.overclaimsStatus).toBe(false);

		// The reach is re-derived from disk, so it names the last record the checkpoint
		// actually commits to rather than the segment count the record carries.
		const lastIndex = Math.max(
			...report.sessions.flatMap((s: { lastIndex: number | null }) => (s.lastIndex === null ? [] : [s.lastIndex])),
		);
		expect(receipt.coveredThroughIndex).toBe(lastIndex);

		for (const session of report.sessions) {
			const layer = session.layers.find((l: { name: string }) => l.name === "anchored");
			expect(layer.state).toBe("pending");
			expect(layer.detail).toContain("waiting on a Bitcoin block");
		}

		const html = await app.inject({ method: "GET", url: "/evidence" });
		expect(html.body).toContain(">pending<");
		// The word that must never appear against a pending anchor.
		expect(html.body).not.toMatch(/anchored[\s\S]{0,200}>confirmed</);
	});

	it("renders confirmed only when the proof reaches a Bitcoin attestation", async () => {
		const { app, auditPath } = await harness();
		renameSync(auditPath, join(auditPath, "..", "audit.jsonl.1"));
		await app.inject({
			method: "POST",
			url: "/evaluate",
			payload: { agentId: "builder-2", sessionId: "sess-b", plane: "tool", action: "tool.call", payload: { tool: "http.get", url: "https://api.github.com/rate_limit" } },
		});
		await runAnchorPass({ auditPath }, () => new Date(), {
			post: async () => ({ status: 200, body: bitcoinProof(870_123) }),
		} as HttpPoster);

		const report = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		expect(report.layers.find((l: { name: string }) => l.name === "anchored").state).toBe("pass");
		expect(report.anchors[0].state).toBe("confirmed");
		expect(report.anchors[0].bitcoinHeights).toEqual([870_123]);
	});

	it("derives the reach from the live tail alone when nothing has rotated yet", async () => {
		// The commonest deployment shape: one live file, no rotation, so the checkpoint commits
		// a null manifest head and a live tail. The sealed span contributes nothing, and a reader
		// that only looked at the manifest would report every record as unanchored right after a
		// successful anchor.
		const { app, auditPath } = await harness();
		await runAnchorPass({ auditPath }, () => new Date(), {
			post: async () => ({ status: 200, body: pendingProof("https://alice.calendar.example.com") }),
		} as HttpPoster);

		const report = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		expect(report.anchors[0].segments).toBe(0);
		expect(report.anchors[0].coveredThroughIndex).toBe(TRAFFIC.length - 1);
		expect(report.layers.find((l: { name: string }) => l.name === "anchored").state).toBe("pending");
		for (const session of report.sessions) {
			expect(session.layers.find((l: { name: string }) => l.name === "anchored").state).toBe("pending");
			// Nothing has rotated, so no manifest entry covers these records and the view says so
			// instead of borrowing the file-wide vacuous pass.
			const linked = session.layers.find((l: { name: string }) => l.name === "linked");
			expect(linked.state).toBe("absent");
			expect(linked.detail).toContain("live file");
		}
	});

	it("renders an anchor whose record claims confirmed but whose proof is only pending as pending", () => {
		// Corpus case l1 exists to pin a documented limit: `agentwall verify` counts an anchor
		// as confirmed from the record's own status field and never compares that claim against
		// the attestations inside the proof, so l1 passes with exit 0. This view reads the proof
		// bytes instead. It therefore says LESS than the counter, which is the only direction a
		// viewer over signed evidence is allowed to differ in.
		const dir = corpusCase("l1-confirmed-with-pending-proof");
		const auditPath = join(dir, "audit.jsonl");

		const cli = runVerify({ auditPath });
		expect(cli.layers.find((l) => l.name === "anchored")?.ok).toBe(true);
		expect(cli.confirmed).toBe(1);

		const report = buildEvidenceReport({ auditPath });
		const receipt = report.anchors[0];
		expect(receipt.statusClaimed).toBe("confirmed");
		expect(receipt.bitcoinAttestations).toBe(0);
		expect(receipt.pendingAttestations).toBeGreaterThan(0);
		expect(receipt.state).toBe("pending");
		expect(receipt.overclaimsStatus).toBe(true);
		expect(report.layers.find((l) => l.name === "anchored")?.state).toBe("pending");
	});

	it("does not count a submission that never reached a calendar as pending", async () => {
		const { app, auditPath } = await harness();
		renameSync(auditPath, join(auditPath, "..", "audit.jsonl.1"));
		await app.inject({
			method: "POST",
			url: "/evaluate",
			payload: { agentId: "builder-2", sessionId: "sess-b", plane: "tool", action: "tool.call", payload: { tool: "http.get", url: "https://api.github.com/rate_limit" } },
		});
		await runAnchorPass({ auditPath }, () => new Date(), {
			post: async () => {
				throw new Error("calendar unreachable");
			},
		} as HttpPoster);

		const report = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		expect(report.anchors[0].state).toBe("failed");
		expect(report.anchors[0].pendingAttestations).toBe(0);
		const anchored = report.layers.find((l: { name: string }) => l.name === "anchored");
		expect(anchored.state).toBe("fail");
		for (const session of report.sessions) {
			// No session may read as anchored off the back of a submission that never landed.
			expect(session.layers.find((l: { name: string }) => l.name === "anchored").state).not.toBe("pass");
			expect(session.layers.find((l: { name: string }) => l.name === "anchored").state).not.toBe("pending");
		}
	});

	it("does not claim coverage for records written after the anchor", async () => {
		const { app, auditPath } = await harness();
		renameSync(auditPath, join(auditPath, "..", "audit.jsonl.1"));
		await app.inject({
			method: "POST",
			url: "/evaluate",
			payload: { agentId: "builder-2", sessionId: "sess-b", plane: "tool", action: "tool.call", payload: { tool: "http.get", url: "https://api.github.com/rate_limit" } },
		});
		await runAnchorPass({ auditPath }, () => new Date(), {
			post: async () => ({ status: 200, body: pendingProof("https://alice.calendar.example.com") }),
		} as HttpPoster);

		// A decision recorded after the anchor. Nothing off-box describes it yet, and saying
		// otherwise would be the difference between evidence and a green tick.
		await app.inject({
			method: "POST",
			url: "/evaluate",
			payload: { agentId: "late-3", sessionId: "sess-late", plane: "network", action: "network.egress", payload: { url: "http://10.1.2.3/" } },
		});

		const report = (await app.inject({ method: "GET", url: "/api/evidence" })).json();
		const late = report.sessions.find((s: { sessionId: string }) => s.sessionId === "sess-late");
		const layer = late.layers.find((l: { name: string }) => l.name === "anchored");
		expect(layer.state).toBe("absent");
		expect(layer.detail).toContain("rest on local controls alone");
		expect(report.anchors[0].coveredThroughIndex).toBeLessThan(late.lastIndex);
	});

	it("reports a proof file that is truncated rather than counting it as evidence", () => {
		const dir = corpusCase("b10-proof-truncated");
		const report = buildEvidenceReport({ auditPath: join(dir, "audit.jsonl") });
		expect(report.anchors[0].state).toBe("unproven");
		expect(report.anchors[0].proofProblem).not.toBeNull();
		expect(report.layers.find((l) => l.name === "anchored")?.state).toBe("fail");
	});
});

describe("evidence viewer, records the verifier cannot recompute", () => {
	it("separates a record with no canon marker from one that was altered", () => {
		// Corpus l2 holds records hashed under the pre-marker key order. Both shipped verifiers
		// report them as a mismatch, because a verifier without collation tables cannot rebuild
		// that hash and unverifiable is indistinguishable from edited from the outside. The view
		// keeps the verdict and separates the CAUSE, so an operator with old history is not told
		// somebody tampered with it.
		const dir = corpusCase("l2-legacy-canon-unmarked");
		const auditPath = join(dir, "audit.jsonl");
		expect(runVerify({ auditPath }).layers.find((l) => l.name === "chained")?.ok).toBe(false);

		const report = buildEvidenceReport({ auditPath });
		expect(report.layers.find((l) => l.name === "chained")?.state).toBe("fail");
		const faults = report.sessions.flatMap((s) => s.faulty.flatMap((f) => f.faults));
		expect(faults).toContain("unmarked-canon");
		expect(faults).not.toContain("altered");
	});

	it("surfaces a duplicate member without attributing the record to a session", () => {
		const dir = corpusCase("b12-duplicate-key-shadowed");
		const report = buildEvidenceReport({ auditPath: join(dir, "audit.jsonl") });
		expect(report.layers.find((l) => l.name === "chained")?.state).toBe("fail");
		const unattributed = report.sessions.find((s) => s.sessionId === null);
		// What the record says depends on which parser reads it, so it is shown as a fault and
		// not filed under a session it may not belong to.
		expect(unattributed?.faulty.some((f) => f.faults.includes("dup-key"))).toBe(true);
	});

	it("surfaces a torn tail without condemning the file", () => {
		const dir = corpusCase("b11-torn-tail");
		const report = buildEvidenceReport({ auditPath: join(dir, "audit.jsonl") });
		const torn = report.sessions.flatMap((s) => s.faulty).filter((f) => f.faults.includes("torn-tail"));
		expect(torn.length).toBeGreaterThan(0);
		// A hard kill mid-append is not an edit, so the chained layer must not read as a break.
		expect(report.layers.find((l) => l.name === "chained")?.state).toBe("pass");
	});
});

describe("evidence viewer, anchor reach derivation", () => {
	it("names the last record a two-pass anchor log commits to", () => {
		const dir = corpusCase("g7-two-anchor-passes");
		const report = buildEvidenceReport({ auditPath: join(dir, "audit.jsonl") });
		expect(report.anchors.length).toBeGreaterThan(1);
		const highest = Math.max(...report.files.flatMap((f) => (f.lastIndex === null ? [] : [f.lastIndex])));
		for (const receipt of report.anchors) {
			expect(receipt.coveredThroughIndex).not.toBeNull();
			expect(receipt.coveredThroughIndex as number).toBeLessThanOrEqual(highest);
		}
		// Later passes reach at least as far as earlier ones: the chain only grows.
		const reaches = report.anchors.map((a) => a.coveredThroughIndex as number);
		expect([...reaches].sort((x, y) => x - y)).toEqual(reaches);
	});

	it("reports an unknown reach when a rewritten live tail no longer reproduces the composite", () => {
		const dir = corpusCase("b16-live-tail-rewritten-after-checkpoint");
		const report = buildEvidenceReport({ auditPath: join(dir, "audit.jsonl") });
		expect(report.anchors.some((a) => a.coveredThroughIndex === null)).toBe(true);
		// Unknown reach must never render as coverage.
		for (const session of report.sessions) {
			expect(session.layers.find((l) => l.name === "anchored")?.state).not.toBe("pass");
		}
	});

	it("reads a proof container the same way as bare operation bytes", async () => {
		const { app, auditPath } = await harness();
		renameSync(auditPath, join(auditPath, "..", "audit.jsonl.1"));
		await app.inject({
			method: "POST",
			url: "/evaluate",
			payload: { agentId: "builder-2", sessionId: "sess-b", plane: "tool", action: "tool.call", payload: { tool: "http.get", url: "https://api.github.com/rate_limit" } },
		});
		let submitted: Buffer | null = null;
		await runAnchorPass({ auditPath }, () => new Date(), {
			post: async (_url: string, body: Buffer | string) => {
				submitted = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
				return { status: 200, body: pendingProof("https://calendar.example.com") };
			},
		} as HttpPoster);
		expect(submitted).not.toBeNull();

		// Replace the stored proof with the full-file container form of the same operations. A
		// reader that only understands the bare form would report the evidence as corrupt.
		const report = buildEvidenceReport({ auditPath });
		const proofPath = report.anchors[0].proofPath as string;
		writeFileSync(
			proofPath,
			otsContainer(submitted as unknown as Buffer, pendingProof("https://calendar.example.com")),
		);
		const again = buildEvidenceReport({ auditPath });
		expect(again.anchors[0].proofProblem).toBeNull();
		expect(again.anchors[0].state).toBe("pending");
	});
});
