import { afterEach, describe, expect, it } from "@jest/globals";
import { get as httpGet } from "http";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  CANARY_PATH_PREFIX,
  CaptureReport,
  Corroboration,
  MatchedRecord,
  CanaryHit,
  captureExitCode,
  declaredTierOf,
  evaluate,
  findChainRecords,
  formatCaptureReport,
  mintCanaryToken,
  proxyExemptionFor,
  startCanary,
  runVerifyCapture,
  validateCaptureCommandArgv,
  EXIT_CAPTURED,
  EXIT_INCOMPLETE,
  EXIT_NOT_CAPTURED,
} from "../src/capture/verify";
import type { Canary } from "../src/capture/verify";

/**
 * The parts of verify-capture that can be judged without a proxy: the canary's own contract,
 * the chain reader, and the decision table.
 *
 * What is deliberately NOT here: any claim that an agent is captured. That question is answered
 * in verify-capture.integration.test.ts against a real proxy carrying real traffic, because the
 * failure this command exists to catch is precisely the one a unit test cannot see. A suite that
 * asserted the assertion logic and stopped would be the fourth control in this repository to
 * ship green and non-functional.
 */

/**
 * Local stand-in for `Promise.withResolvers`.
 *
 * The project compiles against `lib: ["ES2022"]` (tsconfig.json), which predates the real
 * thing, and widening the project's lib target to suit one test file is not this change's
 * business. Same shape, same linear control flow, no executor callbacks in the tests below.
 */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (err: unknown) => void } {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function fetchText(url: string): Promise<{ status: number; body: string }> {
  const done = deferred<{ status: number; body: string }>();
  httpGet(url, (res) => {
    let body = "";
    res.on("data", (chunk) => (body += String(chunk)));
    res.on("end", () => done.resolve({ status: res.statusCode ?? 0, body }));
  }).on("error", done.reject);
  return done.promise;
}

let open: Canary | null = null;
afterEach(async () => {
  await open?.close();
  open = null;
});

describe("the canary token", () => {
  it("is 256 bits of hex, so it cannot be guessed or collided with by accident", () => {
    const token = mintCanaryToken();
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it("never repeats", () => {
    const minted = new Set<string>();
    for (let i = 0; i < 512; i += 1) minted.add(mintCanaryToken());
    expect(minted.size).toBe(512);
  });
});

describe("the canary listener", () => {
  it("serves the token exactly once and refuses every later presentation", async () => {
    const token = mintCanaryToken();
    open = await startCanary("127.0.0.1", token);

    const first = await fetchText(open.url);
    const second = await fetchText(open.url);
    const third = await fetchText(open.url);

    expect(first.status).toBe(200);
    expect(second.status).toBe(410);
    expect(third.status).toBe(410);

    // All three are recorded. Closing on the first hit, or dropping the later ones, would hide
    // the case this command exists to catch: an agent that is captured AND also goes around.
    expect(open.hits).toHaveLength(3);
    expect(open.hits.map((hit) => hit.replay)).toEqual([false, true, true]);
    expect(open.hits.every((hit) => hit.token)).toBe(true);
  });

  it("records a request for a different path as unrelated rather than as the agent", async () => {
    const token = mintCanaryToken();
    open = await startCanary("127.0.0.1", token);

    const wrong = await fetchText(`${open.url.slice(0, open.url.lastIndexOf("/"))}/${"0".repeat(64)}`);

    expect(wrong.status).toBe(404);
    expect(open.hits).toHaveLength(1);
    expect(open.hits[0].token).toBe(false);
  });

  it("binds an ephemeral port and puts the token in the path where the proxy can read it", async () => {
    const token = mintCanaryToken();
    open = await startCanary("127.0.0.1", token);

    expect(open.port).toBeGreaterThan(0);
    expect(open.url).toBe(`http://127.0.0.1:${open.port}${CANARY_PATH_PREFIX}${token}`);
  });

  it("resolves on the first token hit and does not re-fire for a replay", async () => {
    const token = mintCanaryToken();
    open = await startCanary("127.0.0.1", token);
    const canary = open;

    // Every settlement the promise produces, awaited directly rather than slept on: the code
    // under test already exposes the signal, so there is nothing to wait a fixed duration for.
    const settlements: CanaryHit[] = [];
    void canary.firstTokenHit.then((observed) => settlements.push(observed));

    await fetchText(canary.url);
    await fetchText(canary.url);
    const settled = await canary.firstTokenHit;

    expect(settled.replay).toBe(false);
    expect(settlements).toHaveLength(1);
  });
});

describe("reading the chain", () => {
  const write = (lines: string[]): string => {
    const dir = mkdtempSync(join(tmpdir(), "agentwall-capture-chain-"));
    const path = join(dir, "audit.jsonl");
    writeFileSync(path, lines.join("\n"));
    return path;
  };

  const egressLine = (token: string, overrides: Record<string, unknown> = {}): string =>
    JSON.stringify({
      id: "evt-1",
      timestamp: "2026-08-06T00:00:00.000Z",
      agentId: "alpha",
      plane: "network",
      action: "egress:http",
      decision: "allow",
      metadata: {
        host: "127.0.0.1",
        port: "4321",
        path: CANARY_PATH_PREFIX + token,
        agentMatchedOn: "comm",
        agentDeclared: "true",
      },
      integrity: { chainIndex: 7, hash: "x", previousHash: null, algorithm: "sha256", status: "chained-local" },
      ...overrides,
    });

  it("finds the egress record whose path carries the token", () => {
    const token = mintCanaryToken();
    const path = write([egressLine(token)]);

    const found = findChainRecords(path, token);

    expect(found).toHaveLength(1);
    expect(found[0].chainIndex).toBe(7);
    expect(found[0].matchedOn).toBe("comm");
    expect(found[0].declared).toBe(true);
  });

  it("ignores a record for a different token", () => {
    const path = write([egressLine(mintCanaryToken())]);
    expect(findChainRecords(path, mintCanaryToken())).toHaveLength(0);
  });

  it("ignores non-egress records that happen to mention the token", () => {
    const token = mintCanaryToken();
    const path = write([
      egressLine(token, { action: "mcp:tool_call" }),
      JSON.stringify({ action: "audit:chain-gap", metadata: { note: token } }),
    ]);
    expect(findChainRecords(path, token)).toHaveLength(0);
  });

  it("skips a half-written trailing line instead of reporting no record", () => {
    const token = mintCanaryToken();
    // The writer is another process appending to this file. Reading mid-append is normal, and a
    // parse failure there must not be reported as "the proxy never saw it", which is the same
    // output as a bypass.
    const path = write([egressLine(token), '{"id":"evt-2","action":"egress:http","metad']);
    expect(findChainRecords(path, token)).toHaveLength(1);
  });

  it("returns nothing rather than throwing when the audit file does not exist", () => {
    expect(findChainRecords(join(tmpdir(), "agentwall-capture-absent", "audit.jsonl"), mintCanaryToken())).toEqual([]);
  });

  it("degrades an unrecognised tier to none rather than trusting it", () => {
    const token = mintCanaryToken();
    const path = write([
      egressLine(token, {
        metadata: {
          host: "127.0.0.1",
          port: "4321",
          path: CANARY_PATH_PREFIX + token,
          agentMatchedOn: "vibes",
          agentDeclared: "true",
        },
      }),
    ]);
    expect(findChainRecords(path, token)[0].matchedOn).toBe("none");
  });
});

describe("the declared tier", () => {
  it("takes the strongest signal the operator declared", () => {
    expect(declaredTierOf({ id: "a", match: { credential: "sha256:" + "0".repeat(64), comm: ["x"] } })).toBe(
      "credential"
    );
    expect(declaredTierOf({ id: "a", match: { uid: 1000, comm: ["x"] } })).toBe("uid+comm");
    expect(declaredTierOf({ id: "a", match: { uid: 1000 } })).toBe("uid");
    expect(declaredTierOf({ id: "a", match: { comm: ["x"] } })).toBe("comm");
  });
});

const UNAVAILABLE: Corroboration = { status: "unavailable", detail: "not measured", proxyPids: [] };

function hit(overrides: Partial<CanaryHit> = {}): CanaryHit {
  return {
    at: "2026-08-06T00:00:00.000Z",
    method: "GET",
    path: CANARY_PATH_PREFIX + "a".repeat(64),
    token: true,
    replay: false,
    peer: { address: "127.0.0.1", port: 55555, pid: 4242, comm: "curl", uid: 1000 },
    ...overrides,
  };
}

function record(overrides: Partial<MatchedRecord> = {}): MatchedRecord {
  return {
    id: "evt-1",
    timestamp: "2026-08-06T00:00:00.000Z",
    chainIndex: 3,
    agentId: "alpha",
    decision: "allow",
    matchedOn: "comm",
    declared: true,
    host: "127.0.0.1",
    port: "4321",
    path: CANARY_PATH_PREFIX + "a".repeat(64),
    comm: "aw-alpha",
    pid: "1234",
    uid: "1000",
    transportMode: "forward",
    enforcementMode: "monitor",
    reasons: [],
    ...overrides,
  };
}

const statusOf = (result: { assertions: Array<{ id: string; status: string }> }, id: string): string =>
  result.assertions.find((assertion) => assertion.id === id)?.status ?? "missing";

const detailOf = (result: { assertions: Array<{ id: string; detail: string }> }, id: string): string =>
  result.assertions.find((assertion) => assertion.id === id)?.detail ?? "";

describe("the three assertions", () => {
  it("passes all three when one proxied request produced one record for the named agent", () => {
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [record()],
      corroboration: UNAVAILABLE,
    });

    expect(result.outcome).toBe("captured");
    expect(statusOf(result, "chain-record")).toBe("pass");
    expect(statusOf(result, "agent-binding")).toBe("pass");
    expect(statusOf(result, "no-bypass")).toBe("pass");
    expect(result.observedTier).toBe("comm");
    expect(result.tierStrength).toBe("weak");
  });

  it("calls a hit with no chain record a bypass and names the process that made it", () => {
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [],
      corroboration: UNAVAILABLE,
    });

    expect(result.outcome).toBe("bypass");
    expect(statusOf(result, "no-bypass")).toBe("fail");
    expect(detailOf(result, "no-bypass")).toContain("pid 4242");
    expect(detailOf(result, "no-bypass")).toContain("comm curl");
  });

  it("catches the partial bypass: one request proxied and one that went around", () => {
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [
        hit({ peer: { address: "127.0.0.1", port: 1, pid: 999, comm: "agentwall", uid: 1000 } }),
        hit({ replay: true }),
      ],
      records: [record()],
      corroboration: { status: "contradicted", detail: "pid 4242 is not the proxy", proxyPids: [999] },
    });

    // The naive check passes here: there IS a chain record, and it IS bound to alpha. Only the
    // hit-versus-record count catches the second connection.
    expect(statusOf(result, "chain-record")).toBe("pass");
    expect(statusOf(result, "agent-binding")).toBe("pass");
    expect(statusOf(result, "no-bypass")).toBe("fail");
    expect(result.outcome).toBe("bypass");
    // Only the escapee is named. The proxied connection came from pid 999 and is not accused.
    expect(detailOf(result, "no-bypass")).toContain("pid 4242");
    expect(detailOf(result, "no-bypass")).not.toContain("pid 999");
  });

  it("names every hit when /proc could not tell the proxy's connections from the agent's", () => {
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit({ peer: { address: "127.0.0.1", port: 1, pid: null, comm: null, uid: null } }), hit()],
      records: [record()],
      corroboration: UNAVAILABLE,
    });

    expect(statusOf(result, "no-bypass")).toBe("fail");
    expect(detailOf(result, "no-bypass")).toContain("process unresolved");
    expect(detailOf(result, "no-bypass")).toContain("pid 4242");
  });

  it("fails a peer that is demonstrably not the proxy even when the counts agree", () => {
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [record()],
      corroboration: { status: "contradicted", detail: "pid 4242 is not the proxy", proxyPids: [999] },
    });

    expect(result.outcome).toBe("bypass");
    expect(detailOf(result, "no-bypass")).toContain("not the proxy");
  });

  it("does NOT invent a bypass when peer attribution was merely unavailable", () => {
    // The whole point of the three-valued corroboration. attributeSocket is best-effort: a /proc
    // race, an unreadable /proc/<pid>/fd on another uid, or a non-Linux host all yield a null
    // pid. Treating that as "not the proxy" would fail every correctly captured agent on a host
    // where AgentWall runs as a different user.
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit({ peer: { address: "127.0.0.1", port: 1, pid: null, comm: null, uid: null } })],
      records: [record()],
      corroboration: UNAVAILABLE,
    });

    expect(result.outcome).toBe("captured");
    expect(statusOf(result, "no-bypass")).toBe("pass");
    expect(detailOf(result, "no-bypass")).toContain("Peer attribution unavailable");
  });

  it("refuses an undeclared process even when the chain recorded the agent's own id", () => {
    // The registry falls back to the process comm for a connection no declared agent claims, so
    // `process.title = "alpha"` produces a record whose agentId is "alpha" with declared=false.
    // Comparing the id alone would let any process satisfy the check for any agent.
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [record({ agentId: "alpha", declared: false, matchedOn: "none" })],
      corroboration: UNAVAILABLE,
    });

    expect(result.outcome).toBe("not-captured");
    expect(statusOf(result, "agent-binding")).toBe("fail");
    expect(detailOf(result, "agent-binding")).toContain("unattributed");
  });

  it("refuses a record bound to a different declared agent", () => {
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [record({ agentId: "beta" })],
      corroboration: UNAVAILABLE,
    });

    expect(result.outcome).toBe("not-captured");
    expect(detailOf(result, "agent-binding")).toContain("beta");
  });

  it("reports credential binding as strong and says what that is worth", () => {
    const result = evaluate({
      agentId: "cred",
      declaredTier: "credential",
      hits: [hit()],
      records: [record({ agentId: "cred", matchedOn: "credential" })],
      corroboration: UNAVAILABLE,
    });

    expect(result.tierStrength).toBe("strong");
    expect(result.tierShortfall).toBeNull();
    expect(detailOf(result, "agent-binding")).toContain("credential");
  });

  it("passes but flags an agent configured for a credential that bound by comm instead", () => {
    const result = evaluate({
      agentId: "mixed",
      declaredTier: "credential",
      hits: [hit()],
      records: [record({ agentId: "mixed", matchedOn: "comm" })],
      corroboration: UNAVAILABLE,
    });

    expect(result.outcome).toBe("captured");
    expect(result.tierShortfall).toContain("credential is not being presented");
  });

  it("reports the WEAKEST tier when several records bound the same agent differently", () => {
    const result = evaluate({
      agentId: "mixed",
      declaredTier: "credential",
      hits: [hit(), hit({ replay: true })],
      records: [record({ agentId: "mixed", matchedOn: "credential" }), record({ agentId: "mixed", matchedOn: "comm" })],
      corroboration: UNAVAILABLE,
    });

    expect(result.observedTier).toBe("comm");
  });

  it("treats a proxy denial as capture, because the record exists and the destination never saw it", () => {
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [],
      records: [record({ decision: "deny" })],
      corroboration: UNAVAILABLE,
    });

    expect(result.outcome).toBe("captured");
    expect(detailOf(result, "no-bypass")).toContain("capture and enforcement together");
  });

  it("reports silence as inconclusive rather than as either answer", () => {
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [],
      records: [],
      corroboration: UNAVAILABLE,
    });

    expect(result.outcome).toBe("inconclusive");
    expect(result.assertions.every((assertion) => assertion.status === "unproven")).toBe(true);
  });

  it("counts an unrelated request on the canary port as neither a hit nor a bypass", () => {
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit({ token: false, path: "/favicon.ico" })],
      records: [],
      corroboration: UNAVAILABLE,
    });

    expect(result.outcome).toBe("inconclusive");
  });
});

describe("a canary the environment already exempted from the proxy", () => {
  // NO_PROXY names destinations the client is TOLD to reach directly. An onboarding profile that
  // exports NO_PROXY=localhost,127.0.0.1,::1 (a reasonable-looking line, and one that was about
  // to ship) makes a loopback canary bypass the proxy by construction. Reporting that as a
  // BYPASS would accuse every onboarded agent of a hole its own configuration opened.
  it("grades a bare address, a domain suffix, and the wildcard as exempted", () => {
    expect(proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "localhost,127.0.0.1,::1" })).toMatchObject({
      entry: "127.0.0.1",
      certainty: "exempted",
    });
    expect(proxyExemptionFor("canary.internal", 4321, { NO_PROXY: ".internal" })?.entry).toBe(".internal");
    expect(proxyExemptionFor("canary.internal", 4321, { NO_PROXY: "internal" })?.entry).toBe("internal");
    expect(proxyExemptionFor("10.0.0.5", 4321, { NO_PROXY: "*" })?.certainty).toBe("exempted");
    expect(proxyExemptionFor("127.0.0.1", 4321, { no_proxy: "127.0.0.1" })?.source).toBe("no_proxy");
  });

  it("does not match an unrelated host, or a suffix that is not a domain boundary", () => {
    expect(proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "example.com,10.0.0.1" })).toBeNull();
    expect(proxyExemptionFor("notinternal", 4321, { NO_PROXY: "internal" })).toBeNull();
    expect(proxyExemptionFor("127.0.0.1", 4321, {})).toBeNull();
    expect(proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "  , ," })).toBeNull();
  });

  it("grades an entry naming another port as possible, because all three runtimes compare it", () => {
    // Measured, and the opposite of what an earlier draft of this file asserted from memory:
    // curl 8.5.0, python requests 2.31.0, and node 24 under NODE_USE_ENV_PROXY all compare a
    // :port in a NO_PROXY entry, so "127.0.0.1:3000" exempts nothing in any of them. Grading it
    // `exempted` would suppress a real bypass; ignoring it entirely would hide the entry from an
    // operator hunting one. It is reported, and it changes no verdict.
    const found = proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "127.0.0.1:3000" });
    expect(found?.certainty).toBe("possible");
    expect(found?.detail).toContain("compare the port");
  });

  it("grades an entry naming the canary's OWN port as exempted", () => {
    expect(proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "127.0.0.1:4321" })?.certainty).toBe("exempted");
  });

  it("walks the whole list so a narrow entry cannot mask a broader one after it", () => {
    // Returning on the first match would answer `possible` here and leave a loud BYPASS
    // standing, when the bare entry two characters later exempts the canary for every runtime
    // measured. Both variable spellings are walked for the same reason.
    expect(proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "127.0.0.1:3000,127.0.0.1" })).toMatchObject({
      entry: "127.0.0.1",
      certainty: "exempted",
    });
    expect(
      proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "127.0.0.1:3000", no_proxy: "127.0.0.1" })
    ).toMatchObject({ certainty: "exempted", source: "no_proxy" });
  });

  it("lets the verdict stand for a possible match, rather than suppressing an alarm on a maybe", () => {
    const exemption = proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "127.0.0.1:3000" });
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [],
      corroboration: UNAVAILABLE,
      exemption,
    });

    expect(result.outcome).toBe("bypass");
    expect(detailOf(result, "no-bypass")).toContain("BYPASS");
    // Named anyway, so an operator can rule it in or out themselves.
    expect(detailOf(result, "no-bypass")).toContain("127.0.0.1:3000");
  });

  it("degrades a direct hit to unproven instead of reporting a bypass", () => {
    const exemption = proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "127.0.0.1" });
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [],
      corroboration: UNAVAILABLE,
      exemption,
    });

    expect(result.outcome).toBe("inconclusive");
    expect(result.assertions.every((assertion) => assertion.status === "unproven")).toBe(true);
    // Not silence about the hole: the entry, its cost, and the fix all travel with the verdict.
    expect(detailOf(result, "no-bypass")).toContain("NO_PROXY");
    expect(detailOf(result, "no-bypass")).toContain("--host");
    expect(detailOf(result, "no-bypass")).toContain("told to reach without AgentWall");
    expect(detailOf(result, "no-bypass")).not.toContain("BYPASS");
  });

  it("degrades a contradicted peer to unproven too", () => {
    const exemption = proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "127.0.0.1" });
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [record()],
      corroboration: { status: "contradicted", detail: "pid 4242 is not the proxy", proxyPids: [999] },
      exemption,
    });

    expect(statusOf(result, "no-bypass")).toBe("unproven");
    expect(result.outcome).toBe("inconclusive");
  });

  it("judges normally when the client went through the proxy despite the exemption", () => {
    // Node's global fetch ignores NO_PROXY entirely. A record therefore proves capture whatever
    // the environment asked for, and the exemption must not soften a real pass into unproven.
    const exemption = proxyExemptionFor("127.0.0.1", 4321, { NO_PROXY: "127.0.0.1" });
    const result = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [record()],
      corroboration: UNAVAILABLE,
      exemption,
    });

    expect(result.outcome).toBe("captured");
  });
});

describe("exit codes", () => {
  const reportWith = (outcome: CaptureReport["outcome"]): CaptureReport => ({
    agentId: "alpha",
    canaryUrl: "http://127.0.0.1:1/x",
    token: "a".repeat(64),
    auditPath: "/tmp/audit.jsonl",
    configPath: null,
    declaredTier: "comm",
    observedTier: "comm",
    tierStrength: "weak",
    tierNote: "n",
    tierShortfall: null,
    assertions: [],
    corroboration: UNAVAILABLE,
    exemption: null,
    hits: [],
    records: [],
    fetch: { mode: "command" },
    outcome,
    captured: outcome === "captured",
    limits: [],
  });

  it("separates captured, not captured, and could not be completed", () => {
    expect(captureExitCode(reportWith("captured"))).toBe(EXIT_CAPTURED);
    expect(captureExitCode(reportWith("bypass"))).toBe(EXIT_NOT_CAPTURED);
    expect(captureExitCode(reportWith("not-captured"))).toBe(EXIT_NOT_CAPTURED);
    expect(captureExitCode(reportWith("inconclusive"))).toBe(EXIT_INCOMPLETE);
  });
});

describe("typed capture command execution", () => {
  it("executes a typed argv without a shell and substitutes the canary URL", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agentwall-capture-argv-"));
    const auditPath = join(dir, "audit.jsonl");
    writeFileSync(auditPath, "");

    try {
      const report = await runVerifyCapture({
        agentId: "alpha",
        auditPath,
        host: "127.0.0.1",
        timeoutMs: 2_000,
        settleMs: 0,
        commandArgv: [process.execPath, "-e", "fetch(process.argv[1])", "{url}"],
      });

      expect(report.fetch.exitCode).toBe(0);
      expect(report.hits).toHaveLength(1);
      expect(report.fetch.commandArgv).toEqual([
        process.execPath,
        "-e",
        "fetch(process.argv[1])",
        "{url}",
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects an empty argv and shell syntax before it starts a canary", () => {
    expect(() => validateCaptureCommandArgv([])).toThrow(/empty/i);
    expect(() => validateCaptureCommandArgv(["node;touch", "fetch.js"])).toThrow(/shell syntax/i);
    expect(() => validateCaptureCommandArgv(["node", "$(id)"])).toThrow(/shell syntax/i);
  });
});

describe("the report", () => {
  it("states the limits next to the result, every time", () => {
    const base = evaluate({
      agentId: "alpha",
      declaredTier: "comm",
      hits: [hit()],
      records: [record()],
      corroboration: UNAVAILABLE,
    });
    const text = formatCaptureReport({
      agentId: "alpha",
      canaryUrl: "http://127.0.0.1:1/x",
      token: "a".repeat(64),
      auditPath: "/tmp/audit.jsonl",
      configPath: "/tmp/agentwall.config.yaml",
      declaredTier: "comm",
      observedTier: base.observedTier,
      tierStrength: base.tierStrength,
      tierNote: base.tierNote,
      tierShortfall: base.tierShortfall,
      assertions: base.assertions,
      corroboration: UNAVAILABLE,
      hits: [hit()],
      records: [record()],
      fetch: { mode: "command", command: "curl {url}", exitCode: 0 },
      exemption: null,
      outcome: base.outcome,
      captured: true,
      limits: [
        "This proves the path the agent used for THIS request. It does not prove the agent has no other egress path it simply did not use during the check.",
      ],
    });

    expect(text).toContain("CAPTURED");
    expect(text).toContain("What this does NOT prove:");
    expect(text).toContain("does not prove the agent has no other egress path");
    // A weak binding is never reported as a bare success.
    expect(text).toContain("Captured, and weakly bound.");
  });
});
