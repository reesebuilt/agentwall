import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { createHash } from "crypto";
import { AgentRegistry, FleetConfigSchema, parseProxyCredential } from "../src/fleet/registry";
import { AgentBudgetLedger } from "../src/fleet/budget";
import { PolicyEngine } from "../src/policy/engine";
import { decideEgress, setEgressPolicy, setFleet } from "../src/runtime/enforcement";
import { resetLockdown } from "../src/runtime/lockdown";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { loadConfig } from "../src/config";

/**
 * The parts of per-agent governance the end-to-end suite cannot reach.
 *
 * tests/fleet-governance.integration.test.ts is the proof that this works: it starts the real
 * server, drives real sockets from real processes, and reads the audit chain. What it cannot
 * exercise is the set of configurations the server REFUSES TO START on, and the precedence
 * between identity signals when more than one is present. Both are contracts, and both fail
 * silently if they regress: an ambiguous fleet would resolve to whichever agent the map
 * happened to hold, and an operator would never learn that half their connections were
 * governed by the wrong policy.
 */

const engine = new PolicyEngine();

function fleet(input: unknown): AgentRegistry {
  return new AgentRegistry(FleetConfigSchema.parse(input));
}

describe("a fleet that cannot resolve deterministically is refused", () => {
  it("rejects two agents that claim the same credential", () => {
    const digest = createHash("sha256").update("shared", "utf8").digest("hex");
    expect(() =>
      fleet({
        agents: [
          { id: "one", match: { credential: `sha256:${digest}` } },
          { id: "two", match: { credential: `sha256:${digest}` } },
        ],
      })
    ).toThrow(/both match on credential/);
  });

  it("rejects two agents that claim the same uid with nothing to tell them apart", () => {
    expect(() =>
      fleet({ agents: [{ id: "one", match: { uid: 1000 } }, { id: "two", match: { uid: 1000 } }] })
    ).toThrow(/both match on uid 1000/);
  });

  it("rejects two agents that claim the same process name", () => {
    expect(() =>
      fleet({ agents: [{ id: "one", match: { comm: ["node"] } }, { id: "two", match: { comm: ["node", "bun"] } }] })
    ).toThrow(/both match on comm node/);
  });

  it("allows two agents to share a uid when their process names differ", () => {
    // The tiers exist for exactly this: a specific declaration beats a general one, so a
    // uid+comm pair and a bare uid catch-all can coexist under one account.
    const registry = fleet({
      agents: [
        { id: "scraper", match: { uid: 1000, comm: ["aw-scrape"] } },
        { id: "wrapper", match: { uid: 1000, comm: ["aw-mcp"] } },
        { id: "everything-else", match: { uid: 1000 } },
      ],
    });
    expect(registry.resolve({ uid: 1000, comm: "aw-scrape" }).id).toBe("scraper");
    expect(registry.resolve({ uid: 1000, comm: "aw-mcp" }).id).toBe("wrapper");
    expect(registry.resolve({ uid: 1000, comm: "cron" }).id).toBe("everything-else");
  });

  it("refuses a literal secret in the config file", () => {
    // The config is routinely committed. A proxy credential in git is a credential you have
    // to rotate, so the only accepted forms are a digest and an environment reference.
    expect(() => fleet({ agents: [{ id: "one", match: { credential: "hunter2" } }] })).toThrow(
      /declares a literal credential/
    );
  });

  it("refuses to start when a credential's environment variable is unset", () => {
    delete process.env["AGENTWALL_TEST_MISSING_SECRET"];
    // A boot failure rather than an agent that quietly never binds. Silence here means the
    // fleet falls back to the global allowlist with nothing on screen to say so.
    expect(() =>
      fleet({ agents: [{ id: "one", match: { credential: "env:AGENTWALL_TEST_MISSING_SECRET" } }] })
    ).toThrow(/AGENTWALL_TEST_MISSING_SECRET, which is unset/);
  });

  it("hashes a credential read from the environment", () => {
    process.env["AGENTWALL_TEST_SECRET"] = "from-the-environment";
    try {
      const registry = fleet({ agents: [{ id: "one", match: { credential: "env:AGENTWALL_TEST_SECRET" } }] });
      expect(registry.resolve({ credential: "from-the-environment" }).id).toBe("one");
      expect(registry.resolve({ credential: "not-it" }).declared).toBe(false);
    } finally {
      delete process.env["AGENTWALL_TEST_SECRET"];
    }
  });
});

describe("identity signals are ranked, strongest first", () => {
  const digest = createHash("sha256").update("the-secret", "utf8").digest("hex");
  const registry = fleet({
    agents: [
      { id: "by-credential", match: { credential: `sha256:${digest}` } },
      { id: "by-uid-comm", match: { uid: 1000, comm: ["node"] } },
      { id: "by-uid", match: { uid: 2000 } },
      { id: "by-comm", match: { comm: ["curl"] } },
    ],
  });

  it("prefers a presented credential over anything the process asserted about itself", () => {
    // comm matches `by-comm` too. The credential wins because a secret is evidence and a
    // process name is a string the process chose: `process.title = "curl"` sets it.
    const resolved = registry.resolve({ uid: 2000, comm: "curl", credential: "the-secret" });
    expect(resolved.id).toBe("by-credential");
    expect(resolved.matchedOn).toBe("credential");
  });

  it("prefers uid plus comm over uid alone", () => {
    expect(registry.resolve({ uid: 1000, comm: "node" }).matchedOn).toBe("uid+comm");
  });

  it("falls back to uid when the process name matches nothing", () => {
    expect(registry.resolve({ uid: 2000, comm: "unheard-of" }).matchedOn).toBe("uid");
  });

  it("uses comm only when nothing stronger is available", () => {
    expect(registry.resolve({ uid: 9999, comm: "curl" }).matchedOn).toBe("comm");
  });

  it("reports an unclaimed connection as undeclared rather than guessing", () => {
    const resolved = registry.resolve({ uid: 9999, comm: "stranger" });
    expect(resolved.declared).toBe(false);
    expect(resolved.matchedOn).toBe("none");
    // The comm is carried through as the id, which is exactly what an egress record said
    // before agents existed. Nothing an existing deployment already wrote changes meaning.
    expect(resolved.id).toBe("stranger");
  });

  it("does not match a credential that is a prefix of the real one", () => {
    expect(registry.resolve({ credential: "the-secre" }).declared).toBe(false);
    expect(registry.resolve({ credential: "the-secret " }).declared).toBe(false);
  });
});

describe("Proxy-Authorization parsing", () => {
  it("reads a bearer token", () => {
    expect(parseProxyCredential("Bearer abc123")).toBe("abc123");
    expect(parseProxyCredential("bearer abc123")).toBe("abc123");
  });

  it("reads basic credentials as the decoded user:pass, which is what a proxy URL sends", () => {
    const encoded = Buffer.from("agent:secret", "utf8").toString("base64");
    expect(parseProxyCredential(`Basic ${encoded}`)).toBe("agent:secret");
  });

  it("returns null rather than a guess for anything else", () => {
    expect(parseProxyCredential(undefined)).toBeNull();
    expect(parseProxyCredential("")).toBeNull();
    expect(parseProxyCredential("Bearer")).toBeNull();
    expect(parseProxyCredential("Bearer   ")).toBeNull();
    expect(parseProxyCredential("Digest nonce=1")).toBeNull();
    // Basic without a colon is not a credential pair, and inventing one would let a client
    // steer attribution with a malformed header.
    expect(parseProxyCredential(`Basic ${Buffer.from("nocolon").toString("base64")}`)).toBeNull();
  });
});

describe("a declared fleet changes what an egress decision is measured against", () => {
  const attempt = { host: "api.example.com", port: 443, scheme: "https", method: "CONNECT" };

  beforeEach(() => {
    resetLockdown();
    setEgressPolicy({ hosts: ["global.example.com"], ports: [443] });
  });

  afterEach(() => {
    resetLockdown();
    setFleet(null, null);
    setEgressPolicy({ hosts: [], ports: [] });
  });

  it("judges a declared agent against its own allowlist, not the global one", () => {
    setFleet(
      fleet({
        agents: [{ id: "scraper", match: { comm: ["aw-scrape"] }, egress: { allowedHosts: ["api.example.com"] } }],
      }),
      new AgentBudgetLedger()
    );

    const scoped = decideEgress({ ...attempt, comm: "aw-scrape" }, "strict", engine);
    expect(scoped.decision).toBe("allow");
    expect(scoped.agent.allowlistSource).toBe("agent:scraper");

    // The same destination from anything the fleet does not claim still meets the global
    // list, which does not contain it. One allowlist could not express both answers.
    const other = decideEgress({ ...attempt, comm: "something-else" }, "strict", engine);
    expect(other.decision).toBe("deny");
    expect(other.agent.allowlistSource).toBe("global");
  });

  it("leaves the half an agent did not declare at the global value", () => {
    // Narrowing only the ports stays a one-line change: an agent block replaces the lists it
    // names and nothing else.
    setFleet(
      fleet({ agents: [{ id: "narrow", match: { comm: ["aw-narrow"] }, egress: { allowedPorts: [8443] } }] }),
      new AgentBudgetLedger()
    );

    const onGlobalHost = decideEgress(
      { host: "global.example.com", port: 8443, scheme: "https", comm: "aw-narrow" },
      "strict",
      engine
    );
    expect(onGlobalHost.decision).toBe("allow");

    const onGlobalPort = decideEgress(
      { host: "global.example.com", port: 443, scheme: "https", comm: "aw-narrow" },
      "strict",
      engine
    );
    expect(onGlobalPort.decision).toBe("deny");
    expect(onGlobalPort.reasons[0]).toContain("port 443 is not in the narrow egress allowlist ports");
  });

  it("counts a budget in monitor mode without ever blocking on it", () => {
    // Monitor's whole purpose is that an operator sizes limits by reading the ledger. A
    // counter that stopped at the ceiling would answer "are you over" and hide by how much.
    setFleet(
      fleet({
        agents: [
          {
            id: "loud",
            match: { comm: ["aw-loud"] },
            egress: { allowedHosts: ["api.example.com"] },
            budget: { windowSeconds: 600, maxRequests: 2 },
          },
        ],
      }),
      new AgentBudgetLedger()
    );

    const counts: number[] = [];
    for (let i = 0; i < 4; i += 1) {
      const verdict = decideEgress({ ...attempt, comm: "aw-loud" }, "monitor", engine);
      expect(verdict.decision).toBe("allow");
      counts.push(verdict.budget?.requests ?? -1);
    }
    expect(counts).toEqual([1, 2, 3, 4]);
  });

  it("does not charge a connection it refused", () => {
    setFleet(
      fleet({
        agents: [
          {
            id: "capped",
            match: { comm: ["aw-capped"] },
            // Nothing is reachable, so every attempt is denied by the allowlist before the
            // budget is ever charged.
            egress: { allowedHosts: ["nowhere.example.com"] },
            budget: { windowSeconds: 600, maxRequests: 1 },
          },
        ],
      }),
      new AgentBudgetLedger()
    );

    for (let i = 0; i < 5; i += 1) {
      const verdict = decideEgress({ ...attempt, comm: "aw-capped" }, "strict", engine);
      expect(verdict.decision).toBe("deny");
      // Still zero after five refusals. Charging denials would mean a client's own retry
      // loop keeps its budget permanently spent and the limit never recovers.
      expect(verdict.budget?.requests).toBe(0);
    }
  });

  it("refuses an undeclared agent only when the operator closed the fleet", () => {
    const agents = [{ id: "known", match: { comm: ["aw-known"] }, egress: { allowedHosts: ["api.example.com"] } }];

    setFleet(fleet({ unmatched: "global", agents }), new AgentBudgetLedger());
    const open = decideEgress({ ...attempt, comm: "aw-stranger" }, "strict", engine);
    // Denied by the global allowlist, which does not contain this host, and NOT by identity.
    expect(open.matchedRules).not.toContain("fleet:deny-undeclared-agent");

    setFleet(fleet({ unmatched: "deny", agents }), new AgentBudgetLedger());
    const closed = decideEgress({ ...attempt, comm: "aw-stranger" }, "strict", engine);
    expect(closed.decision).toBe("deny");
    expect(closed.matchedRules).toContain("fleet:deny-undeclared-agent");
    expect(closed.detectionIds).toContain("det.fleet.agent.undeclared");

    // Monitor still records only. An emergency stop is the one control allowed to break
    // monitor's contract; an identity posture is not.
    const observed = decideEgress({ ...attempt, comm: "aw-stranger" }, "monitor", engine);
    expect(observed.decision).toBe("allow");
    expect(observed.reasons.some((reason) => reason.includes("no declared agent claims"))).toBe(true);
  });

  it("produces the same records as before when no fleet is declared", () => {
    setFleet(null, null);
    const verdict = decideEgress({ ...attempt, comm: "node", pid: 42 }, "strict", engine);

    // The agentId is the comm, the allowlist is the global one, and nothing claims an
    // identity that was never established. Upgrading into a version that understands fleets
    // must not change what an existing deployment's ledger means.
    expect(verdict.agent.id).toBe("node");
    expect(verdict.agent.declared).toBe(false);
    expect(verdict.agent.matchedOn).toBe("none");
    expect(verdict.agent.allowlistSource).toBe("global");
    expect(verdict.budget).toBeNull();
    expect(verdict.budgetTicket).toBeNull();
  });
});

describe("a malformed fleet section is a boot failure, not a fallback", () => {
  let dir: string;

  const write = (body: string): string => {
    const path = join(dir, "agentwall.config.yaml");
    writeFileSync(path, `port: 3000\nhost: 127.0.0.1\n${body}`);
    return path;
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "agentwall-fleet-config-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("names the offending field when an agent match is empty", () => {
    // An agent that matches on nothing is not a permissive agent, it is an agent that never
    // binds, and its policy is simply not in force with nothing on screen to say so.
    const path = write(`fleet:\n  agents:\n    - id: broken\n      match: {}\n`);
    expect(() => loadConfig(path)).toThrow(/invalid fleet section/);
    expect(() => loadConfig(path)).toThrow(/at least one of uid, comm, or credential/);
  });

  it("rejects a budget that sets no ceiling", () => {
    const path = write(
      `fleet:\n  agents:\n    - id: pointless\n      match:\n        uid: 1000\n      budget:\n        windowSeconds: 60\n`
    );
    expect(() => loadConfig(path)).toThrow(/maxRequests, maxBytes, or both/);
  });

  it("rejects a closed fleet with nothing declared, and points at the lockdown instead", () => {
    // This configuration refuses all proxied egress in guarded and strict. Accepting it
    // would mean an operator who wrote the posture line before the agent list takes the
    // fleet offline and reads a wall of denials that never mention the cause.
    const path = write(`fleet:\n  unmatched: deny\n  agents: []\n`);
    expect(() => loadConfig(path)).toThrow(/no agents are declared/);
    expect(() => loadConfig(path)).toThrow(/use the lockdown to stop traffic/);
  });

  it("accepts a fleet section and fills in the default posture", () => {
    const path = write(`fleet:\n  agents:\n    - id: ok\n      match:\n        comm: ["node"]\n`);
    const config = loadConfig(path);
    // "global" by default: upgrading into a version that understands fleets must never start
    // blocking traffic that yesterday's identical configuration allowed.
    expect(config.fleet?.unmatched).toBe("global");
    expect(config.fleet?.agents).toHaveLength(1);
  });
});
