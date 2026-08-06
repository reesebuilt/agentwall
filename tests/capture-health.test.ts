import { afterEach, describe, expect, it } from "@jest/globals";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { chainAuditEvent, type AuditChainState } from "../src/audit/chain";
import { readCaptureHealth, readTail, DEFAULT_OBSERVATION_WINDOW_SECONDS } from "../src/evidence/capture";
import { AgentRegistry, UNDECLARED_AGENT_ID, weakestBindingTier } from "../src/fleet/registry";
import type { AuditEvent } from "../src/types";

/**
 * What doctor can tell an operator about capture, measured against a real chain file.
 *
 * The records here are written with the SAME chain builder the server writes with, so the
 * integrity block, the index sequence and the JSONL framing are real rather than mimicked.
 * The attribution metadata is assembled by hand, which is the one thing in this file that
 * could drift from what src/index.ts actually stamps; tests/capture-health.integration.test.ts
 * closes that gap by running doctor over a chain a real server produced. Neither test is
 * sufficient alone: this one reaches states a live proxy cannot be talked into producing on
 * demand (a chain older than the window, a bookmark ahead of the chain), and that one proves
 * the field names are the ones the writer uses.
 */

const dirs: string[] = [];

afterEach(() => {
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const MINUTE = 60_000;

interface EgressLine {
  agentId: string;
  /** Omitted entirely to model a record written before attribution was stamped. */
  declared?: boolean;
  matchedOn?: string;
  host?: string;
  bytesUp?: number;
  bytesDown?: number;
  decision?: "allow" | "deny";
  /** The posture the record states was in force. Omit to model a pre-posture record. */
  unmatched?: "global" | "deny";
  /** The mode the record states was in force. Defaults to an enforcing one. */
  mode?: "monitor" | "guarded" | "strict";
  atMs: number;
}

/**
 * Write one chain file from a list of egress records, oldest first.
 *
 * Field-for-field the shape `recordEgress` in src/index.ts emits: `agentId` at the top
 * level, attribution flattened into `metadata`, byte counters as strings.
 */
function writeChain(lines: EgressLine[], extras: Omit<AuditEvent, "integrity">[] = []): string {
  const dir = mkdtempSync(join(tmpdir(), "agentwall-capture-"));
  dirs.push(dir);
  const auditPath = join(dir, "audit.jsonl");

  const state: AuditChainState = { chainIndex: 0, previousHash: null };
  const rendered: string[] = [];
  const append = (payload: Omit<AuditEvent, "integrity">): void => {
    const event = chainAuditEvent(payload, state);
    state.chainIndex = event.integrity.chainIndex + 1;
    state.previousHash = event.integrity.hash;
    rendered.push(JSON.stringify(event));
  };

  for (const line of lines) {
    const metadata: Record<string, string> = {
      host: line.host ?? "api.example.test",
      port: "443",
      scheme: "https",
      method: "CONNECT",
      bytesUp: String(line.bytesUp ?? 0),
      bytesDown: String(line.bytesDown ?? 0),
      agentMatchedOn: line.matchedOn ?? "comm",
      enforcementMode: line.mode ?? "strict",
    };
    if (line.unmatched !== undefined) metadata.fleetUnmatched = line.unmatched;
    if (line.declared !== undefined) metadata.agentDeclared = line.declared ? "true" : "false";

    append({
      id: `rec-${rendered.length}`,
      timestamp: new Date(line.atMs).toISOString(),
      agentId: line.agentId,
      plane: "network",
      action: "egress:https",
      decision: line.decision ?? "allow",
      riskLevel: "low",
      matchedRules: [],
      reasons: [],
      requiresApproval: false,
      highRiskFlow: false,
      metadata,
    });
  }
  for (const extra of extras) append(extra);

  writeFileSync(auditPath, rendered.length > 0 ? `${rendered.join("\n")}\n` : "");
  return auditPath;
}

/**
 * `minimumMatchTier` arrived with the fleet credential lifecycle and is required on the parsed
 * shape, because the schema gives it a default rather than leaving it optional. These tests
 * predate it and none of them are about it, so the helper supplies the same default the schema
 * would and stays overridable for any test that does care.
 */
type FleetInput = ConstructorParameters<typeof AgentRegistry>[0];
function fleet(
  yamlish: Omit<FleetInput, "minimumMatchTier"> & Partial<Pick<FleetInput, "minimumMatchTier">>,
) {
  return new AgentRegistry({ minimumMatchTier: "any", ...yamlish } as FleetInput).list();
}

describe("capture health, read from the chain", () => {
  const now = Date.UTC(2026, 7, 6, 12, 0, 0);

  it("reports attributed traffic per agent, against the declared budget", () => {
    const agents = fleet({
      unmatched: "deny",
      agents: [
        { id: "alpha", match: { comm: ["aw-alpha"] }, budget: { windowSeconds: 600, maxRequests: 5 } },
        { id: "beta", match: { uid: 1000 }, budget: { windowSeconds: 600, maxBytes: 10_000 } },
      ],
    });

    const auditPath = writeChain([
      { agentId: "alpha", declared: true, matchedOn: "comm", atMs: now - 3 * MINUTE, bytesDown: 1024 },
      { agentId: "alpha", declared: true, matchedOn: "comm", atMs: now - 2 * MINUTE, bytesDown: 2048 },
      { agentId: "beta", declared: true, matchedOn: "uid", atMs: now - MINUTE, bytesUp: 500, bytesDown: 4500 },
    ]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    const alpha = health.agents.find((row) => row.agentId === "alpha");
    expect(alpha?.requests).toBe(2);
    expect(alpha?.bytes).toBe(3072);
    expect(alpha?.maxRequests).toBe(5);
    expect(alpha?.windowSeconds).toBe(600);
    expect(alpha?.windowIsBudget).toBe(true);
    expect(alpha?.lastSeen).toEqual({ at: new Date(now - 2 * MINUTE).toISOString(), tier: "comm" });
    expect(alpha?.observedTiers).toEqual(["comm"]);

    const beta = health.agents.find((row) => row.agentId === "beta");
    expect(beta?.requests).toBe(1);
    // Both directions, because a budget an agent can evade by downloading rather than
    // uploading is not a budget.
    expect(beta?.bytes).toBe(5000);
    expect(beta?.maxBytes).toBe(10_000);
    expect(beta?.lastSeen?.tier).toBe("uid");

    // Attributed traffic is not undeclared traffic. This is the assertion that keeps the
    // alarm from crying wolf on a correctly captured fleet.
    expect(health.undeclared.total).toBe(0);
    expect(health.undeclared.sinceLastRun).toBe(0);
    expect(health.egressRecords).toBe(3);
  });

  it("counts only what is inside the window, and still says when the agent was last seen", () => {
    const agents = fleet({
      unmatched: "global",
      agents: [{ id: "alpha", match: { comm: ["aw-alpha"] }, budget: { windowSeconds: 60, maxRequests: 5 } }],
    });

    const auditPath = writeChain([
      { agentId: "alpha", declared: true, atMs: now - 10 * MINUTE, bytesDown: 9999 },
      { agentId: "alpha", declared: true, atMs: now - 5 * MINUTE, bytesDown: 9999 },
    ]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });
    const alpha = health.agents[0];

    // Zero in the window, but SEEN. An agent that stopped five minutes ago and an agent
    // that never existed must not render the same, and the counts alone cannot tell them
    // apart, which is what `lastSeen` is for.
    expect(alpha.requests).toBe(0);
    expect(alpha.bytes).toBe(0);
    expect(alpha.lastSeen?.at).toBe(new Date(now - 5 * MINUTE).toISOString());
  });

  it("renders a declared agent that has never been seen as never seen, not as zero", () => {
    const agents = fleet({
      unmatched: "deny",
      agents: [
        { id: "alpha", match: { comm: ["aw-alpha"] } },
        { id: "ghost", match: { comm: ["aw-ghost"] } },
      ],
    });

    const auditPath = writeChain([{ agentId: "alpha", declared: true, atMs: now - MINUTE }]);
    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    const ghost = health.agents.find((row) => row.agentId === "ghost");
    expect(ghost?.lastSeen).toBeNull();
    expect(ghost?.observedTiers).toEqual([]);
    expect(ghost?.requests).toBe(0);

    // The distinguishing field is lastSeen, and it is null ONLY for the never-seen agent.
    const alpha = health.agents.find((row) => row.agentId === "alpha");
    expect(alpha?.lastSeen).not.toBeNull();
    expect(alpha?.requests).toBe(1);

    // An agent with no declared budget still gets counts, over a stated observation span
    // rather than a ceiling, so "no budget" does not mean "no visibility".
    expect(alpha?.windowIsBudget).toBe(false);
    expect(alpha?.windowSeconds).toBe(DEFAULT_OBSERVATION_WINDOW_SECONDS);
  });

  it("raises undeclared egress as its own finding, split by identity, host, and outcome", () => {
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });

    const auditPath = writeChain([
      { agentId: "alpha", declared: true, atMs: now - 4 * MINUTE },
      // Something with a name nobody declared, which got out.
      { agentId: "curl", declared: false, matchedOn: "none", host: "pastebin.example", atMs: now - 3 * MINUTE, bytesUp: 700 },
      { agentId: "curl", declared: false, matchedOn: "none", host: "pastebin.example", atMs: now - 3 * MINUTE, bytesUp: 300 },
      // Something with no recoverable identity at all, which the wall refused.
      {
        agentId: UNDECLARED_AGENT_ID,
        declared: false,
        matchedOn: "none",
        host: "evil.example",
        decision: "deny",
        atMs: now - 2 * MINUTE,
      },
    ]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    expect(health.undeclared.total).toBe(3);
    expect(health.undeclared.sinceLastRun).toBe(3);
    expect(health.undeclared.allowedSinceLastRun).toBe(2);
    expect(health.undeclared.deniedSinceLastRun).toBe(1);
    expect(health.undeclared.bytesSinceLastRun).toBe(1000);
    expect(health.undeclared.byIdentity).toEqual([
      { id: "curl", count: 2 },
      { id: UNDECLARED_AGENT_ID, count: 1 },
    ]);
    expect(health.undeclared.topHosts).toEqual([
      { host: "pastebin.example", count: 2 },
      { host: "evil.example", count: 1 },
    ]);
    expect(health.undeclared.firstAt).toBe(new Date(now - 3 * MINUTE).toISOString());
    expect(health.undeclared.lastAt).toBe(new Date(now - 2 * MINUTE).toISOString());

    // None of it is charged to the declared agent. Undeclared traffic that inflated a
    // declared agent's counters would hide the escape inside a row that looks accounted for.
    expect(health.agents[0].requests).toBe(1);
  });

  it("counts undeclared egress since the last run, and only since the last run", () => {
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });

    const auditPath = writeChain([
      { agentId: "curl", declared: false, atMs: now - 30 * MINUTE },
      { agentId: "curl", declared: false, atMs: now - 20 * MINUTE },
      { agentId: "alpha", declared: true, atMs: now - 15 * MINUTE },
      { agentId: "wget", declared: false, atMs: now - 5 * MINUTE },
    ]);

    const first = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });
    expect(first.undeclared.total).toBe(3);
    expect(first.undeclared.sinceLastRun).toBe(3);
    expect(first.watermark?.chainIndex).toBe(3);

    // The bookmark from a run that had already seen the first three records. Only the
    // fourth is new, which is the whole point: an operator wants "what changed", not a
    // total that grows forever and stops meaning anything.
    const second = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: { chainIndex: 2, at: "x" }, now });
    expect(second.undeclared.total).toBe(3);
    expect(second.undeclared.sinceLastRun).toBe(1);
    expect(second.undeclared.byIdentity).toEqual([{ id: "wget", count: 1 }]);

    // And once caught up, nothing is new. A section that kept re-reporting the same records
    // would be indistinguishable from an escape that never stops.
    const third = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: { chainIndex: 3, at: "x" }, now });
    expect(third.undeclared.sinceLastRun).toBe(0);
    expect(third.undeclared.total).toBe(3);
  });

  it("discards a bookmark that is ahead of the chain instead of reporting nothing forever", () => {
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });
    const auditPath = writeChain([{ agentId: "curl", declared: false, atMs: now - MINUTE }]);

    // The chain was replaced, restarted, or rotated away under a bookmark that outlived it.
    // Trusting the bookmark here means every future run reports zero new undeclared records
    // over a chain full of them.
    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: { chainIndex: 900, at: "x" }, now });

    expect(health.watermarkReset).toContain("900");
    expect(health.since).toBeNull();
    expect(health.undeclared.sinceLastRun).toBe(1);
  });

  it("reports the weakest binding any declared agent can be satisfied by", () => {
    const agents = fleet({
      unmatched: "deny",
      agents: [
        { id: "strong", match: { credential: `sha256:${"a".repeat(64)}` } },
        { id: "byuid", match: { uid: 1000 } },
        { id: "byname", match: { comm: ["aw-byname"] } },
      ],
    });

    const health = readCaptureHealth({ auditPath: writeChain([]) }, { agents, unmatched: "deny", since: null, now });

    expect(health.weakestBinding).toEqual({ tier: "comm", agentIds: ["byname"] });
    expect(health.agents.map((row) => row.weakestTier)).toEqual(["credential", "uid", "comm"]);
  });

  it("reports a credential-plus-comm agent at its comm strength, not its credential strength", () => {
    // The registry indexes this agent under BOTH the credential and the comm, and resolve()
    // falls through to comm when no credential is presented. So any process that names
    // itself aw-mixed binds to it without the secret, and reporting "credential" here would
    // describe a property the declaration does not have.
    const agents = fleet({
      unmatched: "deny",
      agents: [{ id: "mixed", match: { credential: `sha256:${"b".repeat(64)}`, comm: ["aw-mixed"] } }],
    });

    expect(weakestBindingTier(agents[0])).toBe("comm");

    const health = readCaptureHealth({ auditPath: writeChain([]) }, { agents, unmatched: "deny", since: null, now });
    expect(health.agents[0].strongestTier).toBe("credential");
    expect(health.agents[0].weakestTier).toBe("comm");
    expect(health.weakestBinding).toEqual({ tier: "comm", agentIds: ["mixed"] });
  });

  it("does not call anything undeclared when no fleet is declared", () => {
    // Every record carries agentDeclared=false when there is no registry, because there is
    // nothing for a connection to be declared AGAINST. Alarming on that would fail every
    // correct single-agent install on the planet, permanently.
    const auditPath = writeChain([
      { agentId: "node", declared: false, atMs: now - MINUTE },
      { agentId: "node", declared: false, atMs: now - MINUTE },
    ]);

    const health = readCaptureHealth({ auditPath }, { agents: [], unmatched: "global", since: null, now });

    expect(health.fleetDeclared).toBe(false);
    expect(health.undeclared.total).toBe(0);
    expect(health.egressRecords).toBe(2);
  });

  it("separates history written before attribution from a new escape", () => {
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });
    const auditPath = writeChain([
      // No agentDeclared marker at all: an older build wrote this.
      { agentId: "node", atMs: now - 40 * MINUTE },
      { agentId: "curl", declared: false, atMs: now - MINUTE },
    ]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    expect(health.undeclared.total).toBe(2);
    expect(health.undeclared.predatingAttribution).toBe(1);
  });

  it("flags an undeclared record that claims a declared agent's id", () => {
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { uid: 1000 } }] });
    // A process calling itself "alpha" that did not satisfy alpha's uid rule. The chain
    // carries the claim; nothing in the counters would show it, because the row it would
    // land in is the row it is impersonating.
    const auditPath = writeChain([{ agentId: "alpha", declared: false, atMs: now - MINUTE }]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    expect(health.agents[0].lastSeen).toBeNull();
    expect(health.notes.join(" ")).toContain("claiming that name");
  });

  it("ignores non-egress records but still bookmarks past them", () => {
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });
    const auditPath = writeChain(
      [{ agentId: "alpha", declared: true, atMs: now - MINUTE }],
      [
        {
          id: "tool-1",
          timestamp: new Date(now).toISOString(),
          agentId: "alpha",
          plane: "tool",
          action: "tool:invoke",
          decision: "allow",
          riskLevel: "low",
          matchedRules: [],
          reasons: [],
          requiresApproval: false,
          highRiskFlow: false,
        },
      ],
    );

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    expect(health.egressRecords).toBe(1);
    // The bookmark covers the tool record too. A bookmark that only tracked egress would
    // slide backwards every time a non-egress record was the last thing written.
    expect(health.watermark?.chainIndex).toBe(1);
  });

  it("says there is no chain rather than reporting an empty one", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentwall-capture-"));
    dirs.push(dir);

    const health = readCaptureHealth({ auditPath: join(dir, "audit.jsonl") }, { agents: [], unmatched: "global", since: null, now });

    expect(health.chainPresent).toBe(false);
    expect(health.watermark).toBeNull();
  });

  it("reads the tail of an oversized chain file instead of skipping it", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentwall-capture-"));
    dirs.push(dir);
    const file = join(dir, "big.jsonl");
    // Ten equal-length lines. The cap below lands inside line 6, so the tail must start at
    // line 7 and must not hand back the fragment of line 6 as if it were a record.
    writeFileSync(file, `${Array.from({ length: 10 }, (_, i) => `{"n":${i},"pad":"${"x".repeat(20)}"}`).join("\n")}\n`);
    const size = statSync(file).size;

    const whole = readTail(file, size, size);
    expect(whole.truncated).toBe(false);
    expect(whole.text.trim().split("\n")).toHaveLength(10);

    const tail = readTail(file, size, Math.floor(size * 0.35));
    expect(tail.truncated).toBe(true);
    const lines = tail.text.trim().split("\n");
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.length).toBeLessThan(10);
    // Every line handed back is a whole record. A partial leading line would parse as a
    // torn record and be reported as chain damage that is not there.
    for (const line of lines) expect(() => JSON.parse(line)).not.toThrow();
    // And it is the NEWEST records that survive, which is the entire reason this exists:
    // truncating at the recent end would report an escaping agent as never seen.
    expect(JSON.parse(lines[lines.length - 1]).n).toBe(9);
  });

  it("finds one undeclared record among hundreds of attributed ones, uncapped", () => {
    // The needle-in-a-haystack case, and the one where "never seen" has to keep its strong
    // meaning: nothing was capped on this read, so a null lastSeen really does mean never.
    // The oversized-file path itself is covered above, against readTail directly, because
    // the real cap is 64 MB and writing that from a unit test is not a measurement.
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });
    const auditPath = writeChain(
      Array.from({ length: 400 }, (_, i) => ({
        agentId: i === 399 ? "curl" : "alpha",
        declared: i === 399 ? false : true,
        atMs: now - (400 - i) * 1000,
      })),
    );

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    expect(health.truncated).toBe(false);
    expect(health.undeclared.sinceLastRun).toBe(1);
    expect(health.agents[0].lastSeen).not.toBeNull();
  });

  it("calls it an escape only when the record says policy told the wall to refuse it", () => {
    // fleet.unmatched: deny under an enforcing mode, and it reached the network anyway.
    // src/runtime/enforcement.ts refuses exactly that before opening an upstream socket, so
    // a record in this shape means something did not pass the gate.
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });
    const auditPath = writeChain([
      { agentId: "curl", declared: false, unmatched: "deny", mode: "strict", atMs: now - 2 * MINUTE },
      { agentId: "curl", declared: false, unmatched: "deny", mode: "guarded", atMs: now - MINUTE },
    ]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    expect(health.undeclared.allowedSinceLastRun).toBe(2);
    expect(health.undeclared.escapedSinceLastRun).toBe(2);
    expect(health.undeclared.permittedByConfigSinceLastRun).toEqual([]);
  });

  it("refuses to call configured behaviour an escape, even when the config has since tightened", () => {
    // The discriminating half of the pair above. Identical records except for the posture
    // the RECORD carries, and the caller's current posture is deliberately the opposite of
    // it. `unmatched: global` is the default and is what docs/fleet.md tells perimeter users
    // to run: undeclared traffic reaching an allowlisted host is precisely what it
    // prescribes. An implementation that judged by the caller's config instead would report
    // an escape here and accuse an operator of a breach that yesterday's own default
    // arranged, which is the whole failure this split exists to prevent.
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });
    const auditPath = writeChain([
      { agentId: "curl", declared: false, unmatched: "global", mode: "strict", atMs: now - MINUTE },
    ]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    expect(health.undeclared.allowedSinceLastRun).toBe(1);
    expect(health.undeclared.escapedSinceLastRun).toBe(0);
    // The reason string is what the operator reads and acts on, so it is asserted, not just
    // its presence: it has to name the setting.
    expect(health.undeclared.permittedByConfigSinceLastRun).toEqual([
      { reason: expect.stringContaining("fleet.unmatched: global"), count: 1 },
    ]);
  });

  it("refuses to call configured behaviour an escape in monitor mode", () => {
    // Monitor returns allow before the undeclared gate is reached, by design and on purpose.
    // An adopter running monitor for a week to size their allowlist must not get a red
    // doctor every day for using the mode the docs tell them to start with.
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });
    const auditPath = writeChain([
      { agentId: "curl", declared: false, unmatched: "deny", mode: "monitor", atMs: now - MINUTE },
    ]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    expect(health.undeclared.escapedSinceLastRun).toBe(0);
    expect(health.undeclared.permittedByConfigSinceLastRun).toEqual([
      { reason: expect.stringContaining("enforcement.mode: monitor"), count: 1 },
    ]);
  });

  it("never counts a refused connection as an escape, whatever the posture", () => {
    const agents = fleet({ unmatched: "deny", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });
    const auditPath = writeChain([
      { agentId: "curl", declared: false, unmatched: "deny", mode: "strict", decision: "deny", atMs: now - MINUTE },
    ]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });

    expect(health.undeclared.deniedSinceLastRun).toBe(1);
    expect(health.undeclared.allowedSinceLastRun).toBe(0);
    expect(health.undeclared.escapedSinceLastRun).toBe(0);
  });

  it("judges a record that predates the posture marker by the current config, and says so", () => {
    const agents = fleet({ unmatched: "global", agents: [{ id: "alpha", match: { comm: ["aw-alpha"] } }] });
    // No fleetUnmatched on the record: an older build wrote it. The caller's posture is the
    // only thing left to judge by, and the report has to admit that rather than presenting
    // the answer as though the record supplied it.
    const auditPath = writeChain([{ agentId: "curl", declared: false, mode: "strict", atMs: now - MINUTE }]);

    const health = readCaptureHealth({ auditPath }, { agents, unmatched: "global", since: null, now });

    expect(health.undeclared.escapedSinceLastRun).toBe(0);
    expect(health.notes.join(" ")).toContain("do not state the fleet posture in force");

    // Same record, a caller whose config now says deny: it converts to an escape, which is
    // exactly why the note above has to be there.
    const tightened = readCaptureHealth({ auditPath }, { agents, unmatched: "deny", since: null, now });
    expect(tightened.undeclared.escapedSinceLastRun).toBe(1);
  });
});
