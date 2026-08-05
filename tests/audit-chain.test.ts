import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { AgentwallConfig } from "../src/config";
import { resetAuditChain } from "../src/audit/logger";
import { buildServer } from "../src/server";
import { createHash } from "crypto";
import {
  canonicalizeAuditPayload,
  canonicalizeAuditPayloadLocaleLegacy,
  chainAuditEvent,
  findDuplicateKey,
  rehashAuditEvent,
  type AuditChainState,
} from "../src/audit/chain";
import { AuditEvent } from "../src/types";

const config: AgentwallConfig = {
  port: 3017,
  host: "127.0.0.1",
  logLevel: "silent",
  dashboard: {},
  approval: {
    mode: "always",
    timeoutMs: 30_000,
    backend: "memory",
  },
  policy: {
    defaultDecision: "deny",
  },
  dlp: {
    enabled: true,
    redactSecrets: true,
  },
  egress: {
    enabled: true,
    defaultDeny: true,
    allowPrivateRanges: false,
    allowedHosts: ["api.openai.com"],
    allowedSchemes: ["https"],
    allowedPorts: [443],
  },
  manifestIntegrity: {
    enabled: true,
  },
  watchdog: {
    enabled: true,
    staleAfterMs: 15_000,
    timeoutMs: 30_000,
    killSwitchMode: "deny_all",
  },
};

describe("Audit chaining", () => {
  let server: Awaited<ReturnType<typeof buildServer>>;

  beforeEach(async () => {
    resetAuditChain();
    server = await buildServer(config);
  });

  afterEach(async () => {
    await server.app.close();
    resetAuditChain();
  });

  it("links successive /evaluate events with tamper-evident integrity metadata", async () => {
    const firstResponse = await server.app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-alpha",
        sessionId: "session-alpha",
        plane: "tool",
        action: "bash_exec",
        payload: { command: "id" },
        provenance: [{ source: "user", trustLabel: "trusted" }],
        flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
      },
    });
    const secondResponse = await server.app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-bravo",
        sessionId: "session-bravo",
        plane: "tool",
        action: "bash_exec",
        payload: { command: "whoami" },
        provenance: [{ source: "user", trustLabel: "trusted" }],
        flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
      },
    });

    expect(firstResponse.statusCode).toBe(200);
    expect(secondResponse.statusCode).toBe(200);

    const snapshot = server.runtime.getSnapshot(server.engine.getRules().length);
    const [latest, previous] = snapshot.auditFeed;

    expect(latest.id).not.toBe(previous.id);
    expect(previous.integrity.chainIndex).toBe(0);
    expect(previous.integrity.previousHash).toBeNull();
    expect(previous.integrity.hash).toEqual(expect.any(String));
    expect(previous.integrity.hash.length).toBeGreaterThan(0);
    expect(previous.integrity.algorithm).toBe("sha256");
    expect(previous.integrity.status).toBe("chained-local");

    expect(latest.integrity.chainIndex).toBe(1);
    expect(latest.integrity.previousHash).toBe(previous.integrity.hash);
    expect(latest.integrity.hash).toEqual(expect.any(String));
    expect(latest.integrity.hash.length).toBeGreaterThan(0);
    expect(latest.integrity.hash).not.toBe(previous.integrity.hash);
    expect(latest.integrity.algorithm).toBe("sha256");
    expect(latest.integrity.status).toBe("chained-local");
  });
});

describe("Audit canonicalization cu1", () => {
  const chainStart: AuditChainState = { chainIndex: 0, previousHash: null };

  function record(overrides: Partial<Omit<AuditEvent, "integrity">> = {}): Omit<AuditEvent, "integrity"> {
    return {
      id: "11111111-1111-4111-8111-111111111111",
      timestamp: "2026-01-01T00:00:00.000Z",
      agentId: "agent-alpha",
      plane: "network",
      action: "egress:https",
      decision: "allow",
      riskLevel: "low",
      matchedRules: [],
      reasons: [],
      requiresApproval: false,
      highRiskFlow: false,
      ...overrides,
    };
  }

  /**
   * The hash material skeleton, spelled out here rather than imported. These tests are the
   * tripwire for a silent format change: a producer that rewrites the skeleton has to fail
   * a test instead of agreeing with itself.
   */
  function hashUnder(canonicalPayload: string, state: AuditChainState): string {
    return createHash("sha256")
      .update(
        JSON.stringify({
          chainIndex: state.chainIndex,
          previousHash: state.previousHash,
          algorithm: "sha256",
          payload: canonicalPayload,
        })
      )
      .digest("hex");
  }

  it("hashes a record identically whatever order its sibling keys were inserted in", () => {
    const forward = chainAuditEvent(record({ metadata: { b: "1", a: "2" } }), chainStart);
    const reversed = chainAuditEvent(record({ metadata: { a: "2", b: "1" } }), chainStart);

    expect(forward.integrity.hash).toBe(reversed.integrity.hash);
  });

  it("orders sibling keys by code unit, putting Zebra before apple", () => {
    const event = record({ metadata: { apple: "1", Zebra: "2" } });

    expect(canonicalizeAuditPayload(event)).toContain('"metadata":{"Zebra":"2","apple":"1"}');
    // Locale collation puts these the other way round. A verifier that cannot see which
    // ordering was used cannot recompute the hash, so cu1 fixes the code unit ordering and
    // the record names it.
    expect(canonicalizeAuditPayloadLocaleLegacy(event)).toContain('"metadata":{"apple":"1","Zebra":"2"}');
  });

  it("keeps array order at every depth while sorting objects nested inside arrays", () => {
    const nested = { outer: [[3, 1, 2], { b: "1", a: "2" }] } as unknown as Omit<AuditEvent, "integrity">;

    expect(canonicalizeAuditPayload(nested)).toBe('{"outer":[[3,1,2],{"a":"2","b":"1"}]}');
  });

  it("changes the hash when array order changes, because order is payload", () => {
    const ascending = chainAuditEvent(record({ reasons: ["first", "second"] }), chainStart);
    const descending = chainAuditEvent(record({ reasons: ["second", "first"] }), chainStart);

    expect(ascending.integrity.hash).not.toBe(descending.integrity.hash);
  });

  it("marks new records canon cu1 and rehashes them to their stored hash", () => {
    const chained = chainAuditEvent(record({ metadata: { command: "id" } }), chainStart);

    expect(chained.integrity.canon).toBe("cu1");
    expect(chained.integrity.hash).toBe(hashUnder(canonicalizeAuditPayload(record({ metadata: { command: "id" } })), chainStart));
    expect(rehashAuditEvent(chained)).toBe(chained.integrity.hash);
  });

  it("still verifies an unmarked record whose keys collate differently than they sort", () => {
    const event = record({ metadata: { aws_key: "redacted", "aws-key": "redacted" } });
    const legacyHash = hashUnder(canonicalizeAuditPayloadLocaleLegacy(event), chainStart);
    const legacy = {
      ...event,
      integrity: {
        chainIndex: 0,
        hash: legacyHash,
        previousHash: null,
        algorithm: "sha256",
        status: "chained-local",
      },
    } as AuditEvent;

    // These two keys are the case that matters: collation and code unit order disagree, so
    // this record is only reproducible through the legacy path. Dropping that path would
    // call an operator's untouched history tampered.
    expect(chainAuditEvent(event, chainStart).integrity.hash).not.toBe(legacyHash);
    expect(rehashAuditEvent(legacy)).toBe(legacyHash);
  });

  it("reports a tampered unmarked record against cu1 rather than the form it was written in", () => {
    const event = record({ metadata: { aws_key: "redacted", "aws-key": "redacted" } });
    const tamperedPayload = record({ metadata: { aws_key: "leaked", "aws-key": "redacted" } });
    const tampered = {
      ...tamperedPayload,
      integrity: {
        chainIndex: 0,
        hash: hashUnder(canonicalizeAuditPayloadLocaleLegacy(event), chainStart),
        previousHash: null,
        algorithm: "sha256",
        status: "chained-local",
      },
    } as AuditEvent;

    const rehashed = rehashAuditEvent(tampered);

    expect(rehashed).not.toBe(tampered.integrity.hash);
    expect(rehashed).toBe(hashUnder(canonicalizeAuditPayload(tamperedPayload), chainStart));
  });

  it("detects a single flipped payload byte", () => {
    const chained = chainAuditEvent(record({ metadata: { command: "id" } }), chainStart);
    const tampered = { ...chained, metadata: { command: "ip" } } as AuditEvent;

    expect(rehashAuditEvent(tampered)).not.toBe(tampered.integrity.hash);
  });
});

/**
 * Duplicate members are found on the raw line, not after parsing.
 *
 * Parsers disagree about them and none of them say so: V8 keeps the last occurrence,
 * other stacks keep the first, a strict decoder refuses the line. A record whose meaning
 * depends on which language read it cannot be evidence, so it has to be caught before
 * JSON.parse collapses the duplicate out of existence.
 */
describe("duplicate member detection", () => {
  it("finds a duplicate that JSON.parse silently collapses", () => {
    const line = '{"decision":"deny","agentId":"curl","decision":"allow"}';
    // What the parser hands every later check: one member, no trace of the other.
    expect(Object.keys(JSON.parse(line))).toEqual(["decision", "agentId"]);
    expect(findDuplicateKey(line)).toBe("decision");
  });

  it("finds a duplicate nested inside metadata or an array element", () => {
    expect(findDuplicateKey('{"a":1,"metadata":{"host":"a.example","host":"b.example"}}')).toBe("host");
    expect(findDuplicateKey('{"matchedRules":[{"id":1,"id":2}]}')).toBe("id");
  });

  it("compares decoded keys, so an escaped spelling is the same member", () => {
    expect(findDuplicateKey('{"a":1,"\\u0061":2}')).toBe("a");
    expect(findDuplicateKey('{"\\ud83d\\ude00":1,"\\ud83d\\ude00":2}')).toBe("\u{1f600}");
  });

  it("accepts the same key in sibling objects, which is ordinary data", () => {
    expect(findDuplicateKey('{"a":{"host":1},"b":{"host":2}}')).toBeNull();
    expect(findDuplicateKey('{"rules":[{"id":1},{"id":2}]}')).toBeNull();
  });

  it("is not fooled by a duplicate spelling that appears inside a string value", () => {
    expect(findDuplicateKey('{"reason":"\\"id\\":1,\\"id\\":2","id":7}')).toBeNull();
  });

  it("gives up quietly on a line it cannot read rather than throwing", () => {
    // This also runs on the write path through summarizeSegment, so a corrupt line must
    // not throw a scheduled anchor pass out of existence. The caller reports the parse
    // failure; guessing at a broken line's structure would invent findings.
    expect(findDuplicateKey('{"a\\qb":1}')).toBeNull();
    expect(findDuplicateKey('{"id":"torn","integ')).toBeNull();
    expect(findDuplicateKey("")).toBeNull();
  });
});
