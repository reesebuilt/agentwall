import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { AgentwallConfig } from "../src/config";
import { resetAuditChain } from "../src/audit/logger";
import { buildServer } from "../src/server";

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
