import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { resetAuditChain } from "../src/audit/logger";
import { AgentwallConfig } from "../src/config";
import { buildServer } from "../src/server";
import { verifyCapabilityTicketSignature } from "../src/runtime/capabilities";

const config: AgentwallConfig = {
  port: 3018,
  host: "127.0.0.1",
  logLevel: "silent",
  dashboard: {},
  approval: {
    mode: "auto",
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

describe("Capability tickets", () => {
  let server: Awaited<ReturnType<typeof buildServer>>;

  beforeEach(async () => {
    resetAuditChain();
    server = await buildServer(config);
  });

  afterEach(async () => {
    await server.app.close();
    resetAuditChain();
  });

  it("issues a signed short-lived ticket for allowed executable requests", async () => {
    const response = await server.app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-capability",
        sessionId: "session-capability",
        plane: "tool",
        action: "write_file",
        actor: {
          userId: "user-123",
          roleIds: ["operator"],
        },
        payload: {
          path: "/tmp/report.txt",
          content: "hello",
        },
        flow: {
          direction: "internal",
          labels: ["destructive_action"],
          highRisk: true,
        },
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.decision).toBe("allow");
    expect(body.requiresApproval).toBe(false);
    expect(body.capabilityTicket).toBeDefined();
    expect(verifyCapabilityTicketSignature(body.capabilityTicket)).toBe(true);
    expect(Date.parse(body.capabilityTicket.expiresAt)).toBeGreaterThan(Date.now());
    expect(Date.parse(body.capabilityTicket.expiresAt)).toBeGreaterThan(Date.parse(body.capabilityTicket.issuedAt));
    expect(body.capabilityTicket).toEqual(
      expect.objectContaining({
        decision: "allow",
        riskLevel: "medium",
        agentId: "agent-capability",
        sessionId: "session-capability",
        plane: "tool",
        action: "write_file",
        actor: {
          userId: "user-123",
          roleIds: ["operator"],
        },
        constraints: {
          payloadKeys: ["content", "path"],
          flow: {
            direction: "internal",
            labels: ["destructive_action"],
            highRisk: true,
          },
        },
        signature: expect.any(String),
      })
    );
  });

  it("does not issue a ticket for denied requests", async () => {
    const response = await server.app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-denied",
        sessionId: "session-denied",
        plane: "network",
        action: "http_request",
        payload: {
          url: "http://127.0.0.1:8080/admin",
        },
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.decision).toBe("deny");
    expect(body.capabilityTicket).toBeUndefined();
  });

  it("does not issue an active ticket when the request still requires approval", async () => {
    const response = await server.app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-approval",
        sessionId: "session-approval",
        plane: "tool",
        action: "bash_exec",
        payload: {
          command: "id",
        },
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.decision).toBe("approve");
    expect(body.requiresApproval).toBe(true);
    expect(body.capabilityTicket).toBeUndefined();
  });
});
