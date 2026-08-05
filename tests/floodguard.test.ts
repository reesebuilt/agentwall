import { describe, expect, it } from "@jest/globals";
import { RuntimeFloodGuard } from "../src/runtime/floodguard";

const guard = new RuntimeFloodGuard({
  enabled: true,
  requestPerMinutePerSession: 2,
  toolActionPerMinutePerSession: 1,
  approvalRequestsPerMinutePerSession: 2,
  approvalResponsesPerMinutePerActor: 1,
  maxPendingApprovalsGlobal: 3,
  maxPendingApprovalsPerSession: 2,
  costBudgetPerHourPerSession: 20,
  shield: {
    requestRateMultiplier: 0.5,
    approvalRequestRateMultiplier: 0.5,
    maxPendingGlobalMultiplier: 0.5,
    maxPendingSessionMultiplier: 0.5,
    defaultDurationMs: 60_000,
    queuePriorityPressureThreshold: 0.5,
  },
  costWeights: {
    evaluateBase: 1,
    approvalRequest: 3,
    approvalRequiresManual: 2,
    toolActionMultiplier: 2,
    highRiskMultiplier: 2,
    criticalRiskMultiplier: 3,
  },
});

describe("RuntimeFloodGuard", () => {
  it("limits evaluate request bursts per session", () => {
    const base = 1_000_000;
    const ctx = { agentId: "a1", sessionId: "s1", plane: "network", action: "http_request", payload: {} } as const;

    expect(guard.evaluateRequest(ctx as never, base).allowed).toBe(true);
    expect(guard.evaluateRequest(ctx as never, base + 10).allowed).toBe(true);
    const third = guard.evaluateRequest(ctx as never, base + 20);
    expect(third.allowed).toBe(false);
    expect(third.reason).toContain("Request flood");
  });

  it("limits tool abuse bursts separately", () => {
    const base = 2_000_000;
    const ctx = { agentId: "a2", sessionId: "s2", plane: "tool", action: "bash_exec", payload: {} } as const;

    expect(guard.evaluateRequest(ctx as never, base).allowed).toBe(true);
    const second = guard.evaluateRequest(ctx as never, base + 100);
    expect(second.allowed).toBe(false);
    expect(second.reason).toContain("Tool action flood");
  });

  it("blocks approval queue floods", () => {
    const req = {
      context: { agentId: "a3", sessionId: "s3", plane: "tool", action: "bash_exec", payload: {} },
      policyResult: { decision: "approve", riskLevel: "high", matchedRules: [], reasons: [], requiresApproval: true, highRiskFlow: true },
    };

    const blockedGlobal = guard.approvalRequest(req as never, "always", 0, 3, 3_000_000);
    expect(blockedGlobal.allowed).toBe(false);
    expect(blockedGlobal.reason).toContain("global pending");

    const blockedSession = guard.approvalRequest(req as never, "always", 2, 0, 3_000_100);
    expect(blockedSession.allowed).toBe(false);
    expect(blockedSession.reason).toContain("session");
  });

  it("throttles approval response floods", () => {
    const base = 4_000_000;
    expect(guard.approvalResponse("operator-1", base).allowed).toBe(true);
    const blocked = guard.approvalResponse("operator-1", base + 50);
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toContain("Approval response flood");
  });

  it("supports shield mode and queue prioritization", () => {
    const base = 5_000_000;
    guard.setShieldMode(true, base, 60_000);
    const req = {
      context: { agentId: "a4", sessionId: "s4", plane: "tool", action: "safe_tool", payload: {} },
      policyResult: { decision: "approve", riskLevel: "low", matchedRules: [], reasons: [], requiresApproval: true, highRiskFlow: false },
    };

    const blocked = guard.approvalRequest(req as never, "always", 1, 1, base + 100);
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toContain("prioritization");

    const snapshot = guard.getTelemetrySnapshot(base + 120);
    expect(snapshot.mode).toBe("shield");
    expect(snapshot.blockedByCategory.queue).toBeGreaterThan(0);

    const override = guard.setSessionOverride("session-high", 2, base + 130, 60_000);
    expect(override.sessionId).toBe("session-high");
    expect(guard.getTelemetrySnapshot(base + 140).sessionOverrides[0]?.sessionId).toBe("session-high");
    expect(guard.clearSessionOverride("session-high").cleared).toBe(true);

    guard.setShieldMode(false, base + 200);
    expect(guard.getStatus(base + 220).mode).toBe("normal");
  });
});
