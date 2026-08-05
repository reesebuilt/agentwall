import { describe, expect, it } from "@jest/globals";
import { PolicyEngine } from "../src/policy/engine";
import { AgentContext } from "../src/types";

function ctx(overrides: Partial<AgentContext> & {
  agentId?: string;
  plane?: AgentContext["plane"];
  action?: string;
  payload?: Record<string, unknown>;
}): AgentContext {
  return {
    agentId: "test-agent",
    plane: "network",
    action: "http_request",
    payload: {},
    ...overrides,
  };
}

describe("PolicyEngine", () => {
  const engine = new PolicyEngine();

  it("denies localhost network requests", () => {
    const result = engine.evaluate(ctx({ payload: { url: "http://localhost:8080/admin" } }));
    expect(result.decision).toBe("deny");
    expect(result.riskLevel).toBe("critical");
    expect(result.matchedRules).toContain("net:block-ssrf-private");
  });

  it("requires approval for shell tool actions", () => {
    const result = engine.evaluate(ctx({ plane: "tool", action: "bash_exec", payload: { command: "ls -la" } }));
    expect(result.decision).toBe("approve");
    expect(result.requiresApproval).toBe(true);
    expect(result.riskLevel).toBe("high");
  });

  it("requires approval for untrusted network egress", () => {
    const result = engine.evaluate(ctx({
      payload: { url: "https://api.example.com/send" },
      provenance: [{ source: "web", trustLabel: "untrusted" }],
      flow: { direction: "egress", labels: ["external_egress"], highRisk: true, crossesBoundary: true },
    }));
    expect(result.decision).toBe("approve");
    expect(result.highRiskFlow).toBe(true);
    expect(result.matchedRules).toContain("net:approve-untrusted-egress");
  });

  it("requires approval for credential access", () => {
    const result = engine.evaluate(ctx({
      plane: "identity",
      action: "read_secret",
      payload: { key: "OPENAI_API_KEY" },
      flow: { direction: "internal", labels: ["credential_access"], highRisk: true },
    }));
    expect(result.decision).toBe("approve");
    expect(result.matchedRules).toContain("identity:flag-credential-access");
  });

  it("denies content with secrets on egress", () => {
    const result = engine.evaluate(ctx({
      plane: "content",
      action: "send_message",
      payload: { text: "Here is my key: AKIAIOSFODNN7EXAMPLE" },
      flow: { direction: "egress", labels: ["secret_material"], highRisk: true, crossesBoundary: true },
    }));
    expect(result.decision).toBe("deny");
    expect(result.matchedRules).toContain("content:block-secret-exfil");
  });

  it("approves manifest drift", () => {
    const result = engine.evaluate(ctx({
      plane: "tool",
      action: "invoke_mcp_tool",
      payload: { requiresReapproval: true },
      flow: { direction: "internal", labels: ["manifest_drift"], highRisk: true },
    }));
    expect(result.decision).toBe("approve");
    expect(result.riskLevel).toBe("critical");
  });

  it("denies communication-channel filesystem mutation", () => {
    const result = engine.evaluate(ctx({
      agentId: "generic-telegram-test-bot",
      plane: "tool",
      action: "write_file",
      payload: { path: "/tmp/pwned.txt", content: "owned" },
      actor: { channelId: "telegram:-1001234567890:4242", userId: "end-user" },
    }));

    expect(result.decision).toBe("deny");
    expect(result.requiresApproval).toBe(false);
    expect(result.riskLevel).toBe("critical");
    expect(result.matchedRules).toContain("channel:deny-filesystem-mutation");
  });

  it("denies communication-channel sensitive data access", () => {
    const result = engine.evaluate(ctx({
      agentId: "generic-telegram-test-bot",
      plane: "identity",
      action: "read_secret",
      payload: { key: "OPENAI_API_KEY" },
      actor: { channelId: "telegram:-1001234567890:4242", userId: "end-user" },
      flow: { direction: "internal", labels: ["credential_access"], highRisk: true },
    }));

    expect(result.decision).toBe("deny");
    expect(result.requiresApproval).toBe(false);
    expect(result.riskLevel).toBe("critical");
    expect(result.matchedRules).toContain("channel:deny-sensitive-data-access");
  });

  it("denies communication-channel replies that contain secrets", () => {
    const fakeCredential = ["api", "_key: ", "ABCDEFGHIJKLMNOPQRST"].join("");
    const result = engine.evaluate(ctx({
      agentId: "generic-slack-test-bot",
      plane: "content",
      action: "slack_reply",
      payload: { text: `Do not send this ${fakeCredential}` },
      actor: { channelId: "slack:C123:thread:999", userId: "employee-1" },
      flow: { direction: "egress", target: "slack:C123:thread:999" },
    }));

    expect(result.decision).toBe("deny");
    expect(result.requiresApproval).toBe(false);
    expect(result.riskLevel).toBe("critical");
    expect(result.matchedRules).toContain("channel:deny-sensitive-content-egress");
  });

  it("redacts communication-channel replies that contain PII", () => {
    const result = engine.evaluate(ctx({
      agentId: "generic-slack-test-bot",
      plane: "content",
      action: "slack_reply",
      payload: { text: "Employee email is teammate@example.com" },
      actor: { channelId: "slack:C123", userId: "employee-1" },
      flow: { direction: "egress", target: "slack:C123" },
    }));

    expect(result.decision).toBe("redact");
    expect(result.requiresApproval).toBe(false);
    expect(result.riskLevel).toBe("high");
    expect(result.matchedRules).toContain("channel:redact-pii-content-egress");
  });


  it("denies mutating tool actions in read-only mode", () => {
    const result = engine.evaluate(ctx({
      plane: "tool",
      action: "write_file",
      payload: { path: "/tmp/out.txt" },
      control: { executionMode: "read_only", reason: "operator containment" },
    }));
    expect(result.decision).toBe("deny");
    expect(result.matchedRules).toContain("control:deny-mutations-read-only");
  });

  it("denies network execution in answer-only mode", () => {
    const result = engine.evaluate(ctx({
      plane: "network",
      action: "http_request",
      payload: { url: "https://example.com" },
      control: { executionMode: "answer_only", reason: "incident containment" },
    }));
    expect(result.decision).toBe("deny");
    expect(result.matchedRules).toContain("control:deny-external-actions-answer-only");
  });

  it("attaches detection metadata for mapped rules", () => {
    const result = engine.evaluate(ctx({
      payload: { url: "http://127.0.0.1:8080/admin" },
      flow: { direction: "egress", labels: ["external_egress"], highRisk: true, crossesBoundary: true },
    }));

    expect(result.detections.length).toBeGreaterThan(0);
    expect(result.detections.map((d) => d.ruleId)).toContain("net:block-ssrf-private");
    expect(result.detections[0].mitreAttack?.techniqueId).toBeDefined();
  });

  it("denies by default when no rules match", () => {
    const result = new PolicyEngine([], "deny").evaluate(ctx({
      plane: "network",
      action: "ping",
      payload: {},
    }));
    expect(result.decision).toBe("deny");
  });
});
