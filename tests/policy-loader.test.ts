import { afterEach, describe, expect, it } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { loadDeclarativePolicyRules } from "../src/policy/loader";
import { PolicyEngine } from "../src/policy/engine";
import { builtinRules } from "../src/policy/rules";
import { AgentContext } from "../src/types";

function writePolicyFile(contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-policy-"));
  const filePath = path.join(dir, "policy.yaml");
  fs.writeFileSync(filePath, contents);
  return filePath;
}

function writePolicyJsonFile(contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-policy-json-"));
  const filePath = path.join(dir, "policy.json");
  fs.writeFileSync(filePath, contents);
  return filePath;
}

function ctx(overrides: Partial<AgentContext>): AgentContext {
  return {
    agentId: "test-agent",
    plane: "network",
    action: "http_request",
    payload: {},
    ...overrides,
  };
}

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("loadDeclarativePolicyRules", () => {
  it("loads hostname and provenance/flow rules from YAML", () => {
    const policyPath = writePolicyFile(`
version: "1"
rules:
  - id: "custom:allow-openai"
    description: "Allow approved API host"
    plane: "network"
    match:
      type: "hostname-equals"
      values: ["api.openai.com"]
    decision: "allow"
    riskLevel: "low"
    reason: "Approved API destination"

  - id: "custom:approve-web-egress"
    description: "Require approval for untrusted web-driven outbound content"
    plane: "content"
    match:
      provenance:
        source: ["web"]
        trustLabel: ["untrusted", "derived"]
      flow:
        direction: "egress"
        labels: ["external_egress"]
    decision: "approve"
    riskLevel: "high"
    reason: "Outbound content is being driven by untrusted web input"
`);
    tempDirs.push(path.dirname(policyPath));

    const rules = loadDeclarativePolicyRules(policyPath);
    const engine = new PolicyEngine([...builtinRules, ...rules], "deny");

    const allowResult = engine.evaluate(ctx({
      payload: { url: "https://api.openai.com/v1/chat/completions" },
    }));
    expect(allowResult.matchedRules).toContain("custom:allow-openai");
    expect(allowResult.decision).toBe("allow");

    const approveResult = engine.evaluate(ctx({
      plane: "content",
      action: "send_message",
      payload: { text: "send it" },
      provenance: [{ source: "web", trustLabel: "untrusted" }],
      flow: { direction: "egress", labels: ["external_egress"], highRisk: true },
    }));
    expect(approveResult.matchedRules).toContain("custom:approve-web-egress");
    expect(approveResult.decision).toBe("approve");
  });

  it("matches actor scope and degraded execution mode rules", () => {
    const policyPath = writePolicyFile(`
version: "1"
rules:
  - id: "custom:deny-discord-mod-shell"
    description: "Deny shell execution for Discord moderators while the workspace is read-only"
    plane: "tool"
    match:
      action:
        includes: ["exec"]
      actor:
        channelId: ["discord:ops"]
        roleId: ["moderator"]
      control:
        executionMode: ["read_only"]
    decision: "deny"
    riskLevel: "high"
    reason: "Read-only containment forbids moderator shell execution in this channel"
`);
    tempDirs.push(path.dirname(policyPath));

    const rules = loadDeclarativePolicyRules(policyPath);
    const engine = new PolicyEngine([...builtinRules, ...rules], "deny");

    const result = engine.evaluate(ctx({
      plane: "tool",
      action: "exec",
      payload: { command: "touch /tmp/pwned" },
      actor: { channelId: "discord:ops", userId: "u-1", roleIds: ["moderator"] },
      control: { executionMode: "read_only" },
    }));

    expect(result.matchedRules).toContain("custom:deny-discord-mod-shell");
    expect(result.decision).toBe("deny");
  });

  it("matches subject plus actor scope for channel-specific agent blockers", () => {
    const policyPath = writePolicyFile(`
version: "1"
rules:
  - id: "custom:deny-finance-agent-file-write-in-shared-slack"
    description: "Shared Slack finance room cannot drive filesystem writes through the finance analyst agent"
    plane: "tool"
    match:
      action:
        includes: ["write", "patch"]
      actor:
        channelId: ["slack:finance-room"]
      subject:
        agentId: ["finance-analyst-agent"]
    decision: "deny"
    riskLevel: "high"
    reason: "Shared business channels cannot mutate the finance analyst agent filesystem"
`);
    tempDirs.push(path.dirname(policyPath));

    const rules = loadDeclarativePolicyRules(policyPath);
    const engine = new PolicyEngine([...builtinRules, ...rules], "allow");

    const blocked = engine.evaluate(ctx({
      agentId: "finance-analyst-agent",
      plane: "tool",
      action: "write_file",
      payload: { path: "/srv/internal/forecast.md", content: "draft" },
      actor: { channelId: "slack:finance-room", userId: "u-finance" },
    }));
    expect(blocked.matchedRules).toContain("custom:deny-finance-agent-file-write-in-shared-slack");
    expect(blocked.decision).toBe("deny");
    expect(rules[0]?.scope).toEqual({
      actor: { channelIds: ["slack:finance-room"], userIds: undefined, roleIds: undefined },
      subject: { agentIds: ["finance-analyst-agent"], sessionIds: undefined },
    });

    const differentAgent = engine.evaluate(ctx({
      agentId: "sales-assistant-agent",
      plane: "tool",
      action: "write_file",
      payload: { path: "/srv/internal/forecast.md", content: "draft" },
      actor: { channelId: "slack:finance-room", userId: "u-finance" },
    }));
    expect(differentAgent.matchedRules).not.toContain("custom:deny-finance-agent-file-write-in-shared-slack");
    expect(differentAgent.matchedRules).toContain("channel:deny-filesystem-mutation");
    expect(differentAgent.decision).toBe("deny");
  });

  it("rejects hostname rules that target private hosts", () => {
    const policyPath = writePolicyFile(`
version: "1"
rules:
  - id: "custom:bad-private-host"
    description: "This should fail"
    plane: "network"
    match:
      type: "hostname-equals"
      values: ["localhost"]
    decision: "allow"
    riskLevel: "low"
    reason: "Nope"
`);
    tempDirs.push(path.dirname(policyPath));

    expect(() => loadDeclarativePolicyRules(policyPath)).toThrow(/private or local hosts/i);
  });

  it("loads declarative rules from JSON", () => {
    const policyPath = writePolicyJsonFile(JSON.stringify({
      version: "1",
      rules: [
        {
          id: "custom:allow-example-json",
          description: "Allow JSON-defined host",
          plane: "network",
          match: {
            type: "hostname-equals",
            values: ["api.example.com"],
          },
          decision: "allow",
          riskLevel: "low",
          reason: "Approved JSON destination",
        },
      ],
    }, null, 2));
    tempDirs.push(path.dirname(policyPath));

    const rules = loadDeclarativePolicyRules(policyPath);
    const engine = new PolicyEngine([...builtinRules, ...rules], "deny");
    const result = engine.evaluate(ctx({
      payload: { url: "https://api.example.com/v1/status" },
    }));

    expect(result.matchedRules).toContain("custom:allow-example-json");
    expect(result.decision).toBe("allow");
  });
});
