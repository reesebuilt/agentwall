import { afterEach, describe, expect, it } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { buildServer } from "../src/server";
import { AgentwallConfig } from "../src/config";
import { FileBackedPolicyRuntime } from "../src/policy/runtime";

function createPolicyDir(): { dir: string; policyPath: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-policy-runtime-"));
  return { dir, policyPath: path.join(dir, "policy.yaml") };
}

function writePolicy(policyPath: string, contents: string): void {
  fs.writeFileSync(policyPath, contents);
}

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("FileBackedPolicyRuntime", () => {
  it("reloads updated rules and keeps the last good rules on failure", () => {
    const { dir, policyPath } = createPolicyDir();
    tempDirs.push(dir);

    writePolicy(policyPath, `
version: "1"
rules:
  - id: "custom:allow-first"
    description: "Allow initial host"
    plane: "network"
    match:
      type: "hostname-equals"
      values: ["api.first.example"]
    decision: "allow"
    riskLevel: "low"
    reason: "First host allowed"
`);

    const runtime = new FileBackedPolicyRuntime(policyPath, {
      watch: false,
      logger: {
        error: () => {},
        warn: () => {},
      },
    });
    expect(runtime.getRules().map((rule) => rule.id)).toEqual(["custom:allow-first"]);

    writePolicy(policyPath, `
version: "1"
rules:
  - id: "custom:allow-second"
    description: "Allow updated host"
    plane: "network"
    match:
      type: "hostname-equals"
      values: ["api.second.example"]
    decision: "allow"
    riskLevel: "low"
    reason: "Second host allowed"
`);

    const reloadResult = runtime.reload();
    expect(reloadResult.reloaded).toBe(true);
    expect(runtime.getRules().map((rule) => rule.id)).toEqual(["custom:allow-second"]);

    writePolicy(policyPath, `
version: "1"
rules:
  - id: "custom:broken"
    description: "Broken rule"
    plane: "network"
    match:
      type: "hostname-equals"
    decision: "allow"
    riskLevel: "low"
    reason: "Broken"
`);

    const failedReload = runtime.reload();
    expect(failedReload.reloaded).toBe(false);
    expect(failedReload.error).toBeDefined();
    expect(runtime.getRules().map((rule) => rule.id)).toEqual(["custom:allow-second"]);
  });
});

describe("buildServer policy reload", () => {
  it("applies updated policy rules without rebuilding the server", async () => {
    const { dir, policyPath } = createPolicyDir();
    tempDirs.push(dir);

    writePolicy(policyPath, `
version: "1"
rules:
  - id: "custom:allow-openai"
    description: "Allow OpenAI"
    plane: "network"
    match:
      type: "hostname-equals"
      values: ["api.openai.com"]
    decision: "allow"
    riskLevel: "low"
    reason: "OpenAI host allowed"
`);

    const config: AgentwallConfig = {
      port: 3000,
      host: "127.0.0.1",
      logLevel: "silent",
      approval: {
        mode: "auto",
        timeoutMs: 30_000,
        backend: "memory",
      },
      policy: {
        defaultDecision: "deny",
        configPath: policyPath,
      },
      dlp: {
        enabled: true,
        redactSecrets: true,
      },
      egress: {
        enabled: true,
        defaultDeny: true,
        allowPrivateRanges: false,
        allowedHosts: [],
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

    const { app, reloadPolicy } = await buildServer(config);

    try {
      const initial = await app.inject({
        method: "POST",
        url: "/evaluate",
        payload: {
          agentId: "agent-reload",
          plane: "network",
          action: "http_request",
          payload: { url: "https://api.openai.com/v1/chat/completions" },
        },
      });
      expect(initial.statusCode).toBe(200);
      expect(initial.json().matchedRules).toContain("custom:allow-openai");
      expect(initial.json().decision).toBe("allow");

      writePolicy(policyPath, `
version: "1"
rules:
  - id: "custom:deny-openai"
    description: "Deny OpenAI"
    plane: "network"
    match:
      type: "hostname-equals"
      values: ["api.openai.com"]
    decision: "deny"
    riskLevel: "high"
    reason: "OpenAI host denied"
`);

      const reloadResult = reloadPolicy();
      expect(reloadResult?.reloaded).toBe(true);

      const afterReload = await app.inject({
        method: "POST",
        url: "/evaluate",
        payload: {
          agentId: "agent-reload",
          plane: "network",
          action: "http_request",
          payload: { url: "https://api.openai.com/v1/chat/completions" },
        },
      });
      expect(afterReload.statusCode).toBe(200);
      expect(afterReload.json().matchedRules).toContain("custom:deny-openai");
      expect(afterReload.json().decision).toBe("deny");
    } finally {
      await app.close();
    }
  });

  it("exposes scoped policy catalog in dashboard state and upserts scoped rules through dashboard control", async () => {
    const { dir, policyPath } = createPolicyDir();
    tempDirs.push(dir);

    writePolicy(policyPath, `
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

    const config: AgentwallConfig = {
      port: 3000,
      host: "127.0.0.1",
      logLevel: "silent",
      approval: {
        mode: "auto",
        timeoutMs: 30_000,
        backend: "memory",
      },
      policy: {
        defaultDecision: "deny",
        configPath: policyPath,
      },
      dlp: {
        enabled: true,
        redactSecrets: true,
      },
      egress: {
        enabled: true,
        defaultDeny: true,
        allowPrivateRanges: false,
        allowedHosts: [],
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

    const { app } = await buildServer(config);

    try {
      const initialState = await app.inject({ method: "GET", url: "/api/dashboard/state" });
      expect(initialState.statusCode).toBe(200);
      const initialCatalog = initialState.json().policyCatalog;
      expect(initialCatalog.editable).toBe(true);
      expect(initialCatalog.scopedRules).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: "custom:deny-finance-agent-file-write-in-shared-slack",
            description: expect.stringContaining("Shared Slack finance room"),
          }),
        ])
      );

      const saveResponse = await app.inject({
        method: "POST",
        url: "/api/dashboard/control/policy-scoped-rule",
        payload: {
          id: "custom:deny-treasury-agent-secret-read-in-telegram",
          description: "Treasury group cannot retrieve secrets through the treasury agent",
          plane: "identity",
          decision: "deny",
          riskLevel: "critical",
          reason: "Shared treasury room cannot trigger secret access",
          actorChannelIds: ["telegram:group:treasury"],
          subjectAgentIds: ["treasury-agent"],
          executionModes: ["answer_only"],
          enabled: true,
        },
      });

      expect(saveResponse.statusCode).toBe(200);
      expect(saveResponse.json().rule).toEqual(
        expect.objectContaining({
          id: "custom:deny-treasury-agent-secret-read-in-telegram",
          scopeSummary: expect.stringContaining("treasury-agent"),
        })
      );

      const policyContents = fs.readFileSync(policyPath, "utf-8");
      expect(policyContents).toContain("custom:deny-treasury-agent-secret-read-in-telegram");
      expect(policyContents).toContain("telegram:group:treasury");
      expect(policyContents).toContain("treasury-agent");

      const reloadedState = await app.inject({ method: "GET", url: "/api/dashboard/state" });
      expect(reloadedState.statusCode).toBe(200);
      expect(reloadedState.json().policyCatalog.scopedRules).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: "custom:deny-treasury-agent-secret-read-in-telegram",
            decision: "deny",
            riskLevel: "critical",
          }),
        ])
      );
    } finally {
      await app.close();
    }
  });

  it("tracks observed communication channels per agent in dashboard state", async () => {
    const config: AgentwallConfig = {
      port: 3000,
      host: "127.0.0.1",
      logLevel: "silent",
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
        allowedHosts: [],
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

    const { app } = await buildServer(config);

    try {
      const evaluate = await app.inject({
        method: "POST",
        url: "/evaluate",
        payload: {
          agentId: "finance-analyst-agent",
          sessionId: "session-finance-room",
          plane: "tool",
          action: "write_file",
          payload: { path: "/srv/forecast.md", content: "draft" },
          actor: {
            channelId: "slack:finance-room",
            userId: "u-finance",
            roleIds: ["analyst", "member"],
          },
        },
      });

      expect(evaluate.statusCode).toBe(200);

      const stateResponse = await app.inject({ method: "GET", url: "/api/dashboard/state" });
      expect(stateResponse.statusCode).toBe(200);
      expect(stateResponse.json().channelInventory.byAgent).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            agentId: "finance-analyst-agent",
            channels: expect.arrayContaining([
              expect.objectContaining({
                channelId: "slack:finance-room",
                sessionIds: expect.arrayContaining(["session-finance-room"]),
                userIds: expect.arrayContaining(["u-finance"]),
                roleIds: expect.arrayContaining(["analyst", "member"]),
              }),
            ]),
          }),
        ])
      );
    } finally {
      await app.close();
    }
  });
});
