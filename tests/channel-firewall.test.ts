import { afterAll, describe, expect, it } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { AgentwallConfig } from "../src/config";
import { buildServer } from "../src/server";

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-channel-firewall-"));
const policyPath = path.join(tempDir, "policy.yaml");
fs.writeFileSync(policyPath, "version: '1'\nrules: []\n");

const config: AgentwallConfig = {
  port: 3000,
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
    enabled: false,
    staleAfterMs: 15_000,
    timeoutMs: 30_000,
    killSwitchMode: "deny_all",
  },
};

describe("channel firewall profile controls", () => {
  const serverPromise = buildServer(config);

  afterAll(async () => {
    const { app } = await serverPromise;
    await app.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("serves the operator console surface for channel controls", async () => {
    const { app } = await serverPromise;
    const html = await app.inject({ method: "GET", url: "/" });
    const js = await app.inject({ method: "GET", url: "/app.js" });

    expect(html.statusCode).toBe(200);
    expect(html.body).toContain("Agentwall status");
    expect(html.body).toContain("Policy");
    expect(html.body).toContain("Agents");
    expect(html.body).toContain("Operations");
    expect(js.body).toContain("function renderPolicy");
    expect(js.body).toContain("function renderOperatorAction");
    expect(js.body).toContain("/api/operator/actions");
  });

  it("writes firewall profile rules and hot-reloads them into policy evaluation", async () => {
    const { app } = await serverPromise;
    const agentId = "generic-telegram-test-bot";
    const channelId = "telegram:-1001234567890:4242";

    const saveResponse = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/channel-firewall-profile",
      payload: { agentId, channelId, profile: "answer_only" },
    });

    expect(saveResponse.statusCode).toBe(200);
    const saved = saveResponse.json();
    expect(saved.ok).toBe(true);
    expect(saved.lane).toMatchObject({ agentId, channelId, profile: "answer_only" });

    const stateResponse = await app.inject({ method: "GET", url: "/api/dashboard/state" });
    const state = stateResponse.json();
    expect(state.policyCatalog.channelFirewall.profiles.answer_only).toBe("Answer only");
    expect(state.policyCatalog.channelFirewall.lanes).toEqual(
      expect.arrayContaining([expect.objectContaining({ agentId, channelId, profile: "answer_only" })])
    );

    const contentResponse = await app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId,
        plane: "content",
        action: "telegram_reply",
        payload: { text: "safe reply" },
        actor: { channelId, userId: "telegram-user:777" },
        flow: { direction: "egress", target: channelId },
      },
    });
    const contentResult = contentResponse.json();
    expect(contentResult.decision).toBe("allow");
    expect(contentResult.matchedRules).toEqual(expect.arrayContaining([expect.stringContaining(":allow-replies")]));

    const toolResponse = await app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId,
        plane: "tool",
        action: "search_web",
        payload: { query: "anything" },
        actor: { channelId, userId: "telegram-user:777" },
      },
    });
    const toolResult = toolResponse.json();
    expect(toolResult.decision).toBe("deny");
    expect(toolResult.matchedRules).toEqual(expect.arrayContaining([expect.stringContaining(":tool-control")]));
  });

  it("runs the product proof suite for an answer-only Telegram lane", async () => {
    const { app } = await serverPromise;
    const agentId = "generic-telegram-test-bot";
    const channelId = "telegram:-1001234567890:4242";

    const saveResponse = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/channel-firewall-profile",
      payload: { agentId, channelId, profile: "answer_only" },
    });
    expect(saveResponse.statusCode).toBe(200);

    const proofResponse = await app.inject({
      method: "POST",
      url: "/api/dashboard/proof/communication-channel",
      payload: { agentId, platform: "telegram", channelId },
    });

    expect(proofResponse.statusCode).toBe(200);
    const proof = proofResponse.json();
    expect(proof.ok).toBe(true);
    expect(proof.target).toMatchObject({ agentId, platform: "telegram", channelId });
    expect(proof.summary.status).toBe("passed");
    expect(proof.checks).toHaveLength(5);

    const byId = Object.fromEntries(proof.checks.map((check: { id: string }) => [check.id, check]));
    expect(byId.safe_reply).toMatchObject({ expected: "allow", passed: true, decision: "allow" });
    expect(byId.write_file_denied).toMatchObject({ expected: "deny", required: true, passed: true, decision: "deny" });
    expect(byId.secret_access_denied).toMatchObject({ expected: "deny", required: true, passed: true, decision: "deny" });
    expect(byId.pii_reply_redacted).toMatchObject({ expected: "redact", required: true, passed: true, decision: "redact" });
    expect(byId.secret_reply_denied).toMatchObject({ expected: "deny", required: true, passed: true, decision: "deny" });
    expect(byId.write_file_denied.matchedRules).toEqual(expect.arrayContaining(["channel:deny-filesystem-mutation"]));
    expect(byId.secret_access_denied.matchedRules).toEqual(expect.arrayContaining(["channel:deny-sensitive-data-access"]));
    proof.checks.forEach((check: { auditEventId?: string }) => expect(check.auditEventId).toBeTruthy());
  });
});
