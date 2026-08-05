import { afterAll, describe, expect, it } from "@jest/globals";
import { AgentwallConfig } from "../src/config";
import { buildCommunicationChannelContext, normalizeCommunicationChannelId } from "../src/integrations/communication-channel/control";
import { buildServer } from "../src/server";

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

describe("platform-neutral communication channel guardrails", () => {
  const serverPromise = buildServer(config);

  afterAll(async () => {
    const { app } = await serverPromise;
    await app.close();
  });

  it("normalizes Slack and Telegram channel/thread ids", () => {
    expect(normalizeCommunicationChannelId({ platform: "slack", channelId: "C123", threadId: "171000.1" })).toBe("slack:C123:thread:171000.1");
    expect(normalizeCommunicationChannelId({ platform: "slack", channelId: "slack:C123", threadId: "171000.1" })).toBe("slack:C123:thread:171000.1");
    expect(normalizeCommunicationChannelId({ platform: "slack", channelId: "slack:C123:thread:171000.1", threadId: "171000.1" })).toBe("slack:C123:thread:171000.1");
    expect(normalizeCommunicationChannelId({ platform: "telegram", channelId: "-100123", threadId: "4242" })).toBe("telegram:-100123:4242");
    expect(normalizeCommunicationChannelId({ platform: "telegram", channelId: "telegram:-100123", threadId: "4242" })).toBe("telegram:-100123:4242");
    expect(normalizeCommunicationChannelId({ platform: "telegram", channelId: "telegram:-100123:4242", threadId: "4242" })).toBe("telegram:-100123:4242");
  });

  it("builds an Agentwall context scoped to the communication channel", () => {
    const context = buildCommunicationChannelContext({
      agentId: "generic-slack-test-bot",
      platform: "slack",
      channelId: "C123",
      userId: "U456",
      plane: "tool",
      action: "write_file",
      payload: { path: "/tmp/nope" },
    });

    expect(context.actor?.channelId).toBe("slack:C123");
    expect(context.actor?.userId).toBe("slack-user:U456");
    expect(context.flow?.labels).toEqual(expect.arrayContaining(["destructive_action", "high_risk"]));
  });

  it("denies secret-bearing Slack replies before delivery", async () => {
    const { app } = await serverPromise;
    const fakeCredential = ["api", "_key: ", "ABCDEFGHIJKLMNOPQRST"].join("");

    const response = await app.inject({
      method: "POST",
      url: "/integrations/communication-channel/guardrail",
      payload: {
        agentId: "generic-slack-test-bot",
        platform: "slack",
        channelId: "C123",
        threadId: "171000.1",
        userId: "U456",
        plane: "content",
        action: "slack_reply",
        text: `Here is the internal credential ${fakeCredential}`,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.channelId).toBe("slack:C123:thread:171000.1");
    expect(body.policy.decision).toBe("deny");
    expect(body.policy.matchedRules).toContain("channel:deny-sensitive-content-egress");
    expect(body.delivery).toMatchObject({ status: "blocked", sendAllowed: false });
    expect(body.content.containsSecrets).toBe(true);
  });

  it("redacts PII-bearing Telegram replies and records the channel inventory", async () => {
    const { app } = await serverPromise;

    const response = await app.inject({
      method: "POST",
      url: "/integrations/communication-channel/guardrail",
      payload: {
        agentId: "generic-telegram-test-bot",
        platform: "telegram",
        channelId: "-1001234567890",
        threadId: "4242",
        userId: "777",
        plane: "content",
        action: "telegram_reply",
        text: "Employee email is teammate@example.com",
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.policy.decision).toBe("redact");
    expect(body.policy.matchedRules).toContain("channel:redact-pii-content-egress");
    expect(body.delivery).toMatchObject({ status: "redaction_required", sendAllowed: false });
    expect(body.content.redactedText).toContain("[REDACTED:EMAIL]");

    const stateResponse = await app.inject({ method: "GET", url: "/api/dashboard/state" });
    const state = stateResponse.json();
    expect(state.channelInventory.recent).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ agentId: "generic-telegram-test-bot", channelId: "telegram:-1001234567890:4242" }),
      ])
    );
  });
});
