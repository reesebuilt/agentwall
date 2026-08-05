import { afterAll, describe, expect, it, jest } from "@jest/globals";
import { AgentwallConfig } from "../src/config";
import { normalizeTelegramChannelId, planGenericTelegramTestBotAction } from "../src/integrations/telegram/generic-test-bot";
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

const telegramWriteUpdate = {
  update_id: 1001,
  message: {
    message_id: 42,
    message_thread_id: 4242,
    from: { id: 777, is_bot: false, first_name: "End", username: "enduser" },
    chat: { id: -1001234567890, type: "supergroup", title: "Agentwall Buildout" },
    text: "/write path=/tmp/pwned.txt content=owned",
  },
};

const telegramSecretUpdate = {
  update_id: 1002,
  message: {
    message_id: 43,
    message_thread_id: 4242,
    from: { id: 777, is_bot: false, first_name: "End", username: "enduser" },
    chat: { id: -1001234567890, type: "supergroup", title: "Agentwall Buildout" },
    text: "/secret key=OPENAI_API_KEY",
  },
};

const TELEGRAM_TEST_HEADER_VALUE = ["test", "webhook", "value"].join("-");

process.env.AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET = TELEGRAM_TEST_HEADER_VALUE;

describe("generic Telegram test bot adapter", () => {
  const serverPromise = buildServer(config);

  afterAll(async () => {
    const { app } = await serverPromise;
    await app.close();
    delete process.env.AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET;
  });

  it("normalizes Telegram topic IDs into Agentwall actor channel IDs", () => {
    expect(normalizeTelegramChannelId(telegramWriteUpdate.message)).toBe("telegram:-1001234567890:4242");
  });

  it("plans Telegram write prompts as filesystem tool actions with channel origin", () => {
    const planned = planGenericTelegramTestBotAction(telegramWriteUpdate);

    expect(planned.context.agentId).toBe("generic-telegram-test-bot");
    expect(planned.context.plane).toBe("tool");
    expect(planned.context.action).toBe("write_file");
    expect(planned.context.actor?.channelId).toBe("telegram:-1001234567890:4242");
    expect(planned.context.actor?.userId).toBe("telegram-user:777");
  });

  it("rejects Telegram webhook calls without the configured secret token", async () => {
    const { app } = await serverPromise;

    const response = await app.inject({
      method: "POST",
      url: "/integrations/telegram/generic-test-bot/webhook",
      payload: telegramWriteUpdate,
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ ok: false, error: "Invalid Telegram webhook secret" });
  });

  it("fails closed when the webhook secret environment variable is unset", async () => {
    const { app } = await serverPromise;
    const previous = process.env.AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET;
    delete process.env.AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET;

    try {
      const response = await app.inject({
        method: "POST",
        url: "/integrations/telegram/generic-test-bot/webhook",
        headers: { "x-telegram-bot-api-secret-token": TELEGRAM_TEST_HEADER_VALUE },
        payload: telegramWriteUpdate,
      });

      expect(response.statusCode).toBe(503);
      expect(response.json().ok).toBe(false);
    } finally {
      process.env.AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET = previous;
    }
  });

  it("denies Telegram end-user filesystem mutation through the webhook path", async () => {
    const { app } = await serverPromise;

    const response = await app.inject({
      method: "POST",
      url: "/integrations/telegram/generic-test-bot/webhook",
      headers: { "x-telegram-bot-api-secret-token": TELEGRAM_TEST_HEADER_VALUE },
      payload: telegramWriteUpdate,
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.ok).toBe(true);
    expect(body.channelId).toBe("telegram:-1001234567890:4242");
    expect(body.plannedAction).toMatchObject({
      agentId: "generic-telegram-test-bot",
      plane: "tool",
      action: "write_file",
    });
    expect(body.policy.decision).toBe("deny");
    expect(body.policy.requiresApproval).toBe(false);
    expect(body.policy.matchedRules).toContain("channel:deny-filesystem-mutation");
    expect(body.telegramReply.mode).toBe("dry_run");
    expect(body.telegramReply.status).toBe("skipped_policy_decision");
    expect(body.telegramReply.blocked).toBe(true);
  });

  it("denies Telegram end-user secret access through the webhook path", async () => {
    const { app } = await serverPromise;

    const response = await app.inject({
      method: "POST",
      url: "/integrations/telegram/generic-test-bot/webhook",
      headers: { "x-telegram-bot-api-secret-token": TELEGRAM_TEST_HEADER_VALUE },
      payload: telegramSecretUpdate,
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.ok).toBe(true);
    expect(body.policy.decision).toBe("deny");
    expect(body.policy.requiresApproval).toBe(false);
    expect(body.policy.matchedRules).toContain("channel:deny-sensitive-data-access");
    expect(body.telegramReply.blocked).toBe(true);
  });

  it("does not live-send denied policy replies even when Telegram send is enabled", async () => {
    const { app } = await serverPromise;
    const previousToken = process.env.AGENTWALL_TELEGRAM_TEST_BOT_TOKEN;
    const previousSend = process.env.AGENTWALL_TELEGRAM_TEST_SEND_ENABLED;
    const fetchMock = jest.fn(async () => ({ ok: true, status: 200 }));
    const previousFetch = globalThis.fetch;
    process.env.AGENTWALL_TELEGRAM_TEST_BOT_TOKEN = ["999", "ABC"].join(":");
    process.env.AGENTWALL_TELEGRAM_TEST_SEND_ENABLED = "true";
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await app.inject({
        method: "POST",
        url: "/integrations/telegram/generic-test-bot/webhook",
        headers: { "x-telegram-bot-api-secret-token": TELEGRAM_TEST_HEADER_VALUE },
        payload: telegramWriteUpdate,
      });

      expect(response.statusCode).toBe(200);
      expect(response.json().telegramReply).toMatchObject({ mode: "live", status: "skipped_policy_decision", blocked: true });
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      if (previousToken === undefined) delete process.env.AGENTWALL_TELEGRAM_TEST_BOT_TOKEN;
      else process.env.AGENTWALL_TELEGRAM_TEST_BOT_TOKEN = previousToken;
      if (previousSend === undefined) delete process.env.AGENTWALL_TELEGRAM_TEST_SEND_ENABLED;
      else process.env.AGENTWALL_TELEGRAM_TEST_SEND_ENABLED = previousSend;
      globalThis.fetch = previousFetch;
    }
  });

  it("live-sends allowed replies only when Telegram send is explicitly enabled", async () => {
    const liveServer = await buildServer({ ...config, policy: { defaultDecision: "allow" } });
    const previousToken = process.env.AGENTWALL_TELEGRAM_TEST_BOT_TOKEN;
    const previousSend = process.env.AGENTWALL_TELEGRAM_TEST_SEND_ENABLED;
    const fetchMock = jest.fn(async () => ({ ok: true, status: 200 }));
    const previousFetch = globalThis.fetch;
    process.env.AGENTWALL_TELEGRAM_TEST_BOT_TOKEN = ["999", "ABC"].join(":");
    process.env.AGENTWALL_TELEGRAM_TEST_SEND_ENABLED = "true";
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    try {
      const response = await liveServer.app.inject({
        method: "POST",
        url: "/integrations/telegram/generic-test-bot/webhook",
        headers: { "x-telegram-bot-api-secret-token": TELEGRAM_TEST_HEADER_VALUE },
        payload: {
          update_id: 1003,
          message: {
            message_id: 44,
            message_thread_id: 4242,
            from: { id: 777, is_bot: false, first_name: "End", username: "enduser" },
            chat: { id: -1001234567890, type: "supergroup", title: "Agentwall Buildout" },
            text: "hello",
          },
        },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json().telegramReply).toMatchObject({ mode: "live", status: "sent", blocked: false });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0] as unknown as [string, { body: string }];
      expect(url).toContain("/sendMessage");
      const sentBody = JSON.parse(init.body);
      expect(sentBody).toMatchObject({ chat_id: -1001234567890, message_thread_id: 4242 });
      expect(sentBody.text).toContain("Generic Agentwall Telegram test bot received");
    } finally {
      await liveServer.app.close();
      if (previousToken === undefined) delete process.env.AGENTWALL_TELEGRAM_TEST_BOT_TOKEN;
      else process.env.AGENTWALL_TELEGRAM_TEST_BOT_TOKEN = previousToken;
      if (previousSend === undefined) delete process.env.AGENTWALL_TELEGRAM_TEST_SEND_ENABLED;
      else process.env.AGENTWALL_TELEGRAM_TEST_SEND_ENABLED = previousSend;
      globalThis.fetch = previousFetch;
    }
  });
});
