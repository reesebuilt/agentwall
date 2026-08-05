import { timingSafeEqual } from "crypto";
import { FastifyInstance } from "fastify";
import { emit } from "../audit/logger";
import { RuntimeState } from "../dashboard/state";
import { getTelegramReplyTarget, planGenericTelegramTestBotAction, TelegramUpdate, TelegramUpdateSchema } from "../integrations/telegram/generic-test-bot";
import { PolicyEngine } from "../policy/engine";

const TELEGRAM_WEBHOOK_SECRET_ENV = "AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET";
const TELEGRAM_AGENT_ID_ENV = "AGENTWALL_TELEGRAM_TEST_AGENT_ID";
const TELEGRAM_BOT_TOKEN_ENV = "AGENTWALL_TELEGRAM_TEST_BOT_TOKEN";
const TELEGRAM_SEND_ENABLED_ENV = "AGENTWALL_TELEGRAM_TEST_SEND_ENABLED";

function configuredWebhookSecret(): string | undefined {
  return process.env[TELEGRAM_WEBHOOK_SECRET_ENV];
}

function configuredAgentId(): string {
  return process.env[TELEGRAM_AGENT_ID_ENV] ?? "generic-telegram-test-bot";
}

function configuredBotToken(): string | undefined {
  return process.env[TELEGRAM_BOT_TOKEN_ENV];
}

function telegramSendEnabled(): boolean {
  return process.env[TELEGRAM_SEND_ENABLED_ENV] === "true";
}

function webhookSecretMatches(suppliedSecret: string | string[] | undefined, expectedSecret: string): boolean {
  if (typeof suppliedSecret !== "string") {
    return false;
  }

  const supplied = Buffer.from(suppliedSecret);
  const expected = Buffer.from(expectedSecret);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function sendTelegramMessage(update: TelegramUpdate, text: string) {
  if (!telegramSendEnabled()) {
    return { mode: "dry_run", status: "skipped", reason: `${TELEGRAM_SEND_ENABLED_ENV} is not true` };
  }

  const token = configuredBotToken();
  if (!token) {
    return { mode: "live", status: "skipped", reason: `${TELEGRAM_BOT_TOKEN_ENV} is not configured` };
  }

  const target = getTelegramReplyTarget(update);
  const body = {
    chat_id: target.chatId,
    text,
    ...(target.messageThreadId !== undefined ? { message_thread_id: target.messageThreadId } : {}),
  };
  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      return { mode: "live", status: "failed", httpStatus: response.status };
    }

    return { mode: "live", status: "sent" };
  } catch {
    return { mode: "live", status: "failed" };
  }
}

export async function telegramTestBotRoutes(
  app: FastifyInstance,
  engine: PolicyEngine,
  runtime: RuntimeState
): Promise<void> {
  app.post("/integrations/telegram/generic-test-bot/webhook", async (req, reply) => {
    const expectedSecret = configuredWebhookSecret();
    if (!expectedSecret) {
      return reply.status(503).send({
        ok: false,
        error: `${TELEGRAM_WEBHOOK_SECRET_ENV} is required before the Telegram test bot webhook accepts updates`,
      });
    }

    const suppliedSecret = req.headers["x-telegram-bot-api-secret-token"];
    if (!webhookSecretMatches(suppliedSecret, expectedSecret)) {
      return reply.status(401).send({ ok: false, error: "Invalid Telegram webhook secret" });
    }

    const parsedUpdate = TelegramUpdateSchema.safeParse(req.body);
    if (!parsedUpdate.success) {
      return reply.status(400).send({
        ok: false,
        error: "Invalid Telegram update",
        details: parsedUpdate.error.flatten(),
      });
    }

    let planned;
    try {
      planned = planGenericTelegramTestBotAction(parsedUpdate.data, configuredAgentId());
    } catch (error) {
      const failure = error instanceof Error ? error.message : String(error);
      return reply.status(202).send({ ok: true, ignored: true, reason: failure });
    }

    const result = engine.evaluate(planned.context);
    const auditEvent = emit(planned.context, result);
    runtime.recordAuditEvent(auditEvent);
    const blocked = result.decision === "deny";
    const telegramDelivery = result.decision === "allow"
      ? await sendTelegramMessage(parsedUpdate.data, planned.safeReplyText)
      : {
          mode: telegramSendEnabled() ? "live" : "dry_run",
          status: "skipped_policy_decision",
        };

    return reply.send({
      ok: true,
      channelId: planned.context.actor?.channelId,
      userId: planned.context.actor?.userId,
      plannedAction: {
        agentId: planned.context.agentId,
        sessionId: planned.context.sessionId,
        plane: planned.context.plane,
        action: planned.context.action,
      },
      policy: {
        decision: result.decision,
        riskLevel: result.riskLevel,
        matchedRules: result.matchedRules,
        reasons: result.reasons,
        requiresApproval: result.requiresApproval,
        highRiskFlow: result.highRiskFlow,
        auditEventId: auditEvent.id,
      },
      telegramReply: {
        ...telegramDelivery,
        blocked,
        text: planned.safeReplyText,
      },
    });
  });
}
