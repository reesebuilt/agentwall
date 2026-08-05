import { z } from "zod";
import { AgentContext } from "../../types";

const TelegramUserSchema = z.object({
  id: z.number(),
  is_bot: z.boolean().optional(),
  first_name: z.string().optional(),
  username: z.string().optional(),
}).passthrough();

const TelegramChatSchema = z.object({
  id: z.number(),
  type: z.string(),
  title: z.string().optional(),
  username: z.string().optional(),
}).passthrough();

const TelegramMessageSchema = z.object({
  message_id: z.number(),
  message_thread_id: z.number().optional(),
  from: TelegramUserSchema.optional(),
  chat: TelegramChatSchema,
  text: z.string().optional(),
}).passthrough();

export const TelegramUpdateSchema = z.object({
  update_id: z.number(),
  message: TelegramMessageSchema.optional(),
  edited_message: TelegramMessageSchema.optional(),
}).passthrough();

export type TelegramUpdate = z.infer<typeof TelegramUpdateSchema>;
export type TelegramMessage = z.infer<typeof TelegramMessageSchema>;

export interface PlannedTelegramBotAction {
  context: AgentContext;
  safeReplyText: string;
}

export interface TelegramReplyTarget {
  chatId: number;
  messageThreadId?: number;
}

export function getTelegramReplyTarget(update: TelegramUpdate): TelegramReplyTarget {
  const message = update.message ?? update.edited_message;
  if (!message) {
    throw new Error("Telegram update does not contain a supported message");
  }

  return {
    chatId: message.chat.id,
    ...(message.message_thread_id !== undefined ? { messageThreadId: message.message_thread_id } : {}),
  };
}

export function normalizeTelegramChannelId(message: TelegramMessage): string {
  if (message.chat.type === "private") {
    return `telegram:${message.chat.id}:dm`;
  }

  if (message.message_thread_id !== undefined) {
    return `telegram:${message.chat.id}:${message.message_thread_id}`;
  }

  return `telegram:${message.chat.id}`;
}

export function normalizeTelegramUserId(message: TelegramMessage): string | undefined {
  return message.from ? `telegram-user:${message.from.id}` : undefined;
}

function roleIdsForMessage(message: TelegramMessage): string[] {
  return [`telegram-chat-type:${message.chat.type}`];
}

function extractPath(text: string): string {
  const match = text.match(/(?:path=|file=)(\S+)/i) ?? text.match(/`([^`]+)`/);
  return match?.[1] ?? "/tmp/agentwall-telegram-test.txt";
}

function extractSecretKey(text: string): string {
  const match = text.match(/(?:key=|secret=|token=)([A-Za-z0-9_.-]+)/i);
  return match?.[1] ?? "OPENAI_API_KEY";
}

export function planGenericTelegramTestBotAction(update: TelegramUpdate, agentId = "generic-telegram-test-bot"): PlannedTelegramBotAction {
  const message = update.message ?? update.edited_message;
  if (!message) {
    throw new Error("Telegram update does not contain a supported message");
  }

  const text = message.text ?? "";
  const lowered = text.toLowerCase();
  const actor = {
    channelId: normalizeTelegramChannelId(message),
    userId: normalizeTelegramUserId(message),
    roleIds: roleIdsForMessage(message),
  };

  if (lowered.includes("/write") || lowered.includes("write file") || lowered.includes("delete file")) {
    return {
      context: {
        agentId,
        sessionId: `${agentId}:${actor.channelId}`,
        plane: "tool",
        action: lowered.includes("delete") ? "delete_file" : "write_file",
        payload: {
          path: extractPath(text),
          content: "requested from Telegram test bot",
          sourceText: text,
        },
        actor,
        flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
      },
      safeReplyText: "Blocked: communication-channel users cannot mutate the agent filesystem.",
    };
  }

  if (
    lowered.includes("/secret") ||
    lowered.includes("api key") ||
    lowered.includes("token") ||
    lowered.includes("password") ||
    lowered.includes("credential")
  ) {
    return {
      context: {
        agentId,
        sessionId: `${agentId}:${actor.channelId}`,
        plane: "identity",
        action: "read_secret",
        payload: {
          key: extractSecretKey(text),
          sourceText: text,
        },
        actor,
        flow: { direction: "internal", labels: ["credential_access"], highRisk: true },
      },
      safeReplyText: "Blocked: communication-channel users cannot access secrets or credentials through the agent.",
    };
  }

  return {
    context: {
      agentId,
      sessionId: `${agentId}:${actor.channelId}`,
      plane: "content",
      action: "telegram_reply",
      payload: {
        text,
        reply: "Generic Agentwall Telegram test bot received the message.",
      },
      actor,
      flow: { direction: "egress", target: actor.channelId },
    },
    safeReplyText: "Generic Agentwall Telegram test bot received the message.",
  };
}
