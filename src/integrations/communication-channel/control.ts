import { z } from "zod";
import { scanText } from "../../planes/identity/dlp";
import { AgentContext, FlowLabel, PlaneSchema } from "../../types";

export const CommunicationPlatformSchema = z.enum(["telegram", "slack", "discord", "custom"]);
export type CommunicationPlatform = z.infer<typeof CommunicationPlatformSchema>;

export const CommunicationChannelGuardrailRequestSchema = z.object({
  agentId: z.string().trim().min(1),
  platform: CommunicationPlatformSchema,
  channelId: z.string().trim().min(1),
  threadId: z.string().trim().min(1).optional(),
  userId: z.string().trim().min(1).optional(),
  roleIds: z.array(z.string().trim().min(1)).optional(),
  plane: PlaneSchema,
  action: z.string().trim().min(1),
  text: z.string().optional(),
  payload: z.record(z.unknown()).optional(),
});

export type CommunicationChannelGuardrailRequest = z.infer<typeof CommunicationChannelGuardrailRequestSchema>;

function maybePrefixed(value: string, prefix: string): string {
  return value.startsWith(`${prefix}:`) ? value : `${prefix}:${value}`;
}

export function normalizeCommunicationChannelId(input: Pick<CommunicationChannelGuardrailRequest, "platform" | "channelId" | "threadId">): string {
  if (input.platform === "telegram") {
    const rawChannel = input.channelId.startsWith("telegram:") ? input.channelId.slice("telegram:".length) : input.channelId;
    if (rawChannel.includes(":")) {
      return `telegram:${rawChannel}`;
    }
    return input.threadId ? `telegram:${rawChannel}:${input.threadId}` : `telegram:${rawChannel}`;
  }

  if (input.platform === "slack") {
    const rawChannel = input.channelId.startsWith("slack:") ? input.channelId.slice("slack:".length) : input.channelId;
    if (rawChannel.includes(":thread:")) {
      return `slack:${rawChannel}`;
    }
    return input.threadId ? `slack:${rawChannel}:thread:${input.threadId}` : `slack:${rawChannel}`;
  }

  if (input.platform === "discord") {
    const rawChannel = input.channelId.startsWith("discord:") ? input.channelId.slice("discord:".length) : input.channelId;
    if (rawChannel.includes(":thread:")) {
      return `discord:${rawChannel}`;
    }
    return input.threadId ? `discord:${rawChannel}:thread:${input.threadId}` : `discord:${rawChannel}`;
  }

  const rawChannel = input.channelId.startsWith("custom:") ? input.channelId.slice("custom:".length) : input.channelId;
  if (rawChannel.includes(":thread:")) {
    return `custom:${rawChannel}`;
  }
  return input.threadId ? `custom:${rawChannel}:thread:${input.threadId}` : `custom:${rawChannel}`;
}

export function normalizeCommunicationUserId(input: Pick<CommunicationChannelGuardrailRequest, "platform" | "userId">): string | undefined {
  if (!input.userId) return undefined;
  return maybePrefixed(input.userId, `${input.platform}-user`);
}

export function buildCommunicationChannelContext(input: CommunicationChannelGuardrailRequest): AgentContext {
  const channelId = normalizeCommunicationChannelId(input);
  const textPayload = input.text === undefined ? {} : { text: input.text };
  const payload = { ...textPayload, ...(input.payload ?? {}) };
  const labels: FlowLabel[] = [];

  if (input.plane === "content") {
    const text = input.text ?? Object.values(payload).filter((value): value is string => typeof value === "string").join("\n");
    const scan = scanText(text, false);
    if (scan.containsSecrets) labels.push("secret_material", "high_risk");
    if (scan.containsPII) labels.push("pii", "high_risk");
  }

  if (input.plane === "tool" && ["write", "create", "update", "patch", "delete", "remove", "exec", "shell"].some((term) => input.action.toLowerCase().includes(term))) {
    labels.push("destructive_action", "high_risk");
  }

  return {
    agentId: input.agentId,
    sessionId: `${input.agentId}:${channelId}`,
    plane: input.plane,
    action: input.action,
    payload,
    actor: {
      channelId,
      userId: normalizeCommunicationUserId(input),
      roleIds: input.roleIds,
    },
    flow: {
      direction: input.plane === "content" ? "egress" : "internal",
      target: input.plane === "content" ? channelId : undefined,
      labels: Array.from(new Set(labels)),
      highRisk: labels.includes("high_risk"),
    },
  };
}
