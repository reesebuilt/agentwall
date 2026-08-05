import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "crypto";
import { AgentContext, CapabilityTicket, CapabilityTicketConstraints, PolicyResult } from "../types";

const capabilitySecret = randomBytes(32);

export const CAPABILITY_TICKET_TTL_MS = 5 * 60 * 1000;

function stableSerialize(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableSerialize(entry)).join(",")}]`;
  }

  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));

    return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableSerialize(entryValue)}`).join(",")}}`;
  }

  return JSON.stringify(value);
}

function signCapabilityTicket(ticket: Omit<CapabilityTicket, "signature">): string {
  return createHmac("sha256", capabilitySecret).update(stableSerialize(ticket)).digest("hex");
}

function deriveConstraints(context: AgentContext): CapabilityTicketConstraints {
  const flow = context.flow
    ? {
        direction: context.flow.direction,
        labels: context.flow.labels ? [...context.flow.labels].sort() : undefined,
        target: context.flow.target,
        highRisk: context.flow.highRisk,
        crossesBoundary: context.flow.crossesBoundary,
      }
    : undefined;

  return {
    payloadKeys: Object.keys(context.payload).sort(),
    flow,
  };
}

export function shouldIssueCapabilityTicket(result: PolicyResult): boolean {
  return result.decision === "allow" && !result.requiresApproval;
}

export function issueCapabilityTicket(
  context: AgentContext,
  result: PolicyResult,
  options?: { now?: Date; ttlMs?: number }
): CapabilityTicket | undefined {
  if (!shouldIssueCapabilityTicket(result)) {
    return undefined;
  }

  const issuedAt = options?.now ?? new Date();
  const expiresAt = new Date(issuedAt.getTime() + (options?.ttlMs ?? CAPABILITY_TICKET_TTL_MS));
  const unsignedTicket: Omit<CapabilityTicket, "signature"> = {
    id: randomUUID(),
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    decision: result.decision,
    riskLevel: result.riskLevel,
    agentId: context.agentId,
    sessionId: context.sessionId,
    plane: context.plane,
    action: context.action,
    actor: context.actor,
    constraints: deriveConstraints(context),
  };

  return {
    ...unsignedTicket,
    signature: signCapabilityTicket(unsignedTicket),
  };
}

export function verifyCapabilityTicketSignature(ticket: CapabilityTicket): boolean {
  const { signature, ...unsignedTicket } = ticket;
  const expected = signCapabilityTicket(unsignedTicket);

  const providedBuffer = Buffer.from(signature, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(providedBuffer, expectedBuffer);
}
