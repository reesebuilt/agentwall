import { FastifyInstance } from "fastify";
import { emit } from "../audit/logger";
import { buildCommunicationChannelContext, CommunicationChannelGuardrailRequestSchema } from "../integrations/communication-channel/control";
import { scanText } from "../planes/identity/dlp";
import { PolicyEngine } from "../policy/engine";
import { RuntimeState } from "../dashboard/state";

function collectPayloadText(payload: Record<string, unknown>): string {
  const strings: string[] = [];
  const collect = (value: unknown) => {
    if (typeof value === "string") {
      strings.push(value);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach(collect);
      return;
    }
    if (value && typeof value === "object") {
      Object.values(value as Record<string, unknown>).forEach(collect);
    }
  };
  collect(payload);
  return strings.join("\n");
}

export async function communicationChannelRoutes(
  app: FastifyInstance,
  engine: PolicyEngine,
  runtime: RuntimeState
): Promise<void> {
  app.post("/integrations/communication-channel/guardrail", async (req, reply) => {
    const parsed = CommunicationChannelGuardrailRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({
        ok: false,
        error: "Invalid communication channel guardrail request",
        details: parsed.error.flatten(),
      });
    }

    const context = buildCommunicationChannelContext(parsed.data);
    const result = engine.evaluate(context);
    const auditEvent = emit(context, result);
    runtime.recordAuditEvent(auditEvent);
    const text = parsed.data.text ?? collectPayloadText(context.payload);
    const dlp = scanText(text, true);

    return reply.send({
      ok: true,
      channelId: context.actor?.channelId,
      userId: context.actor?.userId,
      plannedAction: {
        agentId: context.agentId,
        sessionId: context.sessionId,
        plane: context.plane,
        action: context.action,
      },
      policy: {
        decision: result.decision,
        riskLevel: result.riskLevel,
        matchedRules: result.matchedRules,
        reasons: result.reasons,
        requiresApproval: result.requiresApproval,
        highRiskFlow: result.highRiskFlow,
        detections: result.detections,
        auditEventId: auditEvent.id,
      },
      content: {
        containsSecrets: dlp.containsSecrets,
        secretTypes: dlp.secretTypes,
        containsPII: dlp.containsPII,
        piiTypes: dlp.piiTypes,
        redactedText: dlp.redactedText,
      },
      delivery: {
        status: result.decision === "allow" ? "allowed" : result.decision === "redact" ? "redaction_required" : "blocked",
        sendAllowed: result.decision === "allow",
      },
    });
  });
}
