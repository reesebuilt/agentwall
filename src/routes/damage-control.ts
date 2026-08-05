import { FastifyInstance } from "fastify";
import { emit } from "../audit/logger";
import { PolicyEngine } from "../policy/engine";
import { RuntimeState } from "../dashboard/state";
import {
  analyzeCommand,
  combineDecision,
  combineRisk,
  CommandPreflightRequestSchema,
  DEFAULT_DAMAGE_CONTROL_MODE,
} from "../integrations/damage-control/command-firewall";
import { AgentContext } from "../types";

export async function damageControlRoutes(
  app: FastifyInstance,
  engine: PolicyEngine,
  runtime: RuntimeState
): Promise<void> {
  app.post("/integrations/damage-control/command-preflight", async (req, reply) => {
    const parsed = CommandPreflightRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({
        ok: false,
        error: "Invalid damage-control preflight request",
        details: parsed.error.flatten(),
      });
    }

    const analysis = analyzeCommand(parsed.data);
    const mode = parsed.data.mode ?? DEFAULT_DAMAGE_CONTROL_MODE;
    const sessionId = parsed.data.threadId
      ? `${parsed.data.agentId}:${parsed.data.threadId}`
      : parsed.data.channelId
      ? `${parsed.data.agentId}:${parsed.data.channelId}`
      : `${parsed.data.agentId}:damage-control`;

    const context: AgentContext = {
      agentId: parsed.data.agentId,
      sessionId,
      plane: "tool",
      action: "run_command",
      payload: {
        command: parsed.data.command,
        cwd: parsed.data.cwd,
        mode,
        recommendedLevel: analysis.recommendedLevel,
        matchedSignals: analysis.matchedSignals,
        bypassNotes: analysis.bypassNotes,
      },
      metadata: {
        damageControlMode: mode,
        damageControlSource: "preflight",
        damageControlLevel: analysis.recommendedLevel,
      },
      actor: {
        channelId: parsed.data.channelId,
        userId: parsed.data.userId,
      },
      flow: {
        direction: "internal",
        target: "shell",
        labels: analysis.decision === "deny" || analysis.riskLevel === "critical" ? ["destructive_action", "high_risk"] : [],
        highRisk: analysis.riskLevel === "high" || analysis.riskLevel === "critical",
      },
    };

    const policyResult = engine.evaluate(context);
    const finalDecision = combineDecision(analysis.decision, policyResult.decision);
    const finalRisk = combineRisk(analysis.riskLevel, policyResult.riskLevel);
    const combinedReasons = Array.from(
      new Set([
        ...analysis.reasons.map((reason) => `damage-control: ${reason}`),
        ...policyResult.reasons.map((reason) => `policy: ${reason}`),
      ])
    );
    const auditEvent = emit(context, {
      decision: finalDecision,
      riskLevel: finalRisk,
      matchedRules: policyResult.matchedRules,
      reasons: combinedReasons,
      requiresApproval: finalDecision === "approve",
      highRiskFlow: policyResult.highRiskFlow || finalRisk === "critical",
      detections: policyResult.detections,
    });
    runtime.recordAuditEvent(auditEvent);

    return reply.send({
      ok: true,
      analysis,
      policy: {
        decision: policyResult.decision,
        riskLevel: policyResult.riskLevel,
        matchedRules: policyResult.matchedRules,
        reasons: policyResult.reasons,
        requiresApproval: policyResult.requiresApproval,
        highRiskFlow: policyResult.highRiskFlow,
      },
      combined: {
        decision: finalDecision,
        riskLevel: finalRisk,
        reasons: combinedReasons,
      },
      delivery: {
        executionAllowed: finalDecision === "allow",
        status:
          finalDecision === "allow"
            ? "execution_allowed"
            : finalDecision === "approve"
            ? "approval_required"
            : "execution_blocked",
      },
      audit: {
        eventId: auditEvent.id,
        chainIndex: auditEvent.integrity.chainIndex,
      },
    });
  });
}
