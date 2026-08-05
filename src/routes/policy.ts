import { FastifyInstance } from "fastify";
import { PolicyEngine } from "../policy/engine";
import { AgentContextSchema, PolicyEvaluationResponse } from "../types";
import { emit } from "../audit/logger";
import { RuntimeState } from "../dashboard/state";
import { detectionCatalog } from "../policy/detections";
import { issueCapabilityTicket } from "../runtime/capabilities";
import { RuntimeFloodGuard } from "../runtime/floodguard";
import { DecisionTraceExporter } from "../telemetry/otel";

export async function policyRoutes(
  app: FastifyInstance,
  engine: PolicyEngine,
  runtime: RuntimeState,
  floodGuard: RuntimeFloodGuard,
  telemetry: DecisionTraceExporter
): Promise<void> {
  app.post("/evaluate", async (req, reply) => {
    const startedAtMs = Date.now();
    const startedAtHrTime = process.hrtime.bigint();
    const parsed = AgentContextSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid request body", details: parsed.error.flatten() });
    }

    const ctx = parsed.data;
    const floodResult = floodGuard.evaluateRequest(ctx);
    if (!floodResult.allowed) {
      if (floodResult.retryAfterMs) {
        reply.header("retry-after", String(Math.ceil(floodResult.retryAfterMs / 1000)));
      }

      const statusCode = 429;
      await telemetry.export({
        routeName: "policy.evaluate",
        routePath: "/evaluate",
        plane: ctx.plane,
        action: ctx.action,
        decision: "deny",
        riskLevel: "high",
        resultStatus: "runtime_guard_blocked",
        startedAtMs,
        durationNs: process.hrtime.bigint() - startedAtHrTime,
        httpMethod: req.method,
        httpStatusCode: statusCode,
        attributes: {
          "agentwall.agent_id": ctx.agentId,
          "agentwall.session_id": ctx.sessionId,
          "agentwall.retry_after_ms": floodResult.retryAfterMs,
          "agentwall.block_reason": floodResult.reason,
        },
      });

      return reply.status(statusCode).send({
        error: "Runtime guard blocked request",
        reason: floodResult.reason,
        retryAfterMs: floodResult.retryAfterMs,
      });
    }

    const session = runtime.getSessionState(ctx.sessionId ?? `${ctx.agentId}:default`);
    if (session?.status === "paused" || session?.status === "terminated") {
      const reason = `Session ${session.sessionId} is ${session.status}; operator intervention required`;
      runtime.recordSessionRejection(ctx, reason);
      const statusCode = session.status === "terminated" ? 403 : 423;

      await telemetry.export({
        routeName: "policy.evaluate",
        routePath: "/evaluate",
        plane: ctx.plane,
        action: ctx.action,
        decision: "deny",
        riskLevel: "high",
        resultStatus: `session_${session.status}`,
        startedAtMs,
        durationNs: process.hrtime.bigint() - startedAtHrTime,
        httpMethod: req.method,
        httpStatusCode: statusCode,
        attributes: {
          "agentwall.agent_id": ctx.agentId,
          "agentwall.session_id": session.sessionId,
          "agentwall.session_status": session.status,
          "agentwall.block_reason": reason,
        },
      });

      return reply.status(statusCode).send({
        error: "Session blocked",
        sessionId: session.sessionId,
        sessionStatus: session.status,
        reason,
      });
    }

    const result = engine.evaluate(ctx);
    const auditEvent = emit(ctx, result);
    const capabilityTicket = issueCapabilityTicket(ctx, result);
    runtime.recordAuditEvent(auditEvent);

    const response: PolicyEvaluationResponse = {
      decision: result.decision,
      riskLevel: result.riskLevel,
      matchedRules: result.matchedRules,
      reasons: result.reasons,
      requiresApproval: result.requiresApproval,
      highRiskFlow: result.highRiskFlow,
      detections: result.detections,
      auditEventId: auditEvent.id,
      capabilityTicket,
    };

    await telemetry.export({
      routeName: "policy.evaluate",
      routePath: "/evaluate",
      plane: ctx.plane,
      action: ctx.action,
      decision: result.decision,
      riskLevel: result.riskLevel,
      resultStatus: result.requiresApproval ? "requires_approval" : result.decision,
      startedAtMs,
      durationNs: process.hrtime.bigint() - startedAtHrTime,
      httpMethod: req.method,
      httpStatusCode: 200,
      attributes: {
        "agentwall.agent_id": ctx.agentId,
        "agentwall.session_id": ctx.sessionId,
        "agentwall.audit_event_id": auditEvent.id,
        "agentwall.requires_approval": result.requiresApproval,
        "agentwall.high_risk_flow": result.highRiskFlow,
        "agentwall.matched_rule_count": result.matchedRules.length,
        "agentwall.detection_count": result.detections.length,
      },
    });

    return reply.send(response);
  });

  app.get("/detections", async (_req, reply) => {
    return reply.send({ detections: detectionCatalog, count: detectionCatalog.length });
  });

  app.get("/rules", async (_req, reply) => {
    const rules = engine.getRules().map((r) => ({
      id: r.id,
      description: r.description,
      plane: r.plane,
      decision: r.decision,
      riskLevel: r.riskLevel,
      scope: r.scope,
    }));
    return reply.send({ rules, count: rules.length });
  });
}
