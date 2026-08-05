import { randomUUID } from "crypto";
import { chainAuditEvent, AuditChainState } from "./chain";
import { AuditEvent, AgentContext, PolicyResult } from "../types";

export type AuditSink = (event: AuditEvent) => void;

const sinks: AuditSink[] = [];

function initialChainState(): AuditChainState {
  return {
    chainIndex: 0,
    previousHash: null,
  };
}

let auditChainState = initialChainState();

export function registerAuditSink(sink: AuditSink): void {
  if (!sinks.includes(sink)) {
    sinks.push(sink);
  }
}

/**
 * Resume the chain from a prior run. Called once at boot, before any sink fires, so a
 * restart continues the record instead of starting a second disjoint chain at index 0.
 */
export function seedAuditChain(state: AuditChainState): void {
  auditChainState = { ...state };
}

export function resetAuditChain(): void {
  auditChainState = initialChainState();
}

export function emit(ctx: AgentContext, result: PolicyResult): AuditEvent {
  const event = chainAuditEvent(
    {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: ctx.agentId,
      sessionId: ctx.sessionId,
      plane: ctx.plane,
      action: ctx.action,
      decision: result.decision,
      riskLevel: result.riskLevel,
      matchedRules: result.matchedRules,
      reasons: result.reasons,
      requiresApproval: result.requiresApproval,
      highRiskFlow: result.highRiskFlow,
      detections: result.detections,
      metadata: ctx.metadata,
      actor: ctx.actor,
      provenance: ctx.provenance,
      flow: ctx.flow,
    },
    auditChainState
  );

  auditChainState = {
    chainIndex: event.integrity.chainIndex + 1,
    previousHash: event.integrity.hash,
  };

  for (const sink of sinks) {
    try {
      sink(event);
    } catch {
      // sinks must not throw
    }
  }

  return event;
}

export function stdoutSink(event: AuditEvent): void {
  process.stdout.write(JSON.stringify({ agentwall_audit: event }) + "\n");
}
