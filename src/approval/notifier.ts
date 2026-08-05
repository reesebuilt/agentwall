import { ApprovalRequest, ApprovalResponse } from "../types";

export interface ApprovalNotifierOptions {
  webhookUrl?: string;
  fetchImpl?: typeof fetch;
  logger?: {
    warn: (payload: Record<string, unknown>, message: string) => void;
  };
}

export interface ApprovalNotificationPayload {
  event: "approval.pending" | "approval.resolved";
  requestId: string;
  mode: "manual" | "auto";
  timestamp: string;
  approval: {
    agentId: string;
    sessionId?: string;
    plane: string;
    action: string;
    riskLevel: string;
    requiresApproval: boolean;
    matchedRules: string[];
    reasons: string[];
  };
  response?: {
    decision: ApprovalResponse["decision"];
    approvedBy?: string;
    note?: string;
    timestamp: string;
  };
}

export class ApprovalNotifier {
  private readonly webhookUrl?: string;
  private readonly fetchImpl?: typeof fetch;
  private readonly logger?: ApprovalNotifierOptions["logger"];

  constructor(options: ApprovalNotifierOptions = {}) {
    this.webhookUrl = options.webhookUrl;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.logger = options.logger;
  }

  notifyPending(requestId: string, request: ApprovalRequest, mode: "manual" | "auto"): void {
    this.send({
      event: "approval.pending",
      requestId,
      mode,
      timestamp: new Date().toISOString(),
      approval: {
        agentId: request.context.agentId,
        sessionId: request.context.sessionId,
        plane: request.context.plane,
        action: request.context.action,
        riskLevel: request.policyResult.riskLevel,
        requiresApproval: request.policyResult.requiresApproval,
        matchedRules: request.policyResult.matchedRules,
        reasons: request.policyResult.reasons,
      },
    });
  }

  notifyResolved(requestId: string, request: ApprovalRequest, response: ApprovalResponse, mode: "manual" | "auto"): void {
    this.send({
      event: "approval.resolved",
      requestId,
      mode,
      timestamp: new Date().toISOString(),
      approval: {
        agentId: request.context.agentId,
        sessionId: request.context.sessionId,
        plane: request.context.plane,
        action: request.context.action,
        riskLevel: request.policyResult.riskLevel,
        requiresApproval: request.policyResult.requiresApproval,
        matchedRules: request.policyResult.matchedRules,
        reasons: request.policyResult.reasons,
      },
      response: {
        decision: response.decision,
        approvedBy: response.approvedBy,
        note: response.note,
        timestamp: response.timestamp,
      },
    });
  }

  private send(payload: ApprovalNotificationPayload): void {
    if (!this.webhookUrl || !this.fetchImpl) {
      return;
    }

    void this.fetchImpl(this.webhookUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    }).catch((error: unknown) => {
      this.logger?.warn(
        {
          err: error instanceof Error ? error.message : String(error),
          webhookUrl: this.webhookUrl,
          event: payload.event,
          requestId: payload.requestId,
        },
        "Approval webhook notification failed"
      );
    });
  }
}
