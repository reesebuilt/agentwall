import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { ApprovalGate } from "../src/approval/gate";
import { ApprovalRequest } from "../src/types";

const request: ApprovalRequest = {
  context: {
    agentId: "agent-webhook",
    sessionId: "session-webhook",
    plane: "tool",
    action: "bash_exec",
    payload: { command: "rm -rf /tmp/webhook-check" },
  },
  policyResult: {
    decision: "approve",
    riskLevel: "high",
    matchedRules: ["tool:require-approval-shell"],
    reasons: ["Shell execution requires human approval"],
    requiresApproval: true,
    highRiskFlow: true,
  },
  timeoutMs: 30_000,
};

describe("Approval webhook notifications", () => {
  afterEach(() => {
    delete (globalThis as { fetch?: typeof fetch }).fetch;
  });

  it("posts a pending approval notification when a manual review is queued", async () => {
    const fetchMock = jest.fn(async () => ({ ok: true, status: 202 }));
    (globalThis as { fetch?: typeof fetch }).fetch = fetchMock as unknown as typeof fetch;

    const gate = new ApprovalGate("always", 30_000, "memory", "./agentwall-approvals.json", {
      webhookUrl: "https://operator.example/webhooks/approvals",
    });

    try {
      const { requestId } = gate.request(request);
      await Promise.resolve();

      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledWith(
        "https://operator.example/webhooks/approvals",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({ "content-type": "application/json" }),
          body: expect.any(String),
        })
      );

      const [, init] = fetchMock.mock.calls[0] as unknown as [string, { body: string }];
      expect(JSON.parse(init.body)).toMatchObject({
        event: "approval.pending",
        requestId,
        mode: "manual",
        approval: {
          action: "bash_exec",
          sessionId: "session-webhook",
          agentId: "agent-webhook",
          plane: "tool",
          riskLevel: "high",
          requiresApproval: true,
          matchedRules: ["tool:require-approval-shell"],
          reasons: ["Shell execution requires human approval"],
        },
      });
    } finally {
      gate.close();
    }
  });

  it("posts a resolved approval notification when an operator responds", async () => {
    const fetchMock = jest.fn(async () => ({ ok: true, status: 202 }));
    (globalThis as { fetch?: typeof fetch }).fetch = fetchMock as unknown as typeof fetch;

    const gate = new ApprovalGate("always", 30_000, "memory", "./agentwall-approvals.json", {
      webhookUrl: "https://operator.example/webhooks/approvals",
    });

    try {
      const { requestId } = gate.request(request);
      await Promise.resolve();
      gate.respond(requestId, "approved", "operator-webhook", "Looks contained");
      await Promise.resolve();

      expect(fetchMock).toHaveBeenCalledTimes(2);

      const [, init] = fetchMock.mock.calls[1] as unknown as [string, { body: string }];
      expect(JSON.parse(init.body)).toMatchObject({
        event: "approval.resolved",
        requestId,
        mode: "manual",
        approval: {
          action: "bash_exec",
          sessionId: "session-webhook",
          agentId: "agent-webhook",
          plane: "tool",
          riskLevel: "high",
        },
        response: {
          decision: "approved",
          note: "Looks contained",
        },
      });
    } finally {
      gate.close();
    }
  });
});
