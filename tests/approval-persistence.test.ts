import { afterAll, describe, expect, it } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ApprovalGate } from "../src/approval/gate";
import { AgentwallConfig } from "../src/config";
import { buildServer } from "../src/server";
import { ApprovalRequest } from "../src/types";

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-approval-"));
}

const tempDirs: string[] = [];

afterAll(() => {
  for (const dir of tempDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("Approval queue persistence", () => {
  it("persists pending approvals across gate and server reinitialization", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const persistencePath = path.join(dir, "approvals.json");

    const request: ApprovalRequest = {
      context: {
        agentId: "agent-restart",
        sessionId: "session-restart",
        plane: "tool",
        action: "bash_exec",
        payload: { command: "rm -rf /tmp/restart-check" },
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

    const gate = new ApprovalGate("always", 30_000, "file", persistencePath);
    const { requestId } = gate.request(request);
    expect(gate.listPending().map((item) => item.requestId)).toContain(requestId);
    gate.close();

    const config: AgentwallConfig = {
      port: 3000,
      host: "127.0.0.1",
      logLevel: "silent",
      approval: {
        mode: "always",
        timeoutMs: 30_000,
        backend: "file",
        persistencePath,
      },
      policy: {
        defaultDecision: "deny",
      },
      dlp: {
        enabled: true,
        redactSecrets: true,
      },
      egress: {
        enabled: true,
        defaultDeny: true,
        allowPrivateRanges: false,
        allowedHosts: [],
        allowedSchemes: ["https"],
        allowedPorts: [443],
      },
      manifestIntegrity: {
        enabled: true,
      },
      watchdog: {
        enabled: true,
        staleAfterMs: 15_000,
        timeoutMs: 30_000,
        killSwitchMode: "deny_all",
      },
    };

    const { app } = await buildServer(config);

    try {
      const pendingResponse = await app.inject({ method: "GET", url: "/approval/pending" });
      expect(pendingResponse.statusCode).toBe(200);
      expect(pendingResponse.json().pending.map((item: { requestId: string }) => item.requestId)).toContain(requestId);

      const stateResponse = await app.inject({ method: "GET", url: "/api/dashboard/state" });
      expect(stateResponse.statusCode).toBe(200);
      expect(stateResponse.json().approvals.pending.map((item: { requestId: string }) => item.requestId)).toContain(requestId);

      const response = await app.inject({
        method: "POST",
        url: `/approval/${requestId}/respond`,
        payload: {
          decision: "approved",
          note: "Approved after restart",
        },
      });
      expect(response.statusCode).toBe(200);

      const emptyPendingResponse = await app.inject({ method: "GET", url: "/approval/pending" });
      expect(emptyPendingResponse.json().pending).toEqual([]);
    } finally {
      await app.close();
    }

    const reloadedGate = new ApprovalGate("always", 30_000, "file", persistencePath);
    try {
      expect(reloadedGate.listPending()).toEqual([]);
      expect(reloadedGate.getHistory(5).some((item) => item.requestId === requestId && item.decision === "approved")).toBe(true);
    } finally {
      reloadedGate.close();
    }
  });
});
