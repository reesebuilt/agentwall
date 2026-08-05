/**
 * Monitor-first preflight seam for an agent harness.
 *
 * "Harness" means whatever process actually runs the agent's tools: a chat gateway, an
 * IDE agent, a cron worker, a homegrown loop. Agentwall does not care which. The harness
 * calls in before it performs a network or tool action and gets back proceed/stop.
 *
 * Fail-open is deliberate at this layer. A monitoring seam that takes the harness down
 * when Agentwall is unreachable will be removed by the first operator it pages, which
 * leaves them with no seam at all. Enforcement is opt-in per rollout mode; see
 * HarnessRolloutMode.
 */

import * as http from "http";
import * as https from "https";
import { AgentContext, NetworkInspection, NetworkRequest } from "../../types";

export type HarnessRolloutMode = "observe" | "enforce_critical";

export interface HarnessPreflightConfig {
  agentwallUrl: string;
  rolloutMode?: HarnessRolloutMode;
  timeoutMs?: number;
  onEvent?: (event: HarnessPreflightEvent) => void;
}

export interface HarnessPreflightEvent {
  timestamp: string;
  kind: "network.inspect" | "policy.evaluate" | "fail_open" | "outbound.execute";
  mode: HarnessRolloutMode;
  payload: Record<string, unknown>;
}

export interface NetworkPreflightResult {
  proceed: boolean;
  mode: HarnessRolloutMode;
  failOpen: boolean;
  inspection?: NetworkInspection;
  reason: string;
}

export interface PolicyPreflightResult {
  proceed: boolean;
  mode: HarnessRolloutMode;
  failOpen: boolean;
  evaluation?: {
    decision: "allow" | "deny" | "approve" | "redact";
    riskLevel: "low" | "medium" | "high" | "critical";
    reasons: string[];
    requiresApproval: boolean;
  };
  reason: string;
}

interface JsonResponse<T> {
  statusCode: number;
  body: T;
}

function isCriticalNetworkBlock(result: NetworkInspection): boolean {
  return result.ssrf || result.privateRange || result.riskLevel === "critical";
}

async function postJson<T>(baseUrl: string, route: string, payload: unknown, timeoutMs: number): Promise<JsonResponse<T>> {
  const url = new URL(route, baseUrl);
  const body = JSON.stringify(payload);
  const client = url.protocol === "https:" ? https : http;

  return await new Promise((resolve, reject) => {
    const req = client.request(
      url,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        res.on("end", () => {
          try {
            const raw = Buffer.concat(chunks).toString("utf-8") || "{}";
            const parsed = JSON.parse(raw) as T;
            resolve({ statusCode: res.statusCode ?? 0, body: parsed });
          } catch (error) {
            reject(error);
          }
        });
      }
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`request timed out after ${timeoutMs}ms`));
    });
    req.on("error", (error) => reject(error));
    req.write(body);
    req.end();
  });
}

export class HarnessPreflightAdapter {
  private readonly config: Required<Pick<HarnessPreflightConfig, "agentwallUrl" | "rolloutMode" | "timeoutMs">> &
    Pick<HarnessPreflightConfig, "onEvent">;

  constructor(config: HarnessPreflightConfig) {
    this.config = {
      agentwallUrl: config.agentwallUrl,
      rolloutMode: config.rolloutMode ?? "observe",
      timeoutMs: config.timeoutMs ?? 1000,
      onEvent: config.onEvent,
    };
  }

  async inspectNetwork(request: NetworkRequest): Promise<NetworkPreflightResult> {
    try {
      const response = await postJson<NetworkInspection>(
        this.config.agentwallUrl,
        "/inspect/network",
        request,
        this.config.timeoutMs
      );

      const inspection = response.body;
      const critical = isCriticalNetworkBlock(inspection);
      const shouldBlock = this.config.rolloutMode === "enforce_critical" && !inspection.allowed && critical;
      const reason = shouldBlock
        ? `Blocked by Agentwall critical network preflight: ${inspection.reason}`
        : `Monitor-first preflight observed (${inspection.reason})`;

      this.emit({
        kind: "network.inspect",
        payload: { request, inspection, statusCode: response.statusCode, shouldBlock },
      });

      return {
        proceed: !shouldBlock,
        mode: this.config.rolloutMode,
        failOpen: false,
        inspection,
        reason,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emit({
        kind: "fail_open",
        payload: { route: "/inspect/network", request, error: message },
      });
      return {
        proceed: true,
        mode: this.config.rolloutMode,
        failOpen: true,
        reason: `Agentwall unavailable; fail-open network preflight: ${message}`,
      };
    }
  }

  async evaluatePolicy(context: AgentContext): Promise<PolicyPreflightResult> {
    try {
      const response = await postJson<{
        decision: "allow" | "deny" | "approve" | "redact";
        riskLevel: "low" | "medium" | "high" | "critical";
        reasons: string[];
        requiresApproval: boolean;
      }>(this.config.agentwallUrl, "/evaluate", context, this.config.timeoutMs);

      const evaluation = response.body;
      const shouldBlock =
        this.config.rolloutMode === "enforce_critical" && evaluation.decision === "deny" && evaluation.riskLevel === "critical";
      const reason = shouldBlock
        ? `Blocked by Agentwall critical policy result: ${evaluation.reasons.join("; ") || "critical deny"}`
        : "Monitor-first policy evaluation observed";

      this.emit({
        kind: "policy.evaluate",
        payload: { context, evaluation, statusCode: response.statusCode, shouldBlock },
      });

      return {
        proceed: !shouldBlock,
        mode: this.config.rolloutMode,
        failOpen: false,
        evaluation,
        reason,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emit({
        kind: "fail_open",
        payload: { route: "/evaluate", context, error: message },
      });
      return {
        proceed: true,
        mode: this.config.rolloutMode,
        failOpen: true,
        reason: `Agentwall unavailable; fail-open policy evaluation: ${message}`,
      };
    }
  }

  async runOutbound<T>(params: {
    networkRequest: NetworkRequest;
    context: AgentContext;
    execute: () => Promise<T>;
  }): Promise<{ result?: T; blocked: boolean; network: NetworkPreflightResult; policy: PolicyPreflightResult }> {
    const startedAt = Date.now();
    this.emit({
      kind: "outbound.execute",
      payload: {
        phase: "start",
        route: params.networkRequest.url,
        action: params.context.action,
      },
    });

    const network = await this.inspectNetwork(params.networkRequest);
    const policy = await this.evaluatePolicy(params.context);
    const blocked = !network.proceed || !policy.proceed;

    if (blocked) {
      this.emit({
        kind: "outbound.execute",
        payload: {
          phase: "blocked",
          route: params.networkRequest.url,
          action: params.context.action,
          durationMs: Date.now() - startedAt,
          networkReason: network.reason,
          policyReason: policy.reason,
          networkFailOpen: network.failOpen,
          policyFailOpen: policy.failOpen,
        },
      });
      return { blocked, network, policy };
    }

    try {
      const result = await params.execute();
      this.emit({
        kind: "outbound.execute",
        payload: {
          phase: "allow",
          route: params.networkRequest.url,
          action: params.context.action,
          durationMs: Date.now() - startedAt,
          networkReason: network.reason,
          policyReason: policy.reason,
          networkFailOpen: network.failOpen,
          policyFailOpen: policy.failOpen,
        },
      });
      return { result, blocked: false, network, policy };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.emit({
        kind: "outbound.execute",
        payload: {
          phase: "execute_error",
          route: params.networkRequest.url,
          action: params.context.action,
          durationMs: Date.now() - startedAt,
          error: message,
          networkReason: network.reason,
          policyReason: policy.reason,
          networkFailOpen: network.failOpen,
          policyFailOpen: policy.failOpen,
        },
      });
      throw error;
    }
  }

  private emit(event: Omit<HarnessPreflightEvent, "timestamp" | "mode">): void {
    if (!this.config.onEvent) {
      return;
    }

    this.config.onEvent({
      timestamp: new Date().toISOString(),
      mode: this.config.rolloutMode,
      ...event,
    });
  }
}
