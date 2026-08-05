import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import { EgressPolicy, HeartbeatConfig } from "./types";

export interface AgentwallConfig {
  port: number;
  host: string;
  logLevel: string;
  telemetry?: {
    enabled: boolean;
    endpoint?: string;
    serviceName?: string;
    timeoutMs?: number;
    headers?: Record<string, string>;
  };
  dashboard?: {
    publicBaseUrl?: string;
  };
  organization?: {
    instanceId?: string;
    instanceName?: string;
    environment?: string;
    region?: string;
    instances?: Array<{
      id: string;
      name: string;
      url: string;
      role: "local" | "managed" | "remote";
      status: "online" | "degraded" | "unknown";
      environment?: string;
      region?: string;
      lastSeenAt?: string;
      summaryUrl?: string;
      authTokenEnv?: string;
      authHeaderName?: string;
      pollTimeoutMs?: number;
    }>;
  };
  approval: {
    mode: "auto" | "always" | "never";
    timeoutMs: number;
    webhookUrl?: string;
    backend?: "memory" | "file";
    persistencePath?: string;
  };
  /** Audit chain and off-box anchoring. */
  audit?: {
    /**
     * How often to seal segments, sign a checkpoint, and submit it to OpenTimestamps.
     * Unset or 0 disables anchoring entirely. A sensible starting value is 6h
     * (21600000), which matches how long an OTS anchor takes to confirm anyway.
     */
    anchorIntervalMs?: number;
  };
  policy: {
    defaultDecision: "allow" | "deny";
    configPath?: string;
  };
  dlp: {
    enabled: boolean;
    redactSecrets: boolean;
  };
  egress: EgressPolicy;
  manifestIntegrity: {
    enabled: boolean;
    approvedHashesPath?: string;
  };
  watchdog: HeartbeatConfig;
  runtimeGuards?: {
    enabled: boolean;
    requestPerMinutePerSession: number;
    toolActionPerMinutePerSession: number;
    approvalRequestsPerMinutePerSession: number;
    approvalResponsesPerMinutePerActor: number;
    maxPendingApprovalsGlobal: number;
    maxPendingApprovalsPerSession: number;
    costBudgetPerHourPerSession: number;
    shield?: {
      requestRateMultiplier?: number;
      toolActionRateMultiplier?: number;
      approvalRequestRateMultiplier?: number;
      approvalResponseRateMultiplier?: number;
      maxPendingGlobalMultiplier?: number;
      maxPendingSessionMultiplier?: number;
      costBudgetMultiplier?: number;
      defaultDurationMs?: number;
      queuePriorityPressureThreshold?: number;
    };
    costWeights: {
      evaluateBase: number;
      approvalRequest: number;
      approvalRequiresManual: number;
      toolActionMultiplier: number;
      highRiskMultiplier: number;
      criticalRiskMultiplier: number;
    };
  };
}


export const defaultRuntimeGuards = {
  enabled: true,
  requestPerMinutePerSession: 180,
  toolActionPerMinutePerSession: 60,
  approvalRequestsPerMinutePerSession: 30,
  approvalResponsesPerMinutePerActor: 90,
  maxPendingApprovalsGlobal: 300,
  maxPendingApprovalsPerSession: 25,
  costBudgetPerHourPerSession: 1200,
  shield: {
    requestRateMultiplier: 0.5,
    toolActionRateMultiplier: 0.5,
    approvalRequestRateMultiplier: 0.5,
    approvalResponseRateMultiplier: 0.5,
    maxPendingGlobalMultiplier: 0.6,
    maxPendingSessionMultiplier: 0.6,
    costBudgetMultiplier: 0.75,
    defaultDurationMs: 10 * 60_000,
    queuePriorityPressureThreshold: 0.65,
  },
  costWeights: {
    evaluateBase: 1,
    approvalRequest: 4,
    approvalRequiresManual: 2,
    toolActionMultiplier: 3,
    highRiskMultiplier: 2,
    criticalRiskMultiplier: 3,
  },
};

const defaults: AgentwallConfig = {
  port: 3000,
  host: "127.0.0.1",
  logLevel: "info",
  telemetry: {
    enabled: false,
    serviceName: "agentwall",
    timeoutMs: 1500,
    headers: {},
  },
  dashboard: {},
  approval: {
    mode: "auto",
    timeoutMs: 30000,
    backend: "file",
    persistencePath: "./agentwall-approvals.json",
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
    staleAfterMs: 15000,
    timeoutMs: 30000,
    killSwitchMode: "deny_all",
  },
  runtimeGuards: defaultRuntimeGuards,
};

export function loadConfig(configPath?: string): AgentwallConfig {
  let fileConfig: Partial<AgentwallConfig> = {};

  const candidatePaths = [
    configPath,
    process.env["AGENTWALL_CONFIG"],
    "./agentwall.config.yaml",
    "./agentwall.config.yml",
    "./examples/config.yaml",
  ].filter(Boolean) as string[];

  for (const candidatePath of candidatePaths) {
    const resolved = path.resolve(candidatePath);
    if (fs.existsSync(resolved)) {
      const raw = fs.readFileSync(resolved, "utf-8");
      fileConfig = yaml.load(raw) as Partial<AgentwallConfig>;
      break;
    }
  }

  const merged = deepMerge(defaults as unknown as Record<string, unknown>, fileConfig as Record<string, unknown>);

  // Backward-compatibility for older config files that still use `ssrf`.
  if ("ssrf" in (fileConfig as Record<string, unknown>) && !("egress" in (fileConfig as Record<string, unknown>))) {
    merged["egress"] = deepMerge(
      defaults.egress as unknown as Record<string, unknown>,
      ((fileConfig as Record<string, unknown>)["ssrf"] as Record<string, unknown>) ?? {}
    );
  }

  return merged as unknown as AgentwallConfig;
}

function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    const sourceValue = source[key];
    const targetValue = target[key];
    if (sourceValue && typeof sourceValue === "object" && !Array.isArray(sourceValue) && targetValue && typeof targetValue === "object") {
      result[key] = deepMerge(targetValue as Record<string, unknown>, sourceValue as Record<string, unknown>);
    } else if (sourceValue !== undefined) {
      result[key] = sourceValue;
    }
  }
  return result;
}
