import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import { EgressPolicy, HeartbeatConfig } from "./types";
import type { EnforcementMode } from "./runtime/enforcement";
import { FleetConfigSchema } from "./fleet/registry";
import type { FleetConfig } from "./fleet/registry";

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
  /**
   * The agents that share this host, and what each one is allowed to spend.
   *
   * Absent means one undifferentiated agent, which is the shape most deployments have and
   * the behaviour every earlier version had: records carry the process comm as the agentId
   * and the process-wide allowlist judges everything. Declaring agents is what turns that
   * into per-agent identity, per-agent allowlists, and per-agent budgets.
   *
   * Validated by FleetConfigSchema at load, not here, because the failures worth catching
   * (a literal secret in the file, two agents that match the same connection) are semantic
   * rather than structural. See src/fleet/registry.ts and docs/fleet.md.
   *
   * Scope: one host. There is no cross-instance identity and no shared budget.
   */
  fleet?: FleetConfig;
  /**
   * Egress enforcement. Absent means `monitor`: upgrading AgentWall must never start
   * blocking traffic that yesterday's identical configuration allowed.
   *
   * Optional in the type and always populated by `loadConfig`. The asymmetry is deliberate:
   * a required field would force every config literal already written against this
   * interface to be edited for a section that has one sensible default, and a config a
   * caller assembled by hand is exactly the case where inheriting `monitor` is right.
   * Consumers resolve it as `config.enforcement?.mode ?? "monitor"`.
   */
  enforcement?: { mode: EnforcementMode };
  /**
   * Transparent listener for kernel-redirected egress: the perimeter's data path.
   *
   * Absent means the listener does not start, which is the right default because it is only
   * useful once nftables is redirecting an agent UID's outbound TCP at it. Starting it
   * unbidden would open a second listening port on every upgraded install for no benefit.
   *
   * Optional in the type for the same reason `enforcement` is: a required field would force
   * every config literal already written against this interface to be edited for a section
   * that has a perfectly good "off". `host` defaults to 127.0.0.1, matching everything else
   * this process binds. Consumers resolve it as `config.transparent?.port`.
   *
   * `tlsPort` is the port a TLS destination is assumed to be on, default 443. SNI names a
   * host and nothing else, and the redirect has already replaced the socket's local port with
   * the proxy's, so the original port is not recoverable from a captured connection — the
   * listener has to be told. It MUST agree with the ports the nftables ruleset actually
   * redirects. If the ruleset captures a TLS port this does not name, those connections are
   * resolved to the right host and then opened against this port instead: the wrong service,
   * with an allow verdict that was evaluated against a destination the agent never asked for.
   */
  transparent?: { port: number; host?: string; tlsPort?: number };
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
  /**
   * Absolute path of the file this config was read from, absent when it came from built-in
   * defaults or from a caller-assembled literal.
   *
   * Populated by `loadConfig` and set AFTER the merge, so a config file cannot name its own
   * path and cannot be pointed at a different one. Reload needs it to re-read the same file
   * the process booted from rather than re-running candidate discovery and possibly landing
   * on a different one.
   */
  sourcePath?: string;
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
  enforcement: {
    mode: "monitor",
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

/**
 * The config file `loadConfig` would read, or null when none of the candidates exist.
 *
 * Exported because reload has to re-read THE SAME file the process booted from. Two copies of
 * this candidate list would be free to drift, and a reload that quietly switched to a
 * different candidate would apply a file the operator never edited.
 */
export function resolveConfigSource(configPath?: string): string | null {
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
      return resolved;
    }
  }

  return null;
}

export function loadConfig(configPath?: string): AgentwallConfig {
  let fileConfig: Partial<AgentwallConfig> = {};
  // Which file the values came from. Reported in the enforcement-mode error below: a
  // process that refuses to boot over a config key has to say which of the five candidate
  // paths it actually read, or the operator fixes the wrong file.
  const resolvedSource = resolveConfigSource(configPath);
  const sourcePath = resolvedSource ?? "built-in defaults";

  if (resolvedSource) {
    fileConfig = yaml.load(fs.readFileSync(resolvedSource, "utf-8")) as Partial<AgentwallConfig>;
  }

  const merged = deepMerge(defaults as unknown as Record<string, unknown>, fileConfig as Record<string, unknown>);

  // Backward-compatibility for older config files that still use `ssrf`.
  if ("ssrf" in (fileConfig as Record<string, unknown>) && !("egress" in (fileConfig as Record<string, unknown>))) {
    merged["egress"] = deepMerge(
      defaults.egress as unknown as Record<string, unknown>,
      ((fileConfig as Record<string, unknown>)["ssrf"] as Record<string, unknown>) ?? {}
    );
  }

  // An unrecognised enforcement mode is a startup failure, not a fallback.
  //
  // Both fallbacks are worse than refusing to start. Defaulting a typo down to `monitor`
  // leaves an operator who wrote `strct` believing they are enforcing while nothing is
  // gated, which is the one outcome a security tool must never produce quietly. Defaulting
  // it up to `strict` turns a typo into an outage. A process that will not start is a
  // failure the operator can see and fix in the time it takes to read the message — which
  // is why the message names the file, the key, the value it rejected, and the whole valid
  // set. A boot-time throw that makes an operator go hunting is its own outage.
  const section = merged["enforcement"];
  const mode = section && typeof section === "object" && "mode" in section ? section.mode : undefined;
  if (mode !== "monitor" && mode !== "guarded" && mode !== "strict") {
    throw new Error(
      `agentwall: invalid enforcement.mode ${JSON.stringify(mode ?? section)} in ${sourcePath}. ` +
        `Valid modes are "monitor", "guarded", and "strict". Omit the enforcement section entirely to use "monitor".`
    );
  }

  // Same reasoning as enforcement.mode above, and the stakes here are higher.
  //
  // `policy.defaultDecision` is typed "allow" | "deny", but the value arrives from yaml.load
  // through deepMerge, so the type is a claim about the file rather than a check on it. An
  // unrecognised value used to reach the engine intact and become the decision returned for
  // every request that matched no rule. Nothing downstream treats an unknown decision as a
  // block: src/runtime/enforcement.ts gates on `result.decision === "deny"` and
  // src/routes/telegram.ts on the same comparison, so a typo here did not fail closed, it
  // failed OPEN, for exactly the traffic the default exists to govern. Config reload made that
  // reachable without a restart, which is what turned a latent typo into something worth
  // refusing to start over.
  const policySection = merged["policy"];
  const defaultDecision =
    policySection && typeof policySection === "object" && "defaultDecision" in policySection
      ? policySection.defaultDecision
      : undefined;
  if (defaultDecision !== "allow" && defaultDecision !== "deny") {
    throw new Error(
      `agentwall: invalid policy.defaultDecision ${JSON.stringify(defaultDecision)} in ${sourcePath}. ` +
        `Valid values are "allow" and "deny". Omit the key entirely to use "deny".`
    );
  }

  // After the merge and unconditionally, so a config file that declares its own `sourcePath`
  // cannot make reload re-read a file the operator never wrote. Deleted rather than left when
  // there is no file, so `sourcePath` present always means "this came from a real file".
  if (resolvedSource) {
    merged["sourcePath"] = resolvedSource;
  } else {
    delete merged["sourcePath"];
  }

  // The fleet section is parsed rather than trusted, and a bad one is a boot failure for the
  // same reason a bad enforcement mode is. An agent whose match block has a typo does not
  // half-work: it silently never binds, every one of its connections falls back to the global
  // allowlist, and the operator's per-agent policy is simply not in force with nothing on
  // screen to say so.
  if (merged["fleet"] !== undefined) {
    const parsed = FleetConfigSchema.safeParse(merged["fleet"]);
    if (!parsed.success) {
      const detail = parsed.error.issues
        .map((issue) => `${issue.path.length > 0 ? issue.path.join(".") : "fleet"}: ${issue.message}`)
        .join("; ");
      throw new Error(`agentwall: invalid fleet section in ${sourcePath}. ${detail}`);
    }
    if (parsed.data.unmatched === "deny" && parsed.data.agents.length === 0) {
      // This configuration denies all proxied egress in guarded and strict, which is what the
      // lockdown is for. Accepting it would mean an operator who wrote the posture line before
      // the agent list takes the fleet offline and reads a wall of allowlist denials.
      throw new Error(
        `agentwall: fleet.unmatched is "deny" in ${sourcePath} but no agents are declared, which refuses ` +
          `all proxied egress in guarded and strict. Declare the agents, or use the lockdown to stop traffic.`
      );
    }
    merged["fleet"] = parsed.data;
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
