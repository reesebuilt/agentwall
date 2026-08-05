#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import { spawnSync } from "child_process";
import { loadConfig } from "./config";
import { defaultConfig, OnboardingMode, writeStarterFiles } from "./onboarding";
import { runAnchorPass, runVerify, resolvePaths } from "./audit/anchor-service";

type CliFlags = Record<string, string | boolean>;
const BOOLEAN_FLAGS = new Set(["lan", "force", "json", "confirm"]);

interface ParsedArgs {
  flags: CliFlags;
  positionals: string[];
}

interface PriorityQueueItem {
  category: string;
  title: string;
  owner: string;
  status: string;
  timestamp: string;
  summary?: string;
  primaryAction?: string;
}

interface DashboardState {
  brand: string;
  generatedAt: string;
  service: {
    status: string;
    attentionRequired: boolean;
    operatorSummary: string;
    recommendedActions?: string[];
    host: string;
    port: number;
  };
  posture: {
    highestRisk: string;
    pendingApprovals: number;
    criticalSignals: number;
    activeAgentsNow?: number;
    activeAgents: number;
    totalRequests: number;
  };
  controls: {
    approvalMode: string;
  };
  stats: {
    sessionCounts: Record<string, number>;
  };
  floodGuard?: {
    mode: string;
    blockedTotal: number;
    blockedByCategory?: Record<string, number>;
    pressureByCategory?: Record<string, number>;
    pressureBySession?: Array<{ sessionId: string; pressure: number; blocked: number }>;
    recentBlocks?: Array<{ timestamp: string; category: string; reason: string; sessionId?: string; actor?: string; pressure: number }>;
    shieldUntil?: string | null;
    sessionOverrides?: Array<{ sessionId: string; multiplier: number; expiresAt: string }>;
    operatorGuidance?: {
      status: string;
      summary: string;
      recommendedAction: string;
      hottestSessionId?: string | null;
      pressure?: number;
    };
  };
  freshness?: {
    hasLiveActivity: boolean;
    isFresh: boolean;
    lastLiveEventAt?: string | null;
  };
  sessions?: {
    recent?: Array<{ sessionId: string; status: string }>;
    statusById?: Record<string, string>;
  };
  priorityQueue: PriorityQueueItem[];
}

function printHelp() {
  console.log(`Agentwall CLI

Usage:
  agentwall <command> [options]

Commands:
  init                Create agentwall.config.yaml and policy.yaml
  start               Start Agentwall server from current directory config
  dev                 Start in ts-node dev mode
  doctor              Validate local install and starter files
  status              Read live dashboard state from the running Agentwall server
  anchor              Seal audit segments, sign a checkpoint, submit it off-box
  verify              Check the three audit integrity layers independently
  approval-mode       Set approval mode (auto|always|never)
  shield              Enable FloodGuard shield mode
  normal              Return FloodGuard to normal mode
  session-boost       Temporarily raise FloodGuard limits for one session
  session-reset       Clear a FloodGuard session override
  pause               Pause one runtime session
  resume              Resume one runtime session
  terminate           Terminate one runtime session
  version             Print version
  help                Show this message

Shared options:
  --config <path>                     Read config from a specific file
  --url <http://host:port>            Override server URL instead of config host/port

Init options:
  --mode <monitor|guarded|strict>     Operating mode (default: guarded)
  --host <host>                       Bind host (default: 127.0.0.1)
  --port <port>                       Bind port (default: 3000)
  --allow-hosts <a,b,c>               Comma-separated egress allowlist
  --lan                               Bind to 0.0.0.0
  --force                             Overwrite existing config/policy files

Status options:
  --json                              Print raw JSON

Approval mode options:
  --mode <auto|always|never>          Approval routing mode (or pass as first positional)

Shield options:
  --minutes <n>                       Shield duration in minutes
  --duration-ms <n>                   Shield duration in milliseconds

Session override options:
  --session <id>                      Session ID to boost/reset
  --multiplier <n>                    Override multiplier (default: 1.5)
  --minutes <n>                       Override duration in minutes
  --duration-ms <n>                   Override duration in milliseconds

Session control options:
  --session <id>                      Session ID to pause/resume/terminate
  --note <text>                       Operator note stored with the control action
  --confirm                           Required for terminate to avoid accidental containment
`);
}

export function parseFlags(args: string[]): ParsedArgs {
  const flags: CliFlags = {};
  const positionals: string[] = [];

  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }

    const key = token.slice(2);
    const next = args[i + 1];
    if (BOOLEAN_FLAGS.has(key)) {
      flags[key] = true;
      continue;
    }
    if (!next || next.startsWith("--")) {
      flags[key] = true;
      continue;
    }

    flags[key] = next;
    i += 1;
  }

  return { flags, positionals };
}

function getPackageVersion(): string {
  const packageJsonPath = path.resolve(__dirname, "..", "package.json");
  try {
    const raw = fs.readFileSync(packageJsonPath, "utf8");
    const parsed = JSON.parse(raw) as { version?: string };
    return parsed.version || "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function runNodeScript(args: string[]) {
  const result = spawnSync(process.execPath, args, { stdio: "inherit" });
  process.exit(result.status ?? 1);
}

function commandInit(flags: CliFlags) {
  const modeInput = String(flags.mode || "guarded").toLowerCase();
  const mode: OnboardingMode = modeInput === "monitor" || modeInput === "strict" ? modeInput : "guarded";

  const host = String(flags.host || defaultConfig.host);
  const port = Number(flags.port || defaultConfig.port);
  const allowedHosts = String(flags["allow-hosts"] || "api.openai.com")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const lanAccess = Boolean(flags.lan);
  const force = Boolean(flags.force);

  const configPath = path.resolve(process.cwd(), "agentwall.config.yaml");
  const policyPath = path.resolve(process.cwd(), "policy.yaml");

  if (!force && (fs.existsSync(configPath) || fs.existsSync(policyPath))) {
    console.error("Refusing to overwrite existing agentwall.config.yaml or policy.yaml. Re-run with --force.");
    process.exit(1);
  }

  const { config } = writeStarterFiles(process.cwd(), {
    mode,
    host,
    port: Number.isFinite(port) ? port : defaultConfig.port,
    allowedHosts,
    lanAccess,
  });

  console.log("Created Agentwall starter files:");
  console.log(`- ${configPath}`);
  console.log(`- ${policyPath}`);
  console.log(`\nRun: agentwall start  (dashboard: http://${config.host}:${config.port})`);
}

function commandDoctor() {
  const checks = [
    {
      name: "Node version >= 20",
      ok: Number(process.versions.node.split(".")[0]) >= 20,
      detail: process.versions.node,
    },
    {
      name: "dist/index.js exists",
      ok: fs.existsSync(path.resolve(process.cwd(), "dist/index.js")),
      detail: "npm run build",
    },
    {
      name: "agentwall.config.yaml exists",
      ok: fs.existsSync(path.resolve(process.cwd(), "agentwall.config.yaml")),
      detail: "agentwall init",
    },
    {
      name: "policy.yaml exists",
      ok: fs.existsSync(path.resolve(process.cwd(), "policy.yaml")),
      detail: "agentwall init",
    },
  ];

  let failures = 0;
  for (const check of checks) {
    if (check.ok) {
      console.log(`✅ ${check.name}`);
    } else {
      failures += 1;
      console.log(`❌ ${check.name} (hint: ${check.detail})`);
    }
  }

  if (failures > 0) {
    process.exit(1);
  }
}

function loadCliConfig(flags: CliFlags) {
  const configPath = typeof flags.config === "string" ? flags.config : undefined;
  return loadConfig(configPath);
}

export function createBaseUrl(flags: CliFlags): string {
  if (typeof flags.url === "string" && flags.url.trim().length > 0) {
    return flags.url.replace(/\/$/, "");
  }

  const config = loadCliConfig(flags);
  return `http://${config.host}:${config.port}`;
}

function formatResolvedTarget(flags: CliFlags): string {
  return ` · target ${createBaseUrl(flags)}`;
}

function formatRelative(dateString?: string | null): string {
  if (!dateString) return "n/a";
  const deltaMs = Date.now() - new Date(dateString).getTime();
  if (!Number.isFinite(deltaMs)) return String(dateString);
  const seconds = Math.max(0, Math.round(deltaMs / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return new Date(dateString).toLocaleString();
}

function formatShieldExpiry(dateString?: string | null): string {
  if (!dateString) return "not set";
  const deltaMs = new Date(dateString).getTime() - Date.now();
  if (!Number.isFinite(deltaMs) || deltaMs <= 0) return "expired";
  const minutes = Math.max(1, Math.round(deltaMs / 60_000));
  return `${minutes}m remaining`;
}

function formatSessionOverrideSummary(item: { sessionId: string; multiplier: number; expiresAt: string }): string {
  return `${item.sessionId}×${item.multiplier} (${formatShieldExpiry(item.expiresAt)})`;
}

function humanizeFloodCategory(category: string): string {
  return category.replace(/_/g, " ");
}

function summarizeTopCategoryCounts(counts: Record<string, number> | undefined, limit = 3): string | null {
  if (!counts) return null;
  const top = Object.entries(counts)
    .filter(([, count]) => Number.isFinite(count) && count > 0)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)
    .map(([category, count]) => `${humanizeFloodCategory(category)} ${count}`);
  return top.length > 0 ? top.join(", ") : null;
}

function summarizeTopPressureSessions(
  sessions: Array<{ sessionId: string; pressure: number; blocked: number }> | undefined,
  limit = 3
): string | null {
  if (!sessions) return null;
  const top = sessions
    .filter((item) => item.sessionId && (item.pressure > 0 || item.blocked > 0))
    .slice(0, limit)
    .map((item) => `${item.sessionId} ${(item.pressure * 100).toFixed(0)}%${item.blocked > 0 ? ` (${item.blocked} blocked)` : ""}`);
  return top.length > 0 ? top.join(", ") : null;
}

function quoteShellArg(value: string): string {
  if (/^[A-Za-z0-9_./:-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function buildTargetArgSuffix(flags: CliFlags): string {
  if (typeof flags.url === "string" && flags.url.trim().length > 0) {
    return ` --url ${quoteShellArg(flags.url.trim())}`;
  }

  if (typeof flags.config === "string" && flags.config.trim().length > 0) {
    return ` --config ${quoteShellArg(flags.config.trim())}`;
  }

  return "";
}

function resolveControlTarget(state: DashboardState, flags: CliFlags = {}): { label: string; advertised: string } {
  const advertised = `http://${state.service.host}:${state.service.port}`;
  if (typeof flags.url === "string" && flags.url.trim().length > 0) {
    const requested = flags.url.trim().replace(/\/$/, "");
    if (requested !== advertised) {
      return {
        label: `${requested} (server advertises ${advertised})`,
        advertised,
      };
    }
    return { label: requested, advertised };
  }
  return { label: advertised, advertised };
}

function buildSuggestedCommands(state: DashboardState, flags: CliFlags = {}): string[] {
  const commands: string[] = [];
  const floodGuidance = state.floodGuard?.operatorGuidance;
  const hottestSessionId = floodGuidance?.hottestSessionId?.trim();
  const targetArgs = buildTargetArgSuffix(flags);
  const sessionOverrides = state.floodGuard?.sessionOverrides ?? [];
  const hottestOverride = hottestSessionId
    ? sessionOverrides.find((item) => item.sessionId === hottestSessionId)
    : sessionOverrides[0];
  const approvalMode = state.controls.approvalMode;
  const pendingApprovals = state.posture.pendingApprovals ?? 0;
  const criticalSignals = state.posture.criticalSignals ?? 0;
  const pausedSessions = state.stats.sessionCounts.paused ?? 0;
  const terminatedSessions = state.stats.sessionCounts.terminated ?? 0;
  const guidanceStatus = floodGuidance?.status ?? "normal";
  const hottestSessionStatus = hottestSessionId
    ? state.sessions?.statusById?.[hottestSessionId] ?? state.sessions?.recent?.find((item) => item.sessionId === hottestSessionId)?.status
    : undefined;
  const canNormalizeApprovalMode =
    pendingApprovals === 0 &&
    approvalMode === "always" &&
    guidanceStatus === "normal" &&
    state.floodGuard?.mode !== "shield" &&
    criticalSignals === 0 &&
    pausedSessions === 0 &&
    terminatedSessions === 0 &&
    !state.service.attentionRequired;
  const canNormalizeShield =
    state.floodGuard?.mode === "shield" &&
    guidanceStatus === "normal" &&
    criticalSignals === 0 &&
    pausedSessions === 0 &&
    terminatedSessions === 0 &&
    !state.service.attentionRequired;

  if (guidanceStatus === "recommend") {
    commands.push(`agentwall shield --minutes 10${targetArgs}`);
  } else if (canNormalizeShield) {
    commands.push(`agentwall normal${targetArgs}`);
  }

  if (pendingApprovals > 0 && approvalMode !== "always") {
    commands.push(`agentwall approval-mode always${targetArgs}`);
  } else if (canNormalizeApprovalMode) {
    commands.push(`agentwall approval-mode auto${targetArgs}`);
  }

  if (guidanceStatus !== "normal" && hottestSessionId && (!hottestSessionStatus || hottestSessionStatus === "active")) {
    commands.push(`agentwall pause ${hottestSessionId} --note "Investigate FloodGuard pressure"${targetArgs}`);
  } else if (guidanceStatus === "normal" && hottestOverride) {
    commands.push(`agentwall session-reset ${hottestOverride.sessionId}${targetArgs}`);
  }

  return commands.slice(0, 3);
}

function parseIntegerFlag(value: string | boolean | undefined, label: string): number | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive number`);
  }
  return Math.round(parsed);
}

function parseNumberFlag(value: string | boolean | undefined, label: string): number | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive number`);
  }
  return parsed;
}

function resolveDurationMs(flags: CliFlags, fallbackMs: number): number {
  const direct = parseIntegerFlag(flags["duration-ms"], "duration-ms");
  if (direct) return direct;
  const minutes = parseNumberFlag(flags.minutes, "minutes");
  if (minutes) return Math.round(minutes * 60_000);
  return fallbackMs;
}

function formatApiError(baseUrl: string, method: string, endpoint: string, status: number, detail: string): Error {
  if (status === 404 && endpoint.startsWith("/api/dashboard/control/session/")) {
    return new Error(`${detail}. Seed a live session first with /evaluate or another runtime request, then retry the control.`);
  }
  if (status === 409 && endpoint.startsWith("/api/dashboard/control/session/")) {
    return new Error(`${detail} Hard containment stays closed; start a new runtime session instead of reopening a terminated one.`);
  }
  if (endpoint === "/api/dashboard/state" && method === "GET" && [401, 403, 404].includes(status)) {
    return new Error(
      `Target ${baseUrl} responded with ${status} while fetching Agentwall dashboard state: ${detail}. This usually means you hit the wrong service or port. Start Agentwall first or pass --url for the live instance. The bundled monitor-first example config listens on http://127.0.0.1:3015.`
    );
  }
  return new Error(`Agentwall API ${method} ${endpoint} failed (${status}): ${detail}`);
}

function formatConnectionError(baseUrl: string, endpoint: string, error: unknown): Error {
  const detail = error instanceof Error && error.message.trim().length > 0 ? error.message.trim() : "connection failed";
  return new Error(
    `Could not reach Agentwall at ${baseUrl}${endpoint}: ${detail}. Start Agentwall first or pass --url for the live instance. The bundled monitor-first example config listens on http://127.0.0.1:3015.`
  );
}

async function requestJson<T>(method: string, endpoint: string, body?: unknown, flags: CliFlags = {}): Promise<T> {
  const baseUrl = createBaseUrl(flags);
  let response: Response;
  try {
    response = await fetch(`${baseUrl}${endpoint}`, {
      method,
      headers: body ? { "content-type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (error) {
    throw formatConnectionError(baseUrl, endpoint, error);
  }

  let payload: unknown = null;
  const text = await response.text();
  if (text.length > 0) {
    try {
      payload = JSON.parse(text) as unknown;
    } catch {
      payload = text;
    }
  }

  if (!response.ok) {
    const detail = typeof payload === "string"
      ? payload
      : (payload && typeof payload === "object" && "error" in payload ? String((payload as Record<string, unknown>).error) : response.statusText);
    throw formatApiError(baseUrl, method, endpoint, response.status, detail);
  }

  return payload as T;
}

export function formatStatusReport(state: DashboardState, flags: CliFlags = {}): string {
  const controlTarget = resolveControlTarget(state, flags);
  const lines = [
    `${state.brand} ${state.service.status.toUpperCase()}`,
    `${state.service.operatorSummary}`,
    `Control target: ${controlTarget.label}`,
    "",
    `Approval mode: ${state.controls.approvalMode}`,
    `FloodGuard: ${state.floodGuard?.mode ?? "normal"}${state.floodGuard?.mode === "shield" ? ` (${formatShieldExpiry(state.floodGuard?.shieldUntil)})` : ""}`,
    `Pending approvals: ${state.posture.pendingApprovals}`,
    `Critical signals: ${state.posture.criticalSignals}`,
    `Active agents now: ${state.posture.activeAgentsNow ?? state.posture.activeAgents}`,
    `Tracked sessions paused: ${state.stats.sessionCounts.paused ?? 0}`,
    `Tracked sessions terminated: ${state.stats.sessionCounts.terminated ?? 0}`,
    `Requests evaluated: ${state.posture.totalRequests}`,
  ];

  if (state.freshness?.hasLiveActivity) {
    lines.push(`Last live activity: ${formatRelative(state.freshness?.lastLiveEventAt ?? null)}${state.freshness?.isFresh ? "" : " (stale)"}`);
  } else {
    lines.push("Last live activity: awaiting first runtime event");
  }

  const overrides = state.floodGuard?.sessionOverrides ?? [];
  if (overrides.length > 0) {
    lines.push(`Session overrides: ${overrides.map((item) => formatSessionOverrideSummary(item)).join(", ")}`);
  }

  const floodGuidance = state.floodGuard?.operatorGuidance;
  if (floodGuidance?.summary) {
    lines.push(`FloodGuard guidance: ${floodGuidance.summary}`);
    if (floodGuidance.recommendedAction) {
      lines.push(`FloodGuard next move: ${floodGuidance.recommendedAction}`);
    }
    if (typeof floodGuidance.pressure === "number") {
      lines.push(`FloodGuard pressure: ${(floodGuidance.pressure * 100).toFixed(0)}%${floodGuidance.hottestSessionId ? ` · hottest session ${floodGuidance.hottestSessionId}` : ""}`);
    } else if (floodGuidance.hottestSessionId) {
      lines.push(`FloodGuard hottest session: ${floodGuidance.hottestSessionId}`);
    }
  }

  const blockSummary = summarizeTopCategoryCounts(state.floodGuard?.blockedByCategory);
  if (blockSummary) {
    lines.push(`FloodGuard blocked by type: ${blockSummary}`);
  }

  const categoryPressureSummary = summarizeTopCategoryCounts(state.floodGuard?.pressureByCategory);
  if (categoryPressureSummary) {
    lines.push(`FloodGuard pressure by type: ${categoryPressureSummary}`);
  }

  const sessionPressureSummary = summarizeTopPressureSessions(state.floodGuard?.pressureBySession);
  if (sessionPressureSummary) {
    lines.push(`FloodGuard hottest sessions: ${sessionPressureSummary}`);
  }

  const recentBlock = state.floodGuard?.recentBlocks?.[0];
  if (recentBlock) {
    lines.push(
      `Latest FloodGuard block: ${humanizeFloodCategory(recentBlock.category)} · ${recentBlock.reason}${recentBlock.sessionId ? ` · ${recentBlock.sessionId}` : ""} · ${formatRelative(recentBlock.timestamp)}`
    );
  }

  const recommendedActions = state.service.recommendedActions ?? [];
  if (recommendedActions.length > 0) {
    lines.push("");
    lines.push("Recommended actions:");
    for (const action of recommendedActions) {
      lines.push(`- ${action}`);
    }
  }

  const suggestedCommands = buildSuggestedCommands(state, flags);
  if (suggestedCommands.length > 0) {
    lines.push("");
    lines.push("CLI next moves:");
    for (const command of suggestedCommands) {
      lines.push(`- ${command}`);
    }
  }

  const topPriority = state.priorityQueue.slice(0, 3);
  if (topPriority.length > 0) {
    lines.push("");
    lines.push("Top queue:");
    for (const item of topPriority) {
      const actionLabel = item.primaryAction ? ` · next ${item.primaryAction.toLowerCase()}` : "";
      lines.push(`- [${item.category}/${item.status}] ${item.owner} · ${item.title} · ${formatRelative(item.timestamp)}${actionLabel}`);
      if (item.summary) {
        lines.push(`  ${item.summary}`);
      }
    }
  }

  return lines.join("\n");
}

export async function commandStatus(flags: CliFlags) {
  const state = await requestJson<DashboardState>("GET", "/api/dashboard/state", undefined, flags);
  if (flags.json) {
    console.log(JSON.stringify(state, null, 2));
    return;
  }
  console.log(formatStatusReport(state, flags));
}

export async function commandShield(flags: CliFlags) {
  const config = loadCliConfig(flags);
  const fallbackMs = config.runtimeGuards?.shield?.defaultDurationMs ?? 10 * 60_000;
  const durationMs = resolveDurationMs(flags, fallbackMs);
  const response = await requestJson<{ mode: string; shieldUntil?: string | null }>(
    "POST",
    "/api/dashboard/control/floodguard-mode",
    { mode: "shield", durationMs },
    flags
  );
  console.log(`FloodGuard ${response.mode} enabled for ${Math.round(durationMs / 60_000)}m${response.shieldUntil ? ` · until ${response.shieldUntil}` : ""}${formatResolvedTarget(flags)}`);
}

export async function commandNormal(flags: CliFlags) {
  const response = await requestJson<{ mode: string }>(
    "POST",
    "/api/dashboard/control/floodguard-mode",
    { mode: "normal" },
    flags
  );
  console.log(`FloodGuard ${response.mode}${formatResolvedTarget(flags)}`);
}

type ApprovalMode = "auto" | "always" | "never";
type SessionControlAction = "pause" | "resume" | "terminate";

export function resolveApprovalMode(flags: CliFlags, positionals: string[]): ApprovalMode {
  const mode = typeof flags.mode === "string" && flags.mode.trim().length > 0
    ? flags.mode.trim().toLowerCase()
    : positionals[0]?.trim().toLowerCase();
  if (mode === "auto" || mode === "always" || mode === "never") {
    return mode;
  }
  throw new Error("approval mode required. Use --mode <auto|always|never> or pass it as the first positional argument.");
}

function requireSessionId(flags: CliFlags, positionals: string[]): string {
  const sessionId = typeof flags.session === "string" && flags.session.trim().length > 0
    ? flags.session.trim()
    : positionals[0];
  if (!sessionId) {
    throw new Error("session ID required. Use --session <id> or pass it as the first positional argument.");
  }
  return sessionId;
}

function resolveSessionNote(flags: CliFlags, positionals: string[]): string | undefined {
  if (typeof flags.note === "string" && flags.note.trim().length > 0) {
    return flags.note.trim();
  }
  const startIndex = typeof flags.session === "string" && flags.session.trim().length > 0 ? 0 : 1;
  const note = positionals.slice(startIndex).join(" ").trim();
  return note.length > 0 ? note : undefined;
}

export async function commandApprovalMode(flags: CliFlags, positionals: string[]) {
  const mode = resolveApprovalMode(flags, positionals);
  const response = await requestJson<{ mode: ApprovalMode }>(
    "POST",
    "/api/dashboard/control/approval-mode",
    { mode },
    flags
  );
  console.log(`Approval mode set to ${response.mode}${formatResolvedTarget(flags)}`);
}

export async function commandSessionControl(action: SessionControlAction, flags: CliFlags, positionals: string[]) {
  if (action === "terminate" && !flags.confirm) {
    throw new Error("terminate requires --confirm to avoid accidental containment.");
  }
  const sessionId = requireSessionId(flags, positionals);
  const note = resolveSessionNote(flags, positionals);
  const response = await requestJson<{ session: { sessionId: string; status: string; note?: string } }>(
    "POST",
    `/api/dashboard/control/session/${encodeURIComponent(sessionId)}`,
    action === "terminate"
      ? { action, confirm: true, ...(note ? { note } : {}) }
      : note ? { action, note } : { action },
    flags
  );
  console.log(`Session ${response.session.sessionId} ${response.session.status}${response.session.note ? ` · ${response.session.note}` : ""}${formatResolvedTarget(flags)}`);
}

export async function commandSessionBoost(flags: CliFlags, positionals: string[]) {
  const config = loadCliConfig(flags);
  const sessionId = requireSessionId(flags, positionals);
  const multiplier = parseNumberFlag(flags.multiplier, "multiplier") ?? 1.5;
  const fallbackMs = config.runtimeGuards?.shield?.defaultDurationMs ?? 10 * 60_000;
  const durationMs = resolveDurationMs(flags, fallbackMs);
  const response = await requestJson<{ override: { sessionId: string; multiplier: number; expiresAt: string } }>(
    "POST",
    `/api/dashboard/control/floodguard-session/${encodeURIComponent(sessionId)}`,
    { action: "set", multiplier, durationMs },
    flags
  );
  console.log(`FloodGuard override set for ${response.override.sessionId} ×${response.override.multiplier} until ${response.override.expiresAt}${formatResolvedTarget(flags)}`);
}

export async function commandSessionReset(flags: CliFlags, positionals: string[]) {
  const sessionId = requireSessionId(flags, positionals);
  const response = await requestJson<{ cleared: boolean }>(
    "POST",
    `/api/dashboard/control/floodguard-session/${encodeURIComponent(sessionId)}`,
    { action: "clear" },
    flags
  );
  console.log(
    response.cleared
      ? `FloodGuard override cleared for ${sessionId}${formatResolvedTarget(flags)}`
      : `No FloodGuard override was active for ${sessionId}${formatResolvedTarget(flags)}`
  );
}

/**
 * Resolve the audit file the same way the server does, so the CLI and the running
 * service never disagree about which chain they are talking about.
 */
function auditPathFromEnv(flags: CliFlags): string {
  const explicit = typeof flags.audit === "string" ? flags.audit : undefined;
  const resolved = explicit ?? process.env.AGENTWALL_AUDIT_FILE;
  if (!resolved) {
    console.error(
      "No audit file configured. Set AGENTWALL_AUDIT_FILE or pass --audit <path>.\n" +
        "This is the file the proxy appends decisions to.",
    );
    process.exit(1);
  }
  return resolved;
}

/**
 * `agentwall anchor` - seal closed segments, sign a checkpoint, submit it off-box.
 *
 * Off-box is the point. A signature proves a key holder vouched; on a host where the
 * audited process can read the key, that is necessary and not sufficient. An anchor puts
 * a fingerprint somewhere this machine cannot reach.
 */
async function commandAnchor(flags: CliFlags): Promise<void> {
  const auditPath = auditPathFromEnv(flags);
  const result = await runAnchorPass({ auditPath });

  if (!result.anchored) {
    console.error(`Nothing to anchor: ${result.reason}`);
    process.exit(1);
  }

  const record = result.records?.[0];
  const paths = resolvePaths({ auditPath });

  if (flags.json) {
    console.log(JSON.stringify({ ...result, paths }, null, 2));
    return;
  }

  console.log("Anchored");
  console.log(`  checkpoint index  ${result.checkpoint?.chainIndex}`);
  console.log(`  checkpoint hash   ${result.checkpoint?.hash}`);
  console.log(`  covers            ${result.covered} records (${result.segments} sealed segment(s) + ${result.liveRecords} live)`);
  if (record?.error) {
    console.log(`  backend           FAILED: ${record.error}`);
    console.log("\nThe checkpoint is signed and recorded, but nothing is anchored off-box.");
    process.exit(1);
  }
  console.log(`  calendar          ${record?.reference}`);
  console.log(`  proof             ${record?.proofPath}`);
  console.log(`  status            ${record?.status}`);
  console.log(
    "\nOpenTimestamps anchors into a Bitcoin block, so this stays pending for roughly\n" +
      "one to six hours. It is not proof until a block confirms it.",
  );
}

/**
 * `agentwall verify` - check the three integrity layers independently.
 *
 * Deliberately not a single green tick. They are different properties, and collapsing
 * them is how a tool ends up claiming more than it can show.
 */
async function commandVerify(flags: CliFlags): Promise<void> {
  const auditPath = auditPathFromEnv(flags);
  const report = runVerify({ auditPath });

  if (flags.json) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.ok ? 0 : 1);
  }

  const meaning: Record<string, string> = {
    chained: "records link within each segment, so an edit inside one is detectable",
    linked: "segments link to each other, so removing a whole segment is detectable",
    anchored: "a fingerprint exists off-box, so rewriting everything here is detectable",
  };

  for (const layer of report.layers) {
    console.log(`${layer.ok ? "PASS" : "FAIL"}  ${layer.name.padEnd(9)} ${layer.detail}`);
    console.log(`            ${meaning[layer.name]}`);
    for (const problem of layer.problems) console.log(`            ! ${problem}`);
  }

  if (report.pending > 0) {
    console.log(
      `\n${report.pending} anchor(s) pending a Bitcoin block. Pending is not proof;\n` +
        "re-run verify once a block confirms.",
    );
  }
  if (report.failed > 0) {
    console.log(`\n${report.failed} anchor(s) never reached a calendar. Those records are NOT anchored.`);
  }

  process.exit(report.ok ? 0 : 1);
}


async function main() {
  const [, , command = "help", ...args] = process.argv;
  const { flags, positionals } = parseFlags(args);

  switch (command) {
    case "help":
    case "--help":
    case "-h":
      printHelp();
      return;
    case "version":
    case "--version":
    case "-v":
      console.log(getPackageVersion());
      return;
    case "init":
      commandInit(flags);
      return;
    case "start":
      runNodeScript([path.resolve(process.cwd(), "dist/index.js")]);
      return;
    case "dev":
      runNodeScript([path.resolve(process.cwd(), "node_modules/ts-node/dist/bin.js"), "src/index.ts"]);
      return;
    case "doctor":
      commandDoctor();
      return;
    case "status":
      await commandStatus(flags);
      return;
    case "approval-mode":
      await commandApprovalMode(flags, positionals);
      return;
    case "shield":
      await commandShield(flags);
      return;
    case "normal":
      await commandNormal(flags);
      return;
    case "session-boost":
      await commandSessionBoost(flags, positionals);
      return;
    case "session-reset":
      await commandSessionReset(flags, positionals);
      return;
    case "pause":
      await commandSessionControl("pause", flags, positionals);
      return;
    case "resume":
      await commandSessionControl("resume", flags, positionals);
      return;
    case "terminate":
      await commandSessionControl("terminate", flags, positionals);
      return;
    case "anchor":
      await commandAnchor(flags);
      return;
    case "verify":
      await commandVerify(flags);
      return;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
