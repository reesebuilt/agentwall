import { randomUUID } from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as yaml from "js-yaml";
import { AgentwallConfig } from "../config";
import {
  AgentContext,
  ApprovalRequest,
  ApprovalResponse,
  AuditEvent,
  ContentClassification,
  ManifestDrift,
  ManifestSubjectType,
  NetworkInspection,
  NetworkRequest,
  RiskLevel,
  WatchdogState,
} from "../types";
import { HeartbeatWatchdog } from "../watchdog/heartbeat";
import { buildOrganizationControlPlaneSnapshot } from "../org/control-plane";
import {
  DAMAGE_CONTROL_LADDER,
  DEFAULT_DAMAGE_CONTROL_MODE,
  defaultWhitelistCommands,
  RECOMMENDED_DEFAULT_LEVEL,
} from "../integrations/damage-control/command-firewall";
import { detectionForBlockedCategory } from "../policy/detections";
import { PersistedPendingApproval } from "../approval/store";

type RuntimeEventCategory =
  | "system"
  | "policy"
  | "approval"
  | "audit"
  | "network"
  | "content"
  | "watchdog"
  | "session";

type RuntimeEventStatus = "ok" | "pending" | "warning" | "critical";
type SessionStatus = "active" | "paused" | "terminated";
type RuntimeFlowStatus = "running" | "waiting" | "blocked" | "completed";
type EvidenceKind = "audit" | "approval" | "inspection" | "provenance" | "watchdog" | "session";

interface RuntimeEvent {
  id: string;
  timestamp: string;
  category: RuntimeEventCategory;
  title: string;
  summary: string;
  status: RuntimeEventStatus;
  riskLevel?: RiskLevel;
  plane?: string;
  agentId?: string;
  sessionId?: string;
  detail?: Record<string, unknown>;
  synthetic?: boolean;
  operatorInitiated?: boolean;
}

interface AgentRuntimeActivity {
  agentId: string;
  lastSeenAt: string;
  lastPlane: string;
  lastAction: string;
  sessionId?: string;
  riskLevel?: RiskLevel;
  latestChannelId?: string;
}

interface SessionRuntime {
  sessionId: string;
  agentId: string;
  startedAt: string;
  lastSeenAt: string;
  lastPlane: string;
  lastAction: string;
  status: SessionStatus;
  riskLevel: RiskLevel;
  note?: string;
  pendingApprovals: number;
  evidenceCount: number;
  taskCount: number;
  channelId?: string;
  simulated?: boolean;
  scenarioId?: string;
}

interface ChannelRuntimeActivity {
  id: string;
  agentId: string;
  channelId: string;
  lastSeenAt: string;
  lastPlane: string;
  lastAction: string;
  riskLevel: RiskLevel;
  sessionIds: string[];
  userIds: string[];
  roleIds: string[];
}

interface ApprovalActivity {
  requestId: string;
  createdAt: string;
  resolvedAt?: string;
  status: "pending" | "approved" | "denied" | "timeout";
  mode: "manual" | "auto";
  agentId: string;
  sessionId: string;
  plane: string;
  action: string;
  riskLevel: RiskLevel;
  reasons: string[];
  matchedRules: string[];
  note?: string;
  approvedBy?: string;
  simulated?: boolean;
  scenarioId?: string;
}

interface OperatorSurfaceItem {
  label: string;
  value: string;
  detail: string;
  status: RuntimeEventStatus;
}

interface PriorityQueueItem {
  id: string;
  category: "approval" | "watchdog" | "provenance" | "session";
  title: string;
  owner: string;
  summary: string;
  status: RuntimeEventStatus;
  timestamp: string;
  drilldownKind?: DrilldownPayload["kind"];
  drilldownId?: string;
  primaryAction?: string;
}

interface RuntimeFlow {
  id: string;
  timestamp: string;
  flowType: "policy" | "approval" | "inspection" | "session";
  status: RuntimeFlowStatus;
  agentId: string;
  sessionId: string;
  plane: string;
  action: string;
  direction: string;
  target: string;
  summary: string;
  riskLevel: RiskLevel;
  decision?: string;
  labels: string[];
  crossesBoundary: boolean;
  simulated?: boolean;
  scenarioId?: string;
}

interface EvidenceRecord {
  id: string;
  timestamp: string;
  kind: EvidenceKind;
  title: string;
  summary: string;
  riskLevel: RiskLevel;
  status: RuntimeEventStatus;
  agentId: string;
  sessionId: string;
  plane: string;
  linkedObjectId: string;
  attributes: Record<string, string>;
  relatedTaskIds: string[];
  simulated?: boolean;
  scenarioId?: string;
}

interface TaskNode {
  id: string;
  sessionId: string;
  agentId: string;
  plane: string;
  action: string;
  title: string;
  summary: string;
  status: "active" | "blocked" | "completed";
  riskLevel: RiskLevel;
  createdAt: string;
  updatedAt: string;
  evidenceIds: string[];
  simulated?: boolean;
  scenarioId?: string;
}

interface TaskEdge {
  from: string;
  to: string;
  relationship: "precedes" | "evidenced_by";
}

interface SimulationState {
  enabled: boolean;
  scenarioId: string | null;
  label: string | null;
  injectedAt: string | null;
  disclaimer: string;
}

type KnowledgeBaseCategory = "sources" | "concepts" | "articles" | "tutorials" | "open_questions" | "file_structure" | "runtime_context";

interface KnowledgeBaseEntry {
  id: string;
  category: KnowledgeBaseCategory;
  title: string;
  summary: string;
  detail: string;
  tags: string[];
  chips?: string[];
  value?: string;
  excerpt?: string;
  facts?: Array<{ label: string; value: string }>;
  location?: string;
  href?: string;
  status?: "curated" | "draft" | "open" | "available" | "missing";
}

interface KnowledgeBaseSection {
  id: KnowledgeBaseCategory;
  title: string;
  description: string;
  count: number;
  accent: "accent" | "pending" | "warning";
}

interface KnowledgeBaseAccess {
  baseUrl: string;
  dashboardUrl: string;
  knowledgeBaseUrl: string;
  lastVerifiedAt: string;
  lastVerifiedStatus: "seeded" | "fresh" | "stale";
}

interface DirectorySummary {
  relativePath: string;
  fileCount: number;
  directoryCount: number;
  topExtensions: string[];
  sampleFiles: string[];
}

const REPO_ROOT = path.resolve(__dirname, "../..");
// Where the agent runtime keeps its prompt, memory, profile, and config. Agentwall only
// probes for presence and size here and never returns the contents (see
// buildAgentRuntimeContextEntries), because that directory is the highest-value target in
// the whole deployment. Point AGENTWALL_AGENT_HOME at your own runtime; the default is a
// convention, not a discovery mechanism, so an unset var just reports "not configured".
const AGENT_HOME = path.resolve(
  process.env["AGENTWALL_AGENT_HOME"]?.trim() || path.join(os.homedir(), ".agentwall", "agent")
);

function agentHomePath(...segments: string[]): string {
  return path.join(AGENT_HOME, ...segments);
}

function readTextSafely(absolutePath: string): string {
  try {
    return fs.readFileSync(absolutePath, "utf8");
  } catch {
    return "";
  }
}

function safeStat(absolutePath: string): fs.Stats | null {
  try {
    return fs.statSync(absolutePath);
  } catch {
    return null;
  }
}

function countImmediateDirectories(absolutePath: string): number {
  try {
    return fs.readdirSync(absolutePath, { withFileTypes: true }).filter((entry) => entry.isDirectory()).length;
  } catch {
    return 0;
  }
}

function summarizeMarkdownText(text: string): string {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("```"));
  const paragraph = lines.find((line) => !line.startsWith("- ") && !line.startsWith("* "));
  return paragraph ? paragraph.slice(0, 220) : "";
}

function excerptMarkdownText(text: string, maxLines = 2): string {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("```"))
    .slice(0, maxLines)
    .join(" · ");
}

function probeFirstExistingPath(candidates: string[]): string | null {
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? null;
}

function nestedStringValue(source: unknown, keys: string[]): string | null {
  let current: unknown = source;
  for (const key of keys) {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return null;
    }
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === "string" && current.trim() ? current.trim() : null;
}

function yamlTopLevelKeys(source: unknown): string[] {
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    return [];
  }
  return Object.keys(source as Record<string, unknown>);
}

function summarizeYamlSource(absolutePath: string): { keys: string[]; modelDefault: string | null; modelProvider: string | null; skin: string | null } {
  const text = readTextSafely(absolutePath);
  if (!text) {
    return { keys: [], modelDefault: null, modelProvider: null, skin: null };
  }
  const parsed = yaml.load(text);
  return {
    keys: yamlTopLevelKeys(parsed),
    modelDefault: nestedStringValue(parsed, ["model", "default"]),
    modelProvider: nestedStringValue(parsed, ["model", "provider"]),
    skin: nestedStringValue(parsed, ["display", "skin"]),
  };
}

function formatCountLabel(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

export type SessionControlAction = "pause" | "resume" | "terminate";

export type SessionControlResult =
  | { ok: true; session: SessionRuntime }
  | { ok: false; reason: "not_found"; message: string }
  | { ok: false; reason: "invalid_transition"; message: string; session: SessionRuntime };

interface DrilldownPayload {
  kind: "session" | "approval" | "evidence" | "task" | "agent";
  id: string;
  title: string;
  status: string;
  summary: string;
  facts: Array<{ label: string; value: string }>;
  timeline: Array<{ timestamp: string; title: string; summary: string; status: string }>;
  queueNavigation?: {
    previousRequestId: string | null;
    previousTarget: string | null;
    previousDetail: string | null;
    previousRule: string | null;
    nextRequestId: string | null;
    nextTarget: string | null;
    nextDetail: string | null;
    nextRule: string | null;
  };
  related: {
    sessions: SessionRuntime[];
    approvals: ApprovalActivity[];
    evidence: EvidenceRecord[];
    tasks: TaskNode[];
  };
}

const MAX_FEED_ITEMS = 160;
const MAX_GRAPH_ITEMS = 120;

function limit<T>(items: T[], max = MAX_FEED_ITEMS): T[] {
  return items.slice(0, max);
}

function scoreRisk(level: RiskLevel): number {
  switch (level) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    default:
      return 1;
  }
}

function prioritizePendingApprovals(items: ApprovalActivity[]): ApprovalActivity[] {
  return [...items].sort((left, right) => {
    const riskDelta = scoreRisk(right.riskLevel) - scoreRisk(left.riskLevel);
    if (riskDelta !== 0) return riskDelta;
    return left.createdAt.localeCompare(right.createdAt);
  });
}

function summarizePendingApprovalNeighbor(item: ApprovalActivity | null, now: Date): string | null {
  if (!item) return null;
  return [item.riskLevel, `waiting ${formatAgeShort(item.createdAt, now)}`, item.note ?? item.reasons[0] ?? "Awaiting analyst disposition"]
    .filter(Boolean)
    .join(" · ");
}

function toStatus(level: RiskLevel): RuntimeEventStatus {
  if (level === "critical") return "critical";
  if (level === "high") return "warning";
  return "ok";
}

function trustStateToRiskLevel(trustState: ManifestDrift["trustState"]): RiskLevel {
  if (trustState === "untrusted") return "high";
  if (trustState === "review_required") return "medium";
  return "low";
}

function trustStateToEventStatus(trustState: ManifestDrift["trustState"]): RuntimeEventStatus {
  if (trustState === "untrusted") return "critical";
  if (trustState === "review_required") return "pending";
  return "ok";
}

function countBy<T>(items: T[], key: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const bucket = key(item);
    counts[bucket] = (counts[bucket] ?? 0) + 1;
  }
  return counts;
}

function buildLatestVerifiedOutcome(recentAudits: AuditEvent[], evidence: EvidenceRecord[]) {
  const audit = recentAudits[0];
  if (audit) {
    return {
      source: "audit",
      decision: audit.decision,
      action: audit.action,
      plane: audit.plane,
      agentId: audit.agentId,
      sessionId: audit.sessionId ?? defaultSessionId(audit.agentId),
      riskLevel: audit.riskLevel,
      timestamp: audit.timestamp,
      summary: audit.reasons[0] ?? "Policy evaluation recorded",
      integrityStatus: audit.integrity.status,
      auditEventId: audit.id,
    };
  }

  const verifiedEvidence = evidence.find((record) => record.status !== "pending") ?? evidence[0];
  if (!verifiedEvidence) return null;
  return {
    source: "evidence",
    decision: verifiedEvidence.attributes["decision"] ?? verifiedEvidence.status,
    action: verifiedEvidence.title,
    plane: verifiedEvidence.plane,
    agentId: verifiedEvidence.agentId,
    sessionId: verifiedEvidence.sessionId,
    riskLevel: verifiedEvidence.riskLevel,
    timestamp: verifiedEvidence.timestamp,
    summary: verifiedEvidence.summary,
    evidenceId: verifiedEvidence.id,
  };
}

function formatAgeShort(from: string, now: Date): string {
  const deltaMs = Math.max(0, now.getTime() - new Date(from).getTime());
  const totalSeconds = Math.round(deltaMs / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes < 60) return seconds === 0 ? `${minutes}m` : `${minutes}m ${seconds}s`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes === 0 ? `${hours}h` : `${hours}h ${remainingMinutes}m`;
}

function defaultSessionId(agentId: string): string {
  return `${agentId}:default`;
}

function summarizeTarget(target: unknown): string {
  if (typeof target === "string" && target.length > 0) return target;
  if (target && typeof target === "object") {
    const maybeTarget = (target as Record<string, unknown>)["url"] ?? (target as Record<string, unknown>)["target"];
    if (typeof maybeTarget === "string" && maybeTarget.length > 0) return maybeTarget;
  }
  return "control-plane";
}

function compareIsoTimestampsDescending(left: string, right: string): number {
  return right.localeCompare(left);
}

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function buildCanonicalBaseUrl(config: AgentwallConfig): string {
  const configuredBaseUrl = config.dashboard?.publicBaseUrl?.trim();
  if (configuredBaseUrl) {
    return trimTrailingSlash(configuredBaseUrl);
  }

  const canonicalHost = config.host || "127.0.0.1";
  const canonicalPort = Number.isFinite(config.port) ? config.port : 3000;
  return `http://${canonicalHost}:${canonicalPort}`;
}

function repoPath(relativePath: string): string {
  return path.join(REPO_ROOT, relativePath);
}

function normalizeRepoRelative(relativePath: string): string {
  return relativePath.replaceAll(path.sep, "/");
}


function safeReadText(relativePath: string): string {
  try {
    return fs.readFileSync(repoPath(relativePath), "utf8");
  } catch {
    return "";
  }
}

function formatExtension(ext: string): string {
  return ext === "(none)" ? "no extension" : ext.replace(/^\./, "");
}

function summarizeMarkdown(relativePath: string, fallback: string): string {
  if (path.extname(relativePath) !== ".md") {
    return fallback;
  }
  const text = safeReadText(relativePath);
  if (!text) return fallback;
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("```"));
  const paragraph = lines.find((line) => !line.startsWith("- ") && !line.startsWith("* "));
  return paragraph ? paragraph.slice(0, 220) : fallback;
}

function summarizeDirectory(relativePath: string): DirectorySummary {
  const root = repoPath(relativePath);
  const extensionCounts: Record<string, number> = {};
  const sampleFiles: string[] = [];
  let fileCount = 0;
  let directoryCount = 0;
  const queue = [root];

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) continue;
    const dirents = fs
      .readdirSync(current, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));

    for (const dirent of dirents) {
      const absolute = path.join(current, dirent.name);
      const relative = normalizeRepoRelative(path.relative(REPO_ROOT, absolute));
      if (dirent.isDirectory()) {
        directoryCount += 1;
        queue.push(absolute);
        continue;
      }
      if (!dirent.isFile()) continue;
      fileCount += 1;
      const ext = path.extname(dirent.name) || "(none)";
      extensionCounts[ext] = (extensionCounts[ext] ?? 0) + 1;
      if (sampleFiles.length < 4) {
        sampleFiles.push(relative);
      }
    }
  }

  const topExtensions = Object.entries(extensionCounts)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 3)
    .map(([ext, count]) => `${formatExtension(ext)} ${count}`);

  return {
    relativePath,
    fileCount,
    directoryCount,
    topExtensions,
    sampleFiles,
  };
}

function buildFileSummaryEntry(relativePath: string, title: string, tags: string[]): KnowledgeBaseEntry {
  const summary = summarizeDirectory(relativePath);
  return {
    id: `structure-${relativePath.replace(/[/.]+/g, "-")}`,
    category: "file_structure",
    title,
    summary: `${summary.relativePath} contains ${summary.fileCount} file(s) across ${summary.directoryCount} nested director${summary.directoryCount === 1 ? "y" : "ies"}.`,
    detail: `Top file types: ${summary.topExtensions.join(", ") || "none"}. Sample paths: ${summary.sampleFiles.join(", ") || "none"}.`,
    tags,
    chips: [...summary.topExtensions],
    location: relativePath,
    status: "curated",
  };
}

function buildSourceEntry(
  id: string,
  title: string,
  relativePath: string,
  fallbackSummary: string,
  detail: string,
  tags: string[],
  href?: string
): KnowledgeBaseEntry {
  return {
    id,
    category: "sources",
    title,
    summary: summarizeMarkdown(relativePath, fallbackSummary),
    detail,
    tags,
    location: relativePath,
    href,
    status: "curated",
  };
}

function buildDocEntry(
  category: Exclude<KnowledgeBaseCategory, "sources" | "file_structure" | "runtime_context">,
  id: string,
  title: string,
  relativePath: string,
  fallbackSummary: string,
  detail: string,
  tags: string[],
  status: KnowledgeBaseEntry["status"]
): KnowledgeBaseEntry {
  return {
    id,
    category,
    title,
    summary: summarizeMarkdown(relativePath, fallbackSummary),
    detail,
    tags,
    location: relativePath,
    status,
  };
}

function buildAgentRuntimeContextEntries(config: AgentwallConfig, baseUrl: string): KnowledgeBaseEntry[] {
  const soulPath = agentHomePath("SOUL.md");
  const memoryCandidates = [
    agentHomePath("memory.md"),
    agentHomePath("memory", "README.md"),
    agentHomePath("memory.json"),
    agentHomePath("memory.sqlite"),
  ];
  const userCandidates = [
    agentHomePath("user.md"),
    agentHomePath("user", "README.md"),
    agentHomePath("profile.md"),
    agentHomePath("profiles"),
  ];
  const configPath = agentHomePath("config.yaml");
  const envPath = agentHomePath(".env");
  const skillsPath = agentHomePath("skills");
  const profilesPath = agentHomePath("profiles");

  const configSnapshot = summarizeYamlSource(configPath);
  const configPresent = Boolean(readTextSafely(configPath));
  const envPresent = Boolean(readTextSafely(envPath));
  const skillsPresent = fs.existsSync(skillsPath);
  const profilesPresent = fs.existsSync(profilesPath);
  const skillCollections = countImmediateDirectories(skillsPath);
  const profileCollections = countImmediateDirectories(profilesPath);
  const soulText = readTextSafely(soulPath);
  const soulPresent = Boolean(soulText);
  const memoryPath = probeFirstExistingPath(memoryCandidates);
  const userPath = probeFirstExistingPath(userCandidates);

  const soulStat = safeStat(soulPath);
  const configStat = safeStat(configPath);
  const envStat = safeStat(envPath);
  const redactedLocation = "[local path redacted]";
  const agentHomeLabel = "~/.agentwall/agent";
  const candidateSummary = (count: number) => `${count} local candidate path${count === 1 ? "" : "s"} redacted`;

  return [
    {
      id: "soul",
      category: "runtime_context",
      title: "Soul",
      summary: soulPresent
        ? "Agent behavior contract is configured. Raw prompt text is withheld from the dashboard API."
        : "No agent behavior contract was found in the expected local home path.",
      detail: soulPresent
        ? "The dashboard only exposes presence, size, and line count for this local runtime file. Full text stays server-side."
        : "Local runtime paths were probed and redacted from the dashboard API response.",
      value: soulPresent ? "configured" : "missing/not configured",
      excerpt: soulPresent ? "[runtime prompt excerpt withheld]" : undefined,
      facts: soulPresent
        ? [
            { label: "Location", value: redactedLocation },
            { label: "Size", value: soulStat ? `${soulStat.size} bytes` : "unknown" },
            { label: "Lines", value: soulText.split(/\r?\n/).length.toString() },
          ]
        : [{ label: "Probe result", value: "missing/not configured" }],
      tags: ["runtime-context", "soul", "agent-home"],
      chips: [soulPresent ? "configured" : "missing/not configured", "withheld"],
      location: `${agentHomeLabel}/SOUL.md`,
      status: soulPresent ? "available" : "missing",
    },
    {
      id: "memory",
      category: "runtime_context",
      title: "Memory",
      summary: memoryPath ? "Memory context is configured. Local path is withheld." : "No local memory file was found.",
      detail: memoryPath
        ? "Memory is backed by a local file or directory. The dashboard does not expose its absolute path."
        : `Probed ${candidateSummary(memoryCandidates.length)} and did not find a memory store.`,
      value: memoryPath ? "configured" : "missing/not configured",
      excerpt: memoryPath ? "[memory path withheld]" : undefined,
      facts: memoryPath
        ? [{ label: "Location", value: redactedLocation }]
        : [
            { label: "Probe result", value: "missing/not configured" },
            { label: "Expected at", value: candidateSummary(memoryCandidates.length) },
          ],
      tags: ["runtime-context", "memory", "state"],
      chips: [memoryPath ? "configured" : "missing/not configured", "withheld"],
      location: `${agentHomeLabel}/memory`,
      status: memoryPath ? "available" : "missing",
    },
    {
      id: "user_profile",
      category: "runtime_context",
      title: "User / Profile",
      summary: userPath ? "User/profile context is configured. Local path is withheld." : "No local user/profile file was found.",
      detail: userPath
        ? "User/profile context exists locally. The dashboard does not expose its absolute path."
        : `Probed ${candidateSummary(userCandidates.length)} and did not find a user/profile file or directory.`,
      value: userPath ? "configured" : "missing/not configured",
      excerpt: userPath ? "[profile path withheld]" : undefined,
      facts: userPath
        ? [{ label: "Location", value: redactedLocation }]
        : [
            { label: "Probe result", value: "missing/not configured" },
            { label: "Expected at", value: candidateSummary(userCandidates.length) },
          ],
      tags: ["runtime-context", "user", "profile"],
      chips: [userPath ? "configured" : "missing/not configured", "withheld"],
      location: `${agentHomeLabel}/profiles`,
      status: userPath ? "available" : "missing",
    },
    {
      id: "system_environment",
      category: "runtime_context",
      title: "System / Environment",
      summary: `Agent home configured; config ${configPresent ? "present" : "missing"}; skills ${skillsPresent ? "present" : "missing"}.`,
      detail: `Live process context comes from local runtime configuration. Sensitive host paths are withheld. Base URL ${baseUrl}.`,
      value: `${config.host}:${config.port}`,
      excerpt: `Base URL: ${baseUrl} · Agent home: ${agentHomeLabel} · Config keys: ${configSnapshot.keys.length ? configSnapshot.keys.join(", ") : "none"}`,
      facts: [
        { label: "Agent home", value: agentHomeLabel },
        { label: "Config file", value: configPresent ? "configured" : "missing/not configured" },
        { label: "Config size", value: configStat ? `${configStat.size} bytes` : "unknown" },
        { label: "Config keys", value: configSnapshot.keys.length ? configSnapshot.keys.join(", ") : "none" },
        { label: "Model", value: configSnapshot.modelDefault || "unknown" },
        { label: "Provider", value: configSnapshot.modelProvider || "unknown" },
        { label: "Display skin", value: configSnapshot.skin || "unknown" },
        { label: "Skills collections", value: formatCountLabel(skillCollections, "collection") },
        { label: "Profiles", value: profilesPresent ? formatCountLabel(profileCollections, "profile") : "missing/not configured" },
        { label: ".env", value: envPresent ? "configured" : "missing/not configured" },
        { label: ".env size", value: envStat ? `${envStat.size} bytes` : "unknown" },
        { label: "Working directory", value: redactedLocation },
        { label: "Base URL", value: baseUrl },
        { label: "Approval mode", value: config.approval.mode },
        { label: "Watchdog", value: config.watchdog.enabled ? "enabled" : "disabled" },
      ],
      tags: ["runtime", "environment", "config", "dashboard"],
      chips: [config.approval.mode, config.watchdog.enabled ? "watchdog on" : "watchdog off", skillsPresent ? "skills present" : "skills missing"],
      location: `${agentHomeLabel}/config.yaml`,
      status: "available",
    },
  ];
}

function buildKnowledgeBaseEntries(config: AgentwallConfig, baseUrl: string): KnowledgeBaseEntry[] {
  return [
    buildSourceEntry(
      "source-dashboard-state",
      "Dashboard state API",
      "src/routes/dashboard.ts",
      "Primary Mission Control state surface for the operator console and knowledge base.",
      "Use the live dashboard payload as the canonical source for posture, approvals, sessions, evidence, canonical access, and knowledge-base state.",
      ["api", "state", "dashboard", "mission-control"],
      "/api/dashboard/state"
    ),
    buildSourceEntry(
      "source-runtime-state",
      "Runtime state aggregator",
      "src/dashboard/state.ts",
      "Collects approvals, audit evidence, sessions, task graph, and operator-facing summaries.",
      "This file now also generates repository-aware knowledge-base entries and transparent runtime-context probes.",
      ["runtime", "aggregation", "evidence", "approvals"]
    ),
    buildSourceEntry(
      "source-ui-shell",
      "Dashboard shell routes",
      "src/routes/ui.ts",
      "Serves the static dashboard shell for the dashboard and knowledge-base views.",
      "Keep KB routing inside the existing Fastify + static frontend surface so operators stay in one shell.",
      ["fastify", "ui", "routes", "shell"]
    ),
    buildSourceEntry(
      "source-docs-index",
      "Docs index",
      "docs/README.md",
      "Narrative entry point for install, architecture, threat model, and runtime documents.",
      "Use the docs index when the dashboard summary is not enough and the operator needs the repo’s longer-form references.",
      ["docs", "index", "reference"]
    ),
    buildSourceEntry(
      "source-config-public-base",
      "Canonical public base config",
      "src/config.ts",
      "Config schema for Agentwall, including the optional dashboard.publicBaseUrl override.",
      `Canonical access links use dashboard.publicBaseUrl when configured, otherwise they safely fall back to ${baseUrl}.`,
      ["config", "publicBaseUrl", "canonical-access", "dashboard"]
    ),
    buildDocEntry(
      "concepts",
      "concept-control-plane",
      "Control-plane-first operator model",
      "README.md",
      "Mission Control is the place to inspect, gate, and contain agent work.",
      "The KB stays aligned with the repository’s core operating model: inspect intent, route risky work into approvals, and preserve evidence.",
      ["operator", "control-plane", "containment"],
      "curated"
    ),
    buildDocEntry(
      "concepts",
      "concept-threat-model",
      "Threat model assumptions",
      "docs/threat-model.md",
      "Threat boundaries define how Agentwall treats tools, browser actions, egress, and insider-style abuse.",
      "Use this to anchor KB interpretation around what the product is explicitly defending against.",
      ["threat-model", "risk", "security"],
      "curated"
    ),
    buildDocEntry(
      "articles",
      "article-architecture",
      "Architecture overview",
      "docs/architecture.md",
      "Maps the runtime, routes, policy engine, and dashboard layers.",
      "Best starting point for engineers changing Mission Control surfaces or adding new evidence/state blocks.",
      ["architecture", "routes", "runtime"],
      "curated"
    ),
    buildDocEntry(
      "articles",
      "article-install",
      "Install guide",
      "docs/install.md",
      "Step-by-step install and bootstrap reference.",
      "Operators can use this when validating a fresh deployment or reconstructing expected startup state.",
      ["install", "setup", "operations"],
      "curated"
    ),
    buildDocEntry(
      "articles",
      "article-floodguard",
      "Runtime FloodGuard guide",
      "docs/runtime-floodguard.md",
      "Explains live pressure management, shield mode, and operator guidance surfaces.",
      "Pairs closely with dashboard behavior because queue pressure and containment guidance are rendered from runtime state.",
      ["floodguard", "operations", "controls"],
      "curated"
    ),
    buildDocEntry(
      "tutorials",
      "tutorial-telegram-answer-only",
      "Telegram Answer Only",
      "docs/tutorials/01-telegram-answer-only.md",
      "Configure one Telegram topic to answer normally while blocking filesystem mutation, secret reads, and unsafe egress.",
      "Use this as the first Agentwall walkthrough because it proves the core channel containment loop in under 90 seconds.",
      ["tutorial", "telegram", "answer-only", "guardrails"],
      "available"
    ),
    buildDocEntry(
      "tutorials",
      "tutorial-demo-verification",
      "Run Demo Verification",
      "docs/tutorials/02-run-demo-verification.md",
      "Run synthetic verification and read the expected-deny evidence path without touching real runtime actions.",
      "The safest walkthrough to run first: it exercises the product loop without touching live work.",
      ["tutorial", "demo", "verification", "evidence"],
      "available"
    ),
    buildDocEntry(
      "tutorials",
      "tutorial-advanced-user-mode",
      "Operator View vs Advanced User",
      "docs/tutorials/03-advanced-user-mode.md",
      "Show the focused default view, then reveal policy, federation, audit, and runtime telemetry only when needed.",
      "Use this to reduce dashboard overwhelm and explain why the simple surface exists.",
      ["tutorial", "operator-view", "advanced-user", "dashboard"],
      "available"
    ),
    buildDocEntry(
      "tutorials",
      "tutorial-approval-queue",
      "Review an Approval",
      "docs/tutorials/04-approval-queue.md",
      "Review a blocked action using evidence, matched rules, risk, and scope before approving or denying.",
      "This walkthrough teaches the human gate instead of letting operators click approvals blindly.",
      ["tutorial", "approval", "queue", "evidence"],
      "available"
    ),
    buildDocEntry(
      "tutorials",
      "tutorial-knowledge-base",
      "Use the Knowledge Base",
      "docs/tutorials/05-knowledge-base.md",
      "Search Agentwall references, category chips, runtime context, and source links from the dashboard KB.",
      "This turns the KB from a document dump into the operator answer surface.",
      ["tutorial", "knowledge-base", "search", "reference"],
      "available"
    ),
    buildDocEntry(
      "tutorials",
      "tutorial-first-real-telegram-topic",
      "Bring Up Your First Real Telegram Topic",
      "docs/tutorials/06-first-real-telegram-topic.md",
      "Use the telegram-channel-bringup helper to set answer_only, run the proof suite, and capture audit IDs for one live Telegram topic.",
      "This is the operator path from a fresh chat id to a contained, audited lane in under two minutes.",
      ["tutorial", "telegram", "bringup", "proof", "audit"],
      "available"
    ),
    buildFileSummaryEntry("docs", "docs/ path summary", ["docs", "repository", "reference"]),
    buildFileSummaryEntry("src", "src/ path summary", ["src", "runtime", "routes"]),
    buildFileSummaryEntry("public", "public/ path summary", ["public", "frontend", "shell"]),
    buildFileSummaryEntry("tests", "tests/ path summary", ["tests", "coverage", "regression"]),
    ...buildAgentRuntimeContextEntries(config, baseUrl),
  ];
}

function buildKnowledgeBaseSections(entries: KnowledgeBaseEntry[]): KnowledgeBaseSection[] {
  return [
    {
      id: "sources",
      title: "Sources",
      description: "Canonical APIs, runtime aggregators, and docs entry points.",
      count: entries.filter((entry) => entry.category === "sources").length,
      accent: "accent",
    },
    {
      id: "concepts",
      title: "Concepts",
      description: "Operating-model ideas that explain how Mission Control is supposed to work.",
      count: entries.filter((entry) => entry.category === "concepts").length,
      accent: "accent",
    },
    {
      id: "articles",
      title: "Articles",
      description: "Longer-form docs for architecture, runtime operations, and current planning.",
      count: entries.filter((entry) => entry.category === "articles").length,
      accent: "pending",
    },
    {
      id: "tutorials",
      title: "Tutorials",
      description: "Quick walkthroughs for learning the Agentwall control loop.",
      count: entries.filter((entry) => entry.category === "tutorials").length,
      accent: "accent",
    },
    {
      id: "open_questions",
      title: "Open Questions",
      description: "Unresolved product and operating questions that still need decisions.",
      count: entries.filter((entry) => entry.category === "open_questions").length,
      accent: "warning",
    },
    {
      id: "file_structure",
      title: "File Structure",
      description: "Where the Mission Control code lives in this repository.",
      count: entries.filter((entry) => entry.category === "file_structure").length,
      accent: "pending",
    },
    {
      id: "runtime_context",
      title: "Runtime Context",
      description: "Transparent probes for Soul, Memory, User/Profile, and live system/environment context.",
      count: entries.filter((entry) => entry.category === "runtime_context").length,
      accent: "warning",
    },
  ];
}

export class RuntimeState {
  private readonly startedAt = new Date();
  private readonly config: AgentwallConfig;
  private readonly watchdog: HeartbeatWatchdog;
  private readonly events: RuntimeEvent[] = [];
  private readonly auditEvents: AuditEvent[] = [];
  private readonly approvals: ApprovalActivity[] = [];
  private readonly agentActivity = new Map<string, AgentRuntimeActivity>();
  private readonly channelActivity = new Map<string, ChannelRuntimeActivity>();
  private readonly sessions = new Map<string, SessionRuntime>();
  private readonly sessionRecency = new Map<string, number>();
  private readonly runtimeFlows: RuntimeFlow[] = [];
  private readonly evidence: EvidenceRecord[] = [];
  private readonly tasks = new Map<string, TaskNode>();
  private readonly taskEdges: TaskEdge[] = [];
  private readonly lastTaskForSession = new Map<string, string>();
  private approvalMode: AgentwallConfig["approval"]["mode"];
  private totalRequests = 0;
  private sessionRecencyCounter = 0;
  private simulation: SimulationState = {
    enabled: false,
    scenarioId: null,
    label: null,
    injectedAt: null,
    disclaimer: "Synthetic incident data only. No real runtime action is executed.",
  };

  constructor(config: AgentwallConfig) {
    this.config = config;
    this.approvalMode = config.approval.mode;
    this.watchdog = new HeartbeatWatchdog(config.watchdog);
    this.seedRuntime();
  }

  recordAuditEvent(event: AuditEvent): void {
    this.auditEvents.unshift(event);
    this.totalRequests += 1;
    const sessionId = event.sessionId ?? defaultSessionId(event.agentId);
    this.observeAgent(event.agentId, event.plane, event.action, event.timestamp, sessionId, event.riskLevel, event.actor?.channelId);
    this.observeSession({
      sessionId,
      agentId: event.agentId,
      plane: event.plane,
      action: event.action,
      timestamp: event.timestamp,
      riskLevel: event.riskLevel,
      channelId: event.actor?.channelId,
    });
    this.observeChannel({
      agentId: event.agentId,
      sessionId,
      channelId: event.actor?.channelId,
      userId: event.actor?.userId,
      roleIds: event.actor?.roleIds,
      plane: event.plane,
      action: event.action,
      timestamp: event.timestamp,
      riskLevel: event.riskLevel,
    });

    const task = this.upsertTask({
      sessionId,
      agentId: event.agentId,
      plane: event.plane,
      action: event.action,
      timestamp: event.timestamp,
      riskLevel: event.riskLevel,
      status: event.decision === "deny" ? "blocked" : "completed",
      summary: event.reasons[0] ?? "Policy evaluation recorded",
    });
    const evidence = this.addEvidence({
      kind: event.highRiskFlow ? "provenance" : "audit",
      title: `${event.plane} policy ${event.decision}`,
      summary: event.reasons[0] ?? "Policy evaluation recorded",
      timestamp: event.timestamp,
      riskLevel: event.riskLevel,
      status: event.requiresApproval ? "pending" : toStatus(event.riskLevel),
      agentId: event.agentId,
      sessionId,
      plane: event.plane,
      linkedObjectId: event.id,
      attributes: {
        decision: event.decision,
        rules: String(event.matchedRules.length),
        approval: event.requiresApproval ? "required" : "not_required",
        integrityChainIndex: String(event.integrity.chainIndex),
        integrityHash: event.integrity.hash,
        integrityPreviousHash: event.integrity.previousHash ?? "null",
        integrityStatus: event.integrity.status,
      },
      relatedTaskIds: [task.id],
    });
    this.linkEvidenceToTask(task.id, evidence.id);
    this.recordFlow({
      timestamp: event.timestamp,
      flowType: "policy",
      status: event.requiresApproval ? "waiting" : event.decision === "deny" ? "blocked" : "completed",
      agentId: event.agentId,
      sessionId,
      plane: event.plane,
      action: event.action,
      direction: event.flow?.direction ?? "internal",
      target: event.flow?.target ?? "policy-engine",
      summary: event.reasons[0] ?? "Policy evaluation recorded",
      riskLevel: event.riskLevel,
      decision: event.decision,
      labels: [
        ...(event.flow?.labels ?? []),
        ...(event.provenance?.map((entry) => `${entry.source}:${entry.trustLabel}`) ?? []),
      ],
      crossesBoundary: event.flow?.crossesBoundary ?? false,
    });
    this.pushEvent({
      id: event.id,
      timestamp: event.timestamp,
      category: "policy",
      title: `${event.plane} decision · ${event.decision.toUpperCase()}`,
      summary: event.reasons[0] ?? "Policy evaluation recorded",
      status: event.requiresApproval ? "pending" : toStatus(event.riskLevel),
      riskLevel: event.riskLevel,
      plane: event.plane,
      agentId: event.agentId,
      sessionId,
      detail: {
        action: event.action,
        matchedRules: event.matchedRules,
        requiresApproval: event.requiresApproval,
        highRiskFlow: event.highRiskFlow,
        taskId: task.id,
        evidenceId: evidence.id,
      },
    });
  }

  recordApprovalRequested(requestId: string, request: ApprovalRequest, mode: "manual" | "auto"): void {
    const createdAt = new Date().toISOString();
    const sessionId = request.context.sessionId ?? defaultSessionId(request.context.agentId);
    const activity: ApprovalActivity = {
      requestId,
      createdAt,
      status: mode === "auto" ? "approved" : "pending",
      mode,
      agentId: request.context.agentId,
      sessionId,
      plane: request.context.plane,
      action: request.context.action,
      riskLevel: request.policyResult.riskLevel,
      reasons: request.policyResult.reasons,
      matchedRules: request.policyResult.matchedRules,
    };

    if (mode === "auto") {
      activity.resolvedAt = createdAt;
      activity.note = "Auto-approved by gate mode or policy";
      activity.approvedBy = "agentwall-auto";
    }

    this.approvals.unshift(activity);
    this.observeAgent(
      request.context.agentId,
      request.context.plane,
      request.context.action,
      createdAt,
      sessionId,
      request.policyResult.riskLevel,
      request.context.actor?.channelId
    );
    this.observeSession({
      sessionId,
      agentId: request.context.agentId,
      plane: request.context.plane,
      action: request.context.action,
      timestamp: createdAt,
      riskLevel: request.policyResult.riskLevel,
      channelId: request.context.actor?.channelId,
    });
    this.observeChannel({
      agentId: request.context.agentId,
      sessionId,
      channelId: request.context.actor?.channelId,
      userId: request.context.actor?.userId,
      roleIds: request.context.actor?.roleIds,
      plane: request.context.plane,
      action: request.context.action,
      timestamp: createdAt,
      riskLevel: request.policyResult.riskLevel,
    });
    this.updateSessionApprovalCount(sessionId);
    const task = this.upsertTask({
      sessionId,
      agentId: request.context.agentId,
      plane: request.context.plane,
      action: request.context.action,
      timestamp: createdAt,
      riskLevel: request.policyResult.riskLevel,
      status: mode === "auto" ? "completed" : "active",
      summary: request.policyResult.reasons[0] ?? "Approval request created",
    });
    const evidence = this.addEvidence({
      kind: "approval",
      title: mode === "auto" ? "Approval auto-resolved" : "Approval queued",
      summary: `${request.context.action} · ${request.policyResult.reasons[0] ?? "Awaiting operator action"}`,
      timestamp: createdAt,
      riskLevel: request.policyResult.riskLevel,
      status: mode === "auto" ? "ok" : "pending",
      agentId: request.context.agentId,
      sessionId,
      plane: request.context.plane,
      linkedObjectId: requestId,
      attributes: {
        mode,
        reasons: String(request.policyResult.reasons.length),
      },
      relatedTaskIds: [task.id],
    });
    this.linkEvidenceToTask(task.id, evidence.id);
    this.recordFlow({
      timestamp: createdAt,
      flowType: "approval",
      status: mode === "auto" ? "completed" : "waiting",
      agentId: request.context.agentId,
      sessionId,
      plane: request.context.plane,
      action: request.context.action,
      direction: request.context.flow?.direction ?? "internal",
      target: "approval-gate",
      summary: request.policyResult.reasons[0] ?? "Approval request created",
      riskLevel: request.policyResult.riskLevel,
      decision: mode === "auto" ? "approved" : "pending",
      labels: request.context.flow?.labels ?? [],
      crossesBoundary: request.context.flow?.crossesBoundary ?? false,
    });
    this.pushEvent({
      id: randomUUID(),
      timestamp: createdAt,
      category: "approval",
      title: mode === "auto" ? "Approval auto-resolved" : "Approval queued",
      summary: `${request.context.agentId} · ${request.context.action}`,
      status: mode === "auto" ? "ok" : "pending",
      riskLevel: request.policyResult.riskLevel,
      plane: request.context.plane,
      agentId: request.context.agentId,
      sessionId,
      detail: {
        requestId,
        reasons: request.policyResult.reasons,
        mode,
        taskId: task.id,
        evidenceId: evidence.id,
      },
    });
  }

  hydrateApprovalQueue(entries: PersistedPendingApproval[]): void {
    for (const entry of entries.sort((left, right) => right.createdAt - left.createdAt)) {
      if (this.approvals.some((item) => item.requestId === entry.requestId)) {
        continue;
      }

      const createdAt = new Date(entry.createdAt).toISOString();
      const sessionId = entry.request.context.sessionId ?? defaultSessionId(entry.request.context.agentId);
      this.approvals.unshift({
        requestId: entry.requestId,
        createdAt,
        status: "pending",
        mode: "manual",
        agentId: entry.request.context.agentId,
        sessionId,
        plane: entry.request.context.plane,
        action: entry.request.context.action,
        riskLevel: entry.request.policyResult.riskLevel,
        reasons: entry.request.policyResult.reasons,
        matchedRules: entry.request.policyResult.matchedRules,
      });
      this.observeAgent(
        entry.request.context.agentId,
        entry.request.context.plane,
        entry.request.context.action,
        createdAt,
        sessionId,
        entry.request.policyResult.riskLevel
      );
      this.observeSession({
        sessionId,
        agentId: entry.request.context.agentId,
        plane: entry.request.context.plane,
        action: entry.request.context.action,
        timestamp: createdAt,
        riskLevel: entry.request.policyResult.riskLevel,
      });
      this.updateSessionApprovalCount(sessionId);
    }
  }

  recordApprovalResolved(
    requestId: string,
    request: ApprovalRequest | undefined,
    response: ApprovalResponse,
    mode: "manual" | "auto"
  ): void {
    const entry = this.approvals.find((item) => item.requestId === requestId) ?? (
      request
        ? {
            requestId,
            createdAt: response.timestamp,
            status: "pending" as const,
            mode,
            agentId: request.context.agentId,
            sessionId: request.context.sessionId ?? defaultSessionId(request.context.agentId),
            plane: request.context.plane,
            action: request.context.action,
            riskLevel: request.policyResult.riskLevel,
            reasons: request.policyResult.reasons,
            matchedRules: request.policyResult.matchedRules,
          }
        : undefined
    );

    if (!entry) return;
    if (entry.status === response.decision && entry.resolvedAt === response.timestamp) {
      return;
    }

    entry.status = response.decision;
    entry.resolvedAt = response.timestamp;
    entry.note = response.note;
    entry.approvedBy = response.approvedBy;
    entry.mode = mode;
    this.updateSessionApprovalCount(entry.sessionId);

    const task = this.upsertTask({
      sessionId: entry.sessionId,
      agentId: entry.agentId,
      plane: entry.plane,
      action: entry.action,
      timestamp: response.timestamp,
      riskLevel: entry.riskLevel,
      status: response.decision === "approved" ? "completed" : "blocked",
      summary: response.note ?? response.decision,
    });
    const evidence = this.addEvidence({
      kind: "approval",
      title: `Approval ${response.decision}`,
      summary: response.note ?? `${entry.action} ${response.decision}`,
      timestamp: response.timestamp,
      riskLevel: entry.riskLevel,
      status: response.decision === "approved" ? "ok" : response.decision === "timeout" ? "warning" : "critical",
      agentId: entry.agentId,
      sessionId: entry.sessionId,
      plane: entry.plane,
      linkedObjectId: requestId,
      attributes: {
        approvedBy: response.approvedBy ?? "unassigned",
        mode,
      },
      relatedTaskIds: [task.id],
    });
    this.linkEvidenceToTask(task.id, evidence.id);
    this.recordFlow({
      timestamp: response.timestamp,
      flowType: "approval",
      status: response.decision === "approved" ? "completed" : "blocked",
      agentId: entry.agentId,
      sessionId: entry.sessionId,
      plane: entry.plane,
      action: entry.action,
      direction: "internal",
      target: "approval-gate",
      summary: response.note ?? `Approval ${response.decision}`,
      riskLevel: entry.riskLevel,
      decision: response.decision,
      labels: [],
      crossesBoundary: false,
    });
    this.pushEvent({
      id: randomUUID(),
      timestamp: response.timestamp,
      category: "approval",
      title: `Approval ${response.decision}`,
      summary: `${entry.agentId} · ${entry.action}`,
      status: response.decision === "approved" ? "ok" : response.decision === "timeout" ? "warning" : "critical",
      riskLevel: entry.riskLevel,
      plane: entry.plane,
      agentId: entry.agentId,
      sessionId: entry.sessionId,
      detail: {
        requestId,
        approvedBy: response.approvedBy,
        note: response.note,
        taskId: task.id,
        evidenceId: evidence.id,
      },
    });
  }

  recordNetworkInspection(request: NetworkRequest, result: NetworkInspection): void {
    const timestamp = new Date().toISOString();
    const sessionId = "inspection:network";
    const agentId = "network-probe";
    this.observeSession({
      sessionId,
      agentId,
      plane: "network",
      action: request.method ?? "GET",
      timestamp,
      riskLevel: result.riskLevel,
    });
    const task = this.upsertTask({
      sessionId,
      agentId,
      plane: "network",
      action: request.method ?? "GET",
      timestamp,
      riskLevel: result.riskLevel,
      status: result.allowed ? "completed" : "blocked",
      summary: result.reason,
    });
    const evidence = this.addEvidence({
      kind: "inspection",
      title: result.allowed ? "Egress permitted" : "Egress blocked",
      summary: request.url,
      timestamp,
      riskLevel: result.riskLevel,
      status: result.allowed ? "ok" : result.ssrf || result.privateRange ? "critical" : "warning",
      agentId,
      sessionId,
      plane: "network",
      linkedObjectId: request.url,
      attributes: {
        reason: result.reason,
        category: result.blockedCategory ?? "none",
        detectionId: detectionForBlockedCategory(result.blockedCategory)?.id ?? "none",
        detectionName: detectionForBlockedCategory(result.blockedCategory)?.name ?? "none",
      },
      relatedTaskIds: [task.id],
    });
    this.linkEvidenceToTask(task.id, evidence.id);
    this.recordFlow({
      timestamp,
      flowType: "inspection",
      status: result.allowed ? "completed" : "blocked",
      agentId,
      sessionId,
      plane: "network",
      action: request.method ?? "GET",
      direction: "egress",
      target: request.url,
      summary: result.reason,
      riskLevel: result.riskLevel,
      decision: result.allowed ? "allow" : "deny",
      labels: [result.blockedCategory ?? "inspection"],
      crossesBoundary: true,
    });
    this.pushEvent({
      id: randomUUID(),
      timestamp,
      category: "network",
      title: result.allowed ? "Egress permitted" : "Egress blocked",
      summary: request.url,
      status: result.allowed ? "ok" : result.ssrf || result.privateRange ? "critical" : "warning",
      riskLevel: result.riskLevel,
      plane: "network",
      agentId,
      sessionId,
      detail: {
        method: request.method ?? "GET",
        reason: result.reason,
        blockedCategory: result.blockedCategory,
        detectionId: detectionForBlockedCategory(result.blockedCategory)?.id ?? "none",
        detectionName: detectionForBlockedCategory(result.blockedCategory)?.name ?? "none",
        ssrf: result.ssrf,
        privateRange: result.privateRange,
        taskId: task.id,
        evidenceId: evidence.id,
      },
    });
  }

  recordContentInspection(sourceText: string, result: ContentClassification): void {
    const timestamp = new Date().toISOString();
    const sessionId = "inspection:content";
    const agentId = "content-probe";
    this.observeSession({
      sessionId,
      agentId,
      plane: "content",
      action: "inspect_content",
      timestamp,
      riskLevel: result.riskLevel,
    });
    const task = this.upsertTask({
      sessionId,
      agentId,
      plane: "content",
      action: "inspect_content",
      timestamp,
      riskLevel: result.riskLevel,
      status: result.containsSecrets ? "blocked" : "completed",
      summary: result.containsSecrets ? "Sensitive content detected" : "Content classified",
    });
    const evidence = this.addEvidence({
      kind: result.containsSecrets || result.containsPII ? "provenance" : "inspection",
      title: result.containsSecrets ? "DLP secret match" : result.containsPII ? "DLP PII match" : "Content scan clean",
      summary: sourceText.slice(0, 96),
      timestamp,
      riskLevel: result.riskLevel,
      status: result.containsSecrets ? "critical" : result.containsPII ? "warning" : "ok",
      agentId,
      sessionId,
      plane: "content",
      linkedObjectId: randomUUID(),
      attributes: {
        secrets: result.secretTypes.join(",") || "none",
        pii: result.piiTypes.join(",") || "none",
        redacted: String(result.redacted),
      },
      relatedTaskIds: [task.id],
    });
    this.linkEvidenceToTask(task.id, evidence.id);
    this.recordFlow({
      timestamp,
      flowType: "inspection",
      status: result.containsSecrets ? "blocked" : "completed",
      agentId,
      sessionId,
      plane: "content",
      action: "inspect_content",
      direction: "ingress",
      target: "dlp-engine",
      summary: result.containsSecrets ? "Secret material detected" : result.containsPII ? "PII classified" : "Content clean",
      riskLevel: result.riskLevel,
      decision: result.redacted ? "redact" : "allow",
      labels: result.labels,
      crossesBoundary: false,
    });
    this.pushEvent({
      id: randomUUID(),
      timestamp,
      category: "content",
      title: result.containsSecrets ? "DLP secret match" : result.containsPII ? "DLP PII match" : "Content scan clean",
      summary: sourceText.slice(0, 96),
      status: result.containsSecrets ? "critical" : result.containsPII ? "warning" : "ok",
      riskLevel: result.riskLevel,
      plane: "content",
      agentId,
      sessionId,
      detail: {
        source: result.source,
        trustLabel: result.trustLabel,
        labels: result.labels,
        secretTypes: result.secretTypes,
        piiTypes: result.piiTypes,
        taskId: task.id,
        evidenceId: evidence.id,
      },
    });
  }

  recordManifestInspection(
    inspection: { subjectId: string; subjectType: ManifestSubjectType },
    result: ManifestDrift
  ): void {
    const timestamp = new Date().toISOString();
    const sessionId = `inspection:manifest:${inspection.subjectType}:${inspection.subjectId}`;
    const agentId = "manifest-probe";
    const riskLevel = trustStateToRiskLevel(result.trustState);
    const eventStatus = trustStateToEventStatus(result.trustState);
    this.observeSession({
      sessionId,
      agentId,
      plane: "governance",
      action: "inspect_manifest",
      timestamp,
      riskLevel,
    });
    const task = this.upsertTask({
      sessionId,
      agentId,
      plane: "governance",
      action: "inspect_manifest",
      timestamp,
      riskLevel,
      status: result.trustState === "untrusted" ? "blocked" : result.trustState === "review_required" ? "active" : "completed",
      summary: result.reason,
    });
    const evidence = this.addEvidence({
      kind: "inspection",
      title: "Manifest trust inspection",
      summary: `${inspection.subjectType} ${inspection.subjectId} · ${result.trustState}`,
      timestamp,
      riskLevel,
      status: eventStatus,
      agentId,
      sessionId,
      plane: "governance",
      linkedObjectId: `${inspection.subjectType}:${inspection.subjectId}`,
      attributes: {
        subjectId: inspection.subjectId,
        subjectType: inspection.subjectType,
        manifestStatus: result.status,
        trustState: result.trustState,
        attestationStatus: result.attestation.status,
        currentHash: result.currentFingerprint.hash,
        approvedHash: result.approvedFingerprint?.hash ?? "none",
      },
      relatedTaskIds: [task.id],
    });
    this.linkEvidenceToTask(task.id, evidence.id);
    this.recordFlow({
      timestamp,
      flowType: "inspection",
      status: result.trustState === "untrusted" ? "blocked" : result.trustState === "review_required" ? "waiting" : "completed",
      agentId,
      sessionId,
      plane: "governance",
      action: "inspect_manifest",
      direction: "internal",
      target: `${inspection.subjectType}:${inspection.subjectId}`,
      summary: result.reason,
      riskLevel,
      decision: result.trustState === "untrusted" ? "deny" : result.trustState === "review_required" ? "approve" : "allow",
      labels: [
        `manifest:${result.status}`,
        `trust:${result.trustState}`,
        `attestation:${result.attestation.status}`,
      ],
      crossesBoundary: false,
    });
    this.pushEvent({
      id: randomUUID(),
      timestamp,
      category: "audit",
      title: "Manifest trust inspection",
      summary: `${inspection.subjectId} · ${result.trustState}`,
      status: eventStatus,
      riskLevel,
      plane: "governance",
      agentId,
      sessionId,
      operatorInitiated: true,
      detail: {
        subjectId: inspection.subjectId,
        subjectType: inspection.subjectType,
        manifestStatus: result.status,
        trustState: result.trustState,
        attestationStatus: result.attestation.status,
        currentHash: result.currentFingerprint.hash,
        approvedHash: result.approvedFingerprint?.hash ?? null,
        taskId: task.id,
        evidenceId: evidence.id,
      },
    });
  }

  updateApprovalMode(mode: AgentwallConfig["approval"]["mode"]): void {
    if (this.approvalMode === mode) return;
    this.approvalMode = mode;
    this.pushEvent({
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      category: "system",
      title: "Approval gate mode changed",
      summary: `Approval mode now ${mode}`,
      status: mode === "always" ? "pending" : "ok",
      detail: { mode },
      operatorInitiated: true,
    });
  }

  getApprovalMode(): AgentwallConfig["approval"]["mode"] {
    return this.approvalMode;
  }

  getSessionState(sessionId?: string): SessionRuntime | undefined {
    if (!sessionId) return undefined;
    return this.sessions.get(sessionId);
  }

  activateIncidentSimulation(): { ok: true; simulation: SimulationState } {
    this.clearSyntheticRecords();
    const now = Date.now();
    const scenarioId = "incident-chain-ransomware";
    const sessionId = `sim:${scenarioId}:session-17`;
    const timeline = [
      { offsetMs: 7 * 60_000, plane: "identity", action: "oauth_token_exchange", title: "Token replay detected", summary: "Untrusted browser token exchanged for privileged API access", risk: "high" as RiskLevel, status: "warning" as RuntimeEventStatus, decision: "allow" },
      { offsetMs: 6 * 60_000, plane: "network", action: "http_request", title: "Outbound C2 beacon blocked", summary: "Attempted egress to suspicious host matched deny list", risk: "critical" as RiskLevel, status: "critical" as RuntimeEventStatus, decision: "deny" },
      { offsetMs: 5 * 60_000, plane: "tool", action: "bash_exec", title: "Privilege escalation command queued", summary: "High-risk shell chain routed to manual approval", risk: "critical" as RiskLevel, status: "pending" as RuntimeEventStatus, decision: "pending" },
      { offsetMs: 4 * 60_000, plane: "content", action: "archive_export", title: "DLP secret match", summary: "Export payload contains simulated API key material", risk: "high" as RiskLevel, status: "warning" as RuntimeEventStatus, decision: "redact" },
      { offsetMs: 2 * 60_000, plane: "governance", action: "session_pause", title: "Containment playbook executed", summary: "Simulation paused high-risk session for triage", risk: "high" as RiskLevel, status: "warning" as RuntimeEventStatus, decision: "pause" },
    ];

    for (const step of timeline) {
      const timestamp = new Date(now - step.offsetMs).toISOString();
      this.observeAgent("sim-operator", step.plane, step.action, timestamp, sessionId, step.risk);
      this.observeSession({
        sessionId,
        agentId: "sim-operator",
        plane: step.plane,
        action: step.action,
        timestamp,
        riskLevel: step.risk,
        simulated: true,
        scenarioId,
      });
      const task = this.upsertTask({
        sessionId,
        agentId: "sim-operator",
        plane: step.plane,
        action: step.action,
        timestamp,
        riskLevel: step.risk,
        status: step.status === "pending" ? "active" : step.status === "critical" ? "blocked" : "completed",
        summary: step.summary,
        simulated: true,
        scenarioId,
      });
      const evidence = this.addEvidence({
        timestamp,
        kind: step.plane === "tool" ? "approval" : step.plane === "network" ? "inspection" : "provenance",
        title: step.title,
        summary: step.summary,
        riskLevel: step.risk,
        status: step.status,
        agentId: "sim-operator",
        sessionId,
        plane: step.plane,
        linkedObjectId: `sim:${scenarioId}:${step.action}`,
        attributes: {
          decision: step.decision,
          source: "simulation",
        },
        relatedTaskIds: [task.id],
        simulated: true,
        scenarioId,
      });
      this.linkEvidenceToTask(task.id, evidence.id);
      this.recordFlow({
        timestamp,
        flowType: step.plane === "tool" ? "approval" : "policy",
        status: step.status === "pending" ? "waiting" : step.status === "critical" ? "blocked" : "completed",
        agentId: "sim-operator",
        sessionId,
        plane: step.plane,
        action: step.action,
        direction: step.plane === "network" ? "egress" : "internal",
        target: step.plane === "network" ? "https://cdn-sync-verifier.co/update" : "incident-simulation",
        summary: step.summary,
        riskLevel: step.risk,
        decision: step.decision,
        labels: ["simulation", "demo"],
        crossesBoundary: step.plane === "network" || step.plane === "identity",
        simulated: true,
        scenarioId,
      });
      this.pushEvent({
        id: randomUUID(),
        timestamp,
        category: step.plane === "network" ? "network" : step.plane === "tool" ? "approval" : "policy",
        title: step.title,
        summary: step.summary,
        status: step.status,
        riskLevel: step.risk,
        plane: step.plane,
        agentId: "sim-operator",
        sessionId,
        synthetic: true,
        detail: {
          taskId: task.id,
          evidenceId: evidence.id,
          scenarioId,
        },
      });
    }

    const createdAt = new Date(now - 5 * 60_000).toISOString();
    this.approvals.unshift({
      requestId: `sim:${scenarioId}:approval-1`,
      createdAt,
      status: "pending",
      mode: "manual",
      agentId: "sim-operator",
      sessionId,
      plane: "tool",
      action: "bash_exec",
      riskLevel: "critical",
      reasons: ["Simulated destructive shell chain requires human approval"],
      matchedRules: ["sim:require-approval-shell"],
      note: "Simulation artifact",
      simulated: true,
      scenarioId,
    });
    this.updateSessionApprovalCount(sessionId);
    const simSession = this.sessions.get(sessionId);
    if (simSession) {
      simSession.note = "Synthetic incident chain for demo mode";
      simSession.status = "paused";
      simSession.simulated = true;
      simSession.scenarioId = scenarioId;
    }

    this.simulation = {
      enabled: true,
      scenarioId,
      label: "Incident chain: token replay -> C2 beacon -> shell escalation",
      injectedAt: new Date(now).toISOString(),
      disclaimer: "Synthetic incident data only. No real runtime action is executed.",
    };

    return { ok: true, simulation: this.simulation };
  }

  clearSimulation(): { ok: true; simulation: SimulationState } {
    this.clearSyntheticRecords();
    this.simulation = {
      enabled: false,
      scenarioId: null,
      label: null,
      injectedAt: null,
      disclaimer: "Synthetic incident data only. No real runtime action is executed.",
    };
    return { ok: true, simulation: this.simulation };
  }

  private clearSyntheticRecords(): void {
    this.events.splice(0, this.events.length, ...this.events.filter((item) => !item.synthetic));
    this.approvals.splice(0, this.approvals.length, ...this.approvals.filter((item) => !item.simulated));
    this.runtimeFlows.splice(0, this.runtimeFlows.length, ...this.runtimeFlows.filter((item) => !item.simulated));
    this.evidence.splice(0, this.evidence.length, ...this.evidence.filter((item) => !item.simulated));
    for (const [id, task] of this.tasks.entries()) {
      if (task.simulated) this.tasks.delete(id);
    }
    for (const [sessionId, taskId] of this.lastTaskForSession.entries()) {
      if (!this.tasks.has(taskId) || this.sessions.get(sessionId)?.simulated) {
        this.lastTaskForSession.delete(sessionId);
      }
    }
    this.taskEdges.splice(0, this.taskEdges.length, ...this.taskEdges.filter((edge) => this.tasks.has(edge.from) && this.tasks.has(edge.to)));
    for (const [id, session] of this.sessions.entries()) {
      if (session.simulated) this.sessions.delete(id);
    }
    for (const [agentId, activity] of this.agentActivity.entries()) {
      if (activity.agentId === "sim-operator" || (activity.sessionId && this.sessions.get(activity.sessionId)?.simulated)) {
        this.agentActivity.delete(agentId);
      }
    }
  }


  controlSession(sessionId: string, action: SessionControlAction, note?: string): SessionControlResult {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return { ok: false, reason: "not_found", message: "Session not found" };
    }

    if ((action === "resume" || action === "pause") && session.status === "terminated") {
      return {
        ok: false,
        reason: "invalid_transition",
        message: `Session ${session.sessionId} is terminated and cannot be ${action}d. Start a new runtime session instead.`,
        session: { ...session },
      };
    }

    session.status = action === "pause" ? "paused" : action === "resume" ? "active" : "terminated";
    session.note = note;
    session.lastSeenAt = new Date().toISOString();
    this.sessionRecency.set(session.sessionId, ++this.sessionRecencyCounter);
    const riskLevel = session.status === "terminated" ? "high" : session.riskLevel;
    const task = this.upsertTask({
      sessionId: session.sessionId,
      agentId: session.agentId,
      plane: session.lastPlane,
      action: `session_${action}`,
      timestamp: session.lastSeenAt,
      riskLevel,
      status: session.status === "active" ? "completed" : "blocked",
      summary: note ?? `Session ${action}`,
    });
    const evidence = this.addEvidence({
      kind: "session",
      title: `Session ${action}`,
      summary: note ?? `${session.sessionId} ${action}d by operator`,
      timestamp: session.lastSeenAt,
      riskLevel,
      status: session.status === "active" ? "ok" : "warning",
      agentId: session.agentId,
      sessionId: session.sessionId,
      plane: session.lastPlane,
      linkedObjectId: session.sessionId,
      attributes: {
        action,
      },
      relatedTaskIds: [task.id],
    });
    this.linkEvidenceToTask(task.id, evidence.id);
    this.recordFlow({
      timestamp: session.lastSeenAt,
      flowType: "session",
      status: session.status === "active" ? "completed" : "blocked",
      agentId: session.agentId,
      sessionId: session.sessionId,
      plane: session.lastPlane,
      action: `session_${action}`,
      direction: "internal",
      target: "runtime-session",
      summary: note ?? `Session ${action}`,
      riskLevel,
      decision: session.status,
      labels: ["operator-control"],
      crossesBoundary: false,
    });
    this.pushEvent({
      id: randomUUID(),
      timestamp: session.lastSeenAt,
      category: "session",
      title: `Session ${action}`,
      summary: `${session.sessionId} · ${session.agentId}`,
      status: session.status === "terminated" ? "critical" : "warning",
      riskLevel,
      plane: session.lastPlane,
      agentId: session.agentId,
      sessionId: session.sessionId,
      detail: {
        note,
        taskId: task.id,
        evidenceId: evidence.id,
      },
      operatorInitiated: true,
    });

    return { ok: true, session: { ...session } };
  }

  recordSessionRejection(context: AgentContext, reason: string): void {
    const timestamp = new Date().toISOString();
    const sessionId = context.sessionId ?? defaultSessionId(context.agentId);
    const status = this.sessions.get(sessionId)?.status ?? "paused";
    this.observeSession({
      sessionId,
      agentId: context.agentId,
      plane: context.plane,
      action: context.action,
      timestamp,
      riskLevel: "high",
      channelId: context.actor?.channelId,
    });
    this.observeChannel({
      agentId: context.agentId,
      sessionId,
      channelId: context.actor?.channelId,
      userId: context.actor?.userId,
      roleIds: context.actor?.roleIds,
      plane: context.plane,
      action: context.action,
      timestamp,
      riskLevel: "high",
    });
    const task = this.upsertTask({
      sessionId,
      agentId: context.agentId,
      plane: context.plane,
      action: context.action,
      timestamp,
      riskLevel: "high",
      status: "blocked",
      summary: reason,
    });
    const evidence = this.addEvidence({
      kind: "session",
      title: "Session blocked by operator control",
      summary: reason,
      timestamp,
      riskLevel: "high",
      status: "critical",
      agentId: context.agentId,
      sessionId,
      plane: context.plane,
      linkedObjectId: sessionId,
      attributes: {
        status,
      },
      relatedTaskIds: [task.id],
    });
    this.linkEvidenceToTask(task.id, evidence.id);
    this.recordFlow({
      timestamp,
      flowType: "session",
      status: "blocked",
      agentId: context.agentId,
      sessionId,
      plane: context.plane,
      action: context.action,
      direction: context.flow?.direction ?? "internal",
      target: summarizeTarget(context.payload),
      summary: reason,
      riskLevel: "high",
      decision: status,
      labels: context.flow?.labels ?? [],
      crossesBoundary: context.flow?.crossesBoundary ?? false,
    });
    this.pushEvent({
      id: randomUUID(),
      timestamp,
      category: "session",
      title: "Session rejected",
      summary: `${context.agentId} · ${reason}`,
      status: "critical",
      riskLevel: "high",
      plane: context.plane,
      agentId: context.agentId,
      sessionId,
      detail: {
        taskId: task.id,
        evidenceId: evidence.id,
      },
    });
  }

  getSnapshot(ruleCount: number) {
    const now = new Date();
    const baseUrl = buildCanonicalBaseUrl(this.config);
    const uptimeMs = now.getTime() - this.startedAt.getTime();
    const recentEvents = this.events.slice(0, 40);
    const recentAudits = this.auditEvents.slice(0, 12);
    const recentApprovals = this.approvals.slice(0, 12);
    const pendingApprovals = this.approvals.filter((item) => item.status === "pending");
    const prioritizedPendingApprovals = prioritizePendingApprovals(pendingApprovals);
    const oldestPendingApproval = pendingApprovals.reduce<ApprovalActivity | null>((oldest, item) => {
      if (!oldest) return item;
      return item.createdAt.localeCompare(oldest.createdAt) < 0 ? item : oldest;
    }, null);
    const allSessions = Array.from(this.sessions.values())
      .sort((left, right) => {
        const timestampDelta = compareIsoTimestampsDescending(left.lastSeenAt, right.lastSeenAt);
        if (timestampDelta !== 0) return timestampDelta;
        return (this.sessionRecency.get(right.sessionId) ?? 0) - (this.sessionRecency.get(left.sessionId) ?? 0);
      });
    const recentSessions = allSessions.slice(0, 12);
    const channelInventory = Array.from(this.channelActivity.values())
      .sort((left, right) => right.lastSeenAt.localeCompare(left.lastSeenAt) || left.channelId.localeCompare(right.channelId));
    const channelInventoryByAgent = Array.from(
      channelInventory.reduce((map, item) => {
        const existing = map.get(item.agentId) ?? [];
        existing.push(item);
        map.set(item.agentId, existing);
        return map;
      }, new Map<string, ChannelRuntimeActivity[]>())
    )
      .map(([agentId, channels]) => ({ agentId, channels }))
      .sort((left, right) => left.agentId.localeCompare(right.agentId));
    const organizationControlPlane = buildOrganizationControlPlaneSnapshot({
      localInstance: {
        id: this.config.organization?.instanceId ?? `${this.config.host}:${this.config.port}`,
        name: this.config.organization?.instanceName ?? "Local Agentwall",
        url: baseUrl,
        environment: this.config.organization?.environment,
        region: this.config.organization?.region,
      },
      configuredInstances: this.config.organization?.instances ?? [],
      observedChannels: channelInventory,
      now: now.toISOString(),
    });
    const sessionStatusById = Object.fromEntries(allSessions.map((item) => [item.sessionId, item.status]));
    const promptRiskEvents = this.auditEvents.filter((event) =>
      event.highRiskFlow &&
      (event.provenance?.some((entry) => entry.trustLabel !== "trusted") ?? false)
    ).slice(0, 8);
    const watchdogStates = this.getWatchdogStates(now);
    const riskCounts = countBy(recentEvents.filter((item) => item.riskLevel), (item) => item.riskLevel as string);
    const approvalCounts = countBy(this.approvals.slice(0, 40), (item) => item.status);
    const decisionCounts = countBy(this.auditEvents.slice(0, 50), (item) => item.decision);
    const inspectionEvents = recentEvents.filter((item) => item.category === "network" || item.category === "content").slice(0, 10);
    const policyHotspots = Object.entries(
      countBy(
        this.auditEvents.flatMap((item) => item.matchedRules.map((ruleId) => ({ ruleId }))).slice(0, 200),
        (item) => item.ruleId
      )
    )
      .map(([ruleId, count]) => ({ ruleId, count }))
      .sort((left, right) => right.count - left.count)
      .slice(0, 6);
    const highestRisk = recentEvents.reduce<RiskLevel>(
      (current, item) => {
        if (!item.riskLevel) return current;
        return scoreRisk(item.riskLevel) > scoreRisk(current) ? item.riskLevel : current;
      },
      "low"
    );
    const sessionCounts = countBy(allSessions, (item) => item.status);
    const controlMatrix: OperatorSurfaceItem[] = [
      {
        label: "Approval Gate",
        value: this.approvalMode,
        detail: `Timeout ${Math.round(this.config.approval.timeoutMs / 1000)}s · ${pendingApprovals.length} queued${oldestPendingApproval ? ` · oldest waiting ${formatAgeShort(oldestPendingApproval.createdAt, now)}` : ""}`,
        status: this.approvalMode === "always" ? "pending" : pendingApprovals.length > 0 ? "warning" : "ok",
      },
      {
        label: "Session Control",
        value: `${sessionCounts["active"] ?? 0} active / ${sessionCounts["paused"] ?? 0} paused`,
        detail: `${sessionCounts["terminated"] ?? 0} terminated session(s) retained for audit`,
        status: (sessionCounts["paused"] ?? 0) > 0 || (sessionCounts["terminated"] ?? 0) > 0 ? "warning" : "ok",
      },
      {
        label: "Egress Policy",
        value: this.config.egress.defaultDeny ? "default deny" : "open",
        detail: `${this.config.egress.allowedHosts.length} allowlisted host(s)`,
        status: this.config.egress.enabled ? "ok" : "warning",
      },
      {
        label: "Content Controls",
        value: this.config.dlp.enabled ? "dlp active" : "dlp disabled",
        detail: this.config.dlp.redactSecrets ? "Secret redaction on" : "Secret redaction off",
        status: this.config.dlp.enabled ? "ok" : "warning",
      },
      {
        label: "Evidence Ledger",
        value: `${this.evidence.length} artifacts`,
        detail: `${this.runtimeFlows.length} runtime flow(s) mapped into evidence and task graph`,
        status: this.evidence.length > 0 ? "ok" : "warning",
      },
      {
        label: "Policy Default",
        value: this.config.policy.defaultDecision,
        detail: `${ruleCount} active rule(s) loaded`,
        status: this.config.policy.defaultDecision === "deny" ? "ok" : "warning",
      },
      {
        label: "Watchdog",
        value: this.config.watchdog.killSwitchMode,
        detail: `Stale ${Math.round(this.config.watchdog.staleAfterMs / 1000)}s / timeout ${Math.round(this.config.watchdog.timeoutMs / 1000)}s`,
        status: watchdogStates.some((item) => item.killSwitchEngaged) ? "critical" : this.config.watchdog.enabled ? "ok" : "warning",
      },
    ];
    const priorityQueue: PriorityQueueItem[] = [
      ...prioritizedPendingApprovals.slice(0, 4).map((item) => ({
        id: item.requestId,
        category: "approval" as const,
        title: `${item.action} awaiting decision`,
        owner: item.agentId,
        summary: `${item.plane} plane · ${item.riskLevel} risk · waiting ${formatAgeShort(item.createdAt, now)}`,
        status: item.riskLevel === "critical" ? "critical" as const : "pending" as const,
        timestamp: item.createdAt,
        drilldownKind: "approval" as const,
        drilldownId: item.requestId,
        primaryAction: "Review",
      })),
      ...recentSessions
        .filter((item) => item.status !== "active")
        .slice(0, 3)
        .map((item) => ({
          id: item.sessionId,
          category: "session" as const,
          title: `${item.sessionId} ${item.status}`,
          owner: item.agentId,
          summary: item.note ?? `${item.lastAction} on ${item.lastPlane}`,
          status: item.status === "terminated" ? "critical" as const : "warning" as const,
          timestamp: item.lastSeenAt,
          drilldownKind: "session" as const,
          drilldownId: item.sessionId,
          primaryAction: item.status === "terminated" ? "Inspect" : "Open",
        })),
      ...watchdogStates
        .filter((item) => item.killSwitchEngaged || item.status === "stale" || item.status === "expired")
        .slice(0, 3)
        .map((item) => ({
          id: `watchdog-${item.agentId}`,
          category: "watchdog" as const,
          title: `${item.agentId} watchdog ${item.status}`,
          owner: item.agentId,
          summary: item.reason,
          status: (item.status === "expired" ? "critical" : "warning") as RuntimeEventStatus,
          timestamp: item.lastHeartbeatAt ?? now.toISOString(),
          drilldownKind: "agent" as const,
          drilldownId: item.agentId,
          primaryAction: "Inspect agent",
        })),
      ...promptRiskEvents.slice(0, 3).map((event) => ({
        id: event.id,
        category: "provenance" as const,
        title: `${event.action} crossed trust boundary`,
        owner: event.agentId,
        summary: event.reasons[0] ?? "Untrusted provenance triggered high-risk flow",
        status: (event.riskLevel === "critical" ? "critical" : "warning") as RuntimeEventStatus,
        timestamp: event.timestamp,
        drilldownKind: event.sessionId ? "session" as const : "agent" as const,
        drilldownId: event.sessionId ?? event.agentId,
        primaryAction: event.sessionId ? "Open session" : "Inspect agent",
      })),
    ];
    const queueStatusRank: Record<RuntimeEventStatus, number> = { critical: 4, pending: 3, warning: 2, ok: 1 };
    priorityQueue.sort((left, right) => {
      const statusDelta = (queueStatusRank[right.status] ?? 0) - (queueStatusRank[left.status] ?? 0);
      if (statusDelta !== 0) return statusDelta;
      return right.timestamp.localeCompare(left.timestamp);
    });
    const trimmedPriorityQueue = priorityQueue.slice(0, 8);
    if (prioritizedPendingApprovals.length > 0 && !trimmedPriorityQueue.some((item) => item.category === "approval")) {
      trimmedPriorityQueue[trimmedPriorityQueue.length - 1] = {
        id: prioritizedPendingApprovals[0].requestId,
        category: "approval",
        title: `${prioritizedPendingApprovals[0].action} awaiting decision`,
        owner: prioritizedPendingApprovals[0].agentId,
        summary: `${prioritizedPendingApprovals[0].plane} plane · ${prioritizedPendingApprovals[0].riskLevel} risk · waiting ${formatAgeShort(prioritizedPendingApprovals[0].createdAt, now)}`,
        status: prioritizedPendingApprovals[0].riskLevel === "critical" ? "critical" : "pending",
        timestamp: prioritizedPendingApprovals[0].createdAt,
        drilldownKind: "approval",
        drilldownId: prioritizedPendingApprovals[0].requestId,
        primaryAction: "Review",
      };
    }
    const watchdogAttentionStates = watchdogStates.filter((item) => item.killSwitchEngaged || item.status === "stale" || item.status === "expired");
    const watchdogCriticalSignals = watchdogAttentionStates.filter((item) => item.killSwitchEngaged || item.status === "expired").length;
    const approvalPressure = pendingApprovals.length;
    const runtimePressure = (riskCounts["critical"] ?? 0) + (approvalCounts["denied"] ?? 0) + (sessionCounts["terminated"] ?? 0);
    const healthPressure = watchdogAttentionStates.length;
    const pausedSessions = sessionCounts["paused"] ?? 0;
    const terminatedSessions = sessionCounts["terminated"] ?? 0;
    const criticalSignals = runtimePressure + watchdogCriticalSignals;
    const operatorPressure = approvalPressure + runtimePressure + healthPressure + pausedSessions;
    const attentionRequired = operatorPressure > 0;
    const liveActivityEvents = this.events.filter((item) => !item.synthetic && !item.operatorInitiated);
    const liveApprovals = this.approvals.filter((item) => !item.simulated);
    const lastLiveEventAt = liveActivityEvents[0]?.timestamp;
    const hasLiveActivity = Boolean(lastLiveEventAt) || this.totalRequests > 0 || liveApprovals.length > 0;
    const freshnessWindowMs = Math.max(this.config.watchdog.staleAfterMs, 30_000);
    const activeAgentsNow = Array.from(this.agentActivity.values()).filter((item) => {
      if (now.getTime() - new Date(item.lastSeenAt).getTime() > freshnessWindowMs) {
        return false;
      }
      if (!item.sessionId) {
        return true;
      }
      const session = this.sessions.get(item.sessionId);
      return !session || session.status === "active";
    }).length;
    const isFresh = !lastLiveEventAt ? false : now.getTime() - new Date(lastLiveEventAt).getTime() <= freshnessWindowMs;
    const latestVerifiedOutcome = buildLatestVerifiedOutcome(recentAudits, this.evidence);
    const operatorSummary = !hasLiveActivity
      ? "Awaiting first live agent activity. Policy and controls are loaded."
      : attentionRequired
        ? `${approvalPressure} approval(s) open, ${criticalSignals} critical signal(s), ${healthPressure} health pressure item(s), ${pausedSessions} session(s) paused${terminatedSessions > 0 ? `, ${terminatedSessions} terminated` : ""}.`
        : `No open approvals, no critical runtime signals, all tracked sessions active.`;
    const recommendedActions = [
      !hasLiveActivity ? "Send a test evaluation or approval request to confirm live telemetry end to end." : null,
      prioritizedPendingApprovals.length > 0 ? `Review the pending approval queue starting with ${prioritizedPendingApprovals[0]?.action ?? "the highest-risk request"}${oldestPendingApproval ? `; oldest has been waiting ${formatAgeShort(oldestPendingApproval.createdAt, now)}.` : "."}` : null,
      pausedSessions > 0 ? "Inspect paused sessions before resuming runtime traffic." : null,
      terminatedSessions > 0 ? "Inspect terminated sessions and capture audit evidence before normalizing controls." : null,
      watchdogAttentionStates.length > 0
        ? watchdogAttentionStates.some((item) => item.killSwitchEngaged || item.status === "expired")
          ? "Investigate expired watchdog or kill-switch health pressure before trusting runtime activity."
          : "Telemetry watchdog is stale. Check agent heartbeats and ingestion wiring."
        : !isFresh && hasLiveActivity
          ? "Telemetry is stale. Check agent heartbeats and ingestion wiring."
          : null,
      (riskCounts["critical"] ?? 0) > 0 ? "Drill into the latest critical signal and capture evidence before clearing it." : null,
    ].filter((item): item is string => Boolean(item)).slice(0, 3);
    const knowledgeBaseEntries = buildKnowledgeBaseEntries(this.config, baseUrl);
    const knowledgeBaseAccess: KnowledgeBaseAccess = {
      baseUrl,
      dashboardUrl: `${baseUrl}/dashboard`,
      knowledgeBaseUrl: `${baseUrl}/dashboard/knowledge-base`,
      lastVerifiedAt: now.toISOString(),
      lastVerifiedStatus: !hasLiveActivity ? "seeded" : isFresh ? "fresh" : "stale",
    };

    return {
      brand: "Agentwall",
      generatedAt: now.toISOString(),
      service: {
        status: watchdogStates.some((item) => item.killSwitchEngaged) ? "degraded" : "operational",
        attentionRequired,
        operatorSummary,
        recommendedActions,
        latestVerifiedOutcome,
        uptimeMs,
        startedAt: this.startedAt.toISOString(),
        host: this.config.host,
        port: this.config.port,
        logLevel: this.config.logLevel,
      },
      posture: {
        highestRisk,
        totalRequests: this.totalRequests,
        activeAgents: this.agentActivity.size,
        activeAgentsNow,
        pendingApprovals: pendingApprovals.length,
        criticalSignals,
        approvalPressure,
        runtimePressure,
        healthPressure,
        operatorPressure,
        approvalRate:
          recentApprovals.length === 0
            ? 100
            : Math.round(((approvalCounts["approved"] ?? 0) / recentApprovals.length) * 100),
      },
      controls: {
        defaultDecision: this.config.policy.defaultDecision,
        approvalMode: this.approvalMode,
        dlpEnabled: this.config.dlp.enabled,
        redactSecrets: this.config.dlp.redactSecrets,
        egress: this.config.egress,
        watchdog: this.config.watchdog,
      },
      health: {
        watchdogStates,
        allowlistedHosts: this.config.egress.allowedHosts,
        ruleCount,
      },
      freshness: {
        hasLiveActivity,
        isFresh,
        lastLiveEventAt: lastLiveEventAt ?? null,
        freshnessWindowMs,
      },
      stats: {
        riskCounts,
        approvalCounts,
        decisionCounts,
        planeCounts: countBy(this.auditEvents.slice(0, 50), (item) => item.plane),
        sessionCounts,
      },
      controlMatrix,
      priorityQueue: trimmedPriorityQueue,
      policyHotspots,
      approvals: {
        pending: pendingApprovals,
        recent: recentApprovals,
      },
      sessions: {
        recent: recentSessions,
        statusById: sessionStatusById,
      },
      channelInventory: {
        total: channelInventory.length,
        byAgent: channelInventoryByAgent,
        recent: channelInventory.slice(0, 16),
      },
      organizationControlPlane,
      runtimeFlows: this.runtimeFlows.slice(0, 12),
      evidenceLedger: this.evidence.slice(0, 12),
      taskGraph: {
        nodes: Array.from(this.tasks.values())
          .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
          .slice(0, 10),
        edges: this.taskEdges.slice(0, 20),
      },
      auditFeed: recentAudits,
      eventFeed: recentEvents,
      inspectionActivity: inspectionEvents,
      promptRiskEvents: promptRiskEvents.map((event) => ({
        id: event.id,
        timestamp: event.timestamp,
        agentId: event.agentId,
        sessionId: event.sessionId ?? defaultSessionId(event.agentId),
        action: event.action,
        plane: event.plane,
        decision: event.decision,
        riskLevel: event.riskLevel,
        summary: event.reasons[0] ?? "High-risk untrusted provenance event",
      })),
      activeAgents: Array.from(this.agentActivity.values()).sort((left, right) =>
        right.lastSeenAt.localeCompare(left.lastSeenAt)
      ),
      simulation: this.simulation,
      knowledgeBase: {
        access: knowledgeBaseAccess,
        sections: buildKnowledgeBaseSections(knowledgeBaseEntries),
        entries: knowledgeBaseEntries,
        runtimeContext: knowledgeBaseEntries.filter((entry) => entry.category === "runtime_context"),
      },
      damageControl: {
        headline: "Bash is the damage funnel",
        subhead: "Every shell call is one step from rm -rf, curl|sh, or terraform destroy. L1-L3 are advisory or reactive. L4 (whitelist) and L5 (no bash) are real enforcement.",
        recommendedLevel: RECOMMENDED_DEFAULT_LEVEL,
        defaultMode: DEFAULT_DAMAGE_CONTROL_MODE,
        ladder: DAMAGE_CONTROL_LADDER,
        defaultWhitelist: defaultWhitelistCommands(),
        endpoint: "/integrations/damage-control/command-preflight",
        recentAudits: this.auditEvents
          .filter((event) => event.action === "run_command" && event.metadata?.["damageControlSource"] === "preflight")
          .slice(0, 6)
          .map((event) => ({
            id: event.id,
            timestamp: event.timestamp,
            agentId: event.agentId,
            decision: event.decision,
            riskLevel: event.riskLevel,
            mode: event.metadata?.["damageControlMode"] ?? "whitelist",
            level: event.metadata?.["damageControlLevel"] ?? RECOMMENDED_DEFAULT_LEVEL,
            reason: event.reasons[0] ?? "",
          })),
      },
    };
  }

  getDrilldown(kind: DrilldownPayload["kind"], id: string): DrilldownPayload | undefined {
    if (kind === "session") {
      const session = this.sessions.get(id);
      if (!session) return undefined;
      return {
        kind,
        id,
        title: `${session.agentId} · ${session.sessionId}`,
        status: session.status,
        summary: session.note ?? `${session.lastAction} on ${session.lastPlane}`,
        facts: [
          { label: "Risk", value: session.riskLevel },
          { label: "Plane", value: session.lastPlane },
          { label: "Pending approvals", value: String(session.pendingApprovals) },
          { label: "Evidence", value: String(session.evidenceCount) },
        ],
        timeline: this.events
          .filter((item) => item.sessionId === id)
          .slice(0, 8)
          .map((item) => ({ timestamp: item.timestamp, title: item.title, summary: item.summary, status: item.status })),
        related: {
          sessions: [session],
          approvals: this.approvals.filter((item) => item.sessionId === id).slice(0, 6),
          evidence: this.evidence.filter((item) => item.sessionId === id).slice(0, 6),
          tasks: Array.from(this.tasks.values()).filter((item) => item.sessionId === id).slice(0, 6),
        },
      };
    }

    if (kind === "approval") {
      const approval = this.approvals.find((item) => item.requestId === id);
      if (!approval) return undefined;
      const prioritizedPendingApprovals = prioritizePendingApprovals(this.approvals.filter((item) => item.status === "pending"));
      const queueIndex = approval.status === "pending"
        ? prioritizedPendingApprovals.findIndex((item) => item.requestId === id)
        : -1;
      const queuePosition = queueIndex >= 0 ? queueIndex + 1 : 0;
      const previousPending = queueIndex > 0 ? prioritizedPendingApprovals[queueIndex - 1] : null;
      const nextPending = queueIndex >= 0 && queueIndex < prioritizedPendingApprovals.length - 1
        ? prioritizedPendingApprovals[queueIndex + 1]
        : null;
      const now = new Date();
      return {
        kind,
        id,
        title: `${approval.agentId} · ${approval.action}`,
        status: approval.status,
        summary: approval.note ?? approval.reasons[0] ?? "Approval activity",
        facts: [
          { label: "Plane", value: approval.plane },
          { label: "Session", value: approval.sessionId },
          { label: "Mode", value: approval.mode },
          { label: "Risk", value: approval.riskLevel },
          ...(approval.status === "pending" && queuePosition > 0
            ? [{ label: "Queue", value: `${queuePosition} of ${prioritizedPendingApprovals.length} pending` }]
            : []),
          ...(approval.matchedRules[0]
            ? [{ label: "Rule hit", value: approval.matchedRules[0] }]
            : []),
        ],
        timeline: this.events
          .filter((item) => item.detail?.["requestId"] === id)
          .slice(0, 8)
          .map((item) => ({ timestamp: item.timestamp, title: item.title, summary: item.summary, status: item.status })),
        queueNavigation: approval.status === "pending"
          ? {
              previousRequestId: previousPending?.requestId ?? null,
              previousTarget: previousPending ? `${previousPending.action} · ${previousPending.sessionId}` : null,
              previousDetail: summarizePendingApprovalNeighbor(previousPending, now),
              previousRule: previousPending?.matchedRules?.[0] ?? null,
              nextRequestId: nextPending?.requestId ?? null,
              nextTarget: nextPending ? `${nextPending.action} · ${nextPending.sessionId}` : null,
              nextDetail: summarizePendingApprovalNeighbor(nextPending, now),
              nextRule: nextPending?.matchedRules?.[0] ?? null,
            }
          : undefined,
        related: {
          sessions: this.sessions.has(approval.sessionId) ? [this.sessions.get(approval.sessionId) as SessionRuntime] : [],
          approvals: [approval],
          evidence: this.evidence.filter((item) => item.linkedObjectId === id).slice(0, 6),
          tasks: Array.from(this.tasks.values()).filter((item) => item.sessionId === approval.sessionId && item.action === approval.action).slice(0, 6),
        },
      };
    }

    if (kind === "evidence") {
      const evidence = this.evidence.find((item) => item.id === id);
      if (!evidence) return undefined;
      return {
        kind,
        id,
        title: evidence.title,
        status: evidence.status,
        summary: evidence.summary,
        facts: [
          { label: "Kind", value: evidence.kind },
          { label: "Plane", value: evidence.plane },
          { label: "Risk", value: evidence.riskLevel },
          { label: "Session", value: evidence.sessionId },
        ],
        timeline: this.events
          .filter((item) => item.detail?.["evidenceId"] === id || item.id === evidence.linkedObjectId)
          .slice(0, 8)
          .map((item) => ({ timestamp: item.timestamp, title: item.title, summary: item.summary, status: item.status })),
        related: {
          sessions: this.sessions.has(evidence.sessionId) ? [this.sessions.get(evidence.sessionId) as SessionRuntime] : [],
          approvals: this.approvals.filter((item) => item.requestId === evidence.linkedObjectId).slice(0, 6),
          evidence: [evidence],
          tasks: Array.from(this.tasks.values()).filter((item) => evidence.relatedTaskIds.includes(item.id)).slice(0, 6),
        },
      };
    }

    if (kind === "task") {
      const task = this.tasks.get(id);
      if (!task) return undefined;
      return {
        kind,
        id,
        title: task.title,
        status: task.status,
        summary: task.summary,
        facts: [
          { label: "Plane", value: task.plane },
          { label: "Action", value: task.action },
          { label: "Risk", value: task.riskLevel },
          { label: "Evidence", value: String(task.evidenceIds.length) },
        ],
        timeline: this.events
          .filter((item) => item.detail?.["taskId"] === id)
          .slice(0, 8)
          .map((item) => ({ timestamp: item.timestamp, title: item.title, summary: item.summary, status: item.status })),
        related: {
          sessions: this.sessions.has(task.sessionId) ? [this.sessions.get(task.sessionId) as SessionRuntime] : [],
          approvals: this.approvals.filter((item) => item.sessionId === task.sessionId && item.action === task.action).slice(0, 6),
          evidence: this.evidence.filter((item) => item.relatedTaskIds.includes(id)).slice(0, 6),
          tasks: [task],
        },
      };
    }

    const agent = this.agentActivity.get(id);
    if (!agent) return undefined;
    return {
      kind: "agent",
      id,
      title: id,
      status: "active",
      summary: `${agent.lastAction} on ${agent.lastPlane}`,
      facts: [
        { label: "Last seen", value: agent.lastSeenAt },
        { label: "Plane", value: agent.lastPlane },
        { label: "Session", value: agent.sessionId ?? "none" },
        { label: "Risk", value: agent.riskLevel ?? "low" },
      ],
      timeline: this.events
        .filter((item) => item.agentId === id)
        .slice(0, 8)
        .map((item) => ({ timestamp: item.timestamp, title: item.title, summary: item.summary, status: item.status })),
      related: {
        sessions: Array.from(this.sessions.values()).filter((item) => item.agentId === id).slice(0, 6),
        approvals: this.approvals.filter((item) => item.agentId === id).slice(0, 6),
        evidence: this.evidence.filter((item) => item.agentId === id).slice(0, 6),
        tasks: Array.from(this.tasks.values()).filter((item) => item.agentId === id).slice(0, 6),
      },
    };
  }

  private getWatchdogStates(now: Date): WatchdogState[] {
    const agents = Array.from(this.agentActivity.values());
    if (agents.length === 0) {
      return [
        this.watchdog.evaluate("control-plane", now, now),
      ];
    }

    return agents.map((agent) =>
      this.watchdog.evaluate(agent.agentId, new Date(agent.lastSeenAt), now)
    );
  }

  private observeAgent(
    agentId: string,
    plane: string,
    action: string,
    timestamp: string,
    sessionId?: string,
    riskLevel?: RiskLevel,
    channelId?: string
  ): void {
    this.agentActivity.set(agentId, {
      agentId,
      lastSeenAt: timestamp,
      lastPlane: plane,
      lastAction: action,
      sessionId,
      riskLevel,
      latestChannelId: channelId,
    });
  }

  private observeChannel(input: {
    agentId: string;
    sessionId: string;
    channelId?: string;
    userId?: string;
    roleIds?: string[];
    plane: string;
    action: string;
    timestamp: string;
    riskLevel: RiskLevel;
  }): void {
    if (!input.channelId) return;
    const key = `${input.agentId}:${input.channelId}`;
    const existing = this.channelActivity.get(key) ?? {
      id: key,
      agentId: input.agentId,
      channelId: input.channelId,
      lastSeenAt: input.timestamp,
      lastPlane: input.plane,
      lastAction: input.action,
      riskLevel: input.riskLevel,
      sessionIds: [],
      userIds: [],
      roleIds: [],
    };

    existing.lastSeenAt = input.timestamp;
    existing.lastPlane = input.plane;
    existing.lastAction = input.action;
    if (scoreRisk(input.riskLevel) > scoreRisk(existing.riskLevel)) {
      existing.riskLevel = input.riskLevel;
    }
    if (!existing.sessionIds.includes(input.sessionId)) {
      existing.sessionIds.unshift(input.sessionId);
      existing.sessionIds = existing.sessionIds.slice(0, 8);
    }
    if (input.userId && !existing.userIds.includes(input.userId)) {
      existing.userIds.unshift(input.userId);
      existing.userIds = existing.userIds.slice(0, 8);
    }
    for (const roleId of input.roleIds ?? []) {
      if (!existing.roleIds.includes(roleId)) {
        existing.roleIds.unshift(roleId);
      }
    }
    existing.roleIds = existing.roleIds.slice(0, 12);
    this.channelActivity.set(key, existing);
  }

  private observeSession(input: {
    sessionId: string;
    agentId: string;
    plane: string;
    action: string;
    timestamp: string;
    riskLevel: RiskLevel;
    channelId?: string;
    simulated?: boolean;
    scenarioId?: string;
  }): SessionRuntime {
    const session = this.sessions.get(input.sessionId) ?? {
      sessionId: input.sessionId,
      agentId: input.agentId,
      startedAt: input.timestamp,
      lastSeenAt: input.timestamp,
      lastPlane: input.plane,
      lastAction: input.action,
      status: "active" as const,
      riskLevel: input.riskLevel,
      pendingApprovals: 0,
      evidenceCount: 0,
      taskCount: 0,
      simulated: input.simulated,
      scenarioId: input.scenarioId,
    };
    session.agentId = input.agentId;
    session.lastSeenAt = input.timestamp;
    session.lastPlane = input.plane;
    session.lastAction = input.action;
    if (scoreRisk(input.riskLevel) > scoreRisk(session.riskLevel)) {
      session.riskLevel = input.riskLevel;
    }
    session.simulated = session.simulated ?? input.simulated;
    session.scenarioId = session.scenarioId ?? input.scenarioId;
    session.channelId = input.channelId ?? session.channelId;
    this.sessions.set(input.sessionId, session);
    this.sessionRecency.set(input.sessionId, ++this.sessionRecencyCounter);
    return session;
  }

  private updateSessionApprovalCount(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    session.pendingApprovals = this.approvals.filter((item) => item.sessionId === sessionId && item.status === "pending").length;
  }

  private recordFlow(flow: Omit<RuntimeFlow, "id">): RuntimeFlow {
    const record: RuntimeFlow = { id: randomUUID(), ...flow };
    this.runtimeFlows.unshift(record);
    this.runtimeFlows.splice(MAX_GRAPH_ITEMS);
    return record;
  }

  private addEvidence(record: Omit<EvidenceRecord, "id">): EvidenceRecord {
    const evidence: EvidenceRecord = { id: randomUUID(), ...record };
    this.evidence.unshift(evidence);
    this.evidence.splice(MAX_GRAPH_ITEMS);
    const session = this.sessions.get(record.sessionId);
    if (session) session.evidenceCount = this.evidence.filter((item) => item.sessionId === record.sessionId).length;
    return evidence;
  }

  private upsertTask(input: {
    sessionId: string;
    agentId: string;
    plane: string;
    action: string;
    timestamp: string;
    riskLevel: RiskLevel;
    status: TaskNode["status"];
    summary: string;
    simulated?: boolean;
    scenarioId?: string;
  }): TaskNode {
    const taskId = `${input.sessionId}:${input.plane}:${input.action}`;
    const existing = this.tasks.get(taskId);
    const task: TaskNode = existing ?? {
      id: taskId,
      sessionId: input.sessionId,
      agentId: input.agentId,
      plane: input.plane,
      action: input.action,
      title: `${input.plane} · ${input.action}`,
      summary: input.summary,
      status: input.status,
      riskLevel: input.riskLevel,
      createdAt: input.timestamp,
      updatedAt: input.timestamp,
      evidenceIds: [],
      simulated: input.simulated,
      scenarioId: input.scenarioId,
    };
    task.summary = input.summary;
    task.status = input.status;
    task.updatedAt = input.timestamp;
    if (scoreRisk(input.riskLevel) > scoreRisk(task.riskLevel)) {
      task.riskLevel = input.riskLevel;
    }
    task.simulated = task.simulated ?? input.simulated;
    task.scenarioId = task.scenarioId ?? input.scenarioId;
    this.tasks.set(taskId, task);
    const previousTaskId = this.lastTaskForSession.get(input.sessionId);
    if (previousTaskId && previousTaskId !== taskId && !this.taskEdges.some((edge) => edge.from === previousTaskId && edge.to === taskId && edge.relationship === "precedes")) {
      this.taskEdges.unshift({ from: previousTaskId, to: taskId, relationship: "precedes" });
      this.taskEdges.splice(MAX_GRAPH_ITEMS);
    }
    this.lastTaskForSession.set(input.sessionId, taskId);
    const session = this.sessions.get(input.sessionId);
    if (session) session.taskCount = Array.from(this.tasks.values()).filter((item) => item.sessionId === input.sessionId).length;
    return task;
  }

  private linkEvidenceToTask(taskId: string, evidenceId: string): void {
    const task = this.tasks.get(taskId);
    if (task && !task.evidenceIds.includes(evidenceId)) {
      task.evidenceIds.unshift(evidenceId);
    }
    if (!this.taskEdges.some((edge) => edge.from === taskId && edge.to === evidenceId && edge.relationship === "evidenced_by")) {
      this.taskEdges.unshift({ from: taskId, to: evidenceId, relationship: "evidenced_by" });
      this.taskEdges.splice(MAX_GRAPH_ITEMS);
    }
  }

  private pushEvent(event: RuntimeEvent): void {
    this.events.unshift(event);
    this.events.splice(MAX_FEED_ITEMS);
    this.auditEvents.splice(MAX_FEED_ITEMS);
    this.approvals.splice(MAX_FEED_ITEMS);
  }

  private seedRuntime(): void {
    const seededAt = new Date().toISOString();
    this.pushEvent({
      id: randomUUID(),
      timestamp: seededAt,
      category: "system",
      title: "Agentwall control plane online",
      summary: `Approval mode ${this.approvalMode}; default policy ${this.config.policy.defaultDecision}`,
      status: "ok",
      detail: {
        host: this.config.host,
        port: this.config.port,
      },
      synthetic: true,
    });
    this.pushEvent({
      id: randomUUID(),
      timestamp: seededAt,
      category: "system",
      title: "Egress and DLP controls loaded",
      summary: `${this.config.egress.allowedHosts.length} allowlisted host(s), redact=${this.config.dlp.redactSecrets}`,
      status: this.config.egress.enabled && this.config.dlp.enabled ? "ok" : "warning",
      synthetic: true,
    });
    this.pushEvent({
      id: randomUUID(),
      timestamp: seededAt,
      category: "watchdog",
      title: "Watchdog policy armed",
      summary: `Kill switch mode ${this.config.watchdog.killSwitchMode}`,
      status: this.config.watchdog.enabled ? "ok" : "warning",
      synthetic: true,
    });
    this.observeSession({
      sessionId: "control-plane",
      agentId: "agentwall-console",
      plane: "governance",
      action: "boot",
      timestamp: seededAt,
      riskLevel: "low",
    });
  }
}
