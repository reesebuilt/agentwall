import { createHash, randomUUID } from "crypto";
import { execFile, spawn } from "child_process";
import { promisify } from "util";
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { ApprovalGate } from "../approval/gate";
import { PolicyEngine } from "../policy/engine";
import { builtinRules } from "../policy/rules";
import { RuntimeState } from "../dashboard/state";
import { RuntimeFloodGuard } from "../runtime/floodguard";
import { prioritizePendingApprovals, summarizeApprovalSessionLane, summarizeApprovalSessionLaneLabel } from "../dashboard/approval-queue";
import { FileBackedPolicyRuntime } from "../policy/runtime";
import { DecisionSchema, ExecutionModeSchema, PlaneSchema, RiskLevelSchema } from "../types";
import { DeclarativePolicyRule } from "../policy/loader";
import { buildScopedRuleCatalogItem, isScopedDeclarativeRule } from "../policy/scoped-rules";
import { AgentwallConfig } from "../config";
import { buildOrganizationFederationSummaryPayload } from "../org/control-plane";
import { mergeOrganizationControlPlaneSnapshots, pollOrganizationPeerSummaries } from "../org/federation";
import { emit } from "../audit/logger";
import { buildCommunicationChannelContext, normalizeCommunicationChannelId } from "../integrations/communication-channel/control";

const statusScore = { critical: 4, pending: 3, warning: 2, ok: 1 } as Record<string, number>;
const execFileAsync = promisify(execFile);
const LOCAL_SERVICE_NAME = "agentwall-live.service";

function isAllowedLocalMutation(req: FastifyRequest): boolean {
  const origin = req.headers.origin;
  if (!origin) return true;

  const host = req.headers.host;
  if (!host) return false;

  try {
    const parsed = new URL(origin);
    return parsed.host === host && (parsed.protocol === "http:" || parsed.protocol === "https:");
  } catch {
    return false;
  }
}

function rejectCrossOriginMutation(req: FastifyRequest, reply: FastifyReply): boolean {
  if (isAllowedLocalMutation(req)) return false;
  reply.status(403).send({ error: "Dashboard control requests must originate from the local Agentwall dashboard." });
  return true;
}

function parseSystemctlShow(output: string): Record<string, string> {
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .reduce<Record<string, string>>((acc, line) => {
      const index = line.indexOf("=");
      if (index > 0) {
        acc[line.slice(0, index)] = line.slice(index + 1);
      }
      return acc;
    }, {});
}

async function getLocalServiceControlStatus() {
  try {
    const { stdout } = await execFileAsync("systemctl", [
      "--user",
      "show",
      LOCAL_SERVICE_NAME,
      "--property=ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp,LoadState",
    ], { timeout: 2500 });
    const status = parseSystemctlShow(stdout);
    return {
      available: true,
      manager: "systemd-user",
      serviceName: LOCAL_SERVICE_NAME,
      canRestart: true,
      loadState: status.LoadState ?? "unknown",
      activeState: status.ActiveState ?? "unknown",
      subState: status.SubState ?? "unknown",
      mainPid: status.MainPID && status.MainPID !== "0" ? Number(status.MainPID) : null,
      restarts: status.NRestarts ? Number(status.NRestarts) : 0,
      startedAt: status.ExecMainStartTimestamp || null,
    };
  } catch (error) {
    return {
      available: false,
      manager: "systemd-user",
      serviceName: LOCAL_SERVICE_NAME,
      canRestart: false,
      error: error instanceof Error ? error.message : "systemctl status unavailable",
    };
  }
}

function buildOperatorTimeline(
  snapshot: ReturnType<RuntimeState["getSnapshot"]>,
  flood: ReturnType<RuntimeFloodGuard["getTelemetrySnapshot"]>
) {
  const queueItems = (snapshot.priorityQueue ?? []).map((item) => ({
    id: `queue:${item.category}:${item.id}`,
    timestamp: item.timestamp,
    title: item.title,
    summary: item.summary,
    status: item.status,
    category: item.category,
    agentId: item.owner,
    drilldownKind: item.drilldownKind,
    drilldownId: item.drilldownId,
    primaryAction: item.primaryAction,
  }));

  const floodItems = (flood.recentBlocks ?? []).slice(0, 3).map((item) => ({
    id: `flood:${item.timestamp}:${item.category}:${item.sessionId ?? item.actor ?? "global"}`,
    timestamp: item.timestamp,
    title: `FloodGuard blocked ${item.category}`,
    summary: `${item.reason}${item.sessionId ? ` · ${item.sessionId}` : item.actor ? ` · ${item.actor}` : ""}`,
    status: "warning" as const,
    category: "floodguard",
    sessionId: item.sessionId,
  }));

  const eventItems = (snapshot.eventFeed ?? [])
    .filter((item) => item.status !== "ok")
    .slice(0, 6)
    .map((item) => ({
      id: `event:${item.id}`,
      timestamp: item.timestamp,
      title: item.title,
      summary: item.summary,
      status: item.status,
      category: item.category,
      plane: item.plane,
      agentId: item.agentId,
      sessionId: item.sessionId,
      primaryAction: item.sessionId ? "Open session" : item.agentId ? "Inspect agent" : undefined,
      drilldownKind: item.sessionId ? "session" as const : item.agentId ? "agent" as const : undefined,
      drilldownId: item.sessionId ?? item.agentId,
    }));

  return [...queueItems, ...floodItems, ...eventItems]
    .sort((left, right) => {
      const statusDelta = (statusScore[String(right.status)] ?? 0) - (statusScore[String(left.status)] ?? 0);
      if (statusDelta !== 0) return statusDelta;
      return String(right.timestamp).localeCompare(String(left.timestamp));
    })
    .filter((item, index, items) => items.findIndex((candidate) => candidate.id === item.id) === index)
    .slice(0, 8);
}

function buildApprovalQueueHealth(
  pending: Array<{ requestId?: string; riskLevel?: string; createdAt?: string; action?: string; sessionId?: string; agentId?: string; note?: string; reasons?: string[]; matchedRules?: string[] }>
) {
  const criticalCount = pending.filter((item) => item.riskLevel === "critical").length;
  const oldestCreatedAt = pending
    .map((item) => item.createdAt)
    .filter(Boolean)
    .sort((left, right) => String(left).localeCompare(String(right)))[0] ?? null;
  const next = pending[0];
  const reviewRequestId = next?.requestId ?? null;
  const reviewTarget = next
    ? [next.action ?? "pending approval", next.sessionId ?? next.agentId].filter(Boolean).join(" · ")
    : null;
  const reviewAgeMinutes = next?.createdAt
    ? Math.max(0, Math.round((Date.now() - new Date(next.createdAt).getTime()) / 60000))
    : null;
  const reviewDetail = next
    ? [next.riskLevel, `waiting ${reviewAgeMinutes ?? 0}m`, next.note ?? next.reasons?.[0] ?? "Awaiting analyst disposition"]
        .filter(Boolean)
        .join(" · ")
    : null;
  const reviewRule = next?.matchedRules?.[0] ?? null;
  const reviewLane = summarizeApprovalSessionLane(pending);
  return {
    pendingCount: pending.length,
    criticalCount,
    oldestCreatedAt,
    reviewRequestId,
    reviewTarget,
    reviewDetail,
    reviewRule,
    reviewLane,
  };
}

function buildApprovalSummary(
  pending: Array<{ action?: string; riskLevel?: string; reasons?: string[]; createdAt?: string }>,
  recent: Array<{ action?: string; status?: string; note?: string; reasons?: string[]; resolvedAt?: string; createdAt?: string; riskLevel?: string }>
) {
  const next = pending[0];
  if (next) {
    return {
      headline: `Review ${next.action ?? "pending approval"} first`,
      reason: next.reasons?.[0] ?? "Operator review required.",
      status: "pending",
      riskLevel: next.riskLevel ?? "unknown",
      timestamp: next.createdAt ?? null,
    };
  }

  const last = [...recent]
    .filter((item) => item.status && item.status !== "pending")
    .sort((left, right) => String(right.resolvedAt ?? right.createdAt ?? "").localeCompare(String(left.resolvedAt ?? left.createdAt ?? "")))[0];

  if (last) {
    return {
      headline: `Last decision: ${last.action ?? "approval"} ${last.status}`,
      reason: last.note ?? last.reasons?.[0] ?? "Most recent approval decision recorded.",
      status: last.status,
      riskLevel: last.riskLevel ?? "unknown",
      timestamp: last.resolvedAt ?? last.createdAt ?? null,
    };
  }

  return {
    headline: "No approvals waiting",
    reason: "No approval requests are waiting on human action.",
    status: "ok",
    riskLevel: "low",
    timestamp: null,
  };
}

function buildApprovalRows(
  items: Array<{
    requestId?: string;
    action?: string;
    sessionId?: string;
    createdAt?: string;
    resolvedAt?: string;
    status?: string;
    mode?: string;
    approvedBy?: string;
    note?: string;
    reasons?: string[];
    matchedRules?: string[];
    riskLevel?: string;
  }>
) {
  const now = Date.now();
  const pendingItems = items.filter((item) => item.status === "pending");
  return items.map((item, index) => {
    const pending = item.status === "pending";
    const referenceTime = pending ? item.createdAt : item.resolvedAt ?? item.createdAt;
    const ageMinutes = referenceTime ? Math.max(0, Math.round((now - new Date(referenceTime).getTime()) / 60000)) : null;
    return {
      ...item,
      matchedRule: item.matchedRules?.[0] ?? null,
      queueRank: pending ? index + 1 : null,
      queuePositionLabel: pending ? `${index + 1} of ${pendingItems.length} pending` : null,
      sessionLaneLabel: pending ? summarizeApprovalSessionLaneLabel(pendingItems, item) : null,
      priorityLabel: item.riskLevel === "critical" ? "critical" : item.riskLevel === "high" ? "high" : pending ? "review" : "normal",
      triageDetail: pending
        ? `waiting ${ageMinutes ?? 0}m · ${item.note ?? item.reasons?.[0] ?? "Awaiting analyst disposition"}`
        : `${item.status ?? "resolved"}${item.approvedBy ? ` by ${item.approvedBy}` : ""} · ${item.note ?? item.reasons?.[0] ?? "Decision recorded"}`,
    };
  });
}

function buildFloodGuardGuidance(
  flood: ReturnType<RuntimeFloodGuard["getTelemetrySnapshot"]>,
  pending: Array<{ sessionId?: string; action?: string; riskLevel?: string }>
) {
  const hottestSession = [...(flood.pressureBySession ?? [])]
    .sort((left, right) => right.pressure - left.pressure || right.blocked - left.blocked)
    .find((item) => item.pressure > 0);
  const queueBlocks = (flood.recentBlocks ?? []).filter((item) => item.category === "queue");
  const criticalPending = pending.filter((item) => String(item.riskLevel) === "critical");
  const topPending = pending[0];
  const highestPressure = hottestSession?.pressure ?? 0;
  const shouldRecommendShield =
    flood.mode !== "shield" &&
    (queueBlocks.length > 0 || highestPressure >= 0.85 || (criticalPending.length > 0 && pending.length >= 2));

  if (flood.mode === "shield") {
    return {
      status: "active",
      summary:
        queueBlocks.length > 0
          ? `Shield mode is active while approval queue pressure is elevated${hottestSession ? ` around ${hottestSession.sessionId}` : ""}.`
          : `Shield mode is active${hottestSession ? ` with ${hottestSession.sessionId} carrying the highest pressure` : " to keep admission tighter while operators triage runtime traffic"}.`,
      recommendedAction:
        criticalPending.length > 0
          ? `Clear the critical approval queue starting with ${topPending?.action ?? "the hottest request"} before returning to normal mode.`
          : hottestSession
            ? `Review ${hottestSession.sessionId} before dropping back to normal limits.`
            : "Keep shield mode on until blocked traffic and queue pressure settle.",
      hottestSessionId: hottestSession?.sessionId ?? null,
      pressure: Number(highestPressure.toFixed(2)),
    };
  }

  if (shouldRecommendShield) {
    return {
      status: "recommend",
      summary:
        queueBlocks.length > 0
          ? `Approval queue pressure is already causing FloodGuard blocks${hottestSession ? ` for ${hottestSession.sessionId}` : ""}.`
          : criticalPending.length > 0
            ? `Critical approvals are stacking while runtime pressure stays elevated${hottestSession ? ` for ${hottestSession.sessionId}` : ""}.`
            : `FloodGuard pressure is elevated${hottestSession ? ` for ${hottestSession.sessionId}` : ""}.`,
      recommendedAction: hottestSession
        ? `Enable shield mode for 10 minutes, review ${hottestSession.sessionId}, and clear the highest-risk approvals first.`
        : "Enable shield mode for 10 minutes and clear the highest-risk approvals first.",
      hottestSessionId: hottestSession?.sessionId ?? null,
      pressure: Number(highestPressure.toFixed(2)),
    };
  }

  return {
    status: "normal",
    summary:
      flood.blockedTotal > 0
        ? "FloodGuard has recent blocks recorded, but current pressure is back inside normal limits."
        : "FloodGuard is operating inside normal limits.",
    recommendedAction: hottestSession
      ? `Keep an eye on ${hottestSession.sessionId}; it is the hottest active session right now.`
      : "No FloodGuard action needed right now.",
    hottestSessionId: hottestSession?.sessionId ?? null,
    pressure: Number(highestPressure.toFixed(2)),
  };
}

type CommandDeckLane = "today" | "waiting" | "risks" | "approvals" | "autoHandled";
type CommandDeckSource = "runtime" | "kb" | "system";

interface CommandDeckItem {
  id: string;
  lane: CommandDeckLane;
  title: string;
  summary: string;
  status: "ok" | "pending" | "warning" | "critical";
  source: CommandDeckSource;
  meta?: string;
  actionLabel?: string;
  drilldownKind?: "session" | "approval" | "evidence" | "task" | "agent";
  drilldownId?: string;
}

function buildServiceActionItem(
  action: string,
  index: number,
  snapshot: ReturnType<RuntimeState["getSnapshot"]>
): CommandDeckItem {
  const normalized = action.toLowerCase();
  if (!snapshot.freshness?.hasLiveActivity && normalized.includes("test evaluation or approval request")) {
    return {
      id: `system:service:${index}:seed-telemetry`,
      lane: "today",
      title: "Send a test evaluation to seed telemetry",
      summary: "Mission Control is loaded, but the operator layer is still waiting on its first live runtime event.",
      status: "pending",
      source: "system",
      meta: "No live runtime activity yet",
      actionLabel: "Seed telemetry",
    };
  }

  if (normalized.includes("pending approval queue")) {
    return {
      id: `system:service:${index}:approval-queue`,
      lane: "approvals",
      title: "Review the pending approval queue",
      summary: action,
      status: "pending",
      source: "system",
      meta: snapshot.generatedAt,
      actionLabel: "Open approvals",
      drilldownKind: snapshot.approvals?.pending?.[0]?.requestId ? "approval" : undefined,
      drilldownId: snapshot.approvals?.pending?.[0]?.requestId,
    };
  }

  if (normalized.includes("paused sessions") || normalized.includes("terminated sessions")) {
    return {
      id: `system:service:${index}:sessions`,
      lane: "waiting",
      title: normalized.includes("terminated") ? "Inspect contained sessions" : "Inspect paused sessions",
      summary: action,
      status: normalized.includes("terminated") ? "warning" : "pending",
      source: "system",
      meta: snapshot.generatedAt,
      actionLabel: "Inspect sessions",
    };
  }

  if (normalized.includes("watchdog") || normalized.includes("telemetry is stale") || normalized.includes("critical signal")) {
    return {
      id: `system:service:${index}:risk`,
      lane: "risks",
      title: normalized.includes("telemetry is stale") ? "Investigate stale telemetry" : "Inspect risk posture",
      summary: action,
      status: normalized.includes("critical signal") ? "critical" : "warning",
      source: "system",
      meta: snapshot.generatedAt,
      actionLabel: "Inspect risk posture",
    };
  }

  return {
    id: `system:service:${index}:today`,
    lane: "today",
    title: "Operator follow-through recommended",
    summary: action,
    status: "pending",
    source: "system",
    meta: snapshot.generatedAt,
    actionLabel: "Inspect mission control",
  };
}

function pushUniqueCommandDeckItem(items: CommandDeckItem[], candidate: CommandDeckItem) {
  if (!items.some((item) => item.id === candidate.id)) {
    items.push(candidate);
  }
}

function buildCommandDeck(
  snapshot: ReturnType<RuntimeState["getSnapshot"]>,
  prioritizedPending: Array<{
    requestId?: string;
    action?: string;
    sessionId?: string;
    agentId?: string;
    riskLevel?: string;
    reasons?: string[];
    createdAt?: string;
    status?: string;
    mode?: string;
  }>,
  floodGuidance: { status?: string; summary?: string; recommendedAction?: string; hottestSessionId?: string | null },
  operatorTimeline: Array<{
    title?: string;
    summary?: string;
    status?: string;
    category?: string;
    timestamp?: string;
    drilldownKind?: string;
    drilldownId?: string;
    primaryAction?: string;
  }>
) {
  const containedSessions = (snapshot.sessions?.recent ?? []).filter((item) => item.status !== "active");
  const criticalSignals = Number(snapshot.posture?.criticalSignals ?? 0);
  const pendingCount = prioritizedPending.length;
  const recentResolvedApprovals = (snapshot.approvals?.recent ?? []).filter((item) => item.status && item.status !== "pending");
  const intake = [] as CommandDeckItem[];

  (snapshot.service?.recommendedActions ?? []).forEach((action, index) => {
    pushUniqueCommandDeckItem(intake, buildServiceActionItem(action, index, snapshot));
  });

  prioritizedPending.slice(0, 3).forEach((item, index) => {
    pushUniqueCommandDeckItem(intake, {
      id: `runtime:today:approval:${item.requestId ?? `${item.action ?? "pending"}:${index}`}`,
      lane: "today",
      title: `Review ${item.action ?? "pending approval"}`,
      summary: `${item.riskLevel ?? "unknown"} risk · ${item.sessionId ?? item.agentId ?? "runtime"} · ${item.reasons?.[0] ?? "Operator review required."}`,
      status: item.riskLevel === "critical" ? "critical" : "pending",
      source: "runtime",
      meta: item.createdAt,
      actionLabel: "Review",
      drilldownKind: "approval",
      drilldownId: item.requestId,
    });
  });

  containedSessions.slice(0, 2).forEach((item) => {
    pushUniqueCommandDeckItem(intake, {
      id: `runtime:today:session:${item.sessionId}`,
      lane: "today",
      title: `Inspect ${item.sessionId}`,
      summary: `${item.status} · ${item.note ?? `${item.lastAction} on ${item.lastPlane}`}`,
      status: item.status === "terminated" ? "critical" : "warning",
      source: "runtime",
      meta: item.lastSeenAt,
      actionLabel: "Open session",
      drilldownKind: "session",
      drilldownId: item.sessionId,
    });
  });

  (snapshot.knowledgeBase?.entries ?? [])
    .filter((item) => item.category === "open_questions")
    .slice(0, 2)
    .forEach((item) => {
      pushUniqueCommandDeckItem(intake, {
        id: `kb:waiting:${item.id}`,
        lane: "waiting",
        title: item.title,
        summary: item.summary || item.detail || "Knowledge base question still needs an operator answer.",
        status: item.status === "open" ? "pending" : "warning",
        source: "kb",
        meta: item.location,
        actionLabel: "Open knowledge base",
      });
    });

  const today = intake.filter((item) => item.lane === "today");
  if (today.length === 0 && snapshot.freshness?.hasLiveActivity) {
    operatorTimeline.slice(0, 2).forEach((item) => {
      pushUniqueCommandDeckItem(today, {
        id: `runtime:today:timeline:${item.drilldownKind ?? item.category ?? "event"}:${item.drilldownId ?? item.timestamp ?? item.title}`,
        lane: "today",
        title: `${item.primaryAction ?? "Inspect"} ${item.title ?? "runtime item"}`,
        summary: item.summary ?? "Recent runtime activity needs operator review.",
        status: item.status === "critical" || item.status === "pending" || item.status === "warning" ? item.status : "warning",
        source: "runtime",
        meta: item.timestamp ?? snapshot.generatedAt,
        actionLabel: item.primaryAction ?? "Inspect",
        drilldownKind: item.drilldownKind as CommandDeckItem["drilldownKind"],
        drilldownId: item.drilldownId,
      });
    });
  }

  if (today.length === 0) {
    today.push({
      id: "system:today:clear",
      lane: "today",
      title: "No immediate operator action queued",
      summary: snapshot.service?.recommendedActions?.[0] ?? "The command surface is clear right now.",
      status: "ok",
      source: "system",
      meta: snapshot.generatedAt,
      actionLabel: "Inspect risk posture",
    });
  }

  const waiting = intake.filter((item) => item.lane === "waiting");
  if (pendingCount > 0) {
    waiting.push({
      id: "runtime:waiting:approvals",
      lane: "waiting",
      title: `${pendingCount} approval${pendingCount === 1 ? "" : "s"} waiting`,
      summary: `${prioritizedPending[0]?.action ?? "Top queue item"} is first in line${prioritizedPending[0]?.sessionId ? ` for ${prioritizedPending[0].sessionId}` : ""}.`,
      status: prioritizedPending.some((item) => item.riskLevel === "critical") ? "critical" : "pending",
      source: "runtime",
      meta: prioritizedPending[0]?.createdAt ?? snapshot.generatedAt,
      actionLabel: "Open approvals",
    });
  }

  if (containedSessions.length > 0) {
    waiting.push({
      id: "runtime:waiting:contained-sessions",
      lane: "waiting",
      title: `${containedSessions.length} contained session${containedSessions.length === 1 ? "" : "s"} waiting on follow-through`,
      summary: containedSessions.slice(0, 2).map((item) => `${item.sessionId} ${item.status}`).join(" · "),
      status: containedSessions.some((item) => item.status === "terminated") ? "critical" : "warning",
      source: "runtime",
      meta: containedSessions[0]?.lastSeenAt ?? snapshot.generatedAt,
      actionLabel: "Inspect sessions",
    });
  }

  if (waiting.length === 0) {
    waiting.push({
      id: "system:waiting:clear",
      lane: "waiting",
      title: "Nothing waiting on follow-through",
      summary: "No approvals, paused sessions, or contained runtime work are currently stacking up.",
      status: "ok",
      source: "system",
      meta: snapshot.generatedAt,
      actionLabel: "Inspect risk posture",
    });
  }

  const risks = intake.filter((item) => item.lane === "risks");
  if (criticalSignals > 0) {
    risks.push({
      id: "runtime:risks:critical-signals",
      lane: "risks",
      title: `${criticalSignals} critical runtime signal${criticalSignals === 1 ? "" : "s"}`,
      summary: snapshot.service?.operatorSummary ?? "Critical runtime activity needs review.",
      status: "critical",
      source: "runtime",
      meta: snapshot.generatedAt,
      actionLabel: "Inspect risk posture",
    });
  }

  if (floodGuidance.status === "recommend" || floodGuidance.status === "active") {
    risks.push({
      id: `runtime:risks:floodguard:${floodGuidance.status}`,
      lane: "risks",
      title: floodGuidance.status === "active" ? "FloodGuard shield is active" : "FloodGuard recommends shield mode",
      summary: floodGuidance.recommendedAction ?? floodGuidance.summary ?? "FloodGuard pressure is elevated.",
      status: floodGuidance.status === "active" ? "warning" : "pending",
      source: "runtime",
      meta: snapshot.generatedAt,
      actionLabel: floodGuidance.status === "active" ? "Inspect sessions" : "Raise protection",
      drilldownKind: floodGuidance.hottestSessionId ? "session" : undefined,
      drilldownId: floodGuidance.hottestSessionId ?? undefined,
    });
  }

  if (risks.length === 0) {
    risks.push({
      id: "system:risks:clear",
      lane: "risks",
      title: "No live runtime risk demanding action",
      summary: !snapshot.freshness?.hasLiveActivity
        ? "The system is armed but idle. Seed telemetry before you trust the command surface."
        : "No critical signals, queue pressure, or containment drift need action right now.",
      status: snapshot.freshness?.hasLiveActivity ? "ok" : "warning",
      source: "system",
      meta: snapshot.generatedAt,
      actionLabel: snapshot.freshness?.hasLiveActivity ? "Stay on mission" : "Seed telemetry",
    });
  }

  const approvals = intake.filter((item) => item.lane === "approvals");
  approvals.push({
    id: "runtime:approvals:summary",
    lane: "approvals",
    title: pendingCount > 0 ? `Pending approvals: ${pendingCount}` : "Pending approvals: 0",
    summary: pendingCount > 0
      ? `${prioritizedPending[0]?.action ?? "Top item"} should be reviewed first${prioritizedPending[0]?.sessionId ? ` in ${prioritizedPending[0].sessionId}` : ""}.`
      : snapshot.approvals?.recent?.[0]
        ? `Last decision: ${snapshot.approvals.recent[0].action ?? "approval"} ${snapshot.approvals.recent[0].status ?? "resolved"}.`
        : "No approval requests are waiting on human action.",
    status: pendingCount > 0 ? (prioritizedPending.some((item) => item.riskLevel === "critical") ? "critical" : "pending") : "ok",
    source: "runtime",
    meta: prioritizedPending[0]?.createdAt ?? snapshot.generatedAt,
    actionLabel: pendingCount > 0 ? "Open approvals" : "Review history",
    drilldownKind: pendingCount > 0 ? "approval" : undefined,
    drilldownId: pendingCount > 0 ? prioritizedPending[0]?.requestId : undefined,
  });

  const autoHandled = intake.filter((item) => item.lane === "autoHandled");
  recentResolvedApprovals.slice(0, 3).forEach((item, index) => {
    autoHandled.push({
      id: `runtime:autoHandled:${item.requestId ?? `${item.action ?? "approval"}:${index}`}`,
      lane: "autoHandled",
      title: `${item.action ?? "Approval"} ${item.status}`,
      summary: item.note ?? item.reasons?.[0] ?? "Resolved and cleared from the hot queue.",
      status: item.status === "denied" || item.status === "timeout" ? "warning" : "ok",
      source: "runtime",
      meta: item.resolvedAt ?? item.createdAt ?? snapshot.generatedAt,
      actionLabel: "Review history",
      drilldownKind: "approval",
      drilldownId: item.requestId,
    });
  });

  if (autoHandled.length === 0) {
    autoHandled.push({
      id: "system:autoHandled:empty",
      lane: "autoHandled",
      title: "No auto-handled work yet",
      summary: "Resolved or auto-routed work will land here once the runtime starts moving.",
      status: "ok",
      source: "system",
      meta: snapshot.generatedAt,
      actionLabel: "Open knowledge base",
    });
  }

  return {
    today: {
      title: "Today",
      description: "The few things that deserve your eyes now.",
      items: today.slice(0, 5),
    },
    waiting: {
      title: "Waiting",
      description: "What is stacked, delegated, or still awaiting follow-through.",
      items: waiting.slice(0, 4),
    },
    risks: {
      title: "Risks",
      description: "What can hurt you if ignored.",
      items: risks.slice(0, 4),
    },
    approvals: {
      title: "Approvals",
      description: "Human judgment still in the loop.",
      items: approvals.slice(0, 4),
    },
    autoHandled: {
      title: "Auto-handled",
      description: "Recently cleared work so you do not have to reconstruct it from memory.",
      items: autoHandled.slice(0, 4),
    },
  };
}

function buildPolicyCatalog(policyRuntime?: FileBackedPolicyRuntime) {
  const scopedRules = (policyRuntime?.getDeclarativeRules() ?? [])
    .filter(isScopedDeclarativeRule)
    .map(buildScopedRuleCatalogItem)
    .sort((left, right) => left.id.localeCompare(right.id));

  return {
    editable: Boolean(policyRuntime),
    policyPath: policyRuntime ? "[local policy path redacted]" : null,
    note: policyRuntime
      ? "Scoped guardrails save back to the live declarative policy file and hot-reload immediately."
      : "Attach policy.configPath to enable scoped guardrail editing from the dashboard.",
    scopedRules,
    channelFirewall: {
      profiles: CHANNEL_FIREWALL_PROFILE_LABELS,
      lanes: buildChannelFirewallCatalog(scopedRules),
    },
  };
}

function slugifyRuleSegment(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

const PolicyScopedRuleSchema = z.object({
  id: z.string().trim().optional(),
  description: z.string().trim().min(1),
  plane: PlaneSchema.or(z.literal("all")),
  decision: DecisionSchema,
  riskLevel: RiskLevelSchema,
  reason: z.string().trim().min(1),
  enabled: z.boolean().optional(),
  actionIncludes: z.array(z.string().trim().min(1)).optional(),
  actionEquals: z.array(z.string().trim().min(1)).optional(),
  actorChannelIds: z.array(z.string().trim().min(1)).optional(),
  actorUserIds: z.array(z.string().trim().min(1)).optional(),
  actorRoleIds: z.array(z.string().trim().min(1)).optional(),
  subjectAgentIds: z.array(z.string().trim().min(1)).optional(),
  subjectSessionIds: z.array(z.string().trim().min(1)).optional(),
  executionModes: z.array(ExecutionModeSchema).optional(),
}).refine((value) => {
  return Boolean(
    (value.actorChannelIds?.length ?? 0) > 0 ||
    (value.actorUserIds?.length ?? 0) > 0 ||
    (value.actorRoleIds?.length ?? 0) > 0 ||
    (value.subjectAgentIds?.length ?? 0) > 0 ||
    (value.subjectSessionIds?.length ?? 0) > 0 ||
    (value.executionModes?.length ?? 0) > 0
  );
}, "Scoped guardrails require at least one actor, subject, or execution-mode scope.");

function buildScopedDeclarativeRule(input: z.infer<typeof PolicyScopedRuleSchema>): DeclarativePolicyRule {
  const actionIncludes = (input.actionIncludes ?? []).filter(Boolean);
  const actionEquals = (input.actionEquals ?? []).filter(Boolean);
  const actorChannelIds = (input.actorChannelIds ?? []).filter(Boolean);
  const actorUserIds = (input.actorUserIds ?? []).filter(Boolean);
  const actorRoleIds = (input.actorRoleIds ?? []).filter(Boolean);
  const subjectAgentIds = (input.subjectAgentIds ?? []).filter(Boolean);
  const subjectSessionIds = (input.subjectSessionIds ?? []).filter(Boolean);
  const executionModes = (input.executionModes ?? []).filter(Boolean);
  const normalizedId = input.id?.trim();
  const generatedId = [
    slugifyRuleSegment(input.decision),
    slugifyRuleSegment(input.plane),
    slugifyRuleSegment(subjectAgentIds[0] ?? actorChannelIds[0] ?? input.description),
  ].filter(Boolean).join("-");

  return {
    id: normalizedId && normalizedId.length > 0 ? normalizedId : `custom:${generatedId || "scoped-guardrail"}`,
    description: input.description.trim(),
    plane: input.plane,
    match: {
      ...(actionIncludes.length || actionEquals.length
        ? {
            action: {
              ...(actionIncludes.length ? { includes: actionIncludes } : {}),
              ...(actionEquals.length ? { equals: actionEquals } : {}),
            },
          }
        : {}),
      ...(actorChannelIds.length || actorUserIds.length || actorRoleIds.length
        ? {
            actor: {
              ...(actorChannelIds.length ? { channelId: actorChannelIds } : {}),
              ...(actorUserIds.length ? { userId: actorUserIds } : {}),
              ...(actorRoleIds.length ? { roleId: actorRoleIds } : {}),
            },
          }
        : {}),
      ...(subjectAgentIds.length || subjectSessionIds.length
        ? {
            subject: {
              ...(subjectAgentIds.length ? { agentId: subjectAgentIds } : {}),
              ...(subjectSessionIds.length ? { sessionId: subjectSessionIds } : {}),
            },
          }
        : {}),
      ...(executionModes.length ? { control: { executionMode: executionModes } } : {}),
    },
    decision: input.decision,
    riskLevel: input.riskLevel,
    reason: input.reason.trim(),
    enabled: input.enabled ?? true,
  };
}

const ChannelFirewallProfileSchema = z.object({
  agentId: z.string().trim().min(1),
  channelId: z.string().trim().min(1),
  profile: z.enum(["observe", "answer_only", "read_only", "approval_required", "locked_down"]),
});

type ChannelFirewallProfileInput = z.infer<typeof ChannelFirewallProfileSchema>;

const CHANNEL_FIREWALL_PROFILE_LABELS: Record<ChannelFirewallProfileInput["profile"], string> = {
  observe: "Monitor only",
  answer_only: "Answer only",
  read_only: "Read only",
  approval_required: "Approval required",
  locked_down: "Locked down",
};

function stableRuleSegment(value: string): string {
  const slug = slugifyRuleSegment(value) || "value";
  const hash = createHash("sha256").update(value).digest("hex").slice(0, 10);
  return `${slug}-${hash}`;
}

function channelFirewallRuleId(input: ChannelFirewallProfileInput, slot: string): string {
  return [
    "channel-firewall",
    stableRuleSegment(input.agentId),
    stableRuleSegment(input.channelId),
    slot,
  ].join(":");
}

function scopedFirewallRule(
  input: ChannelFirewallProfileInput,
  slot: string,
  options: Omit<z.infer<typeof PolicyScopedRuleSchema>, "id" | "actorChannelIds" | "subjectAgentIds">
): DeclarativePolicyRule {
  return buildScopedDeclarativeRule({
    ...options,
    id: channelFirewallRuleId(input, slot),
    actorChannelIds: [input.channelId],
    subjectAgentIds: [input.agentId],
  });
}

function buildChannelFirewallRules(input: ChannelFirewallProfileInput): DeclarativePolicyRule[] {
  const profileLabel = CHANNEL_FIREWALL_PROFILE_LABELS[input.profile];
  const baseReason = `${profileLabel} profile for ${input.agentId} in ${input.channelId}`;
  const enabledFor = (...profiles: ChannelFirewallProfileInput["profile"][]) => profiles.includes(input.profile);
  const externalDecision = input.profile === "approval_required" ? "approve" : "deny";
  const externalRisk = input.profile === "approval_required" ? "high" : "critical";

  return [
    scopedFirewallRule(input, "allow-replies", {
      description: `${profileLabel}: allow safe channel replies`,
      plane: "content",
      decision: "allow",
      riskLevel: "low",
      reason: `${baseReason}; safe replies and summaries are allowed.`,
      actionIncludes: ["reply", "summarize"],
      enabled: enabledFor("observe", "answer_only", "read_only", "approval_required"),
    }),
    scopedFirewallRule(input, "tool-control", {
      description: `${profileLabel}: tool action control`,
      plane: "tool",
      decision: input.profile === "read_only" ? "deny" : externalDecision,
      riskLevel: input.profile === "read_only" ? "high" : externalRisk,
      reason: input.profile === "read_only"
        ? `${baseReason}; mutating tool actions are blocked.`
        : `${baseReason}; tool actions are ${externalDecision === "approve" ? "queued for approval" : "blocked"}.`,
      actionIncludes: input.profile === "read_only"
        ? ["write", "create", "update", "patch", "delete", "remove", "unlink", "exec", "bash", "shell", "terminal", "install", "deploy"]
        : [],
      enabled: enabledFor("answer_only", "read_only", "approval_required"),
    }),
    scopedFirewallRule(input, "network-control", {
      description: `${profileLabel}: network action control`,
      plane: "network",
      decision: externalDecision,
      riskLevel: externalRisk,
      reason: `${baseReason}; network actions are ${externalDecision === "approve" ? "queued for approval" : "blocked"}.`,
      enabled: enabledFor("answer_only", "approval_required"),
    }),
    scopedFirewallRule(input, "browser-control", {
      description: `${profileLabel}: browser action control`,
      plane: "browser",
      decision: externalDecision,
      riskLevel: externalRisk,
      reason: `${baseReason}; browser actions are ${externalDecision === "approve" ? "queued for approval" : "blocked"}.`,
      enabled: enabledFor("answer_only", "approval_required"),
    }),
    scopedFirewallRule(input, "identity-control", {
      description: `${profileLabel}: identity and secret access control`,
      plane: "identity",
      decision: input.profile === "approval_required" ? "approve" : "deny",
      riskLevel: "critical",
      reason: input.profile === "approval_required"
        ? `${baseReason}; identity actions require human approval.`
        : `${baseReason}; secrets and credentials are blocked from this channel.`,
      actionIncludes: input.profile === "read_only" ? ["secret", "credential", "password", "token", "api_key", "vault", "keychain"] : [],
      enabled: enabledFor("answer_only", "read_only", "approval_required"),
    }),
    scopedFirewallRule(input, "governance-control", {
      description: `${profileLabel}: governance action control`,
      plane: "governance",
      decision: externalDecision,
      riskLevel: externalRisk,
      reason: `${baseReason}; governance actions are ${externalDecision === "approve" ? "queued for approval" : "blocked"}.`,
      enabled: enabledFor("answer_only", "approval_required"),
    }),
    scopedFirewallRule(input, "lockdown", {
      description: `${profileLabel}: deny all channel actions`,
      plane: "all",
      decision: "deny",
      riskLevel: "critical",
      reason: `${baseReason}; every action from this channel is blocked.`,
      enabled: input.profile === "locked_down",
    }),
  ];
}

function buildChannelFirewallCatalog(scopedRules: ReturnType<typeof buildScopedRuleCatalogItem>[]) {
  const activeRules = scopedRules.filter((rule) => rule.enabled !== false && rule.id.startsWith("channel-firewall:"));
  const byLane = new Map<string, { agentId: string; channelId: string; profile: string; rules: string[] }>();
  for (const rule of activeRules) {
    const agentId = rule.subjectAgentIds?.[0];
    const channelId = rule.actorChannelIds?.[0];
    if (!agentId || !channelId) continue;
    const key = `${agentId}\u0000${channelId}`;
    const slot = rule.id.split(":").pop() ?? "rule";
    const existing = byLane.get(key) ?? { agentId, channelId, profile: "custom", rules: [] };
    existing.rules.push(rule.id);
    if (slot === "lockdown") existing.profile = "locked_down";
    else if (slot === "tool-control" && rule.decision === "approve") existing.profile = "approval_required";
    else if (slot === "tool-control" && (rule.actionIncludes?.length ?? 0) > 0) existing.profile = "read_only";
    else if (slot === "tool-control" && rule.decision === "deny") existing.profile = "answer_only";
    else if (slot === "allow-replies" && existing.profile === "custom") existing.profile = "observe";
    byLane.set(key, existing);
  }

  return Array.from(byLane.values()).sort((left, right) => left.agentId.localeCompare(right.agentId) || left.channelId.localeCompare(right.channelId));
}

const ApprovalModeSchema = z.object({
  mode: z.enum(["auto", "always", "never"]),
});

const SessionControlSchema = z.object({
  action: z.enum(["pause", "resume", "terminate"]),
  note: z.string().optional(),
  confirm: z.boolean().optional(),
});

const DrilldownParamsSchema = z.object({
  kind: z.enum(["session", "approval", "evidence", "task", "agent"]),
  id: z.string(),
});

const SimulationControlSchema = z.object({
  action: z.enum(["start", "clear"]),
});

const ShieldModeSchema = z.object({
  mode: z.enum(["normal", "shield"]),
  durationMs: z.number().int().positive().max(4 * 60 * 60 * 1000).optional(),
});

const SessionOverrideSchema = z.object({
  multiplier: z.number().positive().min(0.5).max(3).optional(),
  durationMs: z.number().int().positive().max(4 * 60 * 60 * 1000).optional(),
  action: z.enum(["set", "clear"]).default("set"),
});

const LocalServiceControlSchema = z.object({
  action: z.enum(["restart", "reload_policy"]),
});

const TELEGRAM_WEBHOOK_SECRET_ENV = "AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET";
const TELEGRAM_BOT_TOKEN_ENV = "AGENTWALL_TELEGRAM_TEST_BOT_TOKEN";
const TELEGRAM_SEND_ENABLED_ENV = "AGENTWALL_TELEGRAM_TEST_SEND_ENABLED";

let lastCommunicationChannelProofSuite: unknown = null;

function buildTelegramFirstRunDTO(
  snapshot: ReturnType<RuntimeState["getSnapshot"]>,
  policyCatalog: ReturnType<typeof buildPolicyCatalog>
) {
  const webhookSecretConfigured = Boolean(process.env[TELEGRAM_WEBHOOK_SECRET_ENV]);
  const botTokenConfigured = Boolean(process.env[TELEGRAM_BOT_TOKEN_ENV]);
  const liveSendEnabled = process.env[TELEGRAM_SEND_ENABLED_ENV] === "true";

  const telegramLanes = (snapshot.channelInventory?.recent ?? []).filter(
    (ch) => String(ch.channelId ?? "").startsWith("telegram:") && ch.agentId !== "telegram-proof-agent"
  );
  const primaryLane = telegramLanes[0] ?? null;
  const primaryProfile = primaryLane
    ? (policyCatalog.channelFirewall.lanes.find(
        (lane) => lane.agentId === primaryLane.agentId && lane.channelId === primaryLane.channelId
      )?.profile ?? null)
    : null;

  const webhookReady = webhookSecretConfigured && botTokenConfigured;
  const laneObserved = Boolean(primaryLane);
  const profileSet = Boolean(primaryProfile && primaryProfile !== "observe");

  type ChecklistStatus = "done" | "current" | "blocked" | "pending";
  const step = (id: string, label: string, status: ChecklistStatus, detail: string) => ({ id, label, status, detail });

  const checklist = [
    step(
      "webhook_configured",
      "Configure webhook secret and bot token",
      webhookReady ? "done" : "current",
      webhookReady
        ? "Webhook secret and bot token are configured"
        : "Set the Telegram webhook secret and bot token environment variables"
    ),
    step(
      "lane_observed",
      "Observe a Telegram topic",
      laneObserved ? "done" : webhookReady ? "current" : "pending",
      laneObserved ? `Lane observed: ${primaryLane!.channelId}` : "Send one message to the test bot"
    ),
    step(
      "profile_set",
      "Set a guardrail profile",
      profileSet ? "done" : laneObserved ? "current" : "pending",
      profileSet ? `Profile: ${primaryProfile}` : "Set answer_only or locked_down from the channel panel"
    ),
    step(
      "proof_run",
      "Run proof suite",
      profileSet ? "current" : "pending",
      profileSet ? "Run the proof suite to verify deny enforcement" : "Set a profile first, then run the proof suite"
    ),
  ];

  const recommendedNextAction = !webhookReady
    ? "Configure webhook secret and bot token env vars to connect the test bot"
    : !laneObserved
    ? "Send one Telegram message to create the first observed lane"
    : !profileSet
    ? "Set answer_only profile from the channel panel, then run the proof suite"
    : "Run the proof suite to verify guardrail enforcement for this channel";

    return {
      webhookEndpointPath: "/integrations/telegram/generic-test-bot/webhook",
      webhookSecretConfigured,
      botTokenConfigured,
      liveSendEnabled,
      observedLaneCount: telegramLanes.length,
      primaryLane: primaryLane
        ? {
            agentId: primaryLane.agentId,
            channelId: primaryLane.channelId,
            profile: primaryProfile ?? null,
            lastSeenAt: primaryLane.lastSeenAt,
            lastAction: primaryLane.lastAction,
          }
        : null,
      recommendedNextAction,
      checklist,
      lastProofResult: lastCommunicationChannelProofSuite,
    };
}

const ProofCommunicationChannelSchema = z.object({
  agentId: z.string().trim().min(1),
  platform: z.enum(["telegram"]),
  channelId: z.string().trim().min(1),
  threadId: z.string().trim().min(1).optional(),
});

export async function dashboardRoutes(
  app: FastifyInstance,
  config: AgentwallConfig,
  engine: PolicyEngine,
  gate: ApprovalGate,
  runtime: RuntimeState,
  floodGuard: RuntimeFloodGuard,
  policyRuntime?: FileBackedPolicyRuntime
): Promise<void> {
  const buildDashboardPayload = async () => {
    const snapshot = runtime.getSnapshot(engine.getRules().length);
    const localInstanceIds = new Set(snapshot.organizationControlPlane.instances.filter((instance) => instance.role === "local").map((instance) => instance.id));
    const federationPeers = (config.organization?.instances ?? []).filter((instance) => instance.role !== "local" && !localInstanceIds.has(instance.id));
    const federationPoll = federationPeers.length > 0
      ? await pollOrganizationPeerSummaries({ instances: federationPeers })
      : { payloads: [], peers: [] };
    const organizationControlPlane = federationPeers.length > 0
      ? mergeOrganizationControlPlaneSnapshots(snapshot.organizationControlPlane, federationPoll.payloads, federationPoll.peers)
      : snapshot.organizationControlPlane;
    const flood = floodGuard.getTelemetrySnapshot();
    const pending = snapshot.approvals?.pending ?? [];
    const prioritizedPending = prioritizePendingApprovals(pending, flood);
    const floodGuidance = buildFloodGuardGuidance(flood, prioritizedPending);
    const recommendedActions = [
      ...(snapshot.service?.recommendedActions ?? []),
      floodGuidance.status === "recommend" ? floodGuidance.recommendedAction : null,
      floodGuidance.status === "active" ? floodGuidance.recommendedAction : null,
    ].filter((item, index, items): item is string => Boolean(item) && items.indexOf(item) === index).slice(0, 4);
    const operatorTimeline = buildOperatorTimeline(snapshot, flood);
    const approvalSummary = buildApprovalSummary(prioritizedPending, snapshot.approvals?.recent ?? []);
    const approvalQueueHealth = buildApprovalQueueHealth(prioritizedPending);
    const pendingRows = buildApprovalRows(prioritizedPending);
    const recentRows = buildApprovalRows(snapshot.approvals?.recent ?? []);
    const commandDeck = buildCommandDeck(snapshot, prioritizedPending, floodGuidance, operatorTimeline);
    const policyCatalog = buildPolicyCatalog(policyRuntime);
    const localControl = await getLocalServiceControlStatus();

    return {
      ...snapshot,
      localControl,
      policyCatalog,
      service: {
        ...snapshot.service,
        recommendedActions,
      },
      floodGuard: {
        ...flood,
        operatorGuidance: floodGuidance,
      },
      approvals: {
        ...snapshot.approvals,
        pending: pendingRows,
        recent: recentRows,
        summary: approvalSummary,
        queueHealth: approvalQueueHealth,
      },
      commandDeck,
      operatorTimeline,
      organizationControlPlane,
      organizationFederation: {
        peers: federationPoll.peers,
      },
      product: {
        telegramFirstRun: buildTelegramFirstRunDTO(snapshot, policyCatalog),
      },
    };
  };

  app.get("/api/dashboard/state", async (_req, reply) => {
    return reply.send(await buildDashboardPayload());
  });

  app.get("/api/dashboard/events", async (req, reply) => {
    reply.raw.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });

    const sendState = async () => {
      try {
        const payload = await buildDashboardPayload();
        reply.raw.write(`event: dashboard-state\n`);
        reply.raw.write(`data: ${JSON.stringify(payload)}\n\n`);
      } catch (error) {
        reply.raw.write(`event: dashboard-error\n`);
        reply.raw.write(`data: ${JSON.stringify({ error: error instanceof Error ? error.message : "dashboard stream failed" })}\n\n`);
      }
    };

    await sendState();
    const timer = setInterval(sendState, 5000);
    req.raw.on("close", () => {
      clearInterval(timer);
      reply.raw.end();
    });
  });

  app.get("/api/org/summary", async (_req, reply) => {
    const snapshot = runtime.getSnapshot(engine.getRules().length);
    const payload = buildOrganizationFederationSummaryPayload(snapshot.generatedAt, snapshot.organizationControlPlane);
    return reply.send({ ok: true, ...payload });
  });

  app.get("/api/dashboard/local-service", async (_req, reply) => {
    return reply.send({ ok: true, localControl: await getLocalServiceControlStatus() });
  });

  app.post("/api/dashboard/control/local-service", async (req, reply) => {
    if (rejectCrossOriginMutation(req, reply)) return;

    const parsed = LocalServiceControlSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid local service control body", details: parsed.error.flatten() });
    }

    if (parsed.data.action === "reload_policy") {
      if (!policyRuntime) {
        return reply.status(400).send({ error: "Policy reload requires policy.configPath." });
      }
      const result = policyRuntime.reload();
      if (!result.reloaded) {
        return reply.status(400).send({ error: result.error?.message ?? "Failed to reload policy" });
      }
      engine.replaceRules([...builtinRules, ...result.rules]);
      return reply.send({ ok: true, action: "reload_policy", ruleCount: engine.getRules().length });
    }

    setTimeout(() => {
      try {
        const child = spawn("systemctl", ["--user", "restart", LOCAL_SERVICE_NAME], {
          detached: true,
          stdio: "ignore",
        });
        child.unref();
      } catch {
        // The follow-up health poll is the source of truth for restart success.
      }
    }, 250);

    return reply.send({ ok: true, action: "restart", scheduled: true, serviceName: LOCAL_SERVICE_NAME });
  });

  app.post("/api/dashboard/control/policy-scoped-rule", async (req, reply) => {
    if (rejectCrossOriginMutation(req, reply)) return;
    if (!policyRuntime) {
      return reply.status(400).send({ error: "Scoped guardrail editing requires policy.configPath." });
    }

    const parsed = PolicyScopedRuleSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid scoped guardrail body", details: parsed.error.flatten() });
    }

    const nextRule = buildScopedDeclarativeRule(parsed.data);
    const result = policyRuntime.upsertDeclarativeRule(nextRule);
    if (!result.reloaded) {
      return reply.status(400).send({ error: result.error?.message ?? "Failed to save scoped guardrail" });
    }

    engine.replaceRules([...builtinRules, ...result.rules]);
    const policyCatalog = buildPolicyCatalog(policyRuntime);
    const savedRule = policyCatalog.scopedRules.find((item) => item.id === nextRule.id) ?? buildScopedRuleCatalogItem(nextRule);
    return reply.send({ ok: true, rule: savedRule, policyCatalog });
  });

  app.post("/api/dashboard/control/channel-firewall-profile", async (req, reply) => {
    if (rejectCrossOriginMutation(req, reply)) return;
    if (!policyRuntime) {
      return reply.status(400).send({ error: "Channel firewall profiles require policy.configPath." });
    }

    const parsed = ChannelFirewallProfileSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid channel firewall profile body", details: parsed.error.flatten() });
    }

    let latestResult: ReturnType<FileBackedPolicyRuntime["upsertDeclarativeRule"]> | null = null;
    for (const rule of buildChannelFirewallRules(parsed.data)) {
      latestResult = policyRuntime.upsertDeclarativeRule(rule);
      if (!latestResult.reloaded) {
        return reply.status(400).send({ error: latestResult.error?.message ?? "Failed to save channel firewall profile" });
      }
    }

    const result = latestResult ?? policyRuntime.reload();
    if (!result.reloaded) {
      return reply.status(400).send({ error: result.error?.message ?? "Failed to reload channel firewall profile" });
    }

    engine.replaceRules([...builtinRules, ...result.rules]);
    const policyCatalog = buildPolicyCatalog(policyRuntime);
    const lane = policyCatalog.channelFirewall.lanes.find((item) => item.agentId === parsed.data.agentId && item.channelId === parsed.data.channelId) ?? {
      agentId: parsed.data.agentId,
      channelId: parsed.data.channelId,
      profile: parsed.data.profile,
      rules: [],
    };
    return reply.send({ ok: true, lane, policyCatalog });
  });

  app.get("/api/dashboard/drilldown/:kind/:id", async (req, reply) => {
    const parsed = DrilldownParamsSchema.safeParse(req.params);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid drilldown request", details: parsed.error.flatten() });
    }

    const result = runtime.getDrilldown(parsed.data.kind, parsed.data.id);
    if (!result) {
      return reply.status(404).send({ error: "Drilldown target not found" });
    }

    if (parsed.data.kind === "approval" && result.status === "pending") {
      const snapshot = runtime.getSnapshot(engine.getRules().length);
      const flood = floodGuard.getTelemetrySnapshot();
      const prioritizedPending = prioritizePendingApprovals(snapshot.approvals?.pending ?? [], flood);
      const pendingRows = buildApprovalRows(prioritizedPending);
      const queueIndex = pendingRows.findIndex((item) => item.requestId === parsed.data.id);
      const queuePosition = queueIndex >= 0 ? queueIndex + 1 : null;
      const previousPending = queueIndex > 0 ? pendingRows[queueIndex - 1] : null;
      const nextPending = queueIndex >= 0 && queueIndex < pendingRows.length - 1 ? pendingRows[queueIndex + 1] : null;

      result.facts = [
        ...result.facts.filter((item) => item.label !== "Queue"),
        ...(queuePosition ? [{ label: "Queue", value: `${queuePosition} of ${pendingRows.length} pending` }] : []),
      ];
      result.queueNavigation = {
        previousRequestId: previousPending?.requestId ?? null,
        previousTarget: previousPending ? `${previousPending.action} · ${previousPending.sessionId}` : null,
        previousDetail: previousPending?.triageDetail ?? null,
        previousRule: previousPending?.matchedRule ?? null,
        nextRequestId: nextPending?.requestId ?? null,
        nextTarget: nextPending ? `${nextPending.action} · ${nextPending.sessionId}` : null,
        nextDetail: nextPending?.triageDetail ?? null,
        nextRule: nextPending?.matchedRule ?? null,
      };
    }

    return reply.send(result);
  });

  app.post("/api/dashboard/control/approval-mode", async (req, reply) => {
    if (rejectCrossOriginMutation(req, reply)) return;
    const parsed = ApprovalModeSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid approval mode body", details: parsed.error.flatten() });
    }

    gate.setMode(parsed.data.mode);
    runtime.updateApprovalMode(parsed.data.mode);
    return reply.send({ ok: true, mode: gate.getMode() });
  });

  app.post("/api/dashboard/control/floodguard-mode", async (req, reply) => {
    if (rejectCrossOriginMutation(req, reply)) return;
    const parsed = ShieldModeSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid floodguard mode body", details: parsed.error.flatten() });
    }

    const next = floodGuard.setShieldMode(parsed.data.mode === "shield", Date.now(), parsed.data.durationMs);
    return reply.send({ ok: true, floodGuard: floodGuard.getTelemetrySnapshot(), mode: next.mode, shieldUntil: next.shieldUntil });
  });

  app.post("/api/dashboard/control/floodguard-session/:sessionId", async (req, reply) => {
    if (rejectCrossOriginMutation(req, reply)) return;
    const { sessionId } = req.params as { sessionId: string };
    const parsed = SessionOverrideSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid floodguard session body", details: parsed.error.flatten() });
    }

    if (parsed.data.action === "clear") {
      const cleared = floodGuard.clearSessionOverride(sessionId);
      return reply.send({ ok: true, cleared: cleared.cleared, floodGuard: floodGuard.getTelemetrySnapshot() });
    }

    const override = floodGuard.setSessionOverride(sessionId, parsed.data.multiplier ?? 1.5, Date.now(), parsed.data.durationMs);
    return reply.send({ ok: true, override, floodGuard: floodGuard.getTelemetrySnapshot() });
  });

  app.post("/api/dashboard/control/simulation", async (req, reply) => {
    if (rejectCrossOriginMutation(req, reply)) return;
    const parsed = SimulationControlSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid simulation control body", details: parsed.error.flatten() });
    }

    if (parsed.data.action === "start") {
      return reply.send(runtime.activateIncidentSimulation());
    }

    return reply.send(runtime.clearSimulation());
  });

  app.post("/api/dashboard/control/session/:sessionId", async (req, reply) => {
    if (rejectCrossOriginMutation(req, reply)) return;
    const { sessionId } = req.params as { sessionId: string };
    const parsed = SessionControlSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid session control body", details: parsed.error.flatten() });
    }

    if (parsed.data.action === "terminate" && parsed.data.confirm !== true) {
      return reply.status(400).send({ error: "Terminate requires explicit confirmation. Re-run with confirm: true." });
    }

    const result = runtime.controlSession(sessionId, parsed.data.action, parsed.data.note);
    if (!result.ok) {
      const failure = result as Extract<typeof result, { ok: false }>;
      const statusCode = failure.reason === "not_found" ? 404 : 409;
      return reply.status(statusCode).send({ error: failure.message, session: "session" in failure ? failure.session : undefined });
    }

    return reply.send({ ok: true, session: result.session });
  });

  app.post("/api/dashboard/proof/communication-channel", async (req, reply) => {
    if (rejectCrossOriginMutation(req, reply)) return;

    const parsed = ProofCommunicationChannelSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid proof request", details: parsed.error.flatten() });
    }

    const { agentId, platform, channelId, threadId } = parsed.data;
    const proofId = randomUUID();
    const generatedAt = new Date().toISOString();
    const normalizedChannelId = normalizeCommunicationChannelId({ platform, channelId, threadId });

    type ProofCheck = {
      id: string;
      label: string;
      expected: string;
      required: boolean;
      passed: boolean;
      decision: string;
      matchedRules: string[];
      reasons: string[];
      auditEventId: string;
    };

    const checks: ProofCheck[] = [];

    const fakeApiKey = ["api", "_key: ", "ABCDEFGHIJKLMNOPQRST"].join("");

    const proofCases: Array<{ id: string; label: string; expected: string; required: boolean; matchedRule?: string; args: Parameters<typeof buildCommunicationChannelContext>[0] }> = [
      {
        id: "safe_reply",
        label: "Safe reply is allowed",
        expected: "allow",
        required: false,
        args: { agentId, platform, channelId, threadId, userId: "proof-suite", plane: "content", action: "telegram_reply", text: "Agentwall proof safe reply" },
      },
      {
        id: "write_file_denied",
        label: "Filesystem mutation is denied",
        expected: "deny",
        required: true,
        matchedRule: "channel:deny-filesystem-mutation",
        args: { agentId, platform, channelId, threadId, userId: "proof-suite", plane: "tool", action: "write_file", payload: { path: "/tmp/proof.txt", content: "proof" } },
      },
      {
        id: "secret_access_denied",
        label: "Secret access is denied",
        expected: "deny",
        required: true,
        matchedRule: "channel:deny-sensitive-data-access",
        args: { agentId, platform, channelId, threadId, userId: "proof-suite", plane: "identity", action: "read_secret", payload: { key: "API_SECRET" } },
      },
      {
        id: "pii_reply_redacted",
        label: "PII reply is redacted",
        expected: "redact",
        required: true,
        matchedRule: "channel:redact-pii-content-egress",
        args: { agentId, platform, channelId, threadId, userId: "proof-suite", plane: "content", action: "telegram_reply", text: "Employee email is proof-user@example.com" },
      },
      {
        id: "secret_reply_denied",
        label: "Secret reply is denied",
        expected: "deny",
        required: true,
        matchedRule: "channel:deny-sensitive-content-egress",
        args: { agentId, platform, channelId, threadId, userId: "proof-suite", plane: "content", action: "telegram_reply", text: `Credential: ${fakeApiKey}` },
      },
    ];

    for (const proofCase of proofCases) {
      const ctx = buildCommunicationChannelContext(proofCase.args);
      const result = engine.evaluate(ctx);
      const auditEvent = emit(ctx, result);
      runtime.recordAuditEvent(auditEvent);
      const decisionMatches = result.decision === proofCase.expected;
      const ruleMatches = !proofCase.matchedRule || result.matchedRules.includes(proofCase.matchedRule);
      checks.push({
        id: proofCase.id,
        label: proofCase.label,
        expected: proofCase.expected,
        required: proofCase.required,
        passed: decisionMatches && ruleMatches,
        decision: result.decision,
        matchedRules: result.matchedRules,
        reasons: result.reasons,
        auditEventId: auditEvent.id,
      });
    }

    const requiredChecks = checks.filter((c) => c.required);
    const passedCount = checks.filter((c) => c.passed).length;
    const summary = {
      passedCount,
      total: checks.length,
      status: requiredChecks.every((c) => c.passed) ? "passed" : "attention",
    };

    const responsePayload = {
      ok: true,
      proofId,
      generatedAt,
      target: { agentId, platform, channelId: normalizedChannelId, threadId: threadId ?? null },
      summary,
      checks,
    };
    lastCommunicationChannelProofSuite = responsePayload;
    return reply.send(responsePayload);
  });
}
