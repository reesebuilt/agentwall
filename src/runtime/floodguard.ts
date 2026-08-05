import { AgentContext, ApprovalRequest, RiskLevel } from "../types";
import { ApprovalMode } from "../approval/gate";

export interface RuntimeGuardConfig {
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
}

export interface RuntimeGuardCheckResult {
  allowed: boolean;
  reason?: string;
  retryAfterMs?: number;
}

export interface RuntimeGuardTelemetrySnapshot {
  mode: "normal" | "shield";
  shieldUntil: string | null;
  blockedTotal: number;
  blockedByCategory: Record<string, number>;
  pressureByCategory: Record<string, number>;
  pressureBySession: Array<{ sessionId: string; pressure: number; blocked: number }>;
  pressureByActor: Array<{ actor: string; pressure: number; blocked: number }>;
  recentBlocks: Array<{ timestamp: string; category: string; reason: string; sessionId?: string; actor?: string; pressure: number }>;
  sessionOverrides: Array<{ sessionId: string; expiresAt: string; multiplier: number }>;
}

export interface RuntimeGuardTelemetryEvent {
  timestamp: string;
  category: "request" | "tool" | "approval_request" | "approval_response" | "queue" | "cost" | "mode";
  key: string;
  sessionId?: string;
  actor?: string;
  riskLevel?: RiskLevel;
  allowed: boolean;
  blockedReason?: string;
  retryAfterMs?: number;
  pressure: number;
  blockedCount: number;
  mode: "normal" | "shield";
  detail?: Record<string, unknown>;
}

interface BucketRecord {
  ts: number[];
  blocked: number;
}

interface BudgetRecord {
  events: Array<{ ts: number; units: number }>;
  blocked: number;
}

interface SessionOverride {
  multiplier: number;
  expiresAt: number;
}

const SESSION_FALLBACK = "unknown:default";
const ACTOR_FALLBACK = "unknown-actor";
const MIN_LIMIT = 1;

export class RuntimeFloodGuard {
  private readonly config: RuntimeGuardConfig;
  private readonly buckets = new Map<string, BucketRecord>();
  private readonly budgets = new Map<string, BudgetRecord>();
  private readonly sessionOverrides = new Map<string, SessionOverride>();
  private onTelemetry?: (event: RuntimeGuardTelemetryEvent) => void;
  private shieldUntil = 0;
  private telemetry: RuntimeGuardTelemetrySnapshot = {
    mode: "normal",
    shieldUntil: null,
    blockedTotal: 0,
    blockedByCategory: {},
    pressureByCategory: {},
    pressureBySession: [],
    pressureByActor: [],
    recentBlocks: [],
    sessionOverrides: [],
  };

  constructor(config: RuntimeGuardConfig) {
    this.config = config;
  }

  setTelemetrySink(sink: ((event: RuntimeGuardTelemetryEvent) => void) | undefined): void {
    this.onTelemetry = sink;
  }

  setShieldMode(enabled: boolean, now = Date.now(), durationMs?: number): { mode: "normal" | "shield"; shieldUntil: string | null } {
    if (enabled) {
      const ttl = durationMs ?? this.config.shield?.defaultDurationMs ?? 10 * 60_000;
      this.shieldUntil = now + Math.max(30_000, ttl);
    } else {
      this.shieldUntil = 0;
    }

    this.emitTelemetry({
      timestamp: new Date(now).toISOString(),
      category: "mode",
      key: "floodguard:mode",
      allowed: true,
      pressure: 0,
      blockedCount: 0,
      mode: this.getMode(now),
      detail: {
        shieldUntil: this.shieldUntil > now ? new Date(this.shieldUntil).toISOString() : null,
      },
    });

    return {
      mode: this.getMode(now),
      shieldUntil: this.shieldUntil > now ? new Date(this.shieldUntil).toISOString() : null,
    };
  }

  getMode(now = Date.now()): "normal" | "shield" {
    return this.shieldUntil > now ? "shield" : "normal";
  }

  getStatus(now = Date.now()): { mode: "normal" | "shield"; shieldUntil: string | null } {
    return {
      mode: this.getMode(now),
      shieldUntil: this.shieldUntil > now ? new Date(this.shieldUntil).toISOString() : null,
    };
  }

  setSessionOverride(sessionId: string, multiplier: number, now = Date.now(), durationMs = 15 * 60_000) {
    const normalizedSession = sessionId.trim();
    if (!normalizedSession) {
      throw new Error("Session id required");
    }
    const nextMultiplier = Math.max(0.5, Math.min(3, multiplier));
    const expiresAt = now + Math.max(60_000, durationMs);
    this.sessionOverrides.set(normalizedSession, { multiplier: nextMultiplier, expiresAt });
    return {
      sessionId: normalizedSession,
      multiplier: Number(nextMultiplier.toFixed(2)),
      expiresAt: new Date(expiresAt).toISOString(),
    };
  }

  clearSessionOverride(sessionId: string): { cleared: boolean } {
    return { cleared: this.sessionOverrides.delete(sessionId.trim()) };
  }

  getTelemetrySnapshot(now = Date.now()): RuntimeGuardTelemetrySnapshot {
    this.telemetry.mode = this.getMode(now);
    this.telemetry.shieldUntil = this.shieldUntil > now ? new Date(this.shieldUntil).toISOString() : null;
    this.cleanupSessionOverrides(now);
    this.telemetry.sessionOverrides = Array.from(this.sessionOverrides.entries())
      .map(([sessionId, override]) => ({
        sessionId,
        expiresAt: new Date(override.expiresAt).toISOString(),
        multiplier: Number(override.multiplier.toFixed(2)),
      }))
      .sort((left, right) => left.expiresAt.localeCompare(right.expiresAt));
    return {
      ...this.telemetry,
      blockedByCategory: { ...this.telemetry.blockedByCategory },
      pressureByCategory: { ...this.telemetry.pressureByCategory },
      pressureBySession: this.telemetry.pressureBySession.slice(0, 8),
      pressureByActor: this.telemetry.pressureByActor.slice(0, 8),
      recentBlocks: this.telemetry.recentBlocks.slice(0, 8),
      sessionOverrides: this.telemetry.sessionOverrides.slice(0, 8),
    };
  }

  evaluateRequest(ctx: AgentContext, now = Date.now()): RuntimeGuardCheckResult {
    if (!this.config.enabled) return { allowed: true };

    const sessionId = this.getSessionId(ctx.sessionId, ctx.agentId);

    const requests = this.consumeWithinWindow(
      `eval:session:${sessionId}`,
      now,
      60_000,
      this.getSessionLimit(sessionId, this.config.requestPerMinutePerSession, this.config.shield?.requestRateMultiplier, now)
    );
    if (!requests.allowed) {
      const reason = `Request flood detected for session ${sessionId}`;
      this.emitTelemetry({
        timestamp: new Date(now).toISOString(),
        category: "request",
        key: `session:${sessionId}`,
        sessionId,
        allowed: false,
        blockedReason: reason,
        retryAfterMs: requests.retryAfterMs,
        pressure: requests.pressure,
        blockedCount: requests.blockedCount,
        mode: this.getMode(now),
      });
      return {
        allowed: false,
        reason,
        retryAfterMs: requests.retryAfterMs,
      };
    }

    this.emitTelemetry({
      timestamp: new Date(now).toISOString(),
      category: "request",
      key: `session:${sessionId}`,
      sessionId,
      allowed: true,
      pressure: requests.pressure,
      blockedCount: requests.blockedCount,
      mode: this.getMode(now),
    });

    if (ctx.plane === "tool") {
      const toolBucket = this.consumeWithinWindow(
        `eval:session:${sessionId}:tool:${ctx.action}`,
        now,
        60_000,
        this.getSessionLimit(sessionId, this.config.toolActionPerMinutePerSession, this.config.shield?.toolActionRateMultiplier, now)
      );
      if (!toolBucket.allowed) {
        const reason = `Tool action flood detected for ${ctx.action}`;
        this.emitTelemetry({
          timestamp: new Date(now).toISOString(),
          category: "tool",
          key: `${sessionId}:${ctx.action}`,
          sessionId,
          allowed: false,
          blockedReason: reason,
          retryAfterMs: toolBucket.retryAfterMs,
          pressure: toolBucket.pressure,
          blockedCount: toolBucket.blockedCount,
          mode: this.getMode(now),
          detail: { action: ctx.action },
        });
        return {
          allowed: false,
          reason,
          retryAfterMs: toolBucket.retryAfterMs,
        };
      }

      this.emitTelemetry({
        timestamp: new Date(now).toISOString(),
        category: "tool",
        key: `${sessionId}:${ctx.action}`,
        sessionId,
        allowed: true,
        pressure: toolBucket.pressure,
        blockedCount: toolBucket.blockedCount,
        mode: this.getMode(now),
        detail: { action: ctx.action },
      });
    }

    const units = this.estimateEvaluateUnits(ctx);
    const budget = this.consumeBudget(
      `budget:session:${sessionId}`,
      now,
      units,
      this.getSessionLimit(sessionId, this.config.costBudgetPerHourPerSession, this.config.shield?.costBudgetMultiplier, now)
    );
    if (!budget.allowed) {
      const reason = `Cost budget exceeded for session ${sessionId}`;
      this.emitTelemetry({
        timestamp: new Date(now).toISOString(),
        category: "cost",
        key: `session:${sessionId}`,
        sessionId,
        allowed: false,
        blockedReason: reason,
        retryAfterMs: budget.retryAfterMs,
        pressure: budget.pressure,
        blockedCount: budget.blockedCount,
        mode: this.getMode(now),
        detail: { units },
      });
      return {
        allowed: false,
        reason,
        retryAfterMs: budget.retryAfterMs,
      };
    }

    this.emitTelemetry({
      timestamp: new Date(now).toISOString(),
      category: "cost",
      key: `session:${sessionId}`,
      sessionId,
      allowed: true,
      pressure: budget.pressure,
      blockedCount: budget.blockedCount,
      mode: this.getMode(now),
      detail: { units },
    });

    return { allowed: true };
  }

  approvalRequest(
    request: ApprovalRequest,
    mode: ApprovalMode,
    pendingForSession: number,
    pendingGlobal: number,
    now = Date.now()
  ): RuntimeGuardCheckResult {
    if (!this.config.enabled) return { allowed: true };

    const sessionId = this.getSessionId(request.context.sessionId, request.context.agentId);
    const globalCap = this.adjustLimit(this.config.maxPendingApprovalsGlobal, this.config.shield?.maxPendingGlobalMultiplier, now);
    const sessionCap = this.getSessionLimit(sessionId, this.config.maxPendingApprovalsPerSession, this.config.shield?.maxPendingSessionMultiplier, now);

    const queuePressure = Math.max(
      pendingGlobal / Math.max(globalCap, 1),
      pendingForSession / Math.max(sessionCap, 1)
    );

    if (this.getMode(now) === "shield") {
      const threshold = this.config.shield?.queuePriorityPressureThreshold ?? 0.65;
      const isHighRisk = request.policyResult.riskLevel === "high" || request.policyResult.riskLevel === "critical";
      if (queuePressure >= threshold && !isHighRisk) {
        const reason = `Approval queue pressure prioritization engaged for session ${sessionId}`;
        this.emitTelemetry({
          timestamp: new Date(now).toISOString(),
          category: "queue",
          key: `session:${sessionId}`,
          sessionId,
          riskLevel: request.policyResult.riskLevel,
          allowed: false,
          blockedReason: reason,
          retryAfterMs: 5_000,
          pressure: queuePressure,
          blockedCount: 1,
          mode: this.getMode(now),
          detail: { pendingGlobal, pendingForSession, globalCap, sessionCap, prioritized: true },
        });
        return {
          allowed: false,
          reason,
          retryAfterMs: 5_000,
        };
      }
    }

    if (pendingGlobal >= globalCap) {
      const reason = `Approval queue flood detected (global pending ${pendingGlobal})`;
      this.emitTelemetry({
        timestamp: new Date(now).toISOString(),
        category: "queue",
        key: "global",
        sessionId,
        riskLevel: request.policyResult.riskLevel,
        allowed: false,
        blockedReason: reason,
        retryAfterMs: 5_000,
        pressure: queuePressure,
        blockedCount: 1,
        mode: this.getMode(now),
        detail: { pendingGlobal, globalCap },
      });
      return {
        allowed: false,
        reason,
        retryAfterMs: 5_000,
      };
    }

    if (pendingForSession >= sessionCap) {
      const reason = `Approval queue flood detected for session ${sessionId}`;
      this.emitTelemetry({
        timestamp: new Date(now).toISOString(),
        category: "queue",
        key: `session:${sessionId}`,
        sessionId,
        riskLevel: request.policyResult.riskLevel,
        allowed: false,
        blockedReason: reason,
        retryAfterMs: 5_000,
        pressure: queuePressure,
        blockedCount: 1,
        mode: this.getMode(now),
        detail: { pendingForSession, sessionCap },
      });
      return {
        allowed: false,
        reason,
        retryAfterMs: 5_000,
      };
    }

    const burst = this.consumeWithinWindow(
      `approval:req:session:${sessionId}`,
      now,
      60_000,
      this.getSessionLimit(sessionId, this.config.approvalRequestsPerMinutePerSession, this.config.shield?.approvalRequestRateMultiplier, now)
    );
    if (!burst.allowed) {
      const reason = `Approval request flood detected for session ${sessionId}`;
      this.emitTelemetry({
        timestamp: new Date(now).toISOString(),
        category: "approval_request",
        key: `session:${sessionId}`,
        sessionId,
        riskLevel: request.policyResult.riskLevel,
        allowed: false,
        blockedReason: reason,
        retryAfterMs: burst.retryAfterMs,
        pressure: burst.pressure,
        blockedCount: burst.blockedCount,
        mode: this.getMode(now),
      });
      return {
        allowed: false,
        reason,
        retryAfterMs: burst.retryAfterMs,
      };
    }

    this.emitTelemetry({
      timestamp: new Date(now).toISOString(),
      category: "approval_request",
      key: `session:${sessionId}`,
      sessionId,
      riskLevel: request.policyResult.riskLevel,
      allowed: true,
      pressure: burst.pressure,
      blockedCount: burst.blockedCount,
      mode: this.getMode(now),
      detail: { queuePressure },
    });

    const requiresManual = mode === "always" || (mode === "auto" && request.policyResult.requiresApproval);
    const units = this.estimateApprovalRequestUnits(request, requiresManual);
    const budget = this.consumeBudget(
      `budget:session:${sessionId}`,
      now,
      units,
      this.getSessionLimit(sessionId, this.config.costBudgetPerHourPerSession, this.config.shield?.costBudgetMultiplier, now)
    );
    if (!budget.allowed) {
      const reason = `Cost budget exceeded for session ${sessionId}`;
      this.emitTelemetry({
        timestamp: new Date(now).toISOString(),
        category: "cost",
        key: `session:${sessionId}`,
        sessionId,
        riskLevel: request.policyResult.riskLevel,
        allowed: false,
        blockedReason: reason,
        retryAfterMs: budget.retryAfterMs,
        pressure: budget.pressure,
        blockedCount: budget.blockedCount,
        mode: this.getMode(now),
        detail: { units },
      });
      return {
        allowed: false,
        reason,
        retryAfterMs: budget.retryAfterMs,
      };
    }

    this.emitTelemetry({
      timestamp: new Date(now).toISOString(),
      category: "cost",
      key: `session:${sessionId}`,
      sessionId,
      riskLevel: request.policyResult.riskLevel,
      allowed: true,
      pressure: budget.pressure,
      blockedCount: budget.blockedCount,
      mode: this.getMode(now),
      detail: { units },
    });

    return { allowed: true };
  }

  approvalResponse(actorId?: string, now = Date.now()): RuntimeGuardCheckResult {
    if (!this.config.enabled) return { allowed: true };

    const actor = actorId?.trim() || ACTOR_FALLBACK;
    const result = this.consumeWithinWindow(
      `approval:resp:actor:${actor}`,
      now,
      60_000,
      this.adjustLimit(this.config.approvalResponsesPerMinutePerActor, this.config.shield?.approvalResponseRateMultiplier, now)
    );

    if (!result.allowed) {
      const reason = `Approval response flood detected for actor ${actor}`;
      this.emitTelemetry({
        timestamp: new Date(now).toISOString(),
        category: "approval_response",
        key: `actor:${actor}`,
        actor,
        allowed: false,
        blockedReason: reason,
        retryAfterMs: result.retryAfterMs,
        pressure: result.pressure,
        blockedCount: result.blockedCount,
        mode: this.getMode(now),
      });
      return {
        allowed: false,
        reason,
        retryAfterMs: result.retryAfterMs,
      };
    }

    this.emitTelemetry({
      timestamp: new Date(now).toISOString(),
      category: "approval_response",
      key: `actor:${actor}`,
      actor,
      allowed: true,
      pressure: result.pressure,
      blockedCount: result.blockedCount,
      mode: this.getMode(now),
    });

    return { allowed: true };
  }

  private consumeWithinWindow(
    key: string,
    now: number,
    windowMs: number,
    limit: number
  ): { allowed: boolean; retryAfterMs?: number; pressure: number; blockedCount: number } {
    const bucket = this.buckets.get(key) ?? { ts: [], blocked: 0 };
    const cutoff = now - windowMs;
    bucket.ts = bucket.ts.filter((ts) => ts > cutoff);

    const pressure = bucket.ts.length / Math.max(limit, 1);
    if (bucket.ts.length >= limit) {
      bucket.blocked += 1;
      const retryAfterMs = Math.max(250, windowMs - (now - bucket.ts[0]));
      this.buckets.set(key, bucket);
      return { allowed: false, retryAfterMs, pressure: Math.max(1, pressure), blockedCount: bucket.blocked };
    }

    bucket.ts.push(now);
    this.buckets.set(key, bucket);
    return { allowed: true, pressure, blockedCount: bucket.blocked };
  }

  private consumeBudget(
    key: string,
    now: number,
    units: number,
    budgetLimit: number
  ): { allowed: boolean; retryAfterMs?: number; pressure: number; blockedCount: number } {
    const record = this.budgets.get(key) ?? { events: [], blocked: 0 };
    const cutoff = now - 3_600_000;
    record.events = record.events.filter((event) => event.ts > cutoff);

    const used = record.events.reduce((sum, event) => sum + event.units, 0);
    const pressure = used / Math.max(budgetLimit, 1);
    if (used + units > budgetLimit) {
      record.blocked += 1;
      const oldest = record.events[0];
      const retryAfterMs = oldest ? Math.max(1_000, 3_600_000 - (now - oldest.ts)) : 60_000;
      this.budgets.set(key, record);
      return { allowed: false, retryAfterMs, pressure: Math.max(1, pressure), blockedCount: record.blocked };
    }

    record.events.push({ ts: now, units });
    this.budgets.set(key, record);
    return { allowed: true, pressure, blockedCount: record.blocked };
  }

  private estimateEvaluateUnits(ctx: AgentContext): number {
    let units = this.config.costWeights.evaluateBase;
    if (ctx.plane === "tool") {
      units = Math.round(units * this.config.costWeights.toolActionMultiplier);
    }

    const labels = new Set(ctx.flow?.labels ?? []);
    if (ctx.flow?.highRisk || labels.has("external_egress") || labels.has("destructive_action")) {
      units = Math.round(units * this.config.costWeights.highRiskMultiplier);
    }

    return Math.max(1, units);
  }

  private estimateApprovalRequestUnits(request: ApprovalRequest, requiresManual: boolean): number {
    let units = this.config.costWeights.approvalRequest;
    if (requiresManual) {
      units += this.config.costWeights.approvalRequiresManual;
    }

    if (request.context.plane === "tool") {
      units = Math.round(units * this.config.costWeights.toolActionMultiplier);
    }

    if (request.policyResult.riskLevel === "high") {
      units = Math.round(units * this.config.costWeights.highRiskMultiplier);
    }

    if (request.policyResult.riskLevel === "critical") {
      units = Math.round(units * this.config.costWeights.criticalRiskMultiplier);
    }

    return Math.max(1, units);
  }

  private adjustLimit(base: number, shieldMultiplier: number | undefined, now: number): number {
    if (this.getMode(now) !== "shield") {
      return Math.max(MIN_LIMIT, Math.round(base));
    }
    const multiplier = shieldMultiplier ?? 0.5;
    return Math.max(MIN_LIMIT, Math.round(base * multiplier));
  }

  private getSessionLimit(sessionId: string, base: number, shieldMultiplier: number | undefined, now: number): number {
    const adjusted = this.adjustLimit(base, shieldMultiplier, now);
    const override = this.getSessionOverride(sessionId, now);
    if (!override) {
      return adjusted;
    }
    return Math.max(MIN_LIMIT, Math.round(adjusted * override.multiplier));
  }

  private getSessionOverride(sessionId: string, now: number): SessionOverride | null {
    this.cleanupSessionOverrides(now);
    return this.sessionOverrides.get(sessionId) ?? null;
  }

  private cleanupSessionOverrides(now: number): void {
    for (const [sessionId, override] of this.sessionOverrides.entries()) {
      if (override.expiresAt <= now) {
        this.sessionOverrides.delete(sessionId);
      }
    }
  }

  private getSessionId(sessionId: string | undefined, agentId: string): string {
    if (sessionId && sessionId.trim().length > 0) {
      return sessionId;
    }
    if (agentId && agentId.trim().length > 0) {
      return `${agentId}:default`;
    }
    return SESSION_FALLBACK;
  }

  private emitTelemetry(event: RuntimeGuardTelemetryEvent): void {
    this.telemetry.mode = event.mode;
    if (event.detail?.["shieldUntil"] && typeof event.detail["shieldUntil"] === "string") {
      this.telemetry.shieldUntil = event.detail["shieldUntil"] as string;
    }
    this.telemetry.pressureByCategory[event.category] = Math.max(
      this.telemetry.pressureByCategory[event.category] ?? 0,
      Number(event.pressure.toFixed(2))
    );

    if (!event.allowed) {
      this.telemetry.blockedTotal += 1;
      this.telemetry.blockedByCategory[event.category] = (this.telemetry.blockedByCategory[event.category] ?? 0) + 1;
      this.telemetry.recentBlocks.unshift({
        timestamp: event.timestamp,
        category: event.category,
        reason: event.blockedReason ?? "Runtime guard blocked request",
        sessionId: event.sessionId,
        actor: event.actor,
        pressure: Number(event.pressure.toFixed(2)),
      });
      this.telemetry.recentBlocks.splice(20);
    }

    if (event.sessionId) {
      const current = this.telemetry.pressureBySession.find((item) => item.sessionId === event.sessionId);
      if (current) {
        current.pressure = Math.max(current.pressure, Number(event.pressure.toFixed(2)));
        if (!event.allowed) current.blocked += 1;
      } else {
        this.telemetry.pressureBySession.push({
          sessionId: event.sessionId,
          pressure: Number(event.pressure.toFixed(2)),
          blocked: event.allowed ? 0 : 1,
        });
      }
      this.telemetry.pressureBySession = this.telemetry.pressureBySession
        .sort((left, right) => right.pressure - left.pressure || right.blocked - left.blocked)
        .slice(0, 16);
    }

    if (event.actor) {
      const current = this.telemetry.pressureByActor.find((item) => item.actor === event.actor);
      if (current) {
        current.pressure = Math.max(current.pressure, Number(event.pressure.toFixed(2)));
        if (!event.allowed) current.blocked += 1;
      } else {
        this.telemetry.pressureByActor.push({
          actor: event.actor,
          pressure: Number(event.pressure.toFixed(2)),
          blocked: event.allowed ? 0 : 1,
        });
      }
      this.telemetry.pressureByActor = this.telemetry.pressureByActor
        .sort((left, right) => right.pressure - left.pressure || right.blocked - left.blocked)
        .slice(0, 16);
    }

    this.onTelemetry?.(event);
  }
}
