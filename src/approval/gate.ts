import { randomUUID } from "crypto";
import { ApprovalRequest, ApprovalResponse } from "../types";
import {
  ApprovalPersistenceBackend,
  ApprovalQueueStore,
  PersistedApprovalDecision,
  PersistedPendingApproval,
} from "./store";
import { ApprovalNotifier, ApprovalNotifierOptions } from "./notifier";

export type ApprovalMode = "auto" | "always" | "never";

export interface PendingApproval {
  requestId: string;
  request: ApprovalRequest;
  createdAt: number;
  expiresAt: number;
  resolve?: (response: ApprovalResponse) => void;
  reject?: (err: Error) => void;
  timer: NodeJS.Timeout;
}

export interface ApprovalDecisionRecord {
  requestId: string;
  createdAt: string;
  resolvedAt: string;
  decision: ApprovalResponse["decision"];
  approvedBy?: string;
  note?: string;
  agentId: string;
  plane: string;
  action: string;
  sessionId?: string;
}

export class ApprovalGate {
  private mode: ApprovalMode;
  private defaultTimeoutMs: number;
  private readonly store: ApprovalQueueStore;
  private readonly notifier: ApprovalNotifier;
  private pending = new Map<string, PendingApproval>();
  private history: PersistedApprovalDecision[] = [];

  constructor(
    mode: ApprovalMode = "auto",
    defaultTimeoutMs = 30_000,
    backend: ApprovalPersistenceBackend = "file",
    persistencePath = "./agentwall-approvals.json",
    notifierOptions: ApprovalNotifierOptions = {}
  ) {
    this.mode = mode;
    this.defaultTimeoutMs = defaultTimeoutMs;
    this.store = new ApprovalQueueStore(backend, persistencePath);
    this.notifier = new ApprovalNotifier(notifierOptions);
    this.restorePersistedState();
  }

  request(req: ApprovalRequest): { requestId: string; response: Promise<ApprovalResponse>; mode: "manual" | "auto" } {
    const timeoutMs = req.timeoutMs ?? this.defaultTimeoutMs;
    const requestId = randomUUID();

    if (this.mode === "never") {
      const response = this.makeResponse(requestId, "approved", "agentwall-auto", "Auto-approved (mode=never)");
      this.recordDecision(requestId, req, response);
      this.notifier.notifyResolved(requestId, req, response, "auto");
      return { requestId, response: Promise.resolve(response), mode: "auto" };
    }

    if (this.mode === "auto" && !req.policyResult.requiresApproval) {
      const response = this.makeResponse(requestId, "approved", "agentwall-auto", "Auto-approved by policy");
      this.recordDecision(requestId, req, response);
      this.notifier.notifyResolved(requestId, req, response, "auto");
      return { requestId, response: Promise.resolve(response), mode: "auto" };
    }

    // mode=always, or requiresApproval=true with mode=auto
    this.notifier.notifyPending(requestId, req, "manual");
    return { requestId, response: this.enqueue(requestId, req, timeoutMs), mode: "manual" };
  }

  private enqueue(requestId: string, req: ApprovalRequest, timeoutMs: number): Promise<ApprovalResponse> {
    return new Promise<ApprovalResponse>((resolve, reject) => {
      const createdAt = Date.now();
      const entry = this.createPendingEntry({
        requestId,
        request: req,
        createdAt,
        expiresAt: createdAt + timeoutMs,
        resolve,
        reject,
      });
      this.pending.set(requestId, entry);
      this.persistState();
    });
  }

  respond(requestId: string, decision: "approved" | "denied", approvedBy?: string, note?: string): ApprovalResponse | null {
    const entry = this.pending.get(requestId);
    if (!entry) return null;
    clearTimeout(entry.timer);
    this.pending.delete(requestId);
    const response = this.makeResponse(requestId, decision, approvedBy, note);
    this.recordDecision(requestId, entry.request, response, entry.createdAt);
    this.notifier.notifyResolved(requestId, entry.request, response, "manual");
    entry.resolve?.(response);
    return response;
  }

  listPending(): Array<{ requestId: string; agentId: string; sessionId?: string; action: string; plane: string; createdAt: number }> {
    return Array.from(this.pending.values()).map((p) => ({
      requestId: p.requestId,
      agentId: p.request.context.agentId,
      sessionId: p.request.context.sessionId,
      action: p.request.context.action,
      plane: p.request.context.plane,
      createdAt: p.createdAt,
    }));
  }

  getPendingRequest(requestId: string): ApprovalRequest | undefined {
    return this.pending.get(requestId)?.request;
  }

  getHistory(limit = 20): ApprovalDecisionRecord[] {
    return this.history.slice(0, limit).map((entry) => ({
      requestId: entry.requestId,
      createdAt: new Date(entry.createdAt).toISOString(),
      resolvedAt: entry.response.timestamp,
      decision: entry.response.decision,
      approvedBy: entry.response.approvedBy,
      note: entry.response.note,
      agentId: entry.request.context.agentId,
      plane: entry.request.context.plane,
      action: entry.request.context.action,
      sessionId: entry.request.context.sessionId,
    }));
  }

  getMode(): ApprovalMode {
    return this.mode;
  }

  setMode(mode: ApprovalMode): void {
    this.mode = mode;
  }

  getPersistedPending(): PersistedPendingApproval[] {
    return Array.from(this.pending.values())
      .map((entry) => ({
        requestId: entry.requestId,
        request: entry.request,
        createdAt: entry.createdAt,
        expiresAt: entry.expiresAt,
      }))
      .sort((left, right) => right.createdAt - left.createdAt);
  }

  close(): void {
    for (const entry of this.pending.values()) {
      clearTimeout(entry.timer);
    }
    this.pending.clear();
  }

  private makeResponse(
    requestId: string,
    decision: ApprovalResponse["decision"],
    approvedBy?: string,
    note?: string
  ): ApprovalResponse {
    return {
      requestId,
      decision,
      approvedBy,
      note,
      timestamp: new Date().toISOString(),
    };
  }

  private recordDecision(
    requestId: string,
    request: ApprovalRequest,
    response: ApprovalResponse,
    createdAtMs = Date.now()
  ): void {
    this.history.unshift({
      requestId,
      request,
      response,
      createdAt: createdAtMs,
    });
    this.history = this.history.slice(0, 100);
    this.persistState();
  }

  private restorePersistedState(): void {
    const state = this.store.load();
    this.history = state.history.slice(0, 100);
    const now = Date.now();

    for (const pendingApproval of state.pending) {
      if (pendingApproval.expiresAt <= now) {
        const response = this.makeResponse(
          pendingApproval.requestId,
          "timeout",
          undefined,
          `Timed out after ${pendingApproval.expiresAt - pendingApproval.createdAt}ms`
        );
        this.recordDecision(pendingApproval.requestId, pendingApproval.request, response, pendingApproval.createdAt);
        continue;
      }

      const entry = this.createPendingEntry(pendingApproval);
      this.pending.set(entry.requestId, entry);
    }

    this.persistState();
  }

  private createPendingEntry(
    pendingApproval: PersistedPendingApproval & {
      resolve?: (response: ApprovalResponse) => void;
      reject?: (err: Error) => void;
    }
  ): PendingApproval {
    const delayMs = Math.max(0, pendingApproval.expiresAt - Date.now());
    const timer = setTimeout(() => {
      const entry = this.pending.get(pendingApproval.requestId);
      if (!entry) return;
      this.pending.delete(pendingApproval.requestId);
      const response = this.makeResponse(
        pendingApproval.requestId,
        "timeout",
        undefined,
        `Timed out after ${pendingApproval.expiresAt - pendingApproval.createdAt}ms`
      );
      this.recordDecision(pendingApproval.requestId, pendingApproval.request, response, pendingApproval.createdAt);
      this.notifier.notifyResolved(pendingApproval.requestId, pendingApproval.request, response, "manual");
      entry.resolve?.(response);
    }, delayMs);
    timer.unref();

    return {
      requestId: pendingApproval.requestId,
      request: pendingApproval.request,
      createdAt: pendingApproval.createdAt,
      expiresAt: pendingApproval.expiresAt,
      resolve: pendingApproval.resolve,
      reject: pendingApproval.reject,
      timer,
    };
  }

  private persistState(): void {
    this.store.save({
      pending: this.getPersistedPending(),
      history: this.history,
    });
  }
}
