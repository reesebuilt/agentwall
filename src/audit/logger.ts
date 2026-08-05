import { randomUUID } from "crypto";
import { AUDIT_CHAIN_GAP_ACTION, chainAuditEvent, AuditChainState } from "./chain";
import { AuditEvent, AgentContext, PolicyResult } from "../types";

export type AuditSink = (event: AuditEvent) => void;

/**
 * Whether a sink's stream IS the evidence, or only watches it go past.
 *
 * The distinction decides what a write failure means. A file sink's bytes are what `verify`
 * walks, so a record it could not take is a record that does not exist and the chain must not
 * link across it. A stdout sink is a console view; a line missing there costs visibility, not
 * evidence, and must not be able to stall the chain.
 */
export interface AuditSinkOptions {
  durable?: boolean;
}

interface RegisteredSink {
  fn: AuditSink;
  durable: boolean;
}

const sinks: RegisteredSink[] = [];

// Keep a failed console write from killing the service.
//
// When stdout or stderr is a regular file, node backs it with a SyncWriteStream whose
// writeSync throws inside _write. Writable turns that into an 'error' event rather than
// letting it out of write(), so the try/catch around each sink call below never sees it, and
// an unhandled 'error' event terminates the process on the next tick. The partition that
// stopped the audit file accepting records is the same partition an operator redirected
// stdout to, so the console copy of a record would take down the thing that gates egress.
// Both writes are best-effort views; the chain and the drop counters are the record.
process.stdout.on("error", () => {});
process.stderr.on("error", () => {});

function initialChainState(): AuditChainState {
  return {
    chainIndex: 0,
    previousHash: null,
  };
}

let auditChainState = initialChainState();

/**
 * Records the durable sinks refused, waiting to be declared inside the chain.
 *
 * Held in memory only. Persisting it would need a write to the storage that is already
 * refusing writes, so a process that dies during an outage loses the declaration and the
 * loss survives only in the stderr copies. The contiguity guarantee does not depend on it:
 * a restart resumes from the last record actually on disk.
 */
interface PendingGap {
  count: number;
  firstFailureAt: string;
  lastFailureAt: string;
  /** What the durable sink said when the outage began, which is the diagnosis worth keeping. */
  reason: string;
}

let pendingGap: PendingGap | null = null;
let droppedTotal = 0;

export interface AuditDropStats {
  /** Records no durable sink would take, since the last reset. */
  dropped: number;
  /** Of those, the ones no marker in the chain declares yet. */
  undeclared: number;
  /** When the current run of failures began, or null when nothing is outstanding. */
  since: string | null;
  /** Why the current run of failures began, or null when nothing is outstanding. */
  reason: string | null;
}

/**
 * Register a sink.
 *
 * Pass `durable` for a sink whose stream is verified as a chain. The logger assumes at most
 * one of those, matching the single-writer lock the file sink takes: two durable sinks that
 * disagree about a record cannot both stay contiguous, and this treats any durable failure as
 * the record not having been recorded at all.
 */
export function registerAuditSink(sink: AuditSink, options: AuditSinkOptions = {}): void {
  if (!sinks.some((registered) => registered.fn === sink)) {
    sinks.push({ fn: sink, durable: options.durable === true });
  }
}

/**
 * Resume the chain from a prior run. Called once at boot, before any sink fires, so a
 * restart continues the record instead of starting a second disjoint chain at index 0.
 */
export function seedAuditChain(state: AuditChainState): void {
  auditChainState = { ...state };
}

/**
 * Return the logger to its boot state.
 *
 * Sinks go too. A test that builds the server twice would otherwise leave two file sinks
 * registered against one path, and every subsequent record would be appended twice under a
 * single chain index, which reads back as the two-writer interleave the lock exists to stop.
 */
export function resetAuditChain(): void {
  auditChainState = initialChainState();
  pendingGap = null;
  droppedTotal = 0;
  sinks.length = 0;
}

export function auditDropStats(): AuditDropStats {
  return {
    dropped: droppedTotal,
    undeclared: pendingGap?.count ?? 0,
    since: pendingGap?.firstFailureAt ?? null,
    reason: pendingGap?.reason ?? null,
  };
}

export function emit(ctx: AgentContext, result: PolicyResult): AuditEvent {
  // Any earlier loss is declared before this event joins the chain, so the marker sits where
  // the missing records were rather than after the ones that replaced them.
  declarePendingGap();

  const payload: Omit<AuditEvent, "integrity"> = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: ctx.agentId,
    sessionId: ctx.sessionId,
    plane: ctx.plane,
    action: ctx.action,
    decision: result.decision,
    riskLevel: result.riskLevel,
    matchedRules: result.matchedRules,
    reasons: result.reasons,
    requiresApproval: result.requiresApproval,
    highRiskFlow: result.highRiskFlow,
    detections: result.detections,
    metadata: ctx.metadata,
    actor: ctx.actor,
    provenance: ctx.provenance,
    flow: ctx.flow,
  };
  const event = chainAuditEvent(payload, auditChainState);

  // The chain advances only after the record is on the evidence stream. Advancing first, as
  // this did, leaves the next record pointing at a predecessor that a failed append never
  // wrote: the file then carries the index jump and broken link of a DELETED record, which is
  // the signature of the exact attack this product exists to detect. A full disk must not be
  // reportable as tampering.
  const failure = deliverDurable(event);
  if (failure === null) {
    commit(event);
  } else {
    dropRecord(payload, failure);
  }

  return event;
}

/**
 * Offer a record to every durable sink, returning why it was refused, or null on success.
 *
 * Errors are caught per sink rather than allowed out: emit() is called on the request path
 * and a storage fault must not become a failed policy decision. The list stays unallocated
 * until something actually fails, because this runs once per proxied request and the
 * succeeding path should cost nothing it does not use.
 */
function deliverDurable(event: AuditEvent): string | null {
  let failures: string[] | null = null;
  for (const sink of sinks) {
    if (!sink.durable) continue;
    try {
      sink.fn(event);
    } catch (err) {
      (failures ??= []).push(err instanceof Error ? err.message : String(err));
    }
  }
  return failures === null ? null : failures.join("; ");
}

/**
 * Accept a record into the chain and show it to the observers.
 *
 * Observers run only after the evidence stream took the record, so what a console shows is
 * what the chain contains. A line printed for a record that was never stored would invite an
 * operator to believe an unwritten decision is on file.
 */
function commit(event: AuditEvent): void {
  auditChainState = {
    chainIndex: event.integrity.chainIndex + 1,
    previousHash: event.integrity.hash,
  };
  for (const sink of sinks) {
    if (sink.durable) continue;
    try {
      sink.fn(event);
    } catch {
      // An observer must not break the request it is watching.
    }
  }
}

/**
 * Account for a record no durable sink would take.
 *
 * The chain is deliberately left where it was, so the next record reuses this index and links
 * to the same predecessor: the file stays contiguous and verification reports neither a gap
 * nor a broken link for something that was never written.
 *
 * The payload still goes to stderr, without an integrity block, because losing the content
 * silently is the other half of the failure. Stripping the integrity block is the point: the
 * index it was chained at now belongs to a different record, so publishing it would hand a
 * reader a hash that verifies against nothing.
 */
function dropRecord(payload: Omit<AuditEvent, "integrity">, reason: string): void {
  const at = new Date().toISOString();
  droppedTotal++;
  pendingGap =
    pendingGap === null
      ? { count: 1, firstFailureAt: at, lastFailureAt: at, reason }
      : { ...pendingGap, count: pendingGap.count + 1, lastFailureAt: at };

  // A different key from the stdout sink's `agentwall_audit` so no collector can file an
  // unchained record alongside chained ones.
  //
  // Guarded, because the thing that filled the partition fills stderr too. When fd 2 is a
  // regular file Node backs it with a synchronous writer that throws ENOSPC straight back out
  // of write(), and emit() is called inline by the route handlers and the proxy. Letting that
  // escape would turn a full disk into a 500 on every request, which is a worse outage than
  // the silent one this whole change exists to end. The counters and the gap declaration are
  // the record if this line cannot be printed.
  try {
    process.stderr.write(
      JSON.stringify({ agentwall_audit_dropped: { at, reason, record: payload } }) + "\n",
    );
  } catch {
    // Nowhere left to say it. auditDropStats() still counts it.
  }
}

/**
 * Write the marker that says records were produced and could not be stored.
 *
 * Best effort by construction: while the storage is still refusing, nothing can be written,
 * so the count keeps accumulating and the marker lands on the first append that succeeds.
 */
function declarePendingGap(): void {
  if (pendingGap === null) return;

  const marker = chainAuditEvent(gapPayload(pendingGap), auditChainState);
  if (deliverDurable(marker) !== null) {
    // Still refusing. Not counted as another drop: this record stands in for losses that are
    // already counted, and counting it would inflate the number it reports.
    return;
  }
  commit(marker);
  pendingGap = null;
}

function gapPayload(gap: PendingGap): Omit<AuditEvent, "integrity"> {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: "agentwall",
    plane: "governance",
    action: AUDIT_CHAIN_GAP_ACTION,
    // Nothing was permitted here. Every other decision value reads as an outcome a policy
    // produced, and a marker counted as an allow would credit an outage with approvals.
    decision: "deny",
    riskLevel: "critical",
    matchedRules: [],
    reasons: [`${gap.count} audit record(s) could not be written and are absent from this chain`],
    requiresApproval: false,
    highRiskFlow: false,
    detections: [],
    metadata: {
      droppedRecords: String(gap.count),
      firstFailureAt: gap.firstFailureAt,
      lastFailureAt: gap.lastFailureAt,
      reason: gap.reason,
    },
  };
}

export function stdoutSink(event: AuditEvent): void {
  process.stdout.write(JSON.stringify({ agentwall_audit: event }) + "\n");
}
