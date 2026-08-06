import { existsSync } from "fs";
import { emit } from "../audit/logger";
import { AgentContext, PolicyResult } from "../types";

/**
 * Global emergency stop, with four independent activation channels.
 *
 * Why more than one channel: the moment you need an emergency stop is the moment your
 * primary control path is the thing that is broken. An API-only stop is unreachable when
 * the HTTP surface is wedged, the process is pinned at 100% CPU, or the operator token is
 * on a laptop that is not in the room. Each source below therefore stands alone, and ANY
 * one of them holding is enough to keep the stop engaged. That is the whole design: the
 * sources are deliberately redundant, not layered.
 *
 *   config    seeded at start-up, for a box that must come up stopped.
 *   api       POST /killswitch/activate, the normal operator path.
 *   signal    SIGUSR1, which reaches the process from a shell with no network involved.
 *   sentinel  a file on disk, polled; the channel that still works when both the HTTP
 *             surface and the signal path are unavailable to whoever is holding the shell
 *             (a container exec, a config-management run, a cron script, an NFS mount
 *             touched from another host).
 *
 * Release is PER SOURCE and never global. `deactivateKillSwitch("api")` clears the API's
 * hold and nothing else, so a config-seeded or file-held stop cannot be lifted by an HTTP
 * call. This is the property that makes the stop trustworthy: whoever engaged it is the
 * only one who can release it, through the same channel they used to engage it.
 *
 * This is NOT the per-agent watchdog kill switch in src/watchdog/heartbeat.ts. That one is
 * derived from a single agent's heartbeat going stale. This one is a global, operator-driven
 * posture for the whole process.
 *
 * Limits, honestly: this module holds a flag and records the transitions. It gates what
 * flows through AgentWall's own decision paths and nothing else. It does not kill agent
 * processes, does not revoke credentials, and has no effect on a process that never routed
 * through AgentWall in the first place. The sentinel channel is a poll, so it carries up to
 * one interval of latency.
 */

/**
 * How often the sentinel file is stat'd.
 *
 * A second is the compromise: fast enough that an operator typing `touch` does not wonder
 * whether it worked, cheap enough that an idle process is doing one stat per second forever.
 * Watching the file instead of polling it was rejected: fs.watch does not fire reliably for
 * creation on every platform or across network filesystems, and the one channel that has to
 * work when everything else is broken is the wrong place for a best-effort notification API.
 */
export const DEFAULT_SENTINEL_POLL_INTERVAL_MS = 1000;

export interface KillSwitchState {
  active: boolean;
  /** Every source currently holding the stop, sorted for a stable response body. */
  sources: string[];
  /** When the current active period began, absent when nothing holds the stop. */
  since?: string;
  /** Why the current period began: the reason from the oldest still-active hold. */
  reason?: string;
}

export interface KillSwitchInitOptions {
  /** Overrides $AGENTWALL_KILLSWITCH_FILE. Absent on both leaves the sentinel channel off. */
  sentinelPath?: string;
  /** Come up stopped. Not a release: `false` does not clear an existing config hold. */
  configActive?: boolean;
  /** Sentinel poll period. Exists so tests can drive the poll without sleeping a second. */
  pollIntervalMs?: number;
}

interface Hold {
  since: string;
  reason?: string;
}

/**
 * Insertion-ordered so `reason` can resolve to the hold that opened the period rather than
 * to whichever source happens to sort first. The public `sources` list is sorted separately.
 */
const holds = new Map<string, Hold>();

let periodSince: string | undefined;
let sentinelPath: string | undefined;
let sentinelTimer: NodeJS.Timeout | undefined;
let sentinelPollIntervalMs = DEFAULT_SENTINEL_POLL_INTERVAL_MS;
let signalHandler: (() => void) | undefined;

/**
 * A hold nobody can name is a hold nobody can release, which would wedge the stop on
 * permanently. Refusing the activation instead would be worse: an emergency stop must not
 * fail over a naming problem, so an empty name is recorded rather than rejected.
 */
function normalizeSource(source: string): string {
  const trimmed = source.trim();
  return trimmed === "" ? "unspecified" : trimmed;
}

export function killSwitchState(): KillSwitchState {
  const sources = [...holds.keys()].sort();
  const state: KillSwitchState = { active: sources.length > 0, sources };
  if (periodSince !== undefined) {
    state.since = periodSince;
  }
  for (const hold of holds.values()) {
    if (hold.reason !== undefined) {
      state.reason = hold.reason;
      break;
    }
  }
  return state;
}

/**
 * Engage the stop on behalf of one source.
 *
 * Re-engaging a source that already holds is a complete no-op: no second audit record, and
 * `since` keeps pointing at the real start of the period rather than at the last time
 * somebody re-sent the request. A stored reason is therefore immutable for the life of a
 * hold; to correct it, release and engage again.
 */
export function activateKillSwitch(source: string, reason?: string): void {
  const key = normalizeSource(source);
  if (holds.has(key)) {
    return;
  }

  // Engage first, record second. A recording failure must never be able to stop the stop.
  const now = new Date().toISOString();
  holds.set(key, { since: now, reason });
  periodSince ??= now;

  record("activate", key, reason);
}

/**
 * Release ONE source's hold.
 *
 * There is deliberately no way to clear every source at once. An operator who engaged the
 * stop from a shell must not have it lifted out from under them by an HTTP caller who only
 * ever held the `api` source, and a config-seeded stop must survive any amount of API
 * traffic. Callers that want the stop gone have to go back to each channel that holds it.
 */
export function deactivateKillSwitch(source: string): void {
  const key = normalizeSource(source);
  const hold = holds.get(key);
  if (hold === undefined) {
    return;
  }

  holds.delete(key);
  if (holds.size === 0) {
    periodSince = undefined;
  }

  record("deactivate", key, hold.reason);
}

/**
 * Wire up the channels that need process-level state: the signal handler and the sentinel
 * poll. Safe to call repeatedly — a second call re-uses the existing handler and replaces
 * the existing timer rather than adding to them. That matters in two real places: a
 * long-lived process that rebuilds its server, and a test suite that builds one per case.
 * Node starts warning at eleven listeners and leaks silently before that.
 *
 * Init is additive with respect to holds. It never releases anything, because the failure
 * mode of a silent release is an agent that resumes acting while an operator believes it is
 * stopped, and the failure mode of a stale hold is a service that is too safe.
 */
export function initKillSwitch(opts: KillSwitchInitOptions = {}): void {
  if (opts.configActive === true) {
    activateKillSwitch("config", "engaged by configuration at start-up");
  }

  if (signalHandler === undefined) {
    signalHandler = toggleFromSignal;
    process.on("SIGUSR1", signalHandler);
  }

  if (opts.pollIntervalMs !== undefined && Number.isFinite(opts.pollIntervalMs) && opts.pollIntervalMs > 0) {
    sentinelPollIntervalMs = Math.max(1, Math.floor(opts.pollIntervalMs));
  }

  // A later call that names no path keeps the path already configured. Dropping it would
  // silently retire the one channel that works when the API is wedged, and it would do so
  // at exactly the moment somebody is rebuilding the server to recover.
  const requested =
    trimmedOrUndefined(opts.sentinelPath) ??
    trimmedOrUndefined(process.env.AGENTWALL_KILLSWITCH_FILE) ??
    sentinelPath;
  if (requested === undefined) {
    return;
  }
  sentinelPath = requested;

  if (sentinelTimer !== undefined) {
    clearInterval(sentinelTimer);
    sentinelTimer = undefined;
  }
  // Check once before scheduling, so a process that starts with the sentinel already in
  // place comes up stopped instead of running unguarded for one interval.
  pollSentinel();
  sentinelTimer = setInterval(pollSentinel, sentinelPollIntervalMs);
  // Unref'd: an emergency stop that keeps a process alive after its work is done turns a
  // safety control into a hang.
  sentinelTimer.unref();
}

/**
 * Drop all state, the signal handler, and the timer.
 *
 * TESTS ONLY. This is the one operation that clears every source at once, which is precisely
 * what production must not have; nothing in src/ outside this file calls it.
 */
export function resetKillSwitch(): void {
  if (sentinelTimer !== undefined) {
    clearInterval(sentinelTimer);
    sentinelTimer = undefined;
  }
  if (signalHandler !== undefined) {
    process.removeListener("SIGUSR1", signalHandler);
    signalHandler = undefined;
  }
  holds.clear();
  periodSince = undefined;
  sentinelPath = undefined;
  sentinelPollIntervalMs = DEFAULT_SENTINEL_POLL_INTERVAL_MS;
}

function trimmedOrUndefined(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed === undefined || trimmed === "" ? undefined : trimmed;
}

/**
 * SIGUSR1 toggles rather than only engaging, because the operator sending it has no reply
 * channel to read state from and needs the same key to work both ways. SIGUSR1 specifically:
 * SIGUSR2 is taken by common Node tooling, and the terminating signals already mean
 * something. The trade is that two people signalling at once can cancel each other out,
 * which is why the file and API channels exist as level-triggered alternatives.
 */
function toggleFromSignal(): void {
  if (holds.has("signal")) {
    deactivateKillSwitch("signal");
  } else {
    activateKillSwitch("signal", "SIGUSR1 received");
  }
}

function pollSentinel(): void {
  if (sentinelPath === undefined) {
    return;
  }

  let present: boolean;
  try {
    present = existsSync(sentinelPath);
  } catch {
    // Unknown is not absent. A transient filesystem error must not release a stop that an
    // operator engaged; leave the state exactly as it is and re-check next interval.
    return;
  }

  if (present && !holds.has("sentinel")) {
    activateKillSwitch("sentinel", `sentinel file present at ${sentinelPath}`);
  } else if (!present && holds.has("sentinel")) {
    deactivateKillSwitch("sentinel");
  }
}

/**
 * Put the transition on the audit chain.
 *
 * The decision recorded is the resulting posture, not the verb: releasing one of two holds
 * records `deny`/`critical` because the stop is still engaged afterwards. Recording `allow`
 * there would put a line in the evidence saying traffic was permitted at a moment when it
 * was not.
 *
 * Every failure is swallowed. Audit is evidence about the stop, not a precondition for it,
 * and a full disk must not be able to keep an emergency stop from engaging.
 */
function record(kind: "activate" | "deactivate", source: string, reason: string | undefined): void {
  try {
    const state = killSwitchState();
    const verb = kind === "activate" ? "engaged" : "released";

    const reasons = [
      reason === undefined
        ? `Kill switch ${verb} by source '${source}'`
        : `Kill switch ${verb} by source '${source}': ${reason}`,
    ];
    if (kind === "deactivate" && state.active) {
      reasons.push(`Kill switch remains engaged, held by: ${state.sources.join(", ")}`);
    }

    const metadata: Record<string, string> = {
      killSwitchSource: source,
      killSwitchActive: String(state.active),
      killSwitchHolders: state.sources.length > 0 ? state.sources.join(",") : "none",
    };
    if (reason !== undefined) {
      metadata.killSwitchReason = reason;
    }
    if (state.since !== undefined) {
      metadata.killSwitchSince = state.since;
    }

    const ctx: AgentContext = {
      agentId: "agentwall",
      sessionId: "agentwall:killswitch",
      plane: "governance",
      action: kind === "activate" ? "killswitch:activate" : "killswitch:deactivate",
      payload: {
        source,
        reason: reason ?? null,
        active: state.active,
        holders: state.sources,
        since: state.since ?? null,
      },
      metadata,
      flow: {
        direction: "internal",
        target: "agentwall-control-plane",
        highRisk: state.active,
      },
    };

    const result: PolicyResult = {
      decision: state.active ? "deny" : "allow",
      riskLevel: state.active ? "critical" : "low",
      matchedRules: [],
      reasons,
      requiresApproval: false,
      highRiskFlow: state.active,
      detections: [],
    };

    emit(ctx, result);
  } catch {
    // Deliberately empty: see the doc comment above.
  }
}
