import { normalizeHostname } from "../planes/network/ssrf";
import { lockdownState } from "./lockdown";
import type { PolicyEngine } from "../policy/engine";
import type { AgentContext, Decision, PolicyResult, RiskLevel } from "../types";
import type { LockdownState } from "./lockdown";

/**
 * Egress enforcement: the point at which AgentWall stops being only a recorder.
 *
 * Everything upstream of this file observes. The forward proxy sees every destination a
 * cooperating agent reaches for, the audit chain makes that record tamper-evident, and the
 * policy engine has always been able to say "deny" — but nothing turned that word into a
 * closed socket. This module is the translation layer, and the reason it is a layer at all
 * rather than a boolean is that turning enforcement on is the single most likely way to
 * break a working deployment. A firewall that an operator dares not enable protects nothing,
 * so the design problem here is adoption, not blocking.
 *
 * Hence three modes, ordered by how much they can break:
 *
 *   monitor  — evaluates fully, enforces nothing, and reports in `reasons` exactly what each
 *              stricter mode WOULD have done to this request.
 *   guarded  — enforces `deny` verdicts that a policy rule actually produced. Anything no
 *              rule matched is allowed.
 *   strict   — allowlist-only. A destination host that is not in the configured egress
 *              allowlist is denied, whether or not any rule matched it.
 *
 * The intended path is monitor for as long as it takes to read a week of ledger, then build
 * the allowlist from what the ledger shows, then guarded, then strict. Monitor's projections
 * exist to make that path a reading exercise rather than a guess: they are produced by
 * running the real decision function for each enforcing mode, not by a parallel
 * approximation of it, so a projection cannot drift away from what the mode would do.
 *
 * Limits, stated plainly because overselling this would be worse than shipping it later:
 * this only governs traffic that traverses the forward proxy. Capture is cooperative — a
 * process that ignores the proxy environment variables is neither observed nor blocked, and
 * AgentWall installs no iptables or nftables redirection to change that. Enforcement is also
 * connection-level: the proxy does not terminate TLS, so a decision is made from host, port,
 * and scheme, never from request bodies.
 */

export type EnforcementMode = "monitor" | "guarded" | "strict";

/** One connection a cooperating client asked the proxy to make on its behalf. */
export interface EgressAttempt {
  host: string;
  port: number;
  scheme: string;
  method?: string;
  /** Originating process name, or null when /proc attribution failed. */
  comm?: string | null;
  pid?: number | null;
}

export interface EgressVerdict {
  /**
   * What the proxy will actually do, not what policy wished for. Monitor mode reports
   * `allow` even when it is describing a denial in `reasons`, because the connection really
   * is about to be made and evidence that says otherwise is evidence that lies.
   */
  decision: Decision;
  riskLevel: RiskLevel;
  reasons: string[];
  matchedRules: string[];
  detectionIds: string[];
  mode: EnforcementMode;
}

const EGRESS_ALLOWLIST_RULE_ID = "net:deny-egress-not-allowlisted";
const EGRESS_BLOCKED_DETECTION_ID = "det.net.egress.blocked";
const EGRESS_PORT_RULE_ID = "net:deny-egress-port-not-allowlisted";
const EGRESS_PORT_DETECTION_ID = "det.net.egress.port_blocked";
const LOCKDOWN_RULE_ID = "governance:lockdown";
const LOCKDOWN_DETECTION_ID = "det.governance.lockdown.active";

const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Strict mode's allowlist, held as process state rather than passed per call.
 *
 * `decideEgress` runs once per connection on the proxy's critical path and is called from a
 * socket handler that has no view of configuration, so the allowlist is installed once at
 * start-up instead of being threaded through every frame. The trade is that the allowlist is
 * global to the process: one AgentWall instance enforces one allowlist, and a deployment
 * that needs per-agent allowlists needs per-agent instances.
 */
let allowlist: string[] = [];
/**
 * Permitted destination ports. An empty list permits nothing.
 *
 * Empty means deny for the same reason the host list does: strict mode is allowlist-only, and
 * an empty allowlist read as "allow everything" would turn the strictest mode into the most
 * permissive one at exactly the moment an operator misconfigures it. The shipped config
 * defaults this to `[443]`, so reaching the empty case takes writing `allowedPorts: []`, which
 * is a legible request for nothing.
 */
let portAllowlist: number[] = [];

/**
 * Install the strict-mode egress policy. Hostnames are normalised the same way the network
 * inspector normalises them, so an IPv6 entry copied bracketed from a log matches a bare one
 * from a config file and casing never decides an allow.
 *
 * Both fields are required rather than optional. `egress.allowedPorts` was configurable, was
 * defaulted to `[443]`, and was enforced by the `/evaluate` inspector but by nothing on the
 * proxy path — so a strict deployment that had written a port allowlist reached any port on
 * an allowlisted host, and the ledger recorded it as an ordinary allow. A key that reads as a
 * control and is not one is worse than an absent key, because the operator stops looking. An
 * optional parameter here would let a future call site recreate exactly that gap by omission,
 * so omission is a compile error instead.
 */
export function setEgressPolicy(policy: { hosts: readonly string[]; ports: readonly number[] }): void {
  allowlist = policy.hosts.map((entry) => normalizeHostname(entry)).filter((entry) => entry.length > 0);
  portAllowlist = policy.ports.filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);
}

/**
 * Exact host match after normalisation, deliberately with no wildcard or suffix support.
 *
 * This is the same matching the egress inspector already does, and a second, looser
 * convention beside it would be a bypass waiting to happen: `*.example.com` written by one
 * operator and read as a literal by the other half of the codebase silently allows nothing,
 * or silently allows everything, depending on which half wins.
 */
function isAllowlisted(host: string): boolean {
  const normalized = normalizeHostname(host);
  return normalized.length > 0 && allowlist.includes(normalized);
}

function buildContext(
  attempt: EgressAttempt,
  mode: EnforcementMode,
  lockdown: LockdownState,
  allowlisted: boolean
): AgentContext {
  const authority = `${attempt.host}:${attempt.port}`;
  return {
    agentId: attempt.comm ?? "unattributed",
    plane: "network",
    action: `egress:${attempt.scheme}`,
    // `url` is the key the network rules read a hostname out of; host and port are repeated
    // as their own fields so a rule or a reviewer never has to re-parse a URL to get them.
    payload: {
      url: `${attempt.scheme}://${authority}`,
      host: attempt.host,
      port: attempt.port,
    },
    metadata: {
      host: attempt.host,
      port: String(attempt.port),
      scheme: attempt.scheme,
      method: attempt.method ?? "CONNECT",
      comm: attempt.comm ?? "unknown",
      pid: attempt.pid == null ? "unknown" : String(attempt.pid),
      // Markers, following the pattern the MCP gates already use: the expensive or
      // configuration-dependent question is answered here, once, and the rule reads the
      // answer. It keeps the rule set free of imports from the runtime that calls it.
      enforcementMode: mode,
      egressAllowlisted: allowlisted ? "true" : "false",
      egressPortAllowlisted: portAllowlist.includes(attempt.port) ? "true" : "false",
      lockdownActive: lockdown.active ? "true" : "false",
    },
    flow: { direction: "egress" },
  };
}

/**
 * The engine returns `Default decision: deny` as a reason when nothing matched, which is an
 * accurate description of the engine and a misleading one on an egress verdict: it reads
 * like a finding when it means "no rule had an opinion". Reasons are only carried forward
 * when a rule actually produced them.
 */
function policyReasons(result: PolicyResult): string[] {
  return result.matchedRules.length > 0 ? [...result.reasons] : [];
}

/**
 * Risk is reported as `low` when no rule matched, in preference to the engine's answer.
 *
 * `isHighRiskFlow` treats every `direction: "egress"` context as high risk by construction,
 * which is the right default for a flow classifier and the wrong one for a ledger: it would
 * stamp `high` on every ordinary model API call and leave an operator with nothing to
 * triage. A verdict's risk describes the finding, and no rule matching is not a finding.
 */
function verdictRisk(result: PolicyResult): RiskLevel {
  return result.matchedRules.length > 0 ? result.riskLevel : "low";
}

function pushUnique(target: string[], value: string): void {
  if (!target.includes(value)) target.push(value);
}

function describeLockdown(lockdown: LockdownState): string {
  const sources = lockdown.sources.length > 0 ? lockdown.sources.join(", ") : "unknown";
  const because = lockdown.reason ? `: ${lockdown.reason}` : "";
  return `lockdown active (sources: ${sources})${because}`;
}

/**
 * One enforcing mode's real decision. Monitor is not handled here — it is defined in terms
 * of what this function returns, so it cannot be given its own copy of the logic.
 */
function enforce(
  attempt: EgressAttempt,
  mode: "guarded" | "strict",
  engine: PolicyEngine,
  lockdown: LockdownState
): EgressVerdict {
  const allowlisted = isAllowlisted(attempt.host);
  const result = engine.evaluate(buildContext(attempt, mode, lockdown, allowlisted));

  const reasons = policyReasons(result);
  const matchedRules = [...result.matchedRules];
  const detectionIds = result.detections.map((detection) => detection.id);

  if (mode === "strict" && (!allowlisted || !portAllowlist.includes(attempt.port))) {
    // Checked here as well as in the rule set, and this check is the authority.
    //
    // The rule exists so that the denial carries a rule id, a description, and an ATT&CK
    // mapping into the ledger like every other denial does. But the engine is constructed
    // from configuration, and an operator who replaces the rule set loses that rule — which
    // would silently turn strict mode back into guarded mode. Strict must fail closed
    // against its own configuration, so the allowlist gate does not depend on a rule being
    // present to work.
    //
    // The port is part of the gate, not a separate inspector's business. `allowedPorts` was
    // enforced only by the `/evaluate` inspector, so strict mode reached any port on an
    // allowlisted host and recorded it as an ordinary allow: an agent asking for
    // `Host: allowlisted.example.com:22` got a tunnel to SSH under a config that said 443.
    // Host and port are one destination and are judged together.
    if (!allowlisted) {
      pushUnique(matchedRules, EGRESS_ALLOWLIST_RULE_ID);
      pushUnique(detectionIds, EGRESS_BLOCKED_DETECTION_ID);
      // Always name the host, even though the rule already contributes a reason.
      //
      // The rule's reason is generic ("Destination host is not in the configured egress
      // allowlist") because a rule cannot see the attempt. Suppressing this line whenever
      // that generic one is present was a real defect: monitor mode's whole purpose is that
      // an operator builds the allowlist by reading the ledger, and a ledger where every
      // strict-mode projection is the same host-less sentence cannot be read that way. The
      // duplication is worth it — one line carries the rule's meaning, this one carries the
      // fact you need to act on.
      pushUnique(reasons, `${attempt.host} is not in the egress allowlist`);
    }
    if (!portAllowlist.includes(attempt.port)) {
      // Reported separately from the host, and both fire when both are wrong. An operator
      // fixing one and rediscovering the other on the next attempt learns the allowlist one
      // painful round-trip at a time.
      pushUnique(matchedRules, EGRESS_PORT_RULE_ID);
      pushUnique(detectionIds, EGRESS_PORT_DETECTION_ID);
      pushUnique(
        reasons,
        `port ${attempt.port} is not in the egress port allowlist` +
          (portAllowlist.length > 0 ? ` (allowed: ${portAllowlist.join(", ")})` : " (the allowlist is empty)")
      );
    }
    const risk = verdictRisk(result);
    return {
      decision: "deny",
      riskLevel: RISK_ORDER[risk] > RISK_ORDER.high ? risk : "high",
      reasons,
      matchedRules,
      detectionIds,
      mode,
    };
  }

  if (result.matchedRules.length > 0 && result.decision === "deny") {
    return { decision: "deny", riskLevel: result.riskLevel, reasons, matchedRules, detectionIds, mode };
  }

  if (result.decision === "approve" || result.decision === "redact") {
    // Only `deny` is enforceable on a socket. There is no interactive approval channel on a
    // TCP connect — nothing is waiting to answer, and holding the connection open until a
    // human replies would hang the agent — and redaction needs bodies the proxy cannot read
    // without terminating TLS. Both are recorded and allowed rather than quietly upgraded to
    // a denial, because an operator who reads "guarded blocks denies" and gets an outage
    // from an `approve` rule has been lied to. Put such destinations off the allowlist and
    // run strict if they must not be reached.
    reasons.push(
      `policy decision "${result.decision}" is not enforceable on a proxied connection; egress allowed and recorded`
    );
  }

  return {
    decision: "allow",
    riskLevel: verdictRisk(result),
    reasons:
      reasons.length > 0 ? reasons : [`no rule matched ${attempt.host}:${attempt.port}`],
    matchedRules,
    detectionIds,
    mode,
  };
}

/**
 * Decide what happens to one egress attempt.
 *
 * The lockdown is checked first and overrides the mode, INCLUDING MONITOR. This is the
 * one place monitor mode does not merely observe, and it is deliberate: an emergency stop
 * that the majority of deployments ignore because they have not finished their adoption
 * path is not an emergency stop, it is a status field. An operator who engages the lockdown has
 * decided that the blast radius of stopping everything is smaller than the blast radius of
 * continuing, and monitor mode is not entitled to second-guess that. The cost is real and
 * worth naming: enabling AgentWall in monitor mode does hand a component the ability to
 * halt all proxied egress, which is why the lockdown has an explicit, audited activation
 * rather than being inferred from health.
 */
export function decideEgress(
  attempt: EgressAttempt,
  mode: EnforcementMode,
  engine: PolicyEngine
): EgressVerdict {
  const lockdown = lockdownState();

  if (lockdown.active) {
    // Evaluated anyway, so the ledger keeps whatever else was wrong with this destination
    // rather than recording only the stop. The verdict is not derived from the result.
    const result = engine.evaluate(buildContext(attempt, mode, lockdown, isAllowlisted(attempt.host)));
    const matchedRules = [...result.matchedRules];
    const detectionIds = result.detections.map((detection) => detection.id);
    pushUnique(matchedRules, LOCKDOWN_RULE_ID);
    pushUnique(detectionIds, LOCKDOWN_DETECTION_ID);
    return {
      decision: "deny",
      riskLevel: "critical",
      reasons: [describeLockdown(lockdown), ...policyReasons(result)],
      matchedRules,
      detectionIds,
      mode,
    };
  }

  if (mode === "monitor") {
    // Projections are produced by running the real decision function for each enforcing
    // mode, in the order an operator adopts them. Anything cheaper — a second copy of the
    // rules, a heuristic on the host — could disagree with what the mode actually does, and
    // a projection an operator cannot trust is worse than none: it invites the switch to
    // strict that takes production down.
    const guarded = enforce(attempt, "guarded", engine, lockdown);
    const strict = enforce(attempt, "strict", engine, lockdown);
    return {
      decision: "allow",
      // Guarded's risk, not the higher of the two. Every rule-driven finding already shows
      // up in guarded, because the allowlist rule is the only mode-gated one; all strict
      // adds is "this host is absent from a list you have not written yet". Letting that
      // set the risk would stamp `high` on every request in exactly the deployment whose
      // purpose is to discover what the list should contain.
      riskLevel: guarded.riskLevel,
      reasons: [
        "monitor: egress recorded, not gated",
        guarded.decision === "deny"
          ? `monitor: guarded mode would deny — ${guarded.reasons.join("; ")}`
          : "monitor: guarded mode would allow",
        strict.decision === "deny"
          ? `monitor: strict mode would deny — ${strict.reasons.join("; ")}`
          : "monitor: strict mode would allow",
      ],
      // The structured fields describe what policy actually found. The hypothetical stays
      // in the reasons, because a detection named "blocked egress" attached to a request
      // that was allowed is a false statement, and the ledger is the one place that must
      // never overstate what happened.
      matchedRules: guarded.matchedRules,
      detectionIds: guarded.detectionIds,
      mode: "monitor",
    };
  }

  return enforce(attempt, mode, engine, lockdown);
}
