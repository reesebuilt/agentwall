import { normalizeHostname } from "../planes/network/ssrf";
import { lockdownState } from "./lockdown";
import { scanText } from "../planes/identity/dlp";
import { scanInjection } from "../policy/injection";
import { DECOY_DETECTION_ID, DECOY_RULE_ID, scanForDecoys } from "../decoy";
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
 * AgentWall installs no iptables or nftables redirection to change that.
 *
 * How much of a request informs the decision depends entirely on the scheme, and the split is
 * sharp rather than gradual. A CONNECT tunnel is judged from host, port, and scheme alone:
 * the proxy does not terminate TLS, so the path, the headers, and both bodies are ciphertext
 * and no amount of policy can reach them. Plaintext HTTP is judged from all of it, meaning
 * path, headers, request body, response headers and response body, because there is nothing to
 * decrypt and no reason left not to. Nothing here narrows the https statement: it is exactly
 * as opaque as it was.
 */

export type EnforcementMode = "monitor" | "guarded" | "strict";

/**
 * One message the proxy read whole enough to inspect.
 *
 * `text` is what was buffered, which is the entire body only when `truncated` is false. A
 * caller that treats a truncated prefix as the body reports a clean scan of bytes nobody
 * looked at, so the flag travels with the text rather than beside it.
 */
export interface EgressBody {
  direction: "request" | "response";
  text: string;
  /** The body ran past the proxy's buffer cap and only a prefix is here. */
  truncated: boolean;
  /** Wire bytes buffered. Not the body's real length when `truncated`. */
  bytes: number;
  /** Upstream status, on a response. */
  status?: number;
  /** Content-Encoding the body arrived under, when it was anything but identity. */
  encoding?: string;
  /**
   * Why the bytes were not inspected, when they were not. Present means `text` is empty
   * because nobody could read the body, not because the body was empty, and the two must
   * never collapse into the same clean-looking record.
   */
  unscannable?: "stream" | "encoding";
}

/**
 * One connection a cooperating client asked the proxy to make on its behalf.
 *
 * `path`, `headers`, and `body` are optional because the CONNECT path genuinely has none of
 * them: a tunnel carries a host and a port and nothing else this side of the TLS handshake.
 * Making them required would force that path to fabricate values, and a synthesised empty
 * path scanning clean is indistinguishable in the ledger from a real one that did. Absent
 * means "the transport never exposed this", which is the claim the evidence supports.
 *
 * On the plaintext HTTP path all three are real, and are filled in twice per exchange: once
 * with the request headers and body before anything is opened upstream, and once with the
 * response headers and body before anything is written back to the client.
 */
export interface EgressAttempt {
  host: string;
  port: number;
  scheme: string;
  method?: string;
  /** Originating process name, or null when /proc attribution failed. */
  comm?: string | null;
  pid?: number | null;
  /** Request target including the query string. The resource, on both inspection passes. */
  path?: string;
  /** Headers of the message being inspected, names already lowercased. */
  headers?: Readonly<Record<string, string>>;
  /** One buffered body. Its `direction` is what decides which pass this is. */
  body?: EgressBody;
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
  /**
   * Evidence the caller already computed, for its audit record: what class of thing was
   * found and where, never what it was. Carried rather than recomputed because a second
   * evaluation on the record path works from a copy of the event and could disagree with
   * the decision that was actually enforced.
   */
  metadata?: Record<string, string>;
  mode: EnforcementMode;
}

const EGRESS_ALLOWLIST_RULE_ID = "net:deny-egress-not-allowlisted";
const EGRESS_BLOCKED_DETECTION_ID = "det.net.egress.blocked";
const EGRESS_PORT_RULE_ID = "net:deny-egress-port-not-allowlisted";
const EGRESS_PORT_DETECTION_ID = "det.net.egress.port_blocked";
const LOCKDOWN_RULE_ID = "governance:lockdown";
const LOCKDOWN_DETECTION_ID = "det.governance.lockdown.active";

const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/* ---------------------------------------------------------------------------------------
 * Content inspection
 *
 * The scanners have existed and been tested since the beginning and were wired to nothing on
 * this path: no call site under src/proxy/ reached scanInjection, and scanForDecoys had no
 * call site anywhere on a request path. The engines were real, the coverage was zero, and the
 * documentation described the gap as an encryption limit, which implied plaintext HTTP was
 * being read. It was not. This section is where that stops being true for the one scheme that
 * needs no decision about terminating TLS.
 *
 * What is inspected: the request path, the request headers, the request body, the response
 * headers, and the response body, on plaintext HTTP through the forward proxy only. What is
 * not: anything inside a CONNECT tunnel, which is still a host and a port and nothing else.
 * ------------------------------------------------------------------------------------- */

/**
 * Headers excluded from credential scanning, and from that alone.
 *
 * A request's own `Authorization` header is a credential by definition, and so is a session
 * cookie. Reporting them would fire the DLP on every authenticated call an agent makes, and
 * in guarded mode it would not merely be noise, it would block all of them. That is the
 * failure mode where an operator turns the control off and gets nothing, so the credential a
 * request uses to authenticate itself to the destination it is already allowed to reach is
 * not treated as an exfiltration finding.
 *
 * These headers are still scanned for decoys and for injected instructions. A decoy in an
 * Authorization header is not a false positive under any reading: the value is synthetic and
 * has no legitimate use, so its appearance is evidence rather than a heuristic.
 */
const CREDENTIAL_BEARING_HEADERS: Record<string, true> = {
  authorization: true,
  "proxy-authorization": true,
  cookie: true,
  "set-cookie": true,
};

/** What one inspection pass found. Classes and positions; never a matched value. */
export interface ContentFindings {
  direction: "request" | "response";
  /** Which of path, headers, body actually carried text to scan. */
  scanned: string[];
  secretTypes: string[];
  piiTypes: string[];
  injectionPatterns: string[];
  injectionCategories: string[];
  decoyIds: string[];
  decoyKinds: string[];
  /**
   * One entry per located finding, as `surface:class@where`. `where` is a byte-ish offset
   * into the scanned surface for a path or a body, and a header name for a header, because
   * an offset into a synthesised header block points at nothing an operator can go and read.
   */
  sites: string[];
  /** The body ran past the proxy's cap, so everything here describes a prefix. */
  truncated: boolean;
  bytes: number;
  /** Set when the body's bytes were never read: an event stream, or an encoding nobody decoded. */
  unscannable?: "stream" | "encoding";
  /** Content-Encoding the body arrived under, when it was anything but identity. */
  encoding?: string;
}

function emptyFindings(direction: "request" | "response"): ContentFindings {
  return {
    direction,
    scanned: [],
    secretTypes: [],
    piiTypes: [],
    injectionPatterns: [],
    injectionCategories: [],
    decoyIds: [],
    decoyKinds: [],
    sites: [],
    truncated: false,
    bytes: 0,
  };
}

/**
 * Scan one surface and fold what it found into the running result.
 *
 * `where` turns a match position into the label the ledger carries, so a body says "at 1042"
 * and a header says "in x-api-token" without this function needing to know which it is.
 * `scanSecrets` is false only for the headers that carry a request's own credentials.
 */
function scanSurface(
  into: ContentFindings,
  surface: string,
  text: string,
  where: (start: number) => string,
  scanSecrets: boolean,
  agentId: string
): void {
  if (text.length === 0) return;
  pushUnique(into.scanned, surface);

  if (scanSecrets) {
    // `locate` rather than `redact`: the proxy is building an audit record, not rewriting a
    // body. Rewriting one in flight would mean recomputing Content-Length and re-encoding
    // whatever transfer or content encoding it arrived under, and getting that wrong
    // corrupts a response for a finding that may be a false positive.
    const dlp = scanText(text, false, true);
    for (const type of dlp.secretTypes) pushUnique(into.secretTypes, type);
    for (const type of dlp.piiTypes) pushUnique(into.piiTypes, type);
    for (const location of dlp.locations ?? []) {
      pushUnique(into.sites, `${surface}:${location.type}@${where(location.start)}`);
    }
  }

  for (const finding of scanInjection(text).findings) {
    pushUnique(into.injectionPatterns, finding.patternId);
    pushUnique(into.injectionCategories, finding.category);
    // A finding from a decoded pass has no position in the raw bytes, so it is labelled with
    // the pass that surfaced it instead of an offset that would point at nothing.
    pushUnique(
      into.sites,
      `${surface}:${finding.patternId}@${finding.start === undefined ? finding.pass : where(finding.start)}`
    );
  }

  // scanForDecoys records its own audit event per hit, on the identity plane, with the decoy
  // id and never its value. That record is the evidence; the ids collected here are what puts
  // the same finding on the egress record so one connection reads as one story.
  for (const token of scanForDecoys(text, { agentId, surface: `proxy:http:${surface}` })) {
    pushUnique(into.decoyIds, token.id);
    pushUnique(into.decoyKinds, token.kind);
  }
}

/**
 * Inspect whatever content this attempt carries, or return null when it carries none.
 *
 * Called exactly once per decision, at the top of `decideEgress`, and never from `enforce`.
 * That matters for more than cost: monitor mode runs `enforce` twice to build its
 * projections, and `scanForDecoys` emits an audit event per hit, so scanning inside `enforce`
 * would file a decoy trigger twice for one sighting and double the apparent size of an
 * incident.
 */
function inspectContent(attempt: EgressAttempt): ContentFindings | null {
  const body = attempt.body;
  const direction = body?.direction ?? "request";
  const hasHeaders = attempt.headers !== undefined && Object.keys(attempt.headers).length > 0;
  const path = direction === "request" ? attempt.path ?? "" : "";
  if (path.length === 0 && !hasHeaders && body === undefined) return null;

  const findings = emptyFindings(direction);
  const agentId = attempt.comm ?? "unattributed";
  const offset = (start: number): string => String(start);

  // The path is scanned on the request pass only. It identifies the resource on both passes
  // and is reported on both, but scanning it twice would report one query-string secret as
  // two findings and leave an operator triaging an incident that did not happen.
  scanSurface(findings, "path", path, offset, true, agentId);

  if (attempt.headers) {
    for (const [name, value] of Object.entries(attempt.headers)) {
      if (value.length === 0) continue;
      scanSurface(findings, "headers", value, () => name, CREDENTIAL_BEARING_HEADERS[name] !== true, agentId);
    }
  }

  if (body) {
    findings.truncated = body.truncated;
    findings.bytes = body.bytes;
    findings.unscannable = body.unscannable;
    findings.encoding = body.encoding;
    // An unscannable body is skipped rather than scanned as an empty string. Scanning "" and
    // finding nothing would put a clean body result on a record for bytes nobody read, which
    // is the one thing this control is not allowed to do.
    if (body.unscannable === undefined) scanSurface(findings, "body", body.text, offset, true, agentId);
  }

  return findings;
}

/**
 * The findings as audit metadata: the class of each thing found and where it was, never what
 * it was. A DLP record that carries the secret it detected has handed anyone with log access
 * exactly what the detection was protecting, and an audit log is read in more places than the
 * environment it describes.
 *
 * Keys are only present when they have something to say, except the ones that describe the
 * scan itself. `contentTruncated` is always written, because "scanned and found nothing" and
 * "scanned the first 256 KiB and found nothing" are different claims and the reader must not
 * have to infer which one this is.
 */
function contentMetadata(findings: ContentFindings): Record<string, string> {
  const metadata: Record<string, string> = {
    contentInspected: findings.scanned.length > 0 ? "true" : "false",
    contentDirection: findings.direction,
    contentSurfaces: findings.scanned.join(","),
    contentBytes: String(findings.bytes),
    contentTruncated: findings.truncated ? "true" : "false",
  };
  if (findings.unscannable !== undefined) metadata.contentBodyUnscannable = findings.unscannable;
  if (findings.encoding !== undefined) metadata.contentBodyEncoding = findings.encoding;
  if (findings.secretTypes.length > 0) metadata.contentSecretTypes = findings.secretTypes.join(",");
  if (findings.piiTypes.length > 0) metadata.contentPiiTypes = findings.piiTypes.join(",");
  if (findings.injectionPatterns.length > 0) {
    metadata.contentInjectionPatterns = findings.injectionPatterns.join(",");
    metadata.contentInjectionCategories = findings.injectionCategories.join(",");
  }
  if (findings.decoyIds.length > 0) {
    metadata.contentDecoyIds = findings.decoyIds.join(",");
    metadata.contentDecoyKinds = findings.decoyKinds.join(",");
  }
  if (findings.sites.length > 0) metadata.contentSites = findings.sites.join(" ");
  return metadata;
}

/**
 * The sentences a partial scan has to carry with it.
 *
 * Returned as reasons on every verdict over a body that was not read whole, including the
 * clean ones, because "no finding" over a prefix is not "no finding" and the difference is
 * the whole honesty of the control. A clean row that quietly meant "we could not look" is
 * worse than no row: it is the one that gets believed.
 */
function coverageNotes(findings: ContentFindings): string[] {
  const notes: string[] = [];
  if (findings.unscannable === "stream") {
    notes.push(
      `${findings.direction} body was not inspected: an event stream cannot be buffered whole ` +
        "without hanging it, so it is passed through and its headers alone were scanned"
    );
  } else if (findings.unscannable === "encoding") {
    notes.push(
      `${findings.direction} body was not inspected: content-encoding ` +
        `"${findings.encoding ?? "unknown"}" did not decode within the inspection bound`
    );
  } else if (findings.truncated) {
    notes.push(
      `content scan covered the first ${findings.bytes} bytes of the ${findings.direction} body; ` +
        "the remainder was forwarded uninspected"
    );
  }
  return notes;
}

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
  allowlisted: boolean,
  content: Record<string, string> | null
): AgentContext {
  const authority = `${attempt.host}:${attempt.port}`;
  // The path, when the transport exposed one.
  //
  // `url` used to be synthesised as scheme://host:port with nothing after the authority, so a
  // rule written against a URL path matched nothing and said nothing about why. That is the
  // most obvious rule an operator reaches for and its absence was silent, which is the worst
  // shape a gap can take. CONNECT still contributes no path, and an absent path appends
  // nothing rather than a bare slash, so "no path was visible" stays distinguishable from
  // "the path was /".
  const path = attempt.path ?? "";
  return {
    agentId: attempt.comm ?? "unattributed",
    plane: "network",
    action: `egress:${attempt.scheme}`,
    // `url` is the key the network rules read a hostname out of; host and port are repeated
    // as their own fields so a rule or a reviewer never has to re-parse a URL to get them,
    // and `path` for the same reason.
    payload: {
      url: `${attempt.scheme}://${authority}${path}`,
      host: attempt.host,
      port: attempt.port,
      path,
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
      // The content scan's answer, computed once per decision and read by the content rules.
      // Same contract as the markers above and the same safe direction: a forged marker
      // produces a finding, never permission.
      ...(content ?? {}),
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
  lockdown: LockdownState,
  content: ContentFindings | null,
  contentMarkers: Record<string, string> | null
): EgressVerdict {
  const allowlisted = isAllowlisted(attempt.host);
  const result = engine.evaluate(buildContext(attempt, mode, lockdown, allowlisted, contentMarkers));

  const reasons = policyReasons(result);
  const matchedRules = [...result.matchedRules];
  const detectionIds = result.detections.map((detection) => detection.id);

  // A decoy hit is enforced here rather than left to a rule, for the same reason the strict
  // allowlist is: it is the one detection in the system that is evidence rather than
  // inference. The value is synthetic, is planted deliberately, and has no legitimate use,
  // so there is no false-positive rate to trade against and no operator who replaces the
  // rule set should be able to turn it off by accident. The DLP and injection findings below
  // are the opposite case and stay rule-driven: they are heuristics with a real error rate,
  // and an operator who removes their rule has made a legitimate choice.
  const decoyHit = content !== null && content.decoyIds.length > 0;
  if (content !== null && decoyHit) {
    pushUnique(matchedRules, DECOY_RULE_ID);
    pushUnique(detectionIds, DECOY_DETECTION_ID);
    pushUnique(
      reasons,
      `decoy ${content.decoyIds.join(", ")} appeared in the inspected ${content.direction} ` +
        `(${content.scanned.join(", ")}); that value is never legitimately used`
    );
  }

  // Said on every verdict over a body that was not read whole, clean ones included. "Nothing
  // found" over a prefix, an event stream, or bytes that would not decode is a different
  // claim from "nothing found", and the ledger has to carry which one it is.
  if (content !== null) for (const note of coverageNotes(content)) pushUnique(reasons, note);

  const strictBlock = mode === "strict" && (!allowlisted || !portAllowlist.includes(attempt.port));
  if (strictBlock) {
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
  }

  if (strictBlock || decoyHit) {
    const risk = verdictRisk(result);
    const floor: RiskLevel = decoyHit ? "critical" : "high";
    return {
      decision: "deny",
      riskLevel: RISK_ORDER[risk] > RISK_ORDER[floor] ? risk : floor,
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
    // human replies would hang the agent, and redaction is not performed on a proxied body
    // even now that plaintext bodies are read: rewriting one in flight means recomputing
    // Content-Length and re-encoding whatever content or transfer encoding it arrived under,
    // and getting that wrong corrupts a live response over a finding that may be a false
    // positive. An https body cannot be read at all. Both are recorded and allowed rather
    // than quietly upgraded to a denial, because an operator who reads "guarded blocks
    // denies" and gets an outage from an `approve` rule has been lied to. Put such
    // destinations off the allowlist and run strict if they must not be reached.
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
 *
 * Content, when the attempt carries any, is scanned once here and the findings are threaded
 * down rather than recomputed. Monitor mode evaluates twice to build its projections, and a
 * scan repeated inside those would triple the CPU cost of every proxied request and file a
 * decoy trigger three times for one sighting.
 */
export function decideEgress(
  attempt: EgressAttempt,
  mode: EnforcementMode,
  engine: PolicyEngine
): EgressVerdict {
  const lockdown = lockdownState();
  const content = inspectContent(attempt);
  const markers = content === null ? null : contentMetadata(content);
  const verdict = decide(attempt, mode, engine, lockdown, content, markers);
  // Attached to every verdict, denial or allow, so the audit record says what was looked at
  // even when nothing was found. A record that carries findings only when there are findings
  // cannot distinguish a clean scan from an absent one.
  if (markers !== null) verdict.metadata = markers;
  return verdict;
}

/** The mode dispatch. Split out so `decideEgress` owns the one-scan-per-decision guarantee. */
function decide(
  attempt: EgressAttempt,
  mode: EnforcementMode,
  engine: PolicyEngine,
  lockdown: LockdownState,
  content: ContentFindings | null,
  markers: Record<string, string> | null
): EgressVerdict {
  if (lockdown.active) {
    // Evaluated anyway, so the ledger keeps whatever else was wrong with this destination
    // rather than recording only the stop. The verdict is not derived from the result.
    const result = engine.evaluate(
      buildContext(attempt, mode, lockdown, isAllowlisted(attempt.host), markers)
    );
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
    const guarded = enforce(attempt, "guarded", engine, lockdown, content, markers);
    const strict = enforce(attempt, "strict", engine, lockdown, content, markers);
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

  return enforce(attempt, mode, engine, lockdown, content, markers);
}
