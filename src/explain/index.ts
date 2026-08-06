import { NormalizationPass } from "../mcp/types";
import { scanText } from "../planes/identity/dlp";
import { DEFAULT_EGRESS_POLICY, inspectNetworkRequest } from "../planes/network/ssrf";
import { PolicyEngine } from "../policy/engine";
import { INJECTION_PATTERN_COUNT, scanInjection } from "../policy/injection";
import { builtinRules } from "../policy/rules";
import { AgentContext, Decision, EgressPolicy, PolicyResult } from "../types";

/**
 * `explain` - which check fired, and the narrowest knob that silences that one
 * finding.
 *
 * The failure mode this exists to prevent: a scanner fires on something benign,
 * the operator cannot tell which of four layers produced it, and the cheapest
 * available fix is to switch the layer off. A tool that only says "blocked"
 * teaches people to disable it. So every finding here carries the identifier of
 * the exact thing that matched, the surface it matched on, and the most specific
 * change that would stop it.
 *
 * `narrowestKnob` is the whole point, and it is honest rather than helpful. Where
 * a scoped config key exists it is named along with the value to add. Where one
 * does not - a hardcoded host set, a per-type DLP switch this codebase does not
 * have, a builtin rule the engine always loads - the knob says so and stops
 * there. Suggesting a blunt setting because a narrow one is missing is how a tool
 * talks an operator into turning off a whole layer to silence one line; an
 * explicit "there is no narrow knob here, and here is why" leaves them better
 * informed than a suggestion that quietly costs them the rest of the coverage.
 *
 * `cleanReason` carries equal weight. A clean result that says nothing is
 * indistinguishable from a scanner that never ran, so when nothing matches this
 * reports what was actually checked, which passes ran, and what could not be
 * evaluated at all from a subject typed on a command line.
 *
 * Limits, stated here because they bound every result this module returns:
 * explain re-runs the scanners in this process against the argument it was
 * given. It shows what WOULD happen to that input under the rules loaded into the
 * engine it was handed, not what did happen to a real request. It never reads
 * your config file, so it does not know your egress allowlist and cannot explain
 * a rule that lives in a policy file it was not pointed at. And a typed subject
 * carries no provenance, so provenance-dependent rules are neither matched nor
 * ruled out.
 */

export type ExplainKind = "url" | "text" | "tool";

export interface ExplainFinding {
  /** Which scanner produced this: "ssrf", "dlp", "injection", or "policy". */
  scanner: string;
  /** Where in the request pipeline that scanner sits. */
  layer: string;
  /** The rule id, pattern id, or check id that matched. The unit you argue with. */
  ruleOrPattern: string;
  /** What was inspected: "host", "path", "query", "arguments.command", ... */
  surface: string;
  severity: string;
  /** Plain sentence: what matched, and why that counts. */
  why: string;
  /** The most specific change that would suppress THIS finding, or why none exists. */
  narrowestKnob: string;
}

export interface ExplainResult {
  subject: string;
  kind: ExplainKind;
  findings: ExplainFinding[];
  decision: string;
  /** Populated only when nothing matched, listing what was actually checked. */
  cleanReason?: string;
}

const DECISION_PRECEDENCE: Record<Decision, number> = {
  allow: 0,
  redact: 1,
  approve: 2,
  deny: 3,
};

/**
 * Written as an exhaustive record rather than a plain array so that adding a pass
 * to `NormalizationPass` fails the build here instead of quietly leaving
 * `cleanReason` claiming fewer passes ran than actually did. A clean result is
 * evidence, and evidence that undercounts its own coverage is worse than none.
 */
const NORMALIZATION_PASS_INDEX: Record<NormalizationPass, true> = {
  raw: true,
  zero_width: true,
  homoglyph: true,
  leetspeak: true,
  whitespace: true,
  base64: true,
  hex: true,
};

const NORMALIZATION_PASSES = Object.keys(NORMALIZATION_PASS_INDEX) as NormalizationPass[];

/**
 * Membership test for "did this rule ship with AgentWall". Built at load time
 * from the rule list, and consulted per matched rule id, which is what makes a
 * Set the right shape here rather than a literal table.
 */
const BUILTIN_RULE_IDS = new Set(builtinRules.map((rule) => rule.id));

const LAYER = {
  ssrf: "network plane · egress inspector, before a connection is opened",
  dlp: "identity plane · DLP pattern scan",
  injection: "content plane · prompt-injection scan",
  policy: "policy engine · rule evaluation, after every scanner",
} as const;

const PROVENANCE_CAVEAT =
  "provenance-dependent rules could not be evaluated: a subject typed on a command line carries no provenance or " +
  "trust label, so rules keyed on untrusted or derived content were neither matched nor ruled out";

/**
 * The egress policy explain evaluates against.
 *
 * `defaultDeny` is off, and that is the one deliberate difference from what a
 * server would use. Under the shipped default every host that is not in your
 * allowlist is blocked - and explain does not read your config, so it does not
 * know your allowlist. Leaving default-deny on would make explain answer "not
 * allowlisted" for every URL anyone ever asks about, which is both useless and
 * misleading. With it off, the host, scheme, port, and credential checks still
 * run exactly as shipped, and the allowlist question is reported as a check that
 * was not evaluated rather than answered wrongly.
 *
 * Callers that do know the deployed policy can pass it in, and the allowlist
 * branch is then reported like any other check.
 */
const EXPLAIN_EGRESS_BASELINE: EgressPolicy = { ...DEFAULT_EGRESS_POLICY, defaultDeny: false };

interface Scored {
  finding: ExplainFinding;
  /** What this finding alone would drive the decision to. */
  implied: Decision;
}

interface Accumulator {
  scored: Scored[];
  /** One line per check that ran, joined into `cleanReason` when nothing fires. */
  checks: string[];
}

function finish(acc: Accumulator, subject: string, kind: ExplainKind, seed: Decision): ExplainResult {
  const decision = acc.scored.reduce(
    (best, entry) => (DECISION_PRECEDENCE[entry.implied] > DECISION_PRECEDENCE[best] ? entry.implied : best),
    seed,
  );
  const result: ExplainResult = {
    subject,
    kind,
    findings: acc.scored.map((entry) => entry.finding),
    decision,
  };
  if (acc.scored.length === 0) {
    // Check descriptions never contain "; ", so a reader or a formatter can split
    // this back into the list it was built from.
    result.cleanReason = acc.checks.join("; ");
  }
  return result;
}

/** Renders a config list for a knob sentence; "empty" beats printing "[]" at someone. */
function quoteList(values: Array<string | number>): string {
  return values.length === 0 ? "empty" : values.map((value) => String(value)).join(", ");
}

// --- egress inspector -------------------------------------------------------

/**
 * Maps the inspector's blocked category to the surface it looked at and the
 * narrowest change that clears it.
 *
 * Two branches deliberately hand back "there is no narrow knob", and both are
 * load-bearing facts rather than gaps in this table. The cloud-metadata host set
 * is not configurable and is consulted before the allowlist, so allowlisting the
 * metadata address does nothing at all - an operator who is not told that will
 * add the entry, watch the block persist, and reach for `allowPrivateRanges`
 * instead, which opens every private range at once. The private-range block sits
 * before the allowlist for the same reason, so its only switch is the broad one.
 *
 * The `default` branch is not dead code: `blockedCategory` is a plain string on
 * the inspection result, so a category added to the inspector later arrives here
 * and is reported as unmapped rather than silently mislabelled.
 */
function egressKnob(
  category: string,
  hostname: string,
  scheme: string,
  port: number,
  policy: EgressPolicy,
): { surface: string; knob: string } {
  switch (category) {
    case "cloud-metadata":
      return {
        surface: "host",
        knob:
          `none, and none can be added: ${hostname} is in the inspector's fixed cloud-metadata host set, and that ` +
          `check runs before egress.allowedHosts - so allowlisting ${hostname} never reaches it. If an agent ` +
          "genuinely needs instance metadata, hand it a scoped credential instead of a route to the endpoint.",
      };
    case "private-target":
      return {
        surface: "host",
        knob:
          `none scoped to ${hostname}: egress.allowPrivateRanges is the only switch and it opens every private, ` +
          "loopback, and link-local range at once. egress.allowedHosts cannot rescue this host either, because the " +
          "private-range check runs before the allowlist. The narrow move is to reach the service through an " +
          "allowlisted public name rather than its internal address.",
      };
    case "embedded-credentials":
      return {
        surface: "credentials",
        knob:
          "none: userinfo in a URL is refused unconditionally and there is no config key for it. Remove user:pass@ " +
          "from the URL and send the credential in a header, where it is not carried as part of the target.",
      };
    case "blocked-scheme":
      return {
        surface: "scheme",
        knob:
          `egress.allowedSchemes: add "${scheme}" (currently ${quoteList(policy.allowedSchemes)}). Scoped to that ` +
          "scheme only - the host allowlist, the port list, and the private-range block are untouched.",
      };
    case "blocked-port":
      return {
        surface: "port",
        knob:
          `egress.allowedPorts: add ${port} (currently ${quoteList(policy.allowedPorts)}). Scoped to that port only.`,
      };
    case "default-deny-egress":
      return {
        surface: "host",
        knob:
          `egress.allowedHosts: add "${hostname}" - that one host. Not a wildcard, and not egress.defaultDeny: ` +
          "false, which would allow every host the agent can resolve.",
      };
    case "invalid-url":
      return {
        surface: "url",
        knob:
          "none, and none is wanted: the URL did not parse, so no check has run yet and there is nothing to " +
          "suppress. Fix the URL and run explain again.",
      };
    default:
      return {
        surface: "url",
        knob:
          `unknown to explain: the egress inspector reported category "${category}", which this build has no knob ` +
          "mapping for. Quote that category verbatim when you report it rather than guessing at a setting.",
      };
  }
}

// --- DLP --------------------------------------------------------------------

interface DlpHit {
  type: string;
  severity: string;
  note: string;
}

/**
 * Secrets and PII are collected into one list rather than handled in two loops so
 * that the knob sentence - the part of this feature that actually matters - has a
 * single definition and cannot drift between the two classes.
 *
 * PII is reported a step lower than secret material because severity here is not
 * a guess about the pattern's confidence: without a flow, an email address is a
 * fact about the text, while a credential is a fact about what happens if the
 * text moves. The shipped rules escalate secrets on an egress flow, which explain
 * cannot see.
 */
function collectDlp(acc: Accumulator, surface: string, text: string, surfaceNote = ""): void {
  const scan = scanText(text);
  const hits: DlpHit[] = [
    ...scan.secretTypes.map((type) => ({
      type,
      severity: "high",
      note:
        "The DLP scanner classifies this as credential material, which the content and MCP rules redact rather " +
        "than forward.",
    })),
    ...scan.piiTypes.map((type) => ({
      type,
      severity: "medium",
      note:
        "This is personal data rather than a credential, so it is reported at medium: the shipped rules redact " +
        "PII on an outbound flow and leave it alone on an internal one.",
    })),
  ];

  for (const hit of hits) {
    acc.scored.push({
      implied: "redact",
      finding: {
        scanner: "dlp",
        layer: LAYER.dlp,
        ruleOrPattern: hit.type,
        surface,
        severity: hit.severity,
        why: `The ${hit.type} pattern matched in ${surface}${surfaceNote}. ${hit.note}`,
        narrowestKnob:
          `"${hit.type}" is the narrowest unit the DLP scanner names, and this codebase has no per-type switch: ` +
          `config exposes dlp.enabled and dlp.redactSecrets for the whole scanner and nothing finer. Quote ` +
          `"${hit.type}" when you argue with this finding. Reaching for dlp.enabled instead would drop every other ` +
          "secret and PII check with it, which is not a trade worth making for one type.",
      },
    });
  }
}

// --- injection --------------------------------------------------------------

function collectInjection(acc: Accumulator, surface: string, text: string): void {
  for (const finding of scanInjection(text).findings) {
    acc.scored.push({
      implied: "deny",
      finding: {
        scanner: "injection",
        layer: LAYER.injection,
        ruleOrPattern: finding.patternId,
        surface,
        severity: finding.severity,
        why:
          `A ${finding.category.replace(/_/g, " ")} pattern matched in ${surface} on the ${finding.pass} ` +
          `normalization pass` +
          (finding.pass === "raw"
            ? " (the text exactly as given)"
            : " (it does not match the raw text - the pass is what surfaced it)") +
          `. Matched region, bounded and DLP-redacted: ${JSON.stringify(finding.excerpt)}.`,
        narrowestKnob:
          `"${finding.patternId}" is the narrowest unit the injection scanner names, and no config key disables a ` +
          "single pattern. Quote that id when you report a false positive: it identifies one regex out of the pack, " +
          "and it is the only handle that does. The alternative available today is the whole scanner, which is not " +
          "a trade worth making for one pattern.",
      },
    });
  }
}

// --- policy -----------------------------------------------------------------

function collectPolicy(acc: Accumulator, result: PolicyResult, engine: PolicyEngine, surface: string): void {
  const loaded = new Map(engine.getRules().map((rule) => [rule.id, rule]));

  result.matchedRules.forEach((ruleId, position) => {
    const rule = loaded.get(ruleId);
    // `reasons` is built from the same matched-rule list in the same order, so it
    // stays the reliable source for the sentence even if a rule object cannot be
    // read back out of the engine.
    const reason = result.reasons[position] ?? `Rule ${ruleId} matched`;
    const description = rule?.description ?? "see the rule definition; explain could not read it back from the engine";

    // Why a builtin rule gets "no config knob": the engine is always constructed
    // as [...builtinRules, ...fileRules], and `enabled: false` is honoured only
    // for rules declared in the policy file. On top of that, decisions combine by
    // maximum precedence (deny > approve > redact > allow), so adding an `allow`
    // rule cannot override a builtin `deny`. Both facts are unobvious and both
    // cost an operator an afternoon if nobody says them, so the knob says them
    // outright instead of suggesting an edit that will not work.
    const knob = BUILTIN_RULE_IDS.has(ruleId)
      ? `no config knob for ${ruleId}: it is a builtin rule, the engine always loads the builtin set, and the ` +
        "policy file's enabled: false applies only to rules declared in that file. Adding an allow rule will not " +
        "override it either, because decisions combine by highest precedence. The narrow lever is the input: this " +
        `rule fires when - ${description}. Change what the request looks like, or accept the decision.`
      : `${ruleId} came from your policy file, so it has a real narrow knob: set enabled: false on that one rule, ` +
        "or tighten its match block (an actor, subject, or action matcher) so it stops covering this request. " +
        "Both changes are scoped to this rule and leave every other rule in the file alone.";

    acc.scored.push({
      implied: rule?.decision ?? result.decision,
      finding: {
        scanner: "policy",
        layer: LAYER.policy,
        ruleOrPattern: ruleId,
        surface,
        severity: rule?.riskLevel ?? result.riskLevel,
        why: `${reason}. The rule is: ${description}.`,
        narrowestKnob: knob,
      },
    });
  });
}

// --- entry points -----------------------------------------------------------

/** A malformed escape is exactly the case where the raw form is what matters. */
function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * Explain what would happen to a URL.
 *
 * The egress inspector short-circuits on its first blocking check, so at most one
 * `ssrf` finding comes back even when a URL would fail several. That is faithful
 * to what a real request meets rather than a limitation worked around: the first
 * block is the one the request actually hits, and clearing it can reveal the next.
 *
 * The injection scanner is not run here. A URL is not prose, and running a pattern
 * pack tuned for instructions over a path produces noise with no corresponding
 * runtime behaviour. Pass the query string as text if you want it scanned that way.
 */
export function explainUrl(url: string, engine: PolicyEngine, egress?: Partial<EgressPolicy>): ExplainResult {
  const acc: Accumulator = { scored: [], checks: [] };
  const policy: EgressPolicy = { ...EXPLAIN_EGRESS_BASELINE, ...egress };

  const inspection = inspectNetworkRequest({ url, method: "GET" }, policy);
  acc.checks.push(
    "the egress inspector checked host, scheme, port, and embedded credentials" +
      (policy.defaultDeny
        ? `, against an allowlist of ${quoteList(policy.allowedHosts)}`
        : " (the allowlist check was not evaluated: explain does not read your config, so egress.defaultDeny is " +
          "off here and a live request may still require the host to be allowlisted)"),
  );

  let parsed: URL | null = null;
  try {
    parsed = new URL(url);
  } catch {
    parsed = null;
  }

  if (!inspection.allowed) {
    const category = inspection.blockedCategory ?? "unknown";
    const scheme = parsed ? parsed.protocol.replace(/:$/, "") : "";
    // Mirrors the inspector's own default-port resolution so a port knob never
    // prints a number the inspector did not actually test.
    let port = -1;
    if (parsed?.port) port = Number(parsed.port);
    else if (scheme === "https") port = 443;
    else if (scheme === "http") port = 80;

    const mapped = egressKnob(category, parsed?.hostname ?? url, scheme, port, policy);
    acc.scored.push({
      implied: "deny",
      finding: {
        scanner: "ssrf",
        layer: LAYER.ssrf,
        ruleOrPattern: `egress-check:${category}`,
        surface: mapped.surface,
        severity: inspection.riskLevel,
        why:
          `${inspection.reason}. The inspector stops at its first blocking check, so another check may be waiting ` +
          "behind this one.",
        narrowestKnob: mapped.knob,
      },
    });
  }

  if (parsed) {
    const surfaces: Array<[string, string]> = [
      ["path", parsed.pathname],
      ["query", parsed.search],
      ["fragment", parsed.hash],
    ];
    const scanned: string[] = [];
    for (const [surface, raw] of surfaces) {
      if (raw === "" || raw === "/") continue;
      const decoded = safeDecode(raw);
      collectDlp(acc, surface, decoded, decoded === raw ? "" : " (after percent-decoding)");
      scanned.push(surface);
    }
    acc.checks.push(
      scanned.length > 0
        ? `DLP scanned the ${scanned.join(", ")} of the URL for secrets and PII, percent-decoded first, and ` +
          "matched nothing"
        : "DLP had nothing to scan: this URL carries no path, query, or fragment",
    );
  }

  // Direction is egress because an explained URL is by definition an outbound
  // request. Provenance is left off rather than invented - see PROVENANCE_CAVEAT.
  const ctx: AgentContext = {
    agentId: "explain",
    plane: "network",
    action: "http_request",
    payload: { url },
    flow: { direction: "egress" },
  };
  const policyResult = engine.evaluate(ctx);
  collectPolicy(acc, policyResult, engine, "request context (plane network, action http_request, payload.url)");
  acc.checks.push(
    `the policy engine evaluated ${engine.getRules().length} loaded rules against a network-plane egress context ` +
      `and none matched, so its default decision (${policyResult.decision}) is what a real request would get`,
    PROVENANCE_CAVEAT,
  );

  return finish(acc, url, "url", policyResult.decision);
}

/**
 * Explain what the content scanners see in a string.
 *
 * No policy engine here, on purpose. A bare string has no plane, direction, or
 * provenance, and every rule that acts on content keys on at least one of those.
 * The decision reported is therefore what these findings would drive a
 * content-plane rule to - secrets get redacted, injection gets denied - and not a
 * promise about a specific request.
 */
export function explainText(text: string): ExplainResult {
  const acc: Accumulator = { scored: [], checks: [] };

  collectDlp(acc, "text", text);
  acc.checks.push("DLP scanned the text for secret and PII patterns and matched none");

  collectInjection(acc, "text", text);
  acc.checks.push(
    `the injection scanner ran ${INJECTION_PATTERN_COUNT} patterns over ${NORMALIZATION_PASSES.length} ` +
      `normalization passes (${NORMALIZATION_PASSES.join(", ")}) and matched none - which means no known pattern, ` +
      "not that the text is safe, because paraphrase defeats pattern matching",
    "no policy rule was evaluated: a bare string carries no plane, direction, or provenance for a rule to match on",
  );

  return finish(acc, text, "text", "allow");
}

interface FlatString {
  path: string;
  text: string;
}

/**
 * Flattens argument strings to leaf paths so a finding can name the argument it
 * came from rather than "arguments" in general. Mirrors how the rules flatten a
 * payload, with the path retained.
 */
function flattenStrings(value: unknown, path: string, out: FlatString[]): void {
  if (typeof value === "string") {
    out.push({ path, text: value });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => flattenStrings(entry, `${path}[${index}]`, out));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      flattenStrings(entry, `${path}.${key}`, out);
    }
  }
}

/**
 * Explain what would happen to a tool call.
 *
 * Argument strings are scanned per leaf rather than as one concatenated blob, so a
 * finding points at `arguments.command` instead of at the call in general. The
 * cost is a scan per string, which is the right trade for an operator-driven
 * command: the inline gates are where hostile volume has to be bounded, not here.
 */
export function explainToolCall(
  tool: string,
  args: Record<string, unknown>,
  engine: PolicyEngine,
): ExplainResult {
  const acc: Accumulator = { scored: [], checks: [] };

  const leaves: FlatString[] = [];
  flattenStrings(args, "arguments", leaves);
  for (const leaf of leaves) {
    collectDlp(acc, leaf.path, leaf.text);
    collectInjection(acc, leaf.path, leaf.text);
  }
  acc.checks.push(
    leaves.length > 0
      ? `DLP and the injection scanner examined ${leaves.length} argument string(s) - ` +
        `${leaves.map((leaf) => leaf.path).join(", ")} - and matched nothing`
      : "DLP and the injection scanner had no argument strings to examine",
  );

  const ctx: AgentContext = {
    agentId: "explain",
    plane: "tool",
    action: tool,
    payload: args,
  };
  const policyResult = engine.evaluate(ctx);
  collectPolicy(acc, policyResult, engine, `tool call context (plane tool, action ${tool}, payload = arguments)`);
  acc.checks.push(
    `the policy engine evaluated ${engine.getRules().length} loaded rules against a tool-plane context for ` +
      `"${tool}" and none matched, so its default decision (${policyResult.decision}) is what a real call would get`,
    PROVENANCE_CAVEAT,
  );

  return finish(acc, tool, "tool", policyResult.decision);
}

// --- CLI surface ------------------------------------------------------------

export type ExplainFlags = Record<string, string | boolean>;

export interface ExplainRequest {
  kind: ExplainKind;
  /** The URL, the text, or the tool name. */
  subject: string;
  /** Tool name for the tool kind; equal to `subject` there, empty otherwise. */
  tool: string;
  args: Record<string, unknown>;
  json: boolean;
}

export const EXPLAIN_USAGE =
  "Usage: agentwall explain <subject> [--kind url|text|tool] [--tool <name>] [--args <json>] [--json]";

/**
 * Infer the kind from the subject.
 *
 * A scheme plus `://` that parses is a URL; everything else is text. The bar is
 * deliberately that high, because `new URL()` accepts "run: something" as a valid
 * non-special-scheme URL - so treating any colon as a URL would classify a
 * sentence as one and then explain the wrong thing entirely. A scheme-less host
 * like `docs.example.com/guide` is genuinely ambiguous with prose and is treated
 * as text; pass `--kind url`, or include the scheme, when that is not what you meant.
 */
export function inferExplainKind(subject: string): ExplainKind {
  if (!/^[a-z][a-z0-9+.\-]*:\/\//i.test(subject)) return "text";
  try {
    new URL(subject);
    return "url";
  } catch {
    return "text";
  }
}

/**
 * Positionals are joined rather than indexed so that unquoted text works the way
 * a user expects: `explain ignore all previous instructions` arrives as five
 * positionals and means one subject.
 */
export function parseExplainArgs(flags: ExplainFlags, positionals: string[]): ExplainRequest {
  const subject = positionals.join(" ").trim();
  const toolFlag = typeof flags.tool === "string" ? flags.tool : "";

  let args: Record<string, unknown> = {};
  if (typeof flags.args === "string") {
    let decoded: unknown;
    try {
      decoded = JSON.parse(flags.args);
    } catch (error) {
      throw new Error(
        `--args is not valid JSON: ${error instanceof Error ? error.message : String(error)}\n${EXPLAIN_USAGE}`,
      );
    }
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
      throw new Error(`--args must be a JSON object of tool arguments.\n${EXPLAIN_USAGE}`);
    }
    args = decoded as Record<string, unknown>;
  }

  let kind: ExplainKind;
  if (typeof flags.kind === "string") {
    if (flags.kind !== "url" && flags.kind !== "text" && flags.kind !== "tool") {
      throw new Error(`--kind must be url, text, or tool.\n${EXPLAIN_USAGE}`);
    }
    kind = flags.kind;
  } else if (toolFlag !== "" || typeof flags.args === "string") {
    // Naming a tool or its arguments is unambiguous about the kind, so it counts
    // as inference rather than requiring --kind to be typed twice over.
    kind = "tool";
  } else {
    kind = inferExplainKind(subject);
  }

  if (kind === "tool") {
    const tool = toolFlag !== "" ? toolFlag : subject;
    if (tool === "") {
      throw new Error(`explain --kind tool needs a tool name, as --tool <name> or as the subject.\n${EXPLAIN_USAGE}`);
    }
    return { kind, subject: tool, tool, args, json: flags.json === true };
  }

  if (subject === "") {
    throw new Error(`explain needs a subject.\n${EXPLAIN_USAGE}`);
  }
  return { kind, subject, tool: "", args, json: flags.json === true };
}

export function runExplain(request: ExplainRequest, engine: PolicyEngine): ExplainResult {
  if (request.kind === "url") return explainUrl(request.subject, engine);
  if (request.kind === "tool") return explainToolCall(request.tool, request.args, engine);
  return explainText(request.subject);
}

/** Non-zero when anything fired, so `explain` is usable as a gate in a script. */
export function explainExitCode(result: ExplainResult): 0 | 1 {
  return result.findings.length > 0 ? 1 : 0;
}

const REPORT_WIDTH = 96;

function wrapText(text: string, indent: number): string[] {
  const limit = Math.max(REPORT_WIDTH - indent, 32);
  const lines: string[] = [];
  let current = "";
  for (const word of text.split(/\s+/).filter(Boolean)) {
    if (current === "") {
      current = word;
    } else if (current.length + 1 + word.length <= limit) {
      current = `${current} ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current !== "") lines.push(current);
  return lines.length > 0 ? lines : [""];
}

function detailLine(label: string, value: string): string {
  const head = `       ${label.padEnd(10)} `;
  const continuation = " ".repeat(head.length);
  return wrapText(value, head.length)
    .map((line, index) => (index === 0 ? head + line : continuation + line))
    .join("\n");
}

/**
 * Human output. One block per finding, in the shape `verify` uses: a verdict word
 * in the left column, then labelled detail lines under it. The knob is always
 * last because it is the line the reader came for.
 */
export function formatExplainReport(result: ExplainResult): string {
  const lines: string[] = [`explain ${result.subject}`];
  lines.push(
    `kind ${result.kind} · decision ${result.decision} · ` +
      (result.findings.length === 0 ? "nothing fired" : `${result.findings.length} finding(s)`),
  );

  for (const finding of result.findings) {
    lines.push("");
    lines.push(`FIRED  ${finding.scanner.padEnd(10)} ${finding.ruleOrPattern}`);
    lines.push(detailLine("layer", finding.layer));
    lines.push(detailLine("inspected", finding.surface));
    lines.push(detailLine("severity", finding.severity));
    lines.push(detailLine("why", finding.why));
    lines.push(detailLine("knob", finding.narrowestKnob));
  }

  if (result.findings.length === 0) {
    lines.push("");
    lines.push("CLEAN  no check fired. What ran:");
    for (const check of (result.cleanReason ?? "").split("; ")) {
      if (check === "") continue;
      lines.push(
        wrapText(check, 9)
          .map((line, index) => (index === 0 ? `       - ${line}` : `         ${line}`))
          .join("\n"),
      );
    }
  }

  return lines.join("\n");
}
