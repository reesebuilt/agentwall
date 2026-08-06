/**
 * Configuration scoring: is this particular deployment actually switched on?
 *
 * A control mapping answers "does this tool have a control for X". It cannot
 * answer the question an operator actually needs answered, which is whether the
 * controls are enabled on their box. Those come apart badly in practice: every
 * control in src/compliance/mapping.ts can be present in the code and switched
 * off in the config, and the resulting deployment inspects nothing while looking,
 * from the outside, exactly like a protected one. This module reads a deployment
 * description and says what is missing, in a form short enough that someone will
 * read it before going to production rather than after.
 *
 * WHY THE INPUT IS `unknown` AND WHY IT INCLUDES `env`. Half of AgentWall's
 * security posture is not in the YAML file. The operator token, the audit file
 * path, the proxy port, and the lockdown sentinel are all environment
 * variables, deliberately, because a security product should not invent a
 * location in $HOME or bake a credential into a file people commit. A scorer that
 * read only the config document would award a clean bill of health to a
 * deployment with no authentication and no durable audit trail. So the input is a
 * description of the whole deployment: the config document's own keys plus an
 * `env` map.
 *
 * That `env` map is passed in rather than read from `process.env` here. Reaching
 * for a global would make this function's result depend on ambient state that the
 * caller cannot see or control, which is wrong for something whose entire output
 * is a claim about a specific configuration — and it would make the same config
 * score differently in a test than in production. The caller passes
 * `{ env: process.env }` when it wants the live environment.
 *
 * FAIL-CLOSED ON ABSENCE. A signal that is not present in the input scores zero,
 * not "unknown". A scorer that gave benefit of the doubt would rate an empty
 * object highly, which is the exact opposite of useful. The consequence worth
 * knowing: if you forget to pass `env`, the score is an F, and that is correct
 * behaviour rather than a bug — you have described a deployment with no operator
 * token.
 *
 * WHAT THIS DOES NOT DO, plainly: it reads a configuration, not a running system.
 * It cannot tell you the process is using the config you handed it, that the audit
 * file is writable, that the proxy is reachable, that the environment variable
 * holds a strong token rather than the word "token", or that any of it is working.
 * It also scores a named set of signals, not everything that matters — a high
 * score means nothing on this list is obviously wrong, not that the deployment is
 * secure.
 */

export interface ScoreCategory {
  id: string;
  name: string;
  points: number;
  max: number;
  findings: string[];
  /** Concrete next action. Present whenever the category scored below its max. */
  remediation?: string;
}

export interface ConfigScore {
  total: number;
  max: number;
  grade: "A" | "B" | "C" | "D" | "F";
  categories: ScoreCategory[];
  /** Why the grade was forced to F, when a critical exposure overrode the total. */
  capped?: string;
}

/**
 * Percentage thresholds, highest first. An ordered ladder rather than a keyed
 * table, because the lookup is "the first threshold this total clears".
 */
const GRADE_THRESHOLDS: ReadonlyArray<readonly [number, ConfigScore["grade"]]> = [
  [0.9, "A"],
  [0.8, "B"],
  [0.7, "C"],
  [0.6, "D"],
];

/** Enforcement modes, in ascending order of how much the deployment will actually stop. */
const ENFORCEMENT_MODES: Record<string, number> = { monitor: 2, guarded: 6, strict: 10 };

const LOOPBACK_HOSTS: Record<string, true> = {
  localhost: true,
  "ip6-localhost": true,
  "ip6-loopback": true,
  "::1": true,
};

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asPositiveNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : undefined;
}

/** Trimmed, or undefined when absent or blank. A whitespace-only token is not a token. */
function envValue(env: Record<string, unknown>, name: string): string | undefined {
  const raw = asString(env[name])?.trim();
  return raw ? raw : undefined;
}

/**
 * Loopback for the purpose of "is the control surface reachable from off-box".
 *
 * 0.0.0.0 and :: are deliberately NOT loopback: they are every interface, which is
 * the case this check exists to catch. A container binding 0.0.0.0 is a legitimate
 * posture — the network namespace provides the isolation the address does not —
 * but it stops being legitimate the moment the development auth bypass is on.
 */
function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (LOOPBACK_HOSTS[normalized]) return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized);
}

export function scoreConfig(config: unknown): ConfigScore {
  const root = asRecord(config) ?? {};
  const env = asRecord(root["env"]) ?? {};
  const auth = asRecord(root["auth"]) ?? {};
  const audit = asRecord(root["audit"]) ?? {};
  const policy = asRecord(root["policy"]) ?? {};
  const approval = asRecord(root["approval"]) ?? {};
  const dlp = asRecord(root["dlp"]) ?? {};
  const egress = asRecord(root["egress"]) ?? {};
  const enforcement = asRecord(root["enforcement"]) ?? {};
  const telemetry = asRecord(root["telemetry"]) ?? {};
  const watchdog = asRecord(root["watchdog"]) ?? {};
  const guards = asRecord(root["runtimeGuards"]) ?? {};
  const manifest = asRecord(root["manifestIntegrity"]) ?? {};

  // Hoisted because two categories ask the same question of it: strict enforcement is a
  // misconfiguration without an allowlist, and the allowlist is a scored signal itself.
  const allowedHosts = egress["allowedHosts"];
  const allowlistPopulated = Array.isArray(allowedHosts) && allowedHosts.length > 0;

  const categories: ScoreCategory[] = [];
  const caps: string[] = [];

  const add = (
    id: string,
    name: string,
    max: number,
    points: number,
    findings: string[],
    remediation?: string
  ): void => {
    const category: ScoreCategory = { id, name, points, max, findings };
    if (points < max && remediation) category.remediation = remediation;
    categories.push(category);
  };

  // 1. Operator authentication. The heaviest single category, because it is the one
  // whose absence makes every other category irrelevant.
  const tokenSet = Boolean(envValue(env, "AGENTWALL_OPERATOR_TOKEN")) || asBoolean(auth["operatorTokenSet"]) === true;
  const loopbackDev =
    envValue(env, "AGENTWALL_ALLOW_LOOPBACK_DEV") === "1" || asBoolean(auth["allowLoopbackDev"]) === true;

  if (tokenSet) {
    add("auth.operator-token", "Operator authentication", 15, 15, ["AGENTWALL_OPERATOR_TOKEN is set."]);
  } else {
    add(
      "auth.operator-token",
      "Operator authentication",
      15,
      0,
      [
        "No operator token in the deployment description.",
        loopbackDev
          ? "The loopback development bypass is the only way in, so the control surface is unauthenticated."
          : "Every non-public route will return 401, so the deployment is inert rather than protected.",
      ],
      "Set AGENTWALL_OPERATOR_TOKEN to a random secret of at least 32 bytes and pass it as a bearer token on every API call."
    );
    caps.push("no operator token is configured, so the control surface is either unauthenticated or unusable");
  }

  // 2. Listener exposure. The interesting case is not either switch on its own; it is
  // the combination, which is why they are scored together.
  const host = asString(root["host"])?.trim() || "127.0.0.1";
  const hostIsLoopback = isLoopbackHost(host);
  if (!loopbackDev) {
    add("auth.exposure", "Listener exposure", 10, 10, [`Bound to ${host} with the loopback development bypass off.`]);
  } else if (hostIsLoopback) {
    add(
      "auth.exposure",
      "Listener exposure",
      10,
      4,
      [`Loopback development bypass is on, mitigated only by the bind address ${host}.`],
      "Unset AGENTWALL_ALLOW_LOOPBACK_DEV and use AGENTWALL_OPERATOR_TOKEN, including locally. A development convenience that survives into production is how an open control plane happens."
    );
  } else {
    add(
      "auth.exposure",
      "Listener exposure",
      10,
      0,
      [`Loopback development bypass is on while bound to ${host}, which is not a loopback address.`],
      "Unset AGENTWALL_ALLOW_LOOPBACK_DEV immediately, or bind to 127.0.0.1. As configured, anyone who can reach the listener is an operator."
    );
    caps.push(
      `the loopback development bypass is enabled while bound to ${host}, which accepts unauthenticated callers from off-box`
    );
  }

  // 3. Durable audit evidence. Without a file, the chain exists only on stdout, where
  // it is a view of the evidence rather than the evidence.
  if (envValue(env, "AGENTWALL_AUDIT_FILE")) {
    add("audit.evidence-file", "Durable audit evidence", 10, 10, ["Hash-chained audit records are written to a file."]);
  } else {
    add(
      "audit.evidence-file",
      "Durable audit evidence",
      10,
      0,
      ["No audit file: records go to stdout only, so there is nothing for `verify` to walk."],
      "Set AGENTWALL_AUDIT_FILE to a path on a volume that survives a restart. Without it there is no tamper-evident record of any decision."
    );
  }

  // 4. Anchoring. Separate from the file because it answers a different question: the
  // chain proves records were not edited, an anchor proves when they existed.
  if (asPositiveNumber(audit["anchorIntervalMs"])) {
    add("audit.anchoring", "Audit checkpoint anchoring", 5, 5, ["Checkpoints are sealed and anchored on an interval."]);
  } else {
    add(
      "audit.anchoring",
      "Audit checkpoint anchoring",
      5,
      0,
      ["Anchoring is off, so the chain has no external timestamp."],
      "Set audit.anchorIntervalMs (21600000, six hours, is a sensible start). Without it, an operator who controls the file can rewrite history wholesale and the chain will be internally consistent."
    );
  }

  // 5. Egress insertion surface. The proxy is how AgentWall sees destinations at all.
  {
    const findings: string[] = [];
    let points = 0;
    if (asPositiveNumber(Number(envValue(env, "AGENTWALL_PROXY_PORT") ?? 0))) {
      points += 6;
      findings.push("Forward proxy is configured to start.");
    } else {
      findings.push("Forward proxy is not configured, so no destination is observed unless a harness calls the API directly.");
    }
    if (envValue(env, "AGENTWALL_PROXY_LEDGER")) {
      points += 2;
      findings.push("Flat destination ledger is configured for allowlist analysis.");
    } else {
      findings.push("No flat ledger; destinations are only in the audit chain.");
    }
    add(
      "proxy.insertion",
      "Egress insertion surface",
      8,
      points,
      findings,
      "Set AGENTWALL_PROXY_PORT and point the agent's HTTP_PROXY/HTTPS_PROXY at it, and set AGENTWALL_PROXY_LEDGER to build an allowlist from what the agent actually reaches."
    );
  }

  // 6. Enforcement mode. Monitor is a supported and often correct first posture, so it
  // scores low rather than capping: an operator learning their traffic is doing the
  // right thing, and telling them their deployment is an F for it would be noise.
  {
    const mode = asString(enforcement["mode"])?.trim();
    if (mode === undefined) {
      add(
        "enforcement.mode",
        "Enforcement mode",
        10,
        ENFORCEMENT_MODES["monitor"],
        ["No enforcement section, which means monitor: everything is recorded and nothing is stopped."],
        "Once the ledger shows a stable set of destinations, set enforcement.mode to guarded, then strict."
      );
    } else if (ENFORCEMENT_MODES[mode] === undefined) {
      add(
        "enforcement.mode",
        "Enforcement mode",
        10,
        0,
        [`enforcement.mode is "${mode}", which is not a recognised mode.`],
        "Set enforcement.mode to monitor, guarded, or strict."
      );
    } else if (mode === "strict" && !allowlistPopulated) {
      add(
        "enforcement.mode",
        "Enforcement mode",
        10,
        4,
        ["enforcement.mode is strict but egress.allowedHosts is empty, so every outbound request is denied."],
        "Populate egress.allowedHosts with the destinations the agent legitimately needs before running in strict mode, or drop back to guarded while you build that list."
      );
    } else {
      add("enforcement.mode", "Enforcement mode", 10, ENFORCEMENT_MODES[mode], [`enforcement.mode is ${mode}.`],
        "Move to enforcement.mode strict once the destination allowlist is stable.");
    }
  }

  // 7. Egress allowlist.
  {
    const findings: string[] = [];
    let points = 0;
    if (asBoolean(egress["enabled"]) === true) {
      points += 3;
      findings.push("Egress policy is enabled.");
    } else {
      findings.push("Egress policy is disabled; destination rules are not consulted.");
    }
    if (asBoolean(egress["defaultDeny"]) === true) {
      points += 3;
      findings.push("Unlisted destinations are denied by default.");
    } else {
      findings.push("Egress is default-allow, so a destination has to be named to be blocked.");
    }
    if (allowlistPopulated) {
      points += 2;
      findings.push("An explicit host allowlist is present.");
    } else {
      findings.push("egress.allowedHosts is empty.");
    }
    if (asBoolean(egress["allowPrivateRanges"]) !== true) {
      points += 2;
      findings.push("Private and link-local ranges are not reachable.");
    } else {
      findings.push("Private ranges are allowed, so internal services and cloud metadata are in reach.");
    }
    add(
      "egress.allowlist",
      "Egress allowlist",
      10,
      points,
      findings,
      "Set egress.enabled and egress.defaultDeny true, leave allowPrivateRanges false, and list the hosts the agent needs in egress.allowedHosts."
    );
  }

  // 8. Default decision: what happens to an action no rule describes.
  {
    const decision = asString(policy["defaultDecision"]);
    if (decision === "deny") {
      add("policy.default-decision", "Default decision", 8, 8, ["Unmatched actions are denied."]);
    } else {
      add(
        "policy.default-decision",
        "Default decision",
        8,
        0,
        [
          decision === "allow"
            ? "Unmatched actions are allowed, so the rule set is a blocklist and anything nobody thought of gets through."
            : "policy.defaultDecision is not set.",
        ],
        'Set policy.defaultDecision to "deny". A rule set that only stops what it recognises is not a boundary.'
      );
    }
  }

  // 9. Operator policy file. The built-in rules are a floor written without knowledge of
  // your tools; a deployment with no policy file has never described its own risks.
  if (asString(policy["configPath"])?.trim()) {
    add("policy.rule-file", "Operator policy file", 6, 6, ["An external policy file is loaded and hot-reloaded."]);
  } else {
    add(
      "policy.rule-file",
      "Operator policy file",
      6,
      0,
      ["No policy file: the built-in rules are the entire policy."],
      "Run `agentwall init`, then set policy.configPath and add rules naming your own tools. The built-in set cannot know which of your tools are destructive."
    );
  }

  // 10. Approval gating, plus whether the queue survives a restart.
  {
    const findings: string[] = [];
    let points = 0;
    const mode = asString(approval["mode"]);
    if (mode === "always") {
      points += 5;
      findings.push("Every approval-decision action waits for a human.");
    } else if (mode === "auto") {
      points += 3;
      findings.push("Approvals auto-resolve on timeout; only the rules decide what stops.");
    } else if (mode === "never") {
      findings.push('approval.mode is "never", so nothing ever reaches a human and approve decisions collapse.');
    } else {
      findings.push("approval.mode is not set.");
    }
    if (asString(approval["backend"]) === "file" && asString(approval["persistencePath"])?.trim()) {
      points += 3;
      findings.push("Pending approvals are persisted, so a restart does not silently drop them.");
    } else {
      findings.push("Approvals are held in memory; a restart loses every pending decision.");
    }
    add(
      "approval.mode",
      "Approval gating",
      8,
      points,
      findings,
      'Set approval.mode to "always" for the actions you care about, and approval.backend to "file" with a persistencePath so a restart does not lose the queue.'
    );
  }

  // 11. Rate and cost limits.
  {
    const findings: string[] = [];
    let points = 0;
    if (asBoolean(guards["enabled"]) === true) {
      points += 3;
      findings.push("Runtime guards are enabled.");
    } else {
      findings.push("Runtime guards are off: no rate ceiling, no cost budget, no cap on the approval queue.");
    }
    const capsPresent =
      asPositiveNumber(guards["requestPerMinutePerSession"]) !== undefined &&
      asPositiveNumber(guards["toolActionPerMinutePerSession"]) !== undefined &&
      asPositiveNumber(guards["costBudgetPerHourPerSession"]) !== undefined;
    if (capsPresent) {
      points += 3;
      findings.push("Request, tool-action, and cost ceilings are all set.");
    } else {
      findings.push("At least one of the request, tool-action, or cost ceilings is missing or non-positive.");
    }
    add(
      "runtime.rate-limits",
      "Rate and cost limits",
      6,
      points,
      findings,
      "Set runtimeGuards.enabled true with positive values for requestPerMinutePerSession, toolActionPerMinutePerSession, and costBudgetPerHourPerSession. A looping agent is the common failure, not the exotic one."
    );
  }

  // 12. Content scanning.
  {
    const findings: string[] = [];
    let points = 0;
    if (asBoolean(dlp["enabled"]) === true) {
      points += 4;
      findings.push("Content scanning is enabled.");
    } else {
      findings.push("Content scanning is disabled, so secret and PII rules have nothing to act on.");
    }
    if (asBoolean(dlp["redactSecrets"]) === true) {
      points += 2;
      findings.push("Detected secrets are redacted rather than passed through.");
    } else {
      findings.push("Redaction is off: secrets are detected and forwarded unchanged.");
    }
    add(
      "dlp.content-scanning",
      "Content scanning",
      6,
      points,
      findings,
      "Set dlp.enabled and dlp.redactSecrets true."
    );
  }

  // 13. Decision telemetry. Lowest weight on the list on purpose: it is how you see what
  // the boundary did, not part of the boundary. The audit chain is the record.
  {
    const enabled = asBoolean(telemetry["enabled"]) === true;
    const endpoint = asString(telemetry["endpoint"])?.trim();
    if (enabled && endpoint) {
      add("telemetry.decision-traces", "Decision telemetry", 4, 4, [`Decision traces are exported to ${endpoint}.`]);
    } else if (enabled) {
      add(
        "telemetry.decision-traces",
        "Decision telemetry",
        4,
        1,
        ["Telemetry is enabled with no endpoint, so traces are built and go nowhere."],
        "Set telemetry.endpoint, or set telemetry.enabled false and stop paying for the traces."
      );
    } else {
      add(
        "telemetry.decision-traces",
        "Decision telemetry",
        4,
        0,
        ["Decision telemetry is off."],
        "Set telemetry.enabled true with an endpoint if you want decisions visible in your existing tracing stack. This is observability, not enforcement; skipping it is a defensible choice."
      );
    }
  }

  // 14. Lockdown. Scored on whether there is a way to stop the agent that does not
  // require the API to be healthy, which is exactly the situation you need it in.
  {
    const findings: string[] = [];
    let points = 0;
    if (envValue(env, "AGENTWALL_LOCKDOWN_FILE")) {
      points += 4;
      findings.push("A sentinel file path is configured, so lockdown works without a working API.");
    } else {
      findings.push("No sentinel file: stopping the agent depends on the API or a signal reaching the process.");
    }
    if (asBoolean(watchdog["enabled"]) === true) {
      points += 2;
      findings.push("Watchdog is enabled.");
    } else {
      findings.push("Watchdog is off, so a wedged agent is not noticed.");
    }
    if (asString(watchdog["killSwitchMode"]) === "deny_all") {
      points += 2;
      findings.push("A tripped watchdog denies everything.");
    } else {
      findings.push("watchdog.killSwitchMode is not deny_all, so a tripped watchdog does not stop action.");
    }
    add(
      "lockdown.sentinel",
      "Lockdown",
      8,
      points,
      findings,
      'Set AGENTWALL_LOCKDOWN_FILE to a path you can touch from a shell, enable the watchdog, and set watchdog.killSwitchMode to "deny_all".'
    );
  }

  // 15. Tool manifest integrity.
  {
    const findings: string[] = [];
    let points = 0;
    if (asBoolean(manifest["enabled"]) === true) {
      points += 4;
      findings.push("Manifest integrity checking is enabled.");
    } else {
      findings.push("Manifest integrity is off, so a tool set can change without re-approval.");
    }
    if (asString(manifest["approvedHashesPath"])?.trim()) {
      points += 2;
      findings.push("Approved manifest hashes are stored on disk, so drift survives a restart.");
    } else {
      findings.push("No approved-hashes file: the approved baseline is rebuilt each run, so drift across restarts is invisible.");
    }
    add(
      "integrity.manifest",
      "Tool manifest integrity",
      6,
      points,
      findings,
      "Set manifestIntegrity.enabled true and manifestIntegrity.approvedHashesPath to a persisted path."
    );
  }

  const total = categories.reduce((sum, category) => sum + category.points, 0);
  const max = categories.reduce((sum, category) => sum + category.max, 0);

  /**
   * Critical exposures override the arithmetic.
   *
   * This is the part of the model that matters most, and it exists because a
   * weighted average is the wrong shape for security posture. Fifteen categories
   * scored well and one catastrophic hole averages out to a B, and a B tells the
   * operator to move on. An unauthenticated control plane is not eighty-seven
   * percent secure; it is an open door with excellent logging. So a cap is a claim
   * that the deployment is exploitable as configured, not that it is suboptimal,
   * and it forces F no matter what else is right.
   *
   * The cap list is deliberately short for the same reason. Monitor mode,
   * default-allow policy, and absent telemetry all cost points and none of them
   * cap, because each is a legitimate posture for someone who has chosen it — and
   * a cap that fires on a defensible choice teaches operators to ignore caps.
   */
  const score: ConfigScore = {
    total,
    max,
    grade: caps.length > 0 ? "F" : gradeFor(total, max),
    categories,
  };
  if (caps.length > 0) {
    score.capped = `Graded F regardless of the ${total}/${max} total because ${caps.join("; and ")}.`;
  }
  return score;
}

function gradeFor(total: number, max: number): ConfigScore["grade"] {
  const ratio = max > 0 ? total / max : 0;
  for (const [threshold, grade] of GRADE_THRESHOLDS) {
    if (ratio >= threshold) return grade;
  }
  return "F";
}
