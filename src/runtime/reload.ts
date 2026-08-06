import { createHash } from "crypto";
import * as fs from "fs";
import { auditDropStats, emit } from "../audit/logger";
import { AgentwallConfig, loadConfig } from "../config";
import { PolicyEngine } from "../policy/engine";
import { DeclarativePolicyRule } from "../policy/loader";
import { builtinRules } from "../policy/rules";
import { FileBackedPolicyRuntime, NO_POLICY_FILE_HASH, ReloadResult } from "../policy/runtime";
import { AgentContext, PolicyResult } from "../types";

/**
 * Operator-triggered reload of policy.yaml and agentwall.config.yaml.
 *
 * What already existed before this file: policy RULES hot-reloaded, from three triggers, and a
 * bad policy file was already rejected whole with the previous ruleset left enforcing. None of
 * that is rebuilt here. What this adds is the part that was missing.
 *
 *  - One operator action, atomic across BOTH files. Everything is parsed and validated before
 *    anything is applied, so a broken config cannot leave a half-applied policy behind and a
 *    broken policy cannot leave a half-applied config.
 *  - An audit record. A policy change is a security-relevant event, and until now it produced
 *    a log line and nothing on the chain.
 *  - An honest account of the config keys a running process cannot change, returned to the
 *    caller instead of quietly ignored.
 */

type LoggerLike = {
  info: (obj: unknown, msg?: string) => void;
  warn: (obj: unknown, msg?: string) => void;
  error: (obj: unknown, msg?: string) => void;
};

/** Which channel asked for the reload. Recorded verbatim on the chain. */
export type ReloadSource = "sighup" | "api" | "dashboard" | "watch";

export interface ReloadRequest {
  source: ReloadSource;
  /**
   * The authenticated operator principal, when there was one. Absent for `sighup` and
   * `watch`, which carry no identity: anything that can signal the process or write the
   * policy file is already inside the trust boundary, and inventing a name for it would put
   * a claim on the chain that nothing established.
   */
  operatorId?: string;
  /** Optional operator-supplied note, bounded by the route schema. */
  reason?: string;
}

export interface RuleDiff {
  added: string[];
  removed: string[];
  modified: string[];
}

export interface PolicyReloadReport {
  /** The policy file, or null when policy.configPath is unset and there is nothing to reload. */
  path: string | null;
  /** True only when the engine is now serving a different ruleset than before the call. */
  applied: boolean;
  hashBefore: string;
  hashAfter: string;
  /** Version of the snapshot now in force. Increments on every swap, so it never repeats. */
  policyVersion: number;
  ruleCount: number;
  diff: RuleDiff;
  /** Present when the file was refused. The previous ruleset is still enforcing. */
  error?: string;
}

export interface ConfigReloadReport {
  path: string | null;
  hashBefore: string;
  hashAfter: string;
  /** Keys whose new value is now in force. */
  applied: string[];
  /**
   * Keys that CHANGED in the file and are NOT in force, because a running process cannot
   * honestly change them. The file on disk and the running process now disagree about these
   * until a restart.
   */
  restartRequired: string[];
  error?: string;
}

export interface ReloadReport {
  ok: boolean;
  source: ReloadSource;
  operatorId: string | null;
  at: string;
  policy: PolicyReloadReport;
  config: ConfigReloadReport;
  /**
   * Whether the record for this reload actually reached a durable sink and joined the chain.
   *
   * False means the change is in force with no evidence of it, which is the worst outcome
   * this surface can produce, so it is a top-level field rather than something an operator
   * has to go looking for.
   */
  audit: { recorded: boolean; eventId: string | null; detail: string | null };
  /** Anything an operator must read. Empty on a clean, fully recorded reload. */
  warnings: string[];
}

/**
 * Log levels pino accepts. An unrecognised one makes the level setter THROW, and that throw
 * would land after the policy swap, which is the partial application this whole class exists
 * to prevent. So it is checked in phase 1 instead.
 */
const PINO_LEVELS: Record<string, true> = {
  fatal: true,
  error: true,
  warn: true,
  info: true,
  debug: true,
  trace: true,
  silent: true,
};

/**
 * Config keys a running process can change without dropping a connection, each paired with the
 * check that must pass before it is applied.
 *
 * Validation and application live in one entry on purpose. `yaml.load` produces values that the
 * AgentwallConfig type merely asserts, so every key here has to re-establish at runtime what
 * the type claims, and a future key added without a validator would silently trust the file.
 *
 * Deliberately two keys. Everything else in agentwall.config.yaml is captured at boot by
 * something that cannot be re-pointed while it is serving: the HTTP listener owns host and
 * port, the forward and transparent proxies close over `enforcement.mode` and the egress
 * allowlists, and the approval gate, flood guard, watchdog, DLP, telemetry, and audit sinks are
 * each constructed once with their section as a constructor argument.
 *
 * src/index.ts argues that a mode or allowlist change needing a restart is the correct ceremony
 * for a change that can take an agent fleet offline. Reload does not overturn that decision, it
 * reports it. A reload that pretended to apply those keys would be strictly worse than one that
 * names them, because the operator would stop looking.
 */
interface LiveConfigKey {
  /** Null when the incoming value is usable, otherwise the reason the whole reload is refused. */
  validate: (next: AgentwallConfig) => string | null;
  /**
   * Put the value in force. Returns false when THIS process cannot, which is reported as
   * restart-required rather than as an error. Never throws: validate has already run.
   */
  apply: (next: AgentwallConfig, target: LiveConfigTarget) => boolean;
}

interface LiveConfigTarget {
  config: AgentwallConfig;
  engine: PolicyEngine;
  setLogLevel?: (level: string) => void;
}

const LIVE_CONFIG_KEYS: Record<string, LiveConfigKey> = {
  logLevel: {
    validate: (next) =>
      PINO_LEVELS[next.logLevel] === true
        ? null
        : `invalid logLevel ${JSON.stringify(next.logLevel)}. Valid levels are ${Object.keys(PINO_LEVELS).join(", ")}.`,
    apply: (next, target) => {
      if (!target.setLogLevel) {
        return false;
      }
      target.setLogLevel(next.logLevel);
      target.config.logLevel = next.logLevel;
      return true;
    },
  },
  "policy.defaultDecision": {
    // loadConfig refuses anything but allow or deny before this runs, so this is the second of
    // two independent checks on the value that decides every unmatched request. Kept because
    // the cost is one comparison and the failure mode it guards is a firewall that fails open.
    validate: (next) =>
      next.policy.defaultDecision === "allow" || next.policy.defaultDecision === "deny"
        ? null
        : `invalid policy.defaultDecision ${JSON.stringify(next.policy.defaultDecision)}. Valid values are "allow" and "deny".`,
    apply: (next, target) => {
      // Bumps the snapshot version even though no rule changed: the same request evaluated
      // before and after gets a different answer, so it is a different policy.
      target.engine.setDefaultDecision(next.policy.defaultDecision);
      target.config.policy.defaultDecision = next.policy.defaultDecision;
      return true;
    },
  },
};

export const LIVE_APPLIABLE_CONFIG_KEYS = Object.keys(LIVE_CONFIG_KEYS);

export interface ReloadCoordinatorOptions {
  engine: PolicyEngine;
  /**
   * The live config object, mutated in place for applied keys ONLY.
   *
   * RuntimeState holds this same object by reference, so writing a key the process did not
   * actually adopt would make the dashboard report a value that is not in force. Keys outside
   * LIVE_APPLIABLE_CONFIG_KEYS are therefore left at their boot values on purpose.
   */
  config: AgentwallConfig;
  policyRuntime?: FileBackedPolicyRuntime;
  logger: LoggerLike;
  /** Applies `logLevel`. Supplied by the server so this module does not need the Fastify instance. */
  setLogLevel?: (level: string) => void;
}

function canonical(value: unknown): string {
  return JSON.stringify(value ?? null);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Dotted paths of every leaf that differs between two configs.
 *
 * Arrays compare whole rather than element-wise, because `egress.allowedHosts` is one operator
 * decision and reporting `egress.allowedHosts.3` would describe the edit instead of the change.
 */
function diffConfigKeys(before: unknown, after: unknown, prefix: string, out: string[]): void {
  if (isPlainObject(before) && isPlainObject(after)) {
    for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
      // Derived from the resolution walk rather than authored, so it is not an operator-visible
      // change and would appear as a spurious restart-required key for a caller-built config.
      if (prefix === "" && key === "sourcePath") continue;
      diffConfigKeys(before[key], after[key], prefix === "" ? key : `${prefix}.${key}`, out);
    }
    return;
  }

  if (canonical(before) !== canonical(after)) {
    out.push(prefix);
  }
}

function diffRules(before: DeclarativePolicyRule[], after: DeclarativePolicyRule[]): RuleDiff {
  const beforeById = new Map(before.map((rule) => [rule.id, canonical(rule)]));
  const afterById = new Map(after.map((rule) => [rule.id, canonical(rule)]));

  const added: string[] = [];
  const modified: string[] = [];
  for (const [id, serialized] of afterById) {
    const previous = beforeById.get(id);
    if (previous === undefined) {
      added.push(id);
    } else if (previous !== serialized) {
      modified.push(id);
    }
  }

  const removed = [...beforeById.keys()].filter((id) => !afterById.has(id));
  return { added: added.sort(), removed: removed.sort(), modified: modified.sort() };
}

function hashFile(filePath: string | null): string {
  if (filePath === null) {
    return NO_POLICY_FILE_HASH;
  }

  try {
    return createHash("sha256").update(fs.readFileSync(filePath, "utf-8")).digest("hex");
  } catch {
    // Unreadable is indistinguishable from absent for the purpose of a hash, and a reload that
    // could not read the file reports its error separately.
    return NO_POLICY_FILE_HASH;
  }
}

export class ReloadCoordinator {
  private readonly engine: PolicyEngine;
  private readonly config: AgentwallConfig;
  private readonly policyRuntime?: FileBackedPolicyRuntime;
  private readonly logger: LoggerLike;
  private readonly setLogLevel?: (level: string) => void;
  private signalHandler?: () => void;
  private lastReport: ReloadReport | null = null;
  /**
   * The definitions and file hash behind the ruleset currently in the engine.
   *
   * Owned here because this class is the only thing that moves the engine, and because the
   * watcher path cannot recover them: FileBackedPolicyRuntime.start calls reload() itself and
   * only then invokes the callback, so by the time this class sees a watch event the runtime
   * already reports the NEW definitions. Reading the before-state back from the runtime would
   * report every rule as added on the first watch event and an empty diff on every one after,
   * which is wrong evidence on an append-only chain and worse than none.
   */
  private appliedDefinitions: DeclarativePolicyRule[];
  private appliedHash: string;
  /**
   * Hash of the config file as it was when its values were last adopted.
   *
   * Cached for the same reason as the policy hash, and it is the same trap: an operator edits
   * the file and THEN triggers a reload, so hashing the file at reload time twice yields the new
   * hash in both the before and after slots and reports a change as if nothing moved. The
   * before-hash has to be remembered from when the values went into force, not re-derived.
   */
  private appliedConfigHash: string;

  constructor(options: ReloadCoordinatorOptions) {
    this.engine = options.engine;
    this.config = options.config;
    this.policyRuntime = options.policyRuntime;
    this.logger = options.logger;
    this.setLogLevel = options.setLogLevel;
    this.appliedDefinitions = options.policyRuntime?.getDeclarativeRules() ?? [];
    this.appliedHash = options.policyRuntime?.getHash() ?? NO_POLICY_FILE_HASH;
    this.appliedConfigHash = hashFile(options.config.sourcePath ?? null);
  }

  /**
   * Re-read, validate, and apply both files as one action.
   *
   * Two phases, in this order, and the order is the atomicity guarantee:
   *
   *  1. Validate the config file. `loadConfig` parses, merges, and rejects an invalid
   *     enforcement mode, and it has no side effects, so a failure here returns before the
   *     policy file has been touched at all.
   *  2. Reload the policy file. FileBackedPolicyRuntime validates it whole and keeps the last
   *     good ruleset on failure, so a failure here returns before any config key is applied.
   *
   * The consequence is that a bad file of either kind leaves BOTH subsystems exactly as they
   * were. There is no partial outcome to reason about.
   */
  reload(request: ReloadRequest): ReloadReport {
    const at = new Date().toISOString();
    const configPath = this.config.sourcePath ?? null;
    // The adopted hash, not a fresh read: the operator edits the file and THEN triggers, so a
    // fresh read here would be the NEW file in the before slot.
    const configHashBefore = this.appliedConfigHash;
    const policyPath = this.policyRuntime?.getPolicyPath() ?? null;
    // From the cache, not from the runtime: these must describe what the ENGINE is serving. The
    // two agree on this path, but the watcher path is where they diverge, and one source for
    // both keeps the diff meaning the same thing on every trigger.
    const policyHashBefore = this.appliedHash;
    const rulesBefore = this.appliedDefinitions;

    const emptyDiff: RuleDiff = { added: [], removed: [], modified: [] };
    const policy: PolicyReloadReport = {
      path: policyPath,
      applied: false,
      hashBefore: policyHashBefore,
      hashAfter: policyHashBefore,
      policyVersion: this.engine.snapshot().version,
      ruleCount: this.engine.getRules().length,
      diff: emptyDiff,
    };
    const config: ConfigReloadReport = {
      path: configPath,
      hashBefore: configHashBefore,
      hashAfter: configHashBefore,
      applied: [],
      restartRequired: [],
    };

    // Phase 1a: parse and validate the config file. Side-effect free, so a failure returns
    // before the policy file has been touched at all.
    let nextConfig: AgentwallConfig | null = null;
    const changedConfigKeys: string[] = [];
    if (configPath !== null) {
      try {
        nextConfig = loadConfig(configPath);
        config.hashAfter = hashFile(configPath);
      } catch (error) {
        config.error = error instanceof Error ? error.message : String(error);
        return this.finish(request, at, policy, config, false);
      }

      // Phase 1b: validate every CHANGED key this process would actually put in force.
      //
      // Changed keys only. A key that did not change is already in force, so refusing the
      // reload over it would block the operator from fixing something else without making the
      // running process any safer.
      //
      // This phase exists because the apply step is not required to be total: pino throws on an
      // unrecognised level, and a throw during application would land after the policy swap and
      // leave exactly the half-applied state the two-phase split is for.
      diffConfigKeys(this.config, nextConfig, "", changedConfigKeys);
      changedConfigKeys.sort();
      const invalid = changedConfigKeys
        .map((key) => LIVE_CONFIG_KEYS[key]?.validate(nextConfig as AgentwallConfig) ?? null)
        .filter((message): message is string => message !== null);
      if (invalid.length > 0) {
        config.error = `agentwall: ${invalid.join(" ")} Refusing the whole reload; nothing was changed.`;
        return this.finish(request, at, policy, config, false);
      }
    }

    // Phase 2: reload policy. A refused file leaves the running ruleset alone, and returning
    // here means no config key was applied either.
    let policyResult: ReloadResult | null = null;
    if (this.policyRuntime) {
      policyResult = this.policyRuntime.reload();
      policy.hashAfter = policyResult.hash;
      if (!policyResult.reloaded) {
        policy.error = policyResult.error?.message ?? "Failed to reload policy file";
        return this.finish(request, at, policy, config, false);
      }
    }

    // Both files are known good from here on. Nothing below can fail in a way that leaves a
    // subsystem half-changed: what remains is pointer swaps and scalar assignments.
    if (policyResult) {
      policy.diff = diffRules(rulesBefore, policyResult.definitions);
      policy.applied =
        policy.diff.added.length > 0 || policy.diff.removed.length > 0 || policy.diff.modified.length > 0;
      this.engine.replaceRules([...builtinRules, ...policyResult.rules]);
      this.appliedDefinitions = policyResult.definitions;
      this.appliedHash = policyResult.hash;
    }

    if (nextConfig) {
      const target: LiveConfigTarget = {
        config: this.config,
        engine: this.engine,
        setLogLevel: this.setLogLevel,
      };
      for (const key of changedConfigKeys) {
        const live = LIVE_CONFIG_KEYS[key];
        if (live && live.apply(nextConfig, target)) {
          config.applied.push(key);
        } else {
          config.restartRequired.push(key);
        }
      }

      // Adopted now, so the NEXT reload reports this as its before-hash. Recorded even when every
      // changed key turned out to be restart-required: the process has read and accepted this
      // file version, and the restart-required list is the honest account of which of its values
      // are not in force.
      this.appliedConfigHash = config.hashAfter;
    }

    // Read once, after both subsystems have moved, so it names the ruleset now in force rather
    // than an intermediate that no request ever saw.
    policy.policyVersion = this.engine.snapshot().version;
    policy.ruleCount = this.engine.getRules().length;

    return this.finish(request, at, policy, config, true);
  }

  /**
   * Apply and record a reload the policy runtime already performed on its own.
   *
   * Two callers, both of which reload inside FileBackedPolicyRuntime before this class sees
   * anything: the file watcher, which predates this coordinator, and the dashboard rule-writing
   * controls, which write the file and reload it in one call. Validation and rejection have
   * therefore already happened. What is left is moving the engine and getting the change on the
   * chain, which neither path did before.
   *
   * Config is not re-read here. The watcher watches the policy file only, and a dashboard rule
   * write says nothing about the config file, so reporting config hashes as unchanged is
   * accurate rather than lazy.
   */
  applyExternalReload(result: ReloadResult, request: ReloadRequest): ReloadReport {
    const at = new Date().toISOString();
    const configPath = this.config.sourcePath ?? null;
    // The adopted hash in both slots: this action did not read the config file, so its values are
    // exactly as in force. Hashing the file here instead would report whatever an operator happens
    // to have saved but not yet reloaded, which is a claim this path cannot make.
    const configHash = this.appliedConfigHash;
    const config: ConfigReloadReport = {
      path: configPath,
      hashBefore: configHash,
      hashAfter: configHash,
      applied: [],
      restartRequired: [],
    };

    const policy: PolicyReloadReport = {
      path: this.policyRuntime?.getPolicyPath() ?? null,
      applied: false,
      hashBefore: this.appliedHash,
      hashAfter: result.hash,
      policyVersion: this.engine.snapshot().version,
      ruleCount: this.engine.getRules().length,
      diff: { added: [], removed: [], modified: [] },
    };

    if (!result.reloaded) {
      policy.error = result.error?.message ?? "Failed to reload policy file";
      // `hashAfter` stays the REFUSED file's hash, matching reload(). On a rejected reload the
      // pair reads as "this version was refused, that version is still in force", which is what
      // lets an operator identify the exact bytes that failed. `ok: false` and `error` are what
      // say nothing was applied; the hash is evidence, not a claim about what is running.
      return this.finish(request, at, policy, config, false);
    }

    policy.diff = diffRules(this.appliedDefinitions, result.definitions);
    policy.applied =
      policy.diff.added.length > 0 || policy.diff.removed.length > 0 || policy.diff.modified.length > 0;
    this.engine.replaceRules([...builtinRules, ...result.rules]);
    this.appliedDefinitions = result.definitions;
    this.appliedHash = result.hash;
    policy.policyVersion = this.engine.snapshot().version;
    policy.ruleCount = this.engine.getRules().length;

    return this.finish(request, at, policy, config, true);
  }

  /** The report from the most recent reload attempt, or null if none has run. */
  getLastReport(): ReloadReport | null {
    return this.lastReport;
  }

  /**
   * State an operator needs before deciding to reload: what is loaded, what is on disk, and what
   * a reload can and cannot change.
   *
   * Both hashes are reported for each file rather than one. When `hash` and `hashOnDisk` differ,
   * somebody has saved an edit that is not in force yet, and that is the single most useful thing
   * this endpoint can tell an operator who is about to reload.
   */
  state(): {
    policy: { path: string | null; hash: string; hashOnDisk: string; policyVersion: number; ruleCount: number };
    config: { path: string | null; hash: string; hashOnDisk: string; liveAppliableKeys: string[] };
    lastReload: ReloadReport | null;
  } {
    const configPath = this.config.sourcePath ?? null;
    const policyPath = this.policyRuntime?.getPolicyPath() ?? null;
    return {
      policy: {
        path: policyPath,
        hash: this.appliedHash,
        hashOnDisk: hashFile(policyPath),
        policyVersion: this.engine.snapshot().version,
        ruleCount: this.engine.getRules().length,
      },
      config: {
        path: configPath,
        hash: this.appliedConfigHash,
        hashOnDisk: hashFile(configPath),
        liveAppliableKeys: [...LIVE_APPLIABLE_CONFIG_KEYS],
      },
      lastReload: this.lastReport,
    };
  }

  /**
   * Install the SIGHUP handler.
   *
   * NOT called by buildServer. Signals belong to the process, and buildServer is a library
   * function that tests and embedders call repeatedly in one process; installing from there
   * would stack a listener per instance and make one signal reload N times. src/index.ts, the
   * one place that owns the process, calls this. A test that wants the signal path calls it
   * explicitly and calls dispose() after.
   */
  installSignalHandler(): void {
    if (this.signalHandler) {
      return;
    }

    this.signalHandler = () => {
      // SIGHUP carries no reply channel, so the report goes to the log at a level an operator
      // will see whether it worked or not.
      const report = this.reload({ source: "sighup" });
      if (!report.ok) {
        this.logger.error({ report }, "SIGHUP reload REJECTED: nothing was changed");
      }
    };
    process.on("SIGHUP", this.signalHandler);
  }

  dispose(): void {
    if (this.signalHandler) {
      process.removeListener("SIGHUP", this.signalHandler);
      this.signalHandler = undefined;
    }
  }

  /**
   * Record the outcome, log it, and hand it back.
   *
   * The record is written AFTER the change is in force, never before. A record written first
   * would claim a swap that a later throw could still prevent, and the chain must only carry
   * things that happened. The cost of that order is the window this method's `audit.recorded`
   * field exists to expose.
   */
  private finish(
    request: ReloadRequest,
    at: string,
    policy: PolicyReloadReport,
    config: ConfigReloadReport,
    ok: boolean
  ): ReloadReport {
    const warnings: string[] = [];
    if (config.restartRequired.length > 0) {
      warnings.push(
        `Config keys changed in ${config.path ?? "the config file"} that a running process cannot apply: ` +
          `${config.restartRequired.join(", ")}. The file and the running process disagree about these until a restart.`
      );
    }

    const audit = this.record(request, at, policy, config, ok);
    if (!audit.recorded) {
      warnings.push(
        "This reload is NOT on the audit chain: " +
          `${audit.detail ?? "the durable audit sink refused the record"}. ` +
          (ok
            ? "The change IS in force and there is no chained evidence of it."
            : "The rejection was not recorded either.")
      );
    }

    const report: ReloadReport = {
      ok,
      source: request.source,
      operatorId: request.operatorId ?? null,
      at,
      policy,
      config,
      audit,
      warnings,
    };
    this.lastReport = report;

    if (!ok) {
      this.logger.error(
        { source: request.source, policyError: policy.error, configError: config.error },
        "Reload REJECTED: policy and config are unchanged and the previous policy is still enforcing"
      );
    } else {
      this.logger.info(
        {
          source: request.source,
          policyVersion: policy.policyVersion,
          ruleCount: policy.ruleCount,
          policyDiff: policy.diff,
          configApplied: config.applied,
          configRestartRequired: config.restartRequired,
        },
        "Reload applied"
      );
    }

    for (const warning of warnings) {
      this.logger.error({ source: request.source }, warning);
    }

    return report;
  }

  private record(
    request: ReloadRequest,
    at: string,
    policy: PolicyReloadReport,
    config: ConfigReloadReport,
    ok: boolean
  ): { recorded: boolean; eventId: string | null; detail: string | null } {
    const changedAnything =
      policy.applied || config.applied.length > 0 || config.restartRequired.length > 0;

    const reasons = [
      ok
        ? `Configuration reload applied from source '${request.source}'`
        : `Configuration reload REJECTED from source '${request.source}': nothing was changed`,
    ];
    if (policy.error) reasons.push(`Policy file refused: ${policy.error}`);
    if (config.error) reasons.push(`Config file refused: ${config.error}`);
    if (policy.diff.added.length) reasons.push(`Rules added: ${policy.diff.added.join(", ")}`);
    if (policy.diff.removed.length) reasons.push(`Rules removed: ${policy.diff.removed.join(", ")}`);
    if (policy.diff.modified.length) reasons.push(`Rules modified: ${policy.diff.modified.join(", ")}`);
    if (config.applied.length) reasons.push(`Config keys applied: ${config.applied.join(", ")}`);
    if (config.restartRequired.length) {
      reasons.push(`Config keys changed but NOT in force without a restart: ${config.restartRequired.join(", ")}`);
    }
    if (ok && !changedAnything) reasons.push("No rule or config key changed");

    const metadata: Record<string, string> = {
      reloadSource: request.source,
      // No identity for sighup or the watcher, and none is invented: see ReloadRequest.
      reloadOperator: request.operatorId ?? "none",
      reloadOutcome: ok ? (changedAnything ? "applied" : "unchanged") : "rejected",
      policyPath: policy.path ?? "none",
      policyHashBefore: policy.hashBefore,
      policyHashAfter: policy.hashAfter,
      policyVersion: String(policy.policyVersion),
      policyRuleCount: String(policy.ruleCount),
      policyRulesAdded: policy.diff.added.join(",") || "none",
      policyRulesRemoved: policy.diff.removed.join(",") || "none",
      policyRulesModified: policy.diff.modified.join(",") || "none",
      configPath: config.path ?? "none",
      configHashBefore: config.hashBefore,
      configHashAfter: config.hashAfter,
      configKeysApplied: config.applied.join(",") || "none",
      configKeysRestartRequired: config.restartRequired.join(",") || "none",
    };
    if (request.reason !== undefined) metadata.reloadReason = request.reason;
    if (policy.error !== undefined) metadata.policyError = policy.error;
    if (config.error !== undefined) metadata.configError = config.error;

    const ctx: AgentContext = {
      agentId: "agentwall",
      sessionId: "agentwall:reload",
      plane: "governance",
      action: "config:reload",
      payload: {
        source: request.source,
        operatorId: request.operatorId ?? null,
        reason: request.reason ?? null,
        at,
        policy,
        config,
      },
      metadata,
      flow: {
        direction: "internal",
        target: "agentwall-control-plane",
        highRisk: false,
      },
    };

    const result: PolicyResult = {
      // The verdict on the change, following the same convention as the lockdown records: a
      // refused reload is a denied change, and it is worth alerting on because somebody with
      // write access to the policy file produced something the parser would not take.
      decision: ok ? "allow" : "deny",
      riskLevel: ok ? (changedAnything ? "medium" : "low") : "high",
      matchedRules: [],
      reasons,
      requiresApproval: false,
      highRiskFlow: false,
      detections: [],
    };

    // Whether the record reached the chain is read from the logger's own drop counters rather
    // than reimplemented here. emit() offers the record to the durable sink and, if the sink
    // refuses, counts it and leaves the chain index alone so the file stays contiguous. A
    // change in `dropped` across this call is therefore exactly "this record was not chained".
    const droppedBefore = auditDropStats().dropped;
    try {
      const event = emit(ctx, result);
      const stats = auditDropStats();
      if (stats.dropped > droppedBefore) {
        return { recorded: false, eventId: null, detail: stats.reason ?? "durable audit sink refused the record" };
      }
      return { recorded: true, eventId: event.id, detail: null };
    } catch (error) {
      // The change is already in force at this point, so the reload is not failed over a
      // missing record. It is reported instead, loudly, by the caller.
      return {
        recorded: false,
        eventId: null,
        detail: error instanceof Error ? error.message : String(error),
      };
    }
  }
}
