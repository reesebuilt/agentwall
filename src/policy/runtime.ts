import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { PolicyRule } from "../types";
import {
  compileDeclarativePolicyRules,
  DeclarativePolicyFile,
  DeclarativePolicyRule,
  loadDeclarativePolicyFile,
  parseDeclarativePolicyFile,
  writeDeclarativePolicyFile,
} from "./loader";

type LoggerLike = Pick<Console, "error" | "warn">;

export interface PolicyRuntimeOptions {
  logger?: LoggerLike;
  watch?: boolean;
  watchDebounceMs?: number;
}

/**
 * Stand-in hash for "no file was there". A sha256 is 64 hex characters so this cannot
 * collide with one, and a record that says `absent` is honest in a way that hashing the
 * empty string would not be.
 */
export const NO_POLICY_FILE_HASH = "absent";

export interface ReloadResult {
  reloaded: boolean;
  rules: PolicyRule[];
  definitions: DeclarativePolicyRule[];
  /**
   * sha256 of the policy file's raw bytes as read by this call, or NO_POLICY_FILE_HASH.
   *
   * Raw bytes rather than the parsed document, so an operator can reproduce it with
   * sha256sum. A comment-only edit moves this while the rule-level diff stays empty, and
   * that pair of facts is exactly the truth.
   *
   * On a REJECTED reload this is the hash of the file that was refused, NOT of the rules
   * still in force. `reloaded` tells you which one you are holding.
   */
  hash: string;
  error?: Error;
}

function cloneDefinitions(definitions: DeclarativePolicyRule[]): DeclarativePolicyRule[] {
  return JSON.parse(JSON.stringify(definitions)) as DeclarativePolicyRule[];
}

function defaultPolicyFile(): DeclarativePolicyFile {
  return { version: "1", rules: [] };
}

export class FileBackedPolicyRuntime {
  private readonly policyPath: string;
  private readonly logger: LoggerLike;
  private readonly watchEnabled: boolean;
  private readonly watchDebounceMs: number;
  private rules: PolicyRule[];
  private policyFile: DeclarativePolicyFile;
  private fileHash: string;
  private watcher?: fs.FSWatcher;
  private reloadTimer?: NodeJS.Timeout;

  constructor(policyPath: string, options: PolicyRuntimeOptions = {}) {
    this.policyPath = path.resolve(policyPath);
    this.logger = options.logger ?? console;
    this.watchEnabled = options.watch ?? true;
    this.watchDebounceMs = options.watchDebounceMs ?? 50;
    // Throws on a bad file, as before: a policy the process cannot parse at boot is a
    // startup failure, not something to run without.
    const raw = fs.readFileSync(this.policyPath, "utf-8");
    this.policyFile = parseDeclarativePolicyFile(raw);
    this.rules = compileDeclarativePolicyRules(this.policyFile);
    this.fileHash = createHash("sha256").update(raw).digest("hex");
  }

  getPolicyPath(): string {
    return this.policyPath;
  }

  getRules(): PolicyRule[] {
    return [...this.rules];
  }

  getDeclarativeRules(): DeclarativePolicyRule[] {
    return cloneDefinitions(this.policyFile.rules);
  }

  /** sha256 of the file the rules currently in force were compiled from. */
  getHash(): string {
    return this.fileHash;
  }

  reload(): ReloadResult {
    let hash = NO_POLICY_FILE_HASH;
    try {
      // ONE read. The hash and the rules therefore describe the same bytes; two reads would
      // let a concurrent write land between them.
      const raw = fs.readFileSync(this.policyPath, "utf-8");
      hash = createHash("sha256").update(raw).digest("hex");
      const nextPolicyFile = parseDeclarativePolicyFile(raw);
      // Compile before ANY field moves, so all three assignments below are unreachable
      // unless every stage succeeded. The previous order assigned policyFile first, which
      // would have let a compile-stage throw leave the operator-visible declarative view
      // showing rules that were not enforcing while the engine kept the old ones. That was
      // latent, not live: compile re-runs the same validateDeclarativeRuleShape that the
      // load above already ran on the same data, so it cannot be the stage that fails. It is
      // fixed here because the next person to add a check to one path and not the other
      // would make it live without touching this file.
      const nextRules = compileDeclarativePolicyRules(nextPolicyFile);
      this.policyFile = nextPolicyFile;
      this.rules = nextRules;
      this.fileHash = hash;
      return { reloaded: true, rules: this.getRules(), definitions: this.getDeclarativeRules(), hash };
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error));
      this.logger.error(`Failed to reload policy file ${this.policyPath}: ${failure.message}`);
      // `hash` is the REFUSED file's hash when the read got that far, which is what lets an
      // operator identify the version that was rejected. The rules and definitions returned
      // alongside it are the ones still in force. `reloaded: false` distinguishes them.
      return { reloaded: false, rules: this.getRules(), definitions: this.getDeclarativeRules(), hash, error: failure };
    }
  }

  upsertDeclarativeRule(rule: DeclarativePolicyRule): ReloadResult {
    try {
      const currentPolicy = fs.existsSync(this.policyPath) ? loadDeclarativePolicyFile(this.policyPath) : defaultPolicyFile();
      const nextRules = [...currentPolicy.rules];
      const existingIndex = nextRules.findIndex((item) => item.id === rule.id);
      if (existingIndex >= 0) {
        nextRules[existingIndex] = rule;
      } else {
        nextRules.push(rule);
      }

      writeDeclarativePolicyFile(this.policyPath, {
        version: currentPolicy.version ?? "1",
        rules: nextRules,
      });

      return this.reload();
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error));
      this.logger.error(`Failed to write policy file ${this.policyPath}: ${failure.message}`);
      // Nothing was written, so the file in force is still the one this hash covers.
      return { reloaded: false, rules: this.getRules(), definitions: this.getDeclarativeRules(), hash: this.fileHash, error: failure };
    }
  }

  start(onReload: (result: ReloadResult) => void): void {
    if (!this.watchEnabled || this.watcher) {
      return;
    }

    this.watcher = fs.watch(this.policyPath, () => {
      if (this.reloadTimer) {
        clearTimeout(this.reloadTimer);
      }

      this.reloadTimer = setTimeout(() => {
        this.reloadTimer = undefined;
        onReload(this.reload());
      }, this.watchDebounceMs);
    });

    this.watcher.on("error", (error) => {
      this.logger.warn(`Policy watcher error for ${this.policyPath}: ${error.message}`);
    });
  }

  stop(): void {
    if (this.reloadTimer) {
      clearTimeout(this.reloadTimer);
      this.reloadTimer = undefined;
    }

    if (this.watcher) {
      this.watcher.close();
      this.watcher = undefined;
    }
  }
}
