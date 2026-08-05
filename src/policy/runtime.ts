import * as fs from "fs";
import * as path from "path";
import { PolicyRule } from "../types";
import {
  compileDeclarativePolicyRules,
  DeclarativePolicyFile,
  DeclarativePolicyRule,
  loadDeclarativePolicyFile,
  writeDeclarativePolicyFile,
} from "./loader";

type LoggerLike = Pick<Console, "error" | "warn">;

export interface PolicyRuntimeOptions {
  logger?: LoggerLike;
  watch?: boolean;
  watchDebounceMs?: number;
}

export interface ReloadResult {
  reloaded: boolean;
  rules: PolicyRule[];
  definitions: DeclarativePolicyRule[];
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
  private watcher?: fs.FSWatcher;
  private reloadTimer?: NodeJS.Timeout;

  constructor(policyPath: string, options: PolicyRuntimeOptions = {}) {
    this.policyPath = path.resolve(policyPath);
    this.logger = options.logger ?? console;
    this.watchEnabled = options.watch ?? true;
    this.watchDebounceMs = options.watchDebounceMs ?? 50;
    this.policyFile = loadDeclarativePolicyFile(this.policyPath);
    this.rules = compileDeclarativePolicyRules(this.policyFile);
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

  reload(): ReloadResult {
    try {
      const nextPolicyFile = loadDeclarativePolicyFile(this.policyPath);
      this.policyFile = nextPolicyFile;
      this.rules = compileDeclarativePolicyRules(nextPolicyFile);
      return { reloaded: true, rules: this.getRules(), definitions: this.getDeclarativeRules() };
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error));
      this.logger.error(`Failed to reload policy file ${this.policyPath}: ${failure.message}`);
      return { reloaded: false, rules: this.getRules(), definitions: this.getDeclarativeRules(), error: failure };
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
      return { reloaded: false, rules: this.getRules(), definitions: this.getDeclarativeRules(), error: failure };
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
