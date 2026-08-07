import { randomBytes } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { type OnboardingMode, writeStarterFiles } from "./onboarding";

export interface LocalSetupOptions {
  mode: OnboardingMode;
  host: string;
  port: number;
  allowedHosts: string[];
  lanAccess: boolean;
  force: boolean;
}

export interface LocalSetupResult {
  configPath: string;
  policyPath: string;
  environmentPath: string;
  auditPath: string;
  dashboardUrl: string;
  created: boolean;
}

const OPERATOR_DIRECTORY = ".agentwall";
const OPERATOR_ENVIRONMENT = "operator.env";
const AUDIT_FILE = "audit.jsonl";
const DEFAULT_PROXY_PORT = "8899";

const GENERATED_ENVIRONMENT_KEYS = [
  "AGENTWALL_AGENT_HOME",
  "AGENTWALL_ALLOW_LOOPBACK_DEV",
  "AGENTWALL_AUDIT_FILE",
  "AGENTWALL_CA_DIR",
  "AGENTWALL_CONFIG",
  "AGENTWALL_FLEET_EVIDENCE",
  "AGENTWALL_LOCKDOWN_FILE",
  "AGENTWALL_OPERATOR_TOKEN",
  "AGENTWALL_PROXY_HOST",
  "AGENTWALL_PROXY_LEDGER",
  "AGENTWALL_PROXY_PORT",
] as const;

const GENERATED_ENVIRONMENT_KEY_SET = new Set<string>(GENERATED_ENVIRONMENT_KEYS);

function applyMode(filePath: string, mode: number): void {
  try {
    fs.chmodSync(filePath, mode);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "ENOSYS" && code !== "EPERM" && code !== "EINVAL") throw error;
  }
}

function existingRegularFile(filePath: string): boolean {
  try {
    const entry = fs.lstatSync(filePath);
    if (entry.isSymbolicLink() || !entry.isFile()) {
      throw new Error(`Refusing to replace unsafe generated path: ${filePath}.`);
    }
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function ensurePrivateDirectory(directoryPath: string): void {
  try {
    const entry = fs.lstatSync(directoryPath);
    if (entry.isSymbolicLink() || !entry.isDirectory()) {
      throw new Error(`Refusing to use unsafe operator directory: ${directoryPath}.`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    fs.mkdirSync(directoryPath, { mode: 0o700 });
  }
  applyMode(directoryPath, 0o700);
}

function appendGeneratedIgnores(baseDir: string): void {
  const gitignorePath = path.join(baseDir, ".gitignore");
  const exists = existingRegularFile(gitignorePath);
  const current = exists ? fs.readFileSync(gitignorePath, "utf8") : "";
  const lines = current.split(/\r?\n/);
  const missing = [OPERATOR_DIRECTORY + "/", "agentwall-approvals.json", AUDIT_FILE]
    .filter((entry) => !lines.includes(entry));
  if (missing.length === 0) return;

  const separator = current.length > 0 && !current.endsWith("\n") ? "\n" : "";
  fs.writeFileSync(gitignorePath, `${current}${separator}${missing.join("\n")}\n`, { flag: exists ? "w" : "wx" });
}

function assertSafeEnvironmentPath(filePath: string): void {
  if (/\r|\n/.test(filePath)) {
    throw new Error("The setup directory cannot contain a line break.");
  }
}

export function createLocalOperatorFiles(baseDir: string, options: LocalSetupOptions): LocalSetupResult {
  const resolvedBaseDir = path.resolve(baseDir);
  const configPath = path.join(resolvedBaseDir, "agentwall.config.yaml");
  const policyPath = path.join(resolvedBaseDir, "policy.yaml");
  const operatorDirectory = path.join(resolvedBaseDir, OPERATOR_DIRECTORY);
  const environmentPath = path.join(operatorDirectory, OPERATOR_ENVIRONMENT);
  const auditPath = path.join(resolvedBaseDir, AUDIT_FILE);
  const proxyLedgerPath = path.join(operatorDirectory, "proxy-ledger.jsonl");

  assertSafeEnvironmentPath(resolvedBaseDir);
  fs.mkdirSync(resolvedBaseDir, { recursive: true });

  const existingGeneratedFiles = [configPath, policyPath, environmentPath].filter(existingRegularFile);
  if (!options.force && existingGeneratedFiles.length > 0) {
    throw new Error(
      `Refusing to overwrite existing setup file(s): ${existingGeneratedFiles.join(", ")}. Re-run with force to replace them.`,
    );
  }

  ensurePrivateDirectory(operatorDirectory);

  const starter = writeStarterFiles(resolvedBaseDir, {
    mode: options.mode,
    host: options.host,
    port: options.port,
    allowedHosts: options.allowedHosts,
    lanAccess: options.lanAccess,
  });

  const token = randomBytes(32).toString("hex");
  const environment = [
    `AGENTWALL_OPERATOR_TOKEN=${token}`,
    `AGENTWALL_AUDIT_FILE=${auditPath}`,
    "AGENTWALL_PROXY_HOST=127.0.0.1",
    `AGENTWALL_PROXY_PORT=${DEFAULT_PROXY_PORT}`,
    `AGENTWALL_PROXY_LEDGER=${proxyLedgerPath}`,
    "",
  ].join("\n");
  fs.writeFileSync(environmentPath, environment, { mode: 0o600, flag: options.force ? "w" : "wx" });
  applyMode(environmentPath, 0o600);
  appendGeneratedIgnores(resolvedBaseDir);

  return {
    configPath: starter.configPath,
    policyPath: starter.policyPath,
    environmentPath,
    auditPath,
    dashboardUrl: `http://${starter.config.host}:${starter.config.port}`,
    created: true,
  };
}

export function loadGeneratedEnvironment(baseDir: string): Record<string, string> {
  const generated: Record<string, string> = {};
  const environmentPath = path.resolve(baseDir, OPERATOR_DIRECTORY, OPERATOR_ENVIRONMENT);

  if (fs.existsSync(environmentPath)) {
    const lines = fs.readFileSync(environmentPath, "utf8").split(/\r?\n/);
    for (const line of lines) {
      const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
      if (!match || !GENERATED_ENVIRONMENT_KEY_SET.has(match[1])) continue;
      generated[match[1]] = match[2];
    }
  }

  for (const key of GENERATED_ENVIRONMENT_KEYS) {
    const explicit = process.env[key];
    if (explicit !== undefined) generated[key] = explicit;
  }

  return generated;
}
