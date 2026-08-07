#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import { spawnSync } from "child_process";
import { loadConfig, resolveConfigSource } from "./config";
import { defaultConfig, OnboardingMode, writeStarterFiles } from "./onboarding";
import { runOnboardCommand } from "./onboard";
import { createLocalOperatorFiles, loadGeneratedEnvironment } from "./setup";
import { runBootstrapUi } from "./bootstrap";
import { runAnchorPass, runVerify, resolvePaths } from "./audit/anchor-service";
import { runMcpWrap, runMcpHttpWrap } from "./mcp/wrap";
import type { McpBaselineMode } from "./mcp/types";
import { runDecoyCommand } from "./decoy";
import { runPerimeterCommand } from "./perimeter";
import { runSandboxCommand } from "./sandbox";
import { runInterceptCommand } from "./intercept";
import { runVerifyCaptureCommand } from "./capture/verify";
import { fleetDoctorLines, runFleetCommand } from "./fleet/command";
import {
  formatRationaleReport,
  parseRationaleArgs,
  rationaleExitCode,
  runRationale,
} from "./rationale";
import { PolicyEngine } from "./policy/engine";
import { meetsNodeFloor, nodeFloor, packageVersion } from "./version";
import { AgentRegistry, type AgentMatchSignal, type RegisteredAgent } from "./fleet/registry";
import { readCaptureHealth, type CaptureHealth, type CaptureWatermark } from "./evidence/capture";

type CliFlags = Record<string, string | boolean>;
const BOOLEAN_FLAGS = new Set(["lan", "force", "json", "confirm"]);

interface ParsedArgs {
  flags: CliFlags;
  positionals: string[];
}

interface PriorityQueueItem {
  category: string;
  title: string;
  owner: string;
  status: string;
  timestamp: string;
  summary?: string;
  primaryAction?: string;
}

interface DashboardState {
  brand: string;
  generatedAt: string;
  service: {
    status: string;
    attentionRequired: boolean;
    operatorSummary: string;
    recommendedActions?: string[];
    host: string;
    port: number;
  };
  posture: {
    highestRisk: string;
    pendingApprovals: number;
    criticalSignals: number;
    activeAgentsNow?: number;
    activeAgents: number;
    totalRequests: number;
  };
  controls: {
    approvalMode: string;
  };
  stats: {
    sessionCounts: Record<string, number>;
  };
  floodGuard?: {
    mode: string;
    blockedTotal: number;
    blockedByCategory?: Record<string, number>;
    pressureByCategory?: Record<string, number>;
    pressureBySession?: Array<{ sessionId: string; pressure: number; blocked: number }>;
    recentBlocks?: Array<{ timestamp: string; category: string; reason: string; sessionId?: string; actor?: string; pressure: number }>;
    shieldUntil?: string | null;
    sessionOverrides?: Array<{ sessionId: string; multiplier: number; expiresAt: string }>;
    operatorGuidance?: {
      status: string;
      summary: string;
      recommendedAction: string;
      hottestSessionId?: string | null;
      pressure?: number;
    };
  };
  freshness?: {
    hasLiveActivity: boolean;
    isFresh: boolean;
    lastLiveEventAt?: string | null;
  };
  sessions?: {
    recent?: Array<{ sessionId: string; status: string }>;
    statusById?: Record<string, string>;
  };
  priorityQueue: PriorityQueueItem[];
}

export function printHelp() {
  console.log(`Agentwall CLI

Usage:
  agentwall <command> [options]

Commands:
  setup               Create safe local operator files with monitor defaults
  ui                  Start the loopback setup and service control page
  init                Create agentwall.config.yaml and policy.yaml
  onboard             Mint an identity for one agent runtime and print the env it needs
  start               Start Agentwall server from current directory config
  dev                 Start in ts-node dev mode
  doctor              Validate local install, and report per-agent capture from the chain
  status              Read live dashboard state from the running Agentwall server
  anchor              Seal audit segments, sign a checkpoint, submit it off-box
  verify              Check the three audit integrity layers independently
  verify-capture      Prove one agent's traffic really passes through Agentwall
  mcp wrap            Wrap a local MCP server and gate its stdio traffic
  mcp stop <wrapper-id>  Stop one MCP HTTP wrapper managed by Agentwall
  mcp status             List managed MCP HTTP wrappers
  approval-mode       Set approval mode (auto|always|never)
  shield              Enable FloodGuard shield mode
  normal              Return FloodGuard to normal mode
  session-boost       Temporarily raise FloodGuard limits for one session
  session-reset       Clear a FloodGuard session override
  pause               Pause one runtime session
  resume              Resume one runtime session
  terminate           Terminate one runtime session
  fleet               Issue, rotate, and revoke fleet agent credentials
  perimeter           Contain an agent UID behind the transparent proxy
  sandbox             Confine one process with Landlock and seccomp (Linux, no root needed)
  intercept           Manage the local TLS interception CA (opt-in, off by default)
  decoy               Generate and inspect decoy tokens
  why                 Explain which check fires on a URL, some text, or a tool call
  version             Print version
  help                Show this message

Shared options:
  --config <path>                     Read config from a specific file
  --url <http://host:port>            Override server URL instead of config host/port

Setup options:
  --mode <monitor|guarded|strict>     Operating mode (default: monitor)
  --host <host>                       Service bind host (default: 127.0.0.1)
  --port <port>                       Service bind port (default: 3000)
  --allow-hosts <a,b,c>               Comma-separated egress allowlist (default: none)
  --lan                               Bind the service to 0.0.0.0
  --force                             Replace generated setup files

UI options:
  --host <host>                       Bootstrap bind host (default: 127.0.0.1)
  --port <port>                       Bootstrap bind port (default: 3001)
  --service-port <port>               AgentWall service port (default: 3000)

Init options:
  --mode <monitor|guarded|strict>     Operating mode (default: guarded)
  --host <host>                       Bind host (default: 127.0.0.1)
  --port <port>                       Bind port (default: 3000)
  --allow-hosts <a,b,c>               Comma-separated egress allowlist
  --lan                               Bind to 0.0.0.0
  --force                             Overwrite existing config/policy files

Doctor options:
  --audit <path>                      Chain to read capture from (default: $AGENTWALL_AUDIT_FILE)
  --json                              Print raw JSON

  Doctor writes a bookmark (capture-watermark.json, beside the chain) whenever it reads at
  least one record, so "undeclared egress since the last run" means what it says.

  Exit codes: 0 clear, 1 a check failed or traffic reached the network that policy said to
  refuse, 2 inconclusive. 2 means the question was asked and could not be answered, most
  often because the configuration itself permits undeclared egress; the output names the
  setting to change so the next run can answer.

Status options:
  --json                              Print raw JSON

Approval mode options:
  --mode <auto|always|never>          Approval routing mode (or pass as first positional)

Shield options:
  --minutes <n>                       Shield duration in minutes
  --duration-ms <n>                   Shield duration in milliseconds

Session override options:
  --session <id>                      Session ID to boost/reset
  --multiplier <n>                    Override multiplier (default: 1.5)
  --minutes <n>                       Override duration in minutes
  --duration-ms <n>                   Override duration in milliseconds

Session control options:
  --session <id>                      Session ID to pause/resume/terminate
  --note <text>                       Operator note stored with the control action
  --confirm                           Required for terminate to avoid accidental containment

MCP wrap options:
  --server-name <name>                Name recorded for the wrapped server (default: command basename)
  --agent-id <id>                     Agent the wrapped traffic is attributed to in the audit chain
  --baseline-mode <off|learn|lock>    Select inventory behavior (default: off)
  --baseline-file <path>              Set the inventory file (default: .agentwall/mcp-baselines.json)
  -- <command> [args...]              The MCP server to launch; everything after -- is passed through
  --http-upstream <url>               Wrap a remote MCP server over Streamable HTTP instead of stdio
  --http-port <n>                     Port for the local listener clients connect to (0 = ephemeral)
  --http-host <host>                  Listener interface (default: 127.0.0.1); non-loopback needs a token
  --http-auth-token-file <path>       File holding the bearer token clients must present

Perimeter options:
  plan                                Print the nftables ruleset the current spec would install
  install                             Install that ruleset (requires root)
  status                              Report whether the redirect and drop rules are present
  verify                              Check the perimeter end to end from the agent UID
  run -- <cmd>                        Run a command as the agent UID inside the perimeter
  rollback                            Remove the ruleset AgentWall installed

Sandbox options:
  probe                               Measure this kernel's Landlock ABI and seccomp support
  plan                                Print the profile that would be applied, and its gaps
  build                               Compile the launcher from native/agentwall-sandbox.c
  run -- <cmd>                        Apply the profile and exec the command
  --workdir <path>                    The one directory the command may write to
  --allow-read/-write/-exec <path>    Widen the profile by one path. Repeatable.
  --allow-tcp/-bind <port>            Permit one TCP port. Repeatable. Needs Landlock ABI 4.
  --seccomp <off|errno|kill>          Syscall filter action (default: errno)
  --require-abi <n>                   Refuse to run below this Landlock ABI

Decoy options:
  --kind <kind>                       Decoy kind: aws-access-key, github-pat, openai-key, generic-secret, url
  --label <text>                      Operator label kept with the token and folded into its env var name
  --out <path>                        Append the generated token to this decoy file (written at mode 0600)
  --file <path>                       Decoy file to list; refuses one that group or other can read

Fleet credential options (see \`agentwall fleet\` for the full list):
  --agent <id>                        Declared agent the credential speaks for
  --credential <id>                   One issued credential, for revoke
  --overlap <duration>                rotate: how long the old credential keeps working (15m default)
  --reason <text>                     revoke: recorded beside the tombstone

Why options:
  --kind <url|text|tool>              Subject kind (inferred from the subject when omitted)
  --tool <name>                       Tool name for --kind tool
  --args <json>                       JSON object of tool arguments for --kind tool
  --json                              Print the whole result as JSON

Verify-capture options:
  --agent <id>                        Declared agent the traffic must bind to (required)
  --command '<cmd>'                   Command that makes the agent fetch; '{url}' is substituted
  --audit <path>                      Audit chain file (default: $AGENTWALL_AUDIT_FILE)
  --proxy <url>                       Proxy the agent uses; enables the independent peer-pid check
  --host <addr>                       Interface the canary binds (default: 127.0.0.1)
  --timeout <ms>                      How long to wait for the fetch (default: 120000)
  --settle-ms <ms>                    How long to wait for the chain to catch up (default: 3000)
  --json                              Print the whole report as JSON
`);
}

export function parseFlags(args: string[]): ParsedArgs {
  const flags: CliFlags = {};
  const positionals: string[] = [];

  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }

    const key = token.slice(2);
    const next = args[i + 1];
    if (BOOLEAN_FLAGS.has(key)) {
      flags[key] = true;
      continue;
    }
    if (!next || next.startsWith("--")) {
      flags[key] = true;
      continue;
    }

    flags[key] = next;
    i += 1;
  }

  return { flags, positionals };
}

function runNodeScript(args: string[]): void {
  const result = spawnSync(process.execPath, args, {
    stdio: "inherit",
    env: { ...process.env, ...loadGeneratedEnvironment(process.cwd()) },
  });
  process.exit(result.status ?? 1);
}

export function commandSetup(flags: CliFlags): void {
  const modeInput = String(flags.mode || "monitor").toLowerCase();
  const mode: OnboardingMode = modeInput === "guarded" || modeInput === "strict" ? modeInput : "monitor";
  const port = Number(flags.port || defaultConfig.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("--port must be an integer from 1 through 65535.");
  }

  const result = createLocalOperatorFiles(process.cwd(), {
    mode,
    host: String(flags.host || defaultConfig.host),
    port,
    allowedHosts: String(flags["allow-hosts"] || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    lanAccess: Boolean(flags.lan),
    force: Boolean(flags.force),
  });

  console.log("Created AgentWall local operator files:");
  console.log(`- ${result.configPath}`);
  console.log(`- ${result.policyPath}`);
  console.log(`- ${result.environmentPath}`);
  console.log(`- ${result.auditPath}`);
  console.log(`Dashboard: ${result.dashboardUrl}`);
  console.log("Next: agentwall start");
  console.log("Then: agentwall doctor");
}

export async function commandUi(flags: CliFlags): Promise<void> {
  await runBootstrapUi({
    baseDir: process.cwd(),
    host: String(flags.host || "127.0.0.1"),
    port: Number(flags.port || 3001),
    servicePort: Number(flags["service-port"] || defaultConfig.port),
  });
}

function commandInit(flags: CliFlags) {
  const modeInput = String(flags.mode || "guarded").toLowerCase();
  const mode: OnboardingMode = modeInput === "monitor" || modeInput === "strict" ? modeInput : "guarded";

  const host = String(flags.host || defaultConfig.host);
  const port = Number(flags.port || defaultConfig.port);
  const allowedHosts = String(flags["allow-hosts"] || "api.openai.com")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const lanAccess = Boolean(flags.lan);
  const force = Boolean(flags.force);

  const configPath = path.resolve(process.cwd(), "agentwall.config.yaml");
  const policyPath = path.resolve(process.cwd(), "policy.yaml");

  if (!force && (fs.existsSync(configPath) || fs.existsSync(policyPath))) {
    console.error("Refusing to overwrite existing agentwall.config.yaml or policy.yaml. Re-run with --force.");
    process.exit(1);
  }

  const { config } = writeStarterFiles(process.cwd(), {
    mode,
    host,
    port: Number.isFinite(port) ? port : defaultConfig.port,
    allowedHosts,
    lanAccess,
  });

  console.log("Created Agentwall starter files:");
  console.log(`- ${configPath}`);
  console.log(`- ${policyPath}`);
  console.log(`\nRun: agentwall start  (dashboard: http://${config.host}:${config.port})`);
}

/**
 * Read doctor's bookmark in the chain.
 *
 * A missing, unreadable, or malformed bookmark is not an error: it means "no previous run",
 * which is a state doctor has to handle on every fresh install anyway.
 */
function readCaptureWatermark(file: string): CaptureWatermark | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  if (!("chainIndex" in parsed) || typeof parsed.chainIndex !== "number") return null;
  if (!("at" in parsed) || typeof parsed.at !== "string") return null;
  return { chainIndex: parsed.chainIndex, at: parsed.at };
}

/**
 * What the capture section concluded.
 *
 * INCONCLUSIVE is a first-class outcome, not a soft failure. A check that can only say
 * "clean" or "escape" has to pick one when the evidence supports neither, and both wrong
 * answers are expensive: a false clean hides the thing the tool exists to catch, and a false
 * escape accuses an operator of a breach their own configuration prescribes. The second is
 * the one that gets a check switched off.
 */
type CaptureVerdict = "clear" | "inconclusive" | "escape";

interface DoctorCapture {
  /** Null when there was no chain to read. */
  health: CaptureHealth | null;
  /** The config file every fleet claim below is about. Null when built-in defaults were used. */
  configSource: string | null;
  /** Why there was no chain, in the words the operator needs. */
  unavailable: string | null;
  /**
   * The fleet declaration did not load here. `environmental` marks the case where the cause
   * is doctor's OWN environment rather than the file: an `env:VAR` credential the service
   * may well have and this shell does not. Convicting a working config on that basis is the
   * false alarm this flag exists to prevent.
   */
  fleetError: { message: string; environmental: boolean } | null;
  watermarkPath: string | null;
  /** The bookmark could not be advanced, so "since the last run" cannot be trusted again. */
  watermarkError: string | null;
  verdict: CaptureVerdict;
  /** The one-line reason for that verdict, for whatever reads the JSON. */
  verdictReason: string;
}

/**
 * Load the declared fleet the way the server does, and say whether a failure is the file's
 * fault or this shell's.
 *
 * The distinction is not cosmetic. `env:VAR` credentials are resolved at load from the
 * process environment, so doctor run from an operator's shell can fail on a declaration a
 * service started by systemd loads perfectly. Reporting that as a broken fleet would send
 * someone to fix a file that is correct.
 */
function loadDoctorFleet(flags: CliFlags): {
  agents: readonly RegisteredAgent[];
  unmatched: "global" | "deny";
  error: { message: string; environmental: boolean } | null;
} {
  let config;
  try {
    config = loadCliConfig(flags);
  } catch (error) {
    return {
      agents: [],
      unmatched: "global",
      error: { message: error instanceof Error ? error.message : String(error), environmental: false },
    };
  }

  const fleet = config.fleet;
  if (!fleet || fleet.agents.length === 0) return { agents: [], unmatched: fleet?.unmatched ?? "global", error: null };

  // Checked BEFORE constructing the registry, because the registry throws on the first
  // missing variable and the operator wants all of them named at once.
  const missing: string[] = [];
  for (const agent of fleet.agents) {
    const credential = agent.match.credential;
    if (credential === undefined || !credential.startsWith("env:")) continue;
    const name = credential.slice("env:".length).trim();
    if (name.length > 0 && !process.env[name]) missing.push(`$${name} (agent "${agent.id}")`);
  }
  if (missing.length > 0) {
    return {
      agents: [],
      unmatched: fleet.unmatched,
      error: {
        message: `${missing.join(", ")} unset in this shell, and the declaration reads a credential from it`,
        environmental: true,
      },
    };
  }

  try {
    return { agents: new AgentRegistry(fleet).list(), unmatched: fleet.unmatched, error: null };
  } catch (error) {
    return {
      agents: [],
      unmatched: fleet.unmatched,
      error: { message: error instanceof Error ? error.message : String(error), environmental: false },
    };
  }
}

/**
 * Answer "is everything on this host still being captured" from what is already on disk.
 *
 * Offline on purpose. The moment you most want to know whether an agent is escaping is the
 * moment the serving process is suspect, and a check that has to ask that process is a check
 * that goes quiet exactly then. Everything here comes off the chain and the config, and
 * every claim it prints is scoped to the file it actually read: doctor cannot see another
 * process's environment and must not describe one.
 */
function collectDoctorCapture(flags: CliFlags): DoctorCapture {
  const configSource = resolveConfigSource(typeof flags.config === "string" ? flags.config : undefined);
  const base = {
    health: null,
    unavailable: null,
    configSource,
    fleetError: null,
    watermarkPath: null,
    watermarkError: null,
    verdict: "clear" as CaptureVerdict,
    verdictReason: "",
  };

  const auditPath = typeof flags.audit === "string" ? flags.audit : process.env.AGENTWALL_AUDIT_FILE;
  if (!auditPath) {
    return {
      ...base,
      verdictReason: "no chain was named, so capture was not assessed",
      unavailable:
        "doctor was not told which chain to read. Set AGENTWALL_AUDIT_FILE, or pass --audit <path>. " +
        "If the service was started with AGENTWALL_AUDIT_FILE set in its own environment, that is the " +
        "file to point at: doctor cannot see another process's environment.",
    };
  }

  const fleet = loadDoctorFleet(flags);

  // Beside the chain, because that is what it bookmarks: move the chain and the bookmark
  // travels, delete the chain and the bookmark goes with it. The name deliberately does not
  // start with the audit file's own name, because segment discovery globs `<audit>.*`.
  const watermarkPath = path.join(path.dirname(auditPath), "capture-watermark.json");
  const since = readCaptureWatermark(watermarkPath);

  let health: CaptureHealth;
  try {
    health = readCaptureHealth({ auditPath }, { agents: fleet.agents, unmatched: fleet.unmatched, since });
  } catch (error) {
    return {
      ...base,
      fleetError: fleet.error,
      watermarkPath,
      verdict: "inconclusive",
      verdictReason: "the chain could not be read",
      unavailable: `${auditPath} could not be read: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  if (!health.chainPresent) {
    return {
      ...base,
      health,
      fleetError: fleet.error,
      watermarkPath,
      verdictReason: "nothing has been written to the named chain",
      unavailable:
        `nothing has been written to ${auditPath}. If the service is recording somewhere else, ` +
        "point --audit at that file.",
    };
  }

  // Advancing the bookmark is what makes the next run's alarm mean anything, so failing to
  // write it leaves every later run unable to tell new from old.
  let watermarkError: string | null = null;
  if (health.watermark !== null) {
    try {
      fs.writeFileSync(watermarkPath, `${JSON.stringify(health.watermark)}\n`);
    } catch (error) {
      watermarkError = error instanceof Error ? error.message : String(error);
    }
  }

  const undeclared = health.undeclared;
  // Only counted against a previous run. On the first run there is no "since", so the whole
  // chain is reported as a baseline and nothing is alarmed: a cron seeds on its first firing
  // and judges from the second.
  const comparable = health.since !== null;
  let verdict: CaptureVerdict = "clear";
  let verdictReason = "no undeclared egress reached the network since the last run";

  if (comparable && undeclared.escapedSinceLastRun > 0) {
    verdict = "escape";
    verdictReason =
      `${undeclared.escapedSinceLastRun} undeclared connection(s) reached the network under a posture ` +
      "that refuses undeclared egress";
  } else if (comparable && undeclared.permittedByConfigSinceLastRun.length > 0) {
    verdict = "inconclusive";
    verdictReason =
      "undeclared egress reached the network and the configuration in force permitted it, so an escape " +
      "and the configured behaviour cannot be told apart";
  } else if (watermarkError !== null) {
    verdict = "inconclusive";
    verdictReason = "the bookmark could not be advanced, so no future run can tell new records from old";
  } else if (fleet.error?.environmental === true) {
    verdict = "inconclusive";
    verdictReason = "the fleet declaration could not be loaded in this shell, so no agent was assessed";
  }

  return { ...base, health, fleetError: fleet.error, watermarkPath, watermarkError, verdict, verdictReason };
}

function formatByteCount(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = value / 1024;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled.toFixed(1)} ${units[unit]}`;
}

/** What each tier actually proves, wrapped for a terminal rather than left to the shell. */
const TIER_ADVICE: Record<AgentMatchSignal, string[]> = {
  credential: [
    "A presented secret. The only tier that survives a process renaming itself, and the",
    "only one that works across a host boundary.",
  ],
  "uid+comm": [
    "A kernel-owned uid plus a self-chosen name. As strong as the uid on its own; the",
    "name adds precision, not proof.",
  ],
  uid: [
    "A kernel-owned uid. The process cannot change it, but every process running as that",
    "user shares the identity.",
  ],
  comm: [
    "A name the process chose for itself. Anything on this host can claim it, including",
    "whatever you are trying to catch. Bind by uid, or by credential if the agent can be",
    "made to send Proxy-Authorization.",
  ],
  none: ["Nothing bound this at all."],
};

/** The capture section, printed after the install checks. Returns lines, does not exit. */
function renderCaptureSection(capture: DoctorCapture): { lines: string[]; failures: number } {
  const lines: string[] = ["", "Capture"];
  let failures = 0;
  const from = capture.configSource ?? "built-in defaults";

  if (capture.fleetError !== null) {
    if (capture.fleetError.environmental) {
      // NOT a failure, and not a claim about the service. An `env:VAR` credential is read
      // from the environment of whoever loads the config, so a shell without the variable
      // cannot distinguish a broken declaration from a perfectly good one it is not
      // entitled to resolve. Convicting the file here sends someone to fix a correct file.
      lines.push(`⚠️  the fleet declaration in ${from} could not be loaded in this shell.`);
      lines.push(`   ${capture.fleetError.message}.`);
      lines.push("   A service started with that variable set loads this file fine, so nothing here says it is");
      lines.push("   broken. No agent was assessed. Re-run with the variable set to get an answer.");
    } else {
      failures += 1;
      lines.push(`❌ the fleet declaration in ${from} did not load: ${capture.fleetError.message}`);
      lines.push("   The fleet section is validated when a process loads this file, so a start against it fails");
      lines.push("   the same way. No agent was assessed.");
    }
  }

  const health = capture.health;
  if (capture.unavailable !== null || health === null) {
    lines.push(`⚠️  ${capture.unavailable ?? "nothing to read"}`);
    return { lines, failures };
  }

  lines.push(`   chain            ${health.auditPath}`);
  lines.push(`   config           ${from}`);
  lines.push(`   egress records   ${health.egressRecords} read${health.truncated ? " (capped, newest first)" : ""}`);
  lines.push(
    health.since === null
      ? "   since last run   no previous run recorded, so this run is the baseline"
      : `   since last run   chain index ${health.since.chainIndex}, ${formatRelative(health.since.at)}`,
  );

  if (capture.watermarkError !== null) {
    lines.push("");
    lines.push(`⚠️  the capture bookmark at ${capture.watermarkPath} could not be written: ${capture.watermarkError}`);
    // Precisely what happens, not a guess. With no bookmark, `since` stays null on every
    // run, so each one re-reports the WHOLE chain as if it were new. The earlier wording
    // here said it would report zero, which was the opposite of the truth.
    lines.push("   Until it can be, every run re-reads the whole chain as if it were new, so a fresh escape");
    lines.push("   cannot be told apart from history. That makes the verdict below inconclusive, not clean.");
  }

  if (health.egressRecords === 0) {
    lines.push("");
    lines.push("⚠️  this chain holds no egress records, so it can say nothing about capture either way. Either");
    lines.push("   nothing has been proxied yet, or agents are not routed through the proxy: AGENTWALL_PROXY_PORT");
    lines.push("   unset on the service, HTTPS_PROXY unset on the agent, or a NO_PROXY entry covering the");
    lines.push("   destination will each produce exactly this, with no error anywhere.");
    return { lines, failures };
  }

  const undeclared = health.undeclared;
  if (!health.fleetDeclared) {
    lines.push("");
    lines.push(`⚠️  ${from} declares no agents, so no traffic read here can be called undeclared: there is`);
    lines.push("   nothing to declare it against. Each egress record carries the process name it was observed");
    lines.push('   under as its identity, or "unattributed" where none could be recovered. Add a `fleet:`');
    lines.push("   section to turn that into something checkable.");
    return { lines, failures };
  }

  if (undeclared.sinceLastRun > 0) {
    const scope = health.since === null ? "in the chain (no previous run to compare against)" : "since the last run";
    const escaped = undeclared.escapedSinceLastRun > 0 && health.since !== null;
    if (escaped) failures += 1;
    lines.push("");
    lines.push(
      `${escaped ? "❌" : "⚠️ "} ${undeclared.sinceLastRun} undeclared egress ` +
        `${undeclared.sinceLastRun === 1 ? "record" : "records"} ${scope}: ` +
        `${undeclared.allowedSinceLastRun} reached the network, ` +
        `${undeclared.deniedSinceLastRun} ${undeclared.deniedSinceLastRun === 1 ? "was" : "were"} refused.`,
    );
    lines.push(`   identity      ${undeclared.byIdentity.map((row) => `${row.id} ${row.count}`).join(", ")}`);
    lines.push(`   destinations  ${undeclared.topHosts.map((row) => `${row.host} ${row.count}`).join(", ")}`);
    lines.push(`   bytes         ${formatByteCount(undeclared.bytesSinceLastRun)}`);
    lines.push(`   first / last  ${formatRelative(undeclared.firstAt)} / ${formatRelative(undeclared.lastAt)}`);
    if (undeclared.predatingAttribution > 0) {
      lines.push(
        `   ${undeclared.predatingAttribution} of these predate agent attribution and were written by an older build.`,
      );
    }

    if (escaped) {
      lines.push("");
      lines.push(
        `   ESCAPE: ${undeclared.escapedSinceLastRun} of those reached the network while the record itself says`,
      );
      lines.push('   fleet.unmatched was "deny" under an enforcing mode. That combination is refused before an');
      lines.push("   upstream socket is opened, so this is traffic that did not pass the gate. Either an agent");
      lines.push("   nobody declared found another route, or a declared agent's identity binding broke and it");
      lines.push("   was refused as a stranger. Compare the identities above against fleet.agents.");
    }

    for (const permitted of undeclared.permittedByConfigSinceLastRun) {
      lines.push("");
      lines.push(`   INCONCLUSIVE: ${permitted.count} of those were allowed out by the configuration itself.`);
      lines.push(`   ${permitted.reason}`);
      lines.push("   That is not an escape, and it is not proof of innocence either: an undeclared agent talking");
      lines.push("   to an allowlisted host produces exactly this record, and so does an ordinary unlisted");
      lines.push(
        permitted.reason.startsWith("fleet.unmatched")
          ? "   process. Set `fleet.unmatched: deny` to make the next run able to answer."
          : "   process. Move to `enforcement.mode: guarded` to make the next run able to answer.",
      );
    }
  } else {
    lines.push(
      `   undeclared       none${health.since === null ? " in the chain" : " since the last run"}` +
        `${undeclared.total > 0 ? ` (${undeclared.total} earlier, already accounted for)` : ""}`,
    );
  }

  lines.push("");
  lines.push(
    `   ${"agent".padEnd(20)}${"binding".padEnd(13)}${"last seen".padEnd(15)}${"window".padEnd(16)}${"requests".padEnd(14)}bytes`,
  );

  const neverSeen: string[] = [];
  for (const row of health.agents) {
    const binding =
      row.strongestTier === row.weakestTier ? row.weakestTier : `${row.strongestTier}/${row.weakestTier}`;
    const head = `   ${row.agentId.padEnd(20)}${binding.padEnd(13)}`;
    if (row.lastSeen === null) {
      neverSeen.push(row.agentId);
      // Deliberately NOT a row of zeros. "Declared, never seen" and "seen a minute ago and
      // idle" are different states, and rendering both as 0/0 is how an agent that stopped
      // being captured hides in a table.
      lines.push(`${head}${health.truncated ? "DECLARED, NOT SEEN IN WHAT WAS READ" : "DECLARED, NEVER SEEN"}`);
      continue;
    }
    const overRequests = row.maxRequests !== null && row.requests >= row.maxRequests;
    const overBytes = row.maxBytes !== null && row.bytes >= row.maxBytes;
    const requests = `${row.requests} / ${row.maxRequests ?? "-"}${overRequests ? " OVER" : ""}`;
    const bytes = `${formatByteCount(row.bytes)} / ${row.maxBytes === null ? "-" : formatByteCount(row.maxBytes)}${
      overBytes ? " OVER" : ""
    }`;
    const window = `${row.windowSeconds}s ${row.windowIsBudget ? "budget" : "observed"}`;
    lines.push(
      `${head}${formatRelative(row.lastSeen.at).padEnd(15)}${window.padEnd(16)}${requests.padEnd(14)}${bytes}` +
        `${row.denied > 0 ? `  (${row.denied} denied)` : ""}`,
    );
  }

  if (neverSeen.length > 0) {
    lines.push("");
    lines.push(`⚠️  declared but never seen: ${neverSeen.join(", ")}. This says nothing about why on its own.`);
    lines.push("   It has not started yet, or it is running and its traffic never reaches this proxy: no");
    lines.push("   HTTPS_PROXY on the agent, a NO_PROXY entry covering where it goes, or a different chain");
    lines.push("   than the one above. An escaped agent and a misrouted one look identical from here, which");
    lines.push("   is why this is a prompt to go and check rather than a verdict.");
  }

  if (health.weakestBinding !== null) {
    lines.push("");
    lines.push(
      `${health.weakestBinding.tier === "comm" || health.weakestBinding.tier === "none" ? "⚠️ " : "  "} ` +
        `weakest binding in use: ${health.weakestBinding.tier} (${health.weakestBinding.agentIds.join(", ")})`,
    );
    for (const advice of TIER_ADVICE[health.weakestBinding.tier]) lines.push(`   ${advice}`);
  }

  for (const note of health.notes) lines.push(`   note: ${note}`);

  return { lines, failures };
}

function commandDoctor(flags: CliFlags) {
  const checks = [
    {
      name: `Node version >= ${nodeFloor}`,
      ok: meetsNodeFloor(),
      detail: process.versions.node,
    },
    {
      name: "dist/index.js exists",
      ok: fs.existsSync(path.resolve(process.cwd(), "dist/index.js")),
      detail: "npm run build",
    },
    {
      name: "agentwall.config.yaml exists",
      ok: fs.existsSync(path.resolve(process.cwd(), "agentwall.config.yaml")),
      detail: "agentwall init",
    },
    {
      name: "policy.yaml exists",
      ok: fs.existsSync(path.resolve(process.cwd(), "policy.yaml")),
      detail: "agentwall init",
    },
  ];

  const capture = collectDoctorCapture(flags);
  const section = renderCaptureSection(capture);
  const installFailures = checks.filter((check) => !check.ok).length;

  /**
   * Fleet lines are gathered BEFORE the exit code is decided, not printed as a side effect
   * partway through. Two slices met here: one counts install and capture failures into a
   * single total, the other adds credential-lifecycle failures. Reading the store early lets
   * both land in the same total instead of one of them arriving after the arithmetic.
   */
  const fleetLines = fleetDoctorLines(typeof flags.config === "string" ? flags.config : undefined);
  const fleetFailures = fleetLines.filter((line) => line.level === "fail").length;
  const failures = installFailures + section.failures + fleetFailures;

  /**
   * 0 clear, 1 failed, 2 inconclusive.
   *
   * A definite failure outranks an inconclusive measurement, so an install check that failed
   * still gives 1 even when capture could not be assessed: there is something to fix either
   * way, and the more specific answer is the more useful one. 2 is reserved for "the
   * question was asked and could not be answered", which a cron should treat as needing a
   * human rather than as either an alarm or an all-clear.
   */
  const exitCode = failures > 0 ? 1 : capture.verdict === "inconclusive" ? 2 : 0;

  if (flags.json) {
    console.log(
      JSON.stringify(
        {
          checks: checks.map((check) => ({ name: check.name, ok: check.ok, detail: check.detail })),
          capture: {
            configSource: capture.configSource,
            unavailable: capture.unavailable,
            fleetError: capture.fleetError,
            watermarkPath: capture.watermarkPath,
            watermarkError: capture.watermarkError,
            verdict: capture.verdict,
            verdictReason: capture.verdictReason,
            health: capture.health,
          },
          failures,
          exitCode,
        },
        null,
        2,
      ),
    );
    if (exitCode !== 0) process.exit(exitCode);
    return;
  }

  for (const check of checks) {
    console.log(check.ok ? `✅ ${check.name}` : `❌ ${check.name} (hint: ${check.detail})`);
  }

  // Fleet credential lifecycle, when a fleet is declared. Silent otherwise, because a
  // single-agent install should not grow four lines about a feature nobody turned on.
  //
  // A rotation window is a WARN rather than a pass: it is a stated, bounded period during
  // which two secrets both work, and an operator reading doctor during one needs to see how
  // long is left. It does not fail the command, because a rotation in progress is not a
  // broken install. A store that cannot be parsed does fail: nothing can be changed until it
  // is fixed, including a revocation somebody may be trying to make right now.
  for (const line of fleetLines) {
    if (line.level === "fail") {
      console.log(`❌ ${line.text}`);
    } else {
      console.log(`${line.level === "warn" ? "⚠️ " : "✅"} ${line.text}`);
    }
  }

  // Everything prints before anything exits. An earlier resolution of this merge exited on
  // fleet failures here, which silently swallowed the capture section below it: an operator
  // with a credential problem would never learn they also had an agent escaping.
  for (const line of section.lines) console.log(line);

  if (exitCode === 0) return;

  console.log("");
  if (failures > 0) {
    console.log(
      `${installFailures} install check(s), ${section.failures} capture check(s) and ` +
        `${fleetFailures} fleet check(s) failed. (exit 1)`,
    );
    // Only explained when it happened. A standing sentence about escaping agents printed
    // under a run that failed on a missing policy.yaml is how a warning stops being read.
    if (section.failures > 0) {
      console.log("A capture failure means traffic reached the network that policy said to refuse.");
    }
  } else {
    console.log(`INCONCLUSIVE (exit 2): ${capture.verdictReason}.`);
    console.log("Not an all-clear and not an alarm. The remedy above turns the next run into one or the other.");
  }
  process.exit(exitCode);
}

function loadCliConfig(flags: CliFlags) {
  const configPath = typeof flags.config === "string" ? flags.config : undefined;
  return loadConfig(configPath);
}

export function createBaseUrl(flags: CliFlags): string {
  if (typeof flags.url === "string" && flags.url.trim().length > 0) {
    return flags.url.replace(/\/$/, "");
  }

  const config = loadCliConfig(flags);
  return `http://${config.host}:${config.port}`;
}

function formatResolvedTarget(flags: CliFlags): string {
  return ` · target ${createBaseUrl(flags)}`;
}

function formatRelative(dateString?: string | null): string {
  if (!dateString) return "n/a";
  const deltaMs = Date.now() - new Date(dateString).getTime();
  if (!Number.isFinite(deltaMs)) return String(dateString);
  const seconds = Math.max(0, Math.round(deltaMs / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return new Date(dateString).toLocaleString();
}

function formatShieldExpiry(dateString?: string | null): string {
  if (!dateString) return "not set";
  const deltaMs = new Date(dateString).getTime() - Date.now();
  if (!Number.isFinite(deltaMs) || deltaMs <= 0) return "expired";
  const minutes = Math.max(1, Math.round(deltaMs / 60_000));
  return `${minutes}m remaining`;
}

function formatSessionOverrideSummary(item: { sessionId: string; multiplier: number; expiresAt: string }): string {
  return `${item.sessionId}×${item.multiplier} (${formatShieldExpiry(item.expiresAt)})`;
}

function humanizeFloodCategory(category: string): string {
  return category.replace(/_/g, " ");
}

function summarizeTopCategoryCounts(counts: Record<string, number> | undefined, limit = 3): string | null {
  if (!counts) return null;
  const top = Object.entries(counts)
    .filter(([, count]) => Number.isFinite(count) && count > 0)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)
    .map(([category, count]) => `${humanizeFloodCategory(category)} ${count}`);
  return top.length > 0 ? top.join(", ") : null;
}

function summarizeTopPressureSessions(
  sessions: Array<{ sessionId: string; pressure: number; blocked: number }> | undefined,
  limit = 3
): string | null {
  if (!sessions) return null;
  const top = sessions
    .filter((item) => item.sessionId && (item.pressure > 0 || item.blocked > 0))
    .slice(0, limit)
    .map((item) => `${item.sessionId} ${(item.pressure * 100).toFixed(0)}%${item.blocked > 0 ? ` (${item.blocked} blocked)` : ""}`);
  return top.length > 0 ? top.join(", ") : null;
}

function quoteShellArg(value: string): string {
  if (/^[A-Za-z0-9_./:-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function buildTargetArgSuffix(flags: CliFlags): string {
  if (typeof flags.url === "string" && flags.url.trim().length > 0) {
    return ` --url ${quoteShellArg(flags.url.trim())}`;
  }

  if (typeof flags.config === "string" && flags.config.trim().length > 0) {
    return ` --config ${quoteShellArg(flags.config.trim())}`;
  }

  return "";
}

function resolveControlTarget(state: DashboardState, flags: CliFlags = {}): { label: string; advertised: string } {
  const advertised = `http://${state.service.host}:${state.service.port}`;
  if (typeof flags.url === "string" && flags.url.trim().length > 0) {
    const requested = flags.url.trim().replace(/\/$/, "");
    if (requested !== advertised) {
      return {
        label: `${requested} (server advertises ${advertised})`,
        advertised,
      };
    }
    return { label: requested, advertised };
  }
  return { label: advertised, advertised };
}

function buildSuggestedCommands(state: DashboardState, flags: CliFlags = {}): string[] {
  const commands: string[] = [];
  const floodGuidance = state.floodGuard?.operatorGuidance;
  const hottestSessionId = floodGuidance?.hottestSessionId?.trim();
  const targetArgs = buildTargetArgSuffix(flags);
  const sessionOverrides = state.floodGuard?.sessionOverrides ?? [];
  const hottestOverride = hottestSessionId
    ? sessionOverrides.find((item) => item.sessionId === hottestSessionId)
    : sessionOverrides[0];
  const approvalMode = state.controls.approvalMode;
  const pendingApprovals = state.posture.pendingApprovals ?? 0;
  const criticalSignals = state.posture.criticalSignals ?? 0;
  const pausedSessions = state.stats.sessionCounts.paused ?? 0;
  const terminatedSessions = state.stats.sessionCounts.terminated ?? 0;
  const guidanceStatus = floodGuidance?.status ?? "normal";
  const hottestSessionStatus = hottestSessionId
    ? state.sessions?.statusById?.[hottestSessionId] ?? state.sessions?.recent?.find((item) => item.sessionId === hottestSessionId)?.status
    : undefined;
  const canNormalizeApprovalMode =
    pendingApprovals === 0 &&
    approvalMode === "always" &&
    guidanceStatus === "normal" &&
    state.floodGuard?.mode !== "shield" &&
    criticalSignals === 0 &&
    pausedSessions === 0 &&
    terminatedSessions === 0 &&
    !state.service.attentionRequired;
  const canNormalizeShield =
    state.floodGuard?.mode === "shield" &&
    guidanceStatus === "normal" &&
    criticalSignals === 0 &&
    pausedSessions === 0 &&
    terminatedSessions === 0 &&
    !state.service.attentionRequired;

  if (guidanceStatus === "recommend") {
    commands.push(`agentwall shield --minutes 10${targetArgs}`);
  } else if (canNormalizeShield) {
    commands.push(`agentwall normal${targetArgs}`);
  }

  if (pendingApprovals > 0 && approvalMode !== "always") {
    commands.push(`agentwall approval-mode always${targetArgs}`);
  } else if (canNormalizeApprovalMode) {
    commands.push(`agentwall approval-mode auto${targetArgs}`);
  }

  if (guidanceStatus !== "normal" && hottestSessionId && (!hottestSessionStatus || hottestSessionStatus === "active")) {
    commands.push(`agentwall pause ${hottestSessionId} --note "Investigate FloodGuard pressure"${targetArgs}`);
  } else if (guidanceStatus === "normal" && hottestOverride) {
    commands.push(`agentwall session-reset ${hottestOverride.sessionId}${targetArgs}`);
  }

  return commands.slice(0, 3);
}

function parseIntegerFlag(value: string | boolean | undefined, label: string): number | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive number`);
  }
  return Math.round(parsed);
}

function parseNumberFlag(value: string | boolean | undefined, label: string): number | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive number`);
  }
  return parsed;
}

function resolveDurationMs(flags: CliFlags, fallbackMs: number): number {
  const direct = parseIntegerFlag(flags["duration-ms"], "duration-ms");
  if (direct) return direct;
  const minutes = parseNumberFlag(flags.minutes, "minutes");
  if (minutes) return Math.round(minutes * 60_000);
  return fallbackMs;
}

function formatApiError(baseUrl: string, method: string, endpoint: string, status: number, detail: string): Error {
  if (status === 404 && endpoint.startsWith("/api/dashboard/control/session/")) {
    return new Error(`${detail}. Seed a live session first with /evaluate or another runtime request, then retry the control.`);
  }
  if (status === 409 && endpoint.startsWith("/api/dashboard/control/session/")) {
    return new Error(`${detail} Hard containment stays closed; start a new runtime session instead of reopening a terminated one.`);
  }
  if (endpoint === "/api/dashboard/state" && method === "GET" && [401, 403, 404].includes(status)) {
    return new Error(
      `Target ${baseUrl} responded with ${status} while fetching Agentwall dashboard state: ${detail}. This usually means you hit the wrong service or port. Start Agentwall first or pass --url for the live instance. The bundled monitor-first example config listens on http://127.0.0.1:3015.`
    );
  }
  return new Error(`Agentwall API ${method} ${endpoint} failed (${status}): ${detail}`);
}

function formatConnectionError(baseUrl: string, endpoint: string, error: unknown): Error {
  const detail = error instanceof Error && error.message.trim().length > 0 ? error.message.trim() : "connection failed";
  return new Error(
    `Could not reach Agentwall at ${baseUrl}${endpoint}: ${detail}. Start Agentwall first or pass --url for the live instance. The bundled monitor-first example config listens on http://127.0.0.1:3015.`
  );
}

async function requestJson<T>(method: string, endpoint: string, body?: unknown, flags: CliFlags = {}): Promise<T> {
  const baseUrl = createBaseUrl(flags);
  let response: Response;
  try {
    response = await fetch(`${baseUrl}${endpoint}`, {
      method,
      headers: body ? { "content-type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (error) {
    throw formatConnectionError(baseUrl, endpoint, error);
  }

  let payload: unknown = null;
  const text = await response.text();
  if (text.length > 0) {
    try {
      payload = JSON.parse(text) as unknown;
    } catch {
      payload = text;
    }
  }

  if (!response.ok) {
    const detail = typeof payload === "string"
      ? payload
      : (payload && typeof payload === "object" && "error" in payload ? String((payload as Record<string, unknown>).error) : response.statusText);
    throw formatApiError(baseUrl, method, endpoint, response.status, detail);
  }

  return payload as T;
}

export function formatStatusReport(state: DashboardState, flags: CliFlags = {}): string {
  const controlTarget = resolveControlTarget(state, flags);
  const lines = [
    `${state.brand} ${state.service.status.toUpperCase()}`,
    `${state.service.operatorSummary}`,
    `Control target: ${controlTarget.label}`,
    "",
    `Approval mode: ${state.controls.approvalMode}`,
    `FloodGuard: ${state.floodGuard?.mode ?? "normal"}${state.floodGuard?.mode === "shield" ? ` (${formatShieldExpiry(state.floodGuard?.shieldUntil)})` : ""}`,
    `Pending approvals: ${state.posture.pendingApprovals}`,
    `Critical signals: ${state.posture.criticalSignals}`,
    `Active agents now: ${state.posture.activeAgentsNow ?? state.posture.activeAgents}`,
    `Tracked sessions paused: ${state.stats.sessionCounts.paused ?? 0}`,
    `Tracked sessions terminated: ${state.stats.sessionCounts.terminated ?? 0}`,
    `Requests evaluated: ${state.posture.totalRequests}`,
  ];

  if (state.freshness?.hasLiveActivity) {
    lines.push(`Last live activity: ${formatRelative(state.freshness?.lastLiveEventAt ?? null)}${state.freshness?.isFresh ? "" : " (stale)"}`);
  } else {
    lines.push("Last live activity: awaiting first runtime event");
  }

  const overrides = state.floodGuard?.sessionOverrides ?? [];
  if (overrides.length > 0) {
    lines.push(`Session overrides: ${overrides.map((item) => formatSessionOverrideSummary(item)).join(", ")}`);
  }

  const floodGuidance = state.floodGuard?.operatorGuidance;
  if (floodGuidance?.summary) {
    lines.push(`FloodGuard guidance: ${floodGuidance.summary}`);
    if (floodGuidance.recommendedAction) {
      lines.push(`FloodGuard next move: ${floodGuidance.recommendedAction}`);
    }
    if (typeof floodGuidance.pressure === "number") {
      lines.push(`FloodGuard pressure: ${(floodGuidance.pressure * 100).toFixed(0)}%${floodGuidance.hottestSessionId ? ` · hottest session ${floodGuidance.hottestSessionId}` : ""}`);
    } else if (floodGuidance.hottestSessionId) {
      lines.push(`FloodGuard hottest session: ${floodGuidance.hottestSessionId}`);
    }
  }

  const blockSummary = summarizeTopCategoryCounts(state.floodGuard?.blockedByCategory);
  if (blockSummary) {
    lines.push(`FloodGuard blocked by type: ${blockSummary}`);
  }

  const categoryPressureSummary = summarizeTopCategoryCounts(state.floodGuard?.pressureByCategory);
  if (categoryPressureSummary) {
    lines.push(`FloodGuard pressure by type: ${categoryPressureSummary}`);
  }

  const sessionPressureSummary = summarizeTopPressureSessions(state.floodGuard?.pressureBySession);
  if (sessionPressureSummary) {
    lines.push(`FloodGuard hottest sessions: ${sessionPressureSummary}`);
  }

  const recentBlock = state.floodGuard?.recentBlocks?.[0];
  if (recentBlock) {
    lines.push(
      `Latest FloodGuard block: ${humanizeFloodCategory(recentBlock.category)} · ${recentBlock.reason}${recentBlock.sessionId ? ` · ${recentBlock.sessionId}` : ""} · ${formatRelative(recentBlock.timestamp)}`
    );
  }

  const recommendedActions = state.service.recommendedActions ?? [];
  if (recommendedActions.length > 0) {
    lines.push("");
    lines.push("Recommended actions:");
    for (const action of recommendedActions) {
      lines.push(`- ${action}`);
    }
  }

  const suggestedCommands = buildSuggestedCommands(state, flags);
  if (suggestedCommands.length > 0) {
    lines.push("");
    lines.push("CLI next moves:");
    for (const command of suggestedCommands) {
      lines.push(`- ${command}`);
    }
  }

  const topPriority = state.priorityQueue.slice(0, 3);
  if (topPriority.length > 0) {
    lines.push("");
    lines.push("Top queue:");
    for (const item of topPriority) {
      const actionLabel = item.primaryAction ? ` · next ${item.primaryAction.toLowerCase()}` : "";
      lines.push(`- [${item.category}/${item.status}] ${item.owner} · ${item.title} · ${formatRelative(item.timestamp)}${actionLabel}`);
      if (item.summary) {
        lines.push(`  ${item.summary}`);
      }
    }
  }

  return lines.join("\n");
}

export async function commandStatus(flags: CliFlags) {
  const state = await requestJson<DashboardState>("GET", "/api/dashboard/state", undefined, flags);
  if (flags.json) {
    console.log(JSON.stringify(state, null, 2));
    return;
  }
  console.log(formatStatusReport(state, flags));
}

export async function commandShield(flags: CliFlags) {
  const config = loadCliConfig(flags);
  const fallbackMs = config.runtimeGuards?.shield?.defaultDurationMs ?? 10 * 60_000;
  const durationMs = resolveDurationMs(flags, fallbackMs);
  const response = await requestJson<{ mode: string; shieldUntil?: string | null }>(
    "POST",
    "/api/dashboard/control/floodguard-mode",
    { mode: "shield", durationMs },
    flags
  );
  console.log(`FloodGuard ${response.mode} enabled for ${Math.round(durationMs / 60_000)}m${response.shieldUntil ? ` · until ${response.shieldUntil}` : ""}${formatResolvedTarget(flags)}`);
}

export async function commandNormal(flags: CliFlags) {
  const response = await requestJson<{ mode: string }>(
    "POST",
    "/api/dashboard/control/floodguard-mode",
    { mode: "normal" },
    flags
  );
  console.log(`FloodGuard ${response.mode}${formatResolvedTarget(flags)}`);
}

type ApprovalMode = "auto" | "always" | "never";
type SessionControlAction = "pause" | "resume" | "terminate";

export function resolveApprovalMode(flags: CliFlags, positionals: string[]): ApprovalMode {
  const mode = typeof flags.mode === "string" && flags.mode.trim().length > 0
    ? flags.mode.trim().toLowerCase()
    : positionals[0]?.trim().toLowerCase();
  if (mode === "auto" || mode === "always" || mode === "never") {
    return mode;
  }
  throw new Error("approval mode required. Use --mode <auto|always|never> or pass it as the first positional argument.");
}

function requireSessionId(flags: CliFlags, positionals: string[]): string {
  const sessionId = typeof flags.session === "string" && flags.session.trim().length > 0
    ? flags.session.trim()
    : positionals[0];
  if (!sessionId) {
    throw new Error("session ID required. Use --session <id> or pass it as the first positional argument.");
  }
  return sessionId;
}

function resolveSessionNote(flags: CliFlags, positionals: string[]): string | undefined {
  if (typeof flags.note === "string" && flags.note.trim().length > 0) {
    return flags.note.trim();
  }
  const startIndex = typeof flags.session === "string" && flags.session.trim().length > 0 ? 0 : 1;
  const note = positionals.slice(startIndex).join(" ").trim();
  return note.length > 0 ? note : undefined;
}

export async function commandApprovalMode(flags: CliFlags, positionals: string[]) {
  const mode = resolveApprovalMode(flags, positionals);
  const response = await requestJson<{ mode: ApprovalMode }>(
    "POST",
    "/api/dashboard/control/approval-mode",
    { mode },
    flags
  );
  console.log(`Approval mode set to ${response.mode}${formatResolvedTarget(flags)}`);
}

export async function commandSessionControl(action: SessionControlAction, flags: CliFlags, positionals: string[]) {
  if (action === "terminate" && !flags.confirm) {
    throw new Error("terminate requires --confirm to avoid accidental containment.");
  }
  const sessionId = requireSessionId(flags, positionals);
  const note = resolveSessionNote(flags, positionals);
  const response = await requestJson<{ session: { sessionId: string; status: string; note?: string } }>(
    "POST",
    `/api/dashboard/control/session/${encodeURIComponent(sessionId)}`,
    action === "terminate"
      ? { action, confirm: true, ...(note ? { note } : {}) }
      : note ? { action, note } : { action },
    flags
  );
  console.log(`Session ${response.session.sessionId} ${response.session.status}${response.session.note ? ` · ${response.session.note}` : ""}${formatResolvedTarget(flags)}`);
}

export async function commandSessionBoost(flags: CliFlags, positionals: string[]) {
  const config = loadCliConfig(flags);
  const sessionId = requireSessionId(flags, positionals);
  const multiplier = parseNumberFlag(flags.multiplier, "multiplier") ?? 1.5;
  const fallbackMs = config.runtimeGuards?.shield?.defaultDurationMs ?? 10 * 60_000;
  const durationMs = resolveDurationMs(flags, fallbackMs);
  const response = await requestJson<{ override: { sessionId: string; multiplier: number; expiresAt: string } }>(
    "POST",
    `/api/dashboard/control/floodguard-session/${encodeURIComponent(sessionId)}`,
    { action: "set", multiplier, durationMs },
    flags
  );
  console.log(`FloodGuard override set for ${response.override.sessionId} ×${response.override.multiplier} until ${response.override.expiresAt}${formatResolvedTarget(flags)}`);
}

export async function commandSessionReset(flags: CliFlags, positionals: string[]) {
  const sessionId = requireSessionId(flags, positionals);
  const response = await requestJson<{ cleared: boolean }>(
    "POST",
    `/api/dashboard/control/floodguard-session/${encodeURIComponent(sessionId)}`,
    { action: "clear" },
    flags
  );
  console.log(
    response.cleared
      ? `FloodGuard override cleared for ${sessionId}${formatResolvedTarget(flags)}`
      : `No FloodGuard override was active for ${sessionId}${formatResolvedTarget(flags)}`
  );
}

/**
 * Resolve the audit file the same way the server does, so the CLI and the running
 * service never disagree about which chain they are talking about.
 */
function auditPathFromEnv(flags: CliFlags): string {
  const explicit = typeof flags.audit === "string" ? flags.audit : undefined;
  const resolved = explicit ?? process.env.AGENTWALL_AUDIT_FILE;
  if (!resolved) {
    console.error(
      "No audit file configured. Set AGENTWALL_AUDIT_FILE or pass --audit <path>.\n" +
        "This is the file the proxy appends decisions to.",
    );
    process.exit(1);
  }
  return resolved;
}

/**
 * `agentwall anchor` - seal closed segments, sign a checkpoint, submit it off-box.
 *
 * Off-box is the point. A signature proves a key holder vouched; on a host where the
 * audited process can read the key, that is necessary and not sufficient. An anchor puts
 * a fingerprint somewhere this machine cannot reach.
 */
async function commandAnchor(flags: CliFlags): Promise<void> {
  const auditPath = auditPathFromEnv(flags);
  const result = await runAnchorPass({ auditPath });

  if (!result.anchored) {
    console.error(`Nothing to anchor: ${result.reason}`);
    process.exit(1);
  }

  const record = result.records?.[0];
  const paths = resolvePaths({ auditPath });

  if (flags.json) {
    console.log(JSON.stringify({ ...result, paths }, null, 2));
    return;
  }

  console.log("Anchored");
  console.log(`  checkpoint index  ${result.checkpoint?.chainIndex}`);
  console.log(`  checkpoint hash   ${result.checkpoint?.hash}`);
  console.log(`  covers            ${result.covered} records (${result.segments} sealed segment(s) + ${result.liveRecords} live)`);
  if (record?.error) {
    console.log(`  backend           FAILED: ${record.error}`);
    console.log("\nThe checkpoint is signed and recorded, but nothing is anchored off-box.");
    process.exit(1);
  }
  console.log(`  calendar          ${record?.reference}`);
  console.log(`  proof             ${record?.proofPath}`);
  console.log(`  status            ${record?.status}`);
  console.log(
    "\nOpenTimestamps anchors into a Bitcoin block, so this stays pending for roughly\n" +
      "one to six hours. It is not proof until a block confirms it.",
  );
}

/**
 * `agentwall verify` - check the three integrity layers independently.
 *
 * Deliberately not a single green tick. They are different properties, and collapsing
 * them is how a tool ends up claiming more than it can show.
 */
async function commandVerify(flags: CliFlags): Promise<void> {
  const auditPath = auditPathFromEnv(flags);
  const report = runVerify({ auditPath });

  if (flags.json) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.ok ? 0 : 1);
  }

  const meaning: Record<string, string> = {
    chained: "records link within each segment, so an edit inside one is detectable",
    linked: "segments link and match their files, so removing or replacing one is detectable",
    anchored: "a fingerprint exists off-box and still matches what is here, so a local rewrite shows",
  };

  for (const layer of report.layers) {
    console.log(`${layer.ok ? "PASS" : "FAIL"}  ${layer.name.padEnd(9)} ${layer.detail}`);
    console.log(`            ${meaning[layer.name]}`);
    for (const problem of layer.problems) console.log(`            ! ${problem}`);
  }

  if (report.pending > 0) {
    console.log(
      `\n${report.pending} anchor(s) pending a Bitcoin block. Pending is not proof;\n` +
        "re-run verify once a block confirms.",
    );
  }
  if (report.failed > 0) {
    console.log(`\n${report.failed} anchor(s) never reached a calendar. Those records are NOT anchored.`);
  }

  process.exit(report.ok ? 0 : 1);
}

const MCP_USAGE = [
  "Usage: agentwall mcp wrap [options] -- <command> [args...]",
  "       agentwall mcp wrap [options] --http-upstream <url> --http-port <n> [--http-host <h>]",
  "       agentwall mcp stop <wrapper-id> [--url <base-url>] [--config <path>]",
  "       agentwall mcp status [--url <base-url>] [--config <path>]",
  "Options:",
  "  --server-name <name>       Set the server name.",
  "  --agent-id <id>            Set the agent identity.",
  "  --baseline-mode <mode>     Use off, learn, or lock. The default is off.",
  "  --baseline-file <path>     Set the inventory file. The default is .agentwall/mcp-baselines.json.",
  "  --http-auth-token-file <path>  Read the HTTP client token from this file.",
].join("\n");

export interface McpWrapArgs {
  serverName?: string;
  agentId?: string;
  baselineMode?: McpBaselineMode;
  baselineFile?: string;
  /** The server command for the stdio form. Empty when wrapping over HTTP. */
  command: string[];
  /** Set only for the HTTP form. Its presence is what selects that transport. */
  http?: {
    upstreamUrl: string;
    listenPort: number;
    listenHost?: string;
    authTokenFile?: string;
  };
}

/**
 * Parse `mcp <subcommand> ...` arguments.
 *
 * Hand-rolled rather than routed through parseFlags(), because the wrapped server's command line
 * is not ours to interpret. `--` ends our options and everything after it belongs to the server,
 * flags included: parseFlags() would consume the `--` itself and then read the server's own
 * `--port` as an Agentwall option, launching the server without it. A wrapper that silently
 * changes the command it wraps is worse than one that refuses to run.
 */
export function parseMcpArgs(args: string[]): McpWrapArgs {
  const [subcommand, ...rest] = args;
  if (!subcommand) {
    throw new Error(`mcp subcommand required. Supported: wrap, status, stop.\n${MCP_USAGE}`);
  }
  if (subcommand !== "wrap") {
    throw new Error(`Unknown mcp subcommand: ${subcommand}. Supported: wrap, status, stop.\n${MCP_USAGE}`);
  }

  const separator = rest.indexOf("--");
  const ours = separator === -1 ? rest : rest.slice(0, separator);
  const command = separator === -1 ? [] : rest.slice(separator + 1);

  const parsed: McpWrapArgs = { command };
  let upstreamUrl: string | undefined;
  let listenPort: string | undefined;
  let listenHost: string | undefined;
  let authTokenFile: string | undefined;

  const OPTIONS: Record<string, true> = {
    "--server-name": true,
    "--agent-id": true,
    "--http-upstream": true,
    "--http-port": true,
    "--http-host": true,
    "--http-auth-token-file": true,
    "--baseline-mode": true,
    "--baseline-file": true,
  };

  for (let i = 0; i < ours.length; i += 1) {
    const token = ours[i];
    const value = ours[i + 1];
    if (!OPTIONS[token]) {
      throw new Error(`Unknown mcp wrap option: ${token}.\n${MCP_USAGE}`);
    }
    if (!value || value.startsWith("--")) {
      throw new Error(`${token} needs a value.\n${MCP_USAGE}`);
    }
    if (token === "--server-name") parsed.serverName = value;
    else if (token === "--agent-id") parsed.agentId = value;
    else if (token === "--baseline-mode") {
      if (value !== "off" && value !== "learn" && value !== "lock") {
        throw new Error(`--baseline-mode must be off, learn, or lock; got "${value}".\n${MCP_USAGE}`);
      }
      parsed.baselineMode = value;
    } else if (token === "--baseline-file") parsed.baselineFile = value;
    else if (token === "--http-upstream") upstreamUrl = value;
    else if (token === "--http-port") listenPort = value;
    else if (token === "--http-host") listenHost = value;
    else authTokenFile = value;
    i += 1;
  }

  const wantsHttp = Boolean(upstreamUrl || listenPort || listenHost || authTokenFile);

  // The two forms are exclusive, and saying so beats guessing.
  //
  // A command after `--` plus an upstream URL describes two different servers, and picking
  // one silently would wrap something the operator did not ask for. Refusing costs a retry;
  // guessing costs an unmonitored server that looks monitored.
  if (wantsHttp && command.length > 0) {
    throw new Error(
      `mcp wrap takes either a server command after -- or the --http-* options, not both.\n${MCP_USAGE}`
    );
  }

  if (wantsHttp) {
    if (!upstreamUrl) {
      throw new Error(`--http-upstream is required when wrapping over HTTP.\n${MCP_USAGE}`);
    }
    if (!listenPort) {
      throw new Error(`--http-port is required when wrapping over HTTP.\n${MCP_USAGE}`);
    }
    const port = Number(listenPort);
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      throw new Error(`--http-port must be an integer between 0 and 65535, got "${listenPort}".`);
    }
    parsed.http = { upstreamUrl, listenPort: port, listenHost, authTokenFile };
    return parsed;
  }

  if (separator === -1) {
    throw new Error(`mcp wrap needs the server command after --.\n${MCP_USAGE}`);
  }
  if (command.length === 0) {
    throw new Error(`no server command after --: there is nothing to wrap.\n${MCP_USAGE}`);
  }

  return parsed;
}
interface McpStopArgs {
  wrapId: string;
  flags: CliFlags;
}

interface McpServiceArgs {
  flags: CliFlags;
}

function parseMcpStopArgs(args: string[]): McpStopArgs {
  const [subcommand, wrapId, ...rest] = args;
  if (subcommand !== "stop" || !wrapId || wrapId.startsWith("--")) {
    throw new Error(`Usage: agentwall mcp stop <wrapper-id> [--url <base-url>] [--config <path>]\n${MCP_USAGE}`);
  }
  const parsed = parseFlags(rest);
  if (parsed.positionals.length > 0) {
    throw new Error(`Unexpected mcp stop argument: ${parsed.positionals[0]}.\n${MCP_USAGE}`);
  }
  return { wrapId, flags: parsed.flags };
}

function parseMcpServiceArgs(args: string[], subcommand: "status"): McpServiceArgs {
  const [actual, ...rest] = args;
  if (actual !== subcommand) {
    throw new Error(`Usage: agentwall mcp ${subcommand} [--url <base-url>] [--config <path>]\n${MCP_USAGE}`);
  }
  const parsed = parseFlags(rest);
  if (parsed.positionals.length > 0) {
    throw new Error(`Unexpected mcp ${subcommand} argument: ${parsed.positionals[0]}.\n${MCP_USAGE}`);
  }
  return { flags: parsed.flags };
}

function responseMessage(body: unknown): string | undefined {
  if (body === null || typeof body !== "object" || !("message" in body)) return undefined;
  return typeof body.message === "string" ? body.message : undefined;
}

function responseOutput(body: unknown): string | undefined {
  if (body === null || typeof body !== "object" || !("data" in body)) return undefined;
  const data = body.data;
  if (data === null || typeof data !== "object" || !("output" in data)) return undefined;
  return typeof data.output === "string" ? data.output : undefined;
}

function operatorToken(): string {
  const generatedEnvironment = loadGeneratedEnvironment(process.cwd());
  const token = process.env.AGENTWALL_OPERATOR_TOKEN ?? generatedEnvironment.AGENTWALL_OPERATOR_TOKEN;
  if (!token) {
    throw new Error("This MCP control needs AGENTWALL_OPERATOR_TOKEN or a generated operator environment.");
  }
  return token;
}

async function postOperatorAction(flags: CliFlags, payload: Record<string, unknown>): Promise<{ message?: string; output?: string }> {
  const response = await fetch(`${createBaseUrl(flags)}/api/operator/actions`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${operatorToken()}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const raw = await response.text();
  let body: unknown = {};
  try {
    body = JSON.parse(raw) as unknown;
  } catch {
    body = {};
  }
  if (!response.ok) {
    throw new Error(responseMessage(body) ?? `Agentwall returned HTTP ${response.status} for the MCP control.`);
  }
  return { message: responseMessage(body), output: responseOutput(body) };
}

async function commandMcpStop(args: string[]): Promise<void> {
  const parsed = parseMcpStopArgs(args);
  const response = await postOperatorAction(parsed.flags, { action: "mcp-http-stop", wrapId: parsed.wrapId, confirm: true });
  console.log(response.message ?? `MCP HTTP wrapper ${parsed.wrapId} stopped.`);
  if (response.output) console.log(response.output);
}

async function commandMcpStatus(args: string[]): Promise<void> {
  const parsed = parseMcpServiceArgs(args, "status");
  const response = await postOperatorAction(parsed.flags, { action: "mcp-http-list" });
  if (response.output) console.log(response.output);
  else console.log(response.message ?? "MCP HTTP wrapper status is ready.");
}


/**
 * `agentwall mcp wrap` - gate every JSON-RPC frame to and from an MCP server.
 *
 * The stdio form exits with the server's own status, so a wrapped server behaves like the
 * server it wraps and a client watching exit codes cannot tell the difference. That is the
 * property that makes it safe to paste into a client's configuration in place of the
 * original command.
 *
 * The HTTP form owns a listener instead of a child, so it has no exit status to inherit and
 * runs until interrupted. It prints the bound port because `--http-port 0` is the useful
 * form in a test harness and an ephemeral port nobody can discover is not useful.
 */
async function commandMcp(args: string[]): Promise<void> {
  if (args[0] === "status") {
    await commandMcpStatus(args);
    return;
  }
  if (args[0] === "stop") {
    await commandMcpStop(args);
    return;
  }
  const parsed = parseMcpArgs(args);
  const baselineMode = parsed.baselineMode ?? "off";
  const baselineFile = path.resolve(
    parsed.baselineFile ?? path.join(".agentwall", "mcp-baselines.json"),
  );
  console.error(`MCP baseline mode: ${baselineMode}`);
  console.error(`MCP baseline file: ${baselineFile}`);

  if (parsed.http) {
    // Read the token from a file rather than an argument. A token on the command line is
    // visible in `ps` to every user on the host, which for a credential that gates a
    // security control is not an acceptable place to put it.
    let authToken: string | undefined;
    if (parsed.http.authTokenFile) {
      authToken = fs.readFileSync(parsed.http.authTokenFile, "utf8").trim();
      if (!authToken) {
        throw new Error(`--http-auth-token-file ${parsed.http.authTokenFile} is empty.`);
      }
    }
    const handle = await runMcpHttpWrap({
      upstreamUrl: parsed.http.upstreamUrl,
      listenPort: parsed.http.listenPort,
      listenHost: parsed.http.listenHost,
      authToken,
      serverName: parsed.serverName,
      agentId: parsed.agentId,
      baselineMode,
      baselineFile,
    });
    console.log(
      `Agentwall MCP HTTP wrap listening on ${parsed.http.listenHost ?? "127.0.0.1"}:${handle.port}` +
        ` -> ${parsed.http.upstreamUrl}`
    );
    const shutdown = (): void => {
      void handle.close().then(() => process.exit(0));
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
    return;
  }

  const exitCode = await runMcpWrap({
    command: parsed.command,
    serverName: parsed.serverName,
    agentId: parsed.agentId,
    baselineMode,
    baselineFile,
  });
  process.exit(exitCode);
}

/**
 * `agentwall perimeter` - the kernel-level containment commands.
 *
 * Raw argv, and the exit code comes straight back from the perimeter module rather than being
 * re-derived here. `status` and `verify` are gates a deployment script reads, and `run` has to
 * pass the contained command's own status through untouched, so wrapping a build in the
 * perimeter never hides that build failing.
 */
async function commandPerimeter(args: string[]): Promise<void> {
  process.exit(await runPerimeterCommand(args));
}

/**
 * `agentwall intercept` - the local TLS interception CA lifecycle.
 *
 * Raw argv for the same reason `perimeter` and `mcp` take it: the subcommand is a positional, and
 * parseFlags() has already read it as though it were one of our flags. The exit code comes
 * straight back from the intercept module rather than being re-derived here. `status` is a gate a
 * deployment script reads before it turns interception on, and `path` exists to be substituted
 * into another command line, so both need their own status to survive this hop untouched.
 */
async function commandIntercept(args: string[]): Promise<void> {
  process.exit(await runInterceptCommand(args));
}

/**
 * `agentwall why` - re-run the scanners against a subject and print what fired.
 *
 * Exits 1 when anything fired and 0 when nothing did, so this works as a gate in a script
 * without parsing the output. Deliberately keyed on findings rather than on the decision: with
 * a default-deny policy the decision is "deny" even when no check matched, and a script that
 * treated that as a failure would flag every clean subject it was given.
 *
 * The engine is the builtin rule set only. Nothing here loads your policy file, because a
 * partially-loaded policy would make the output look authoritative about a deployment it has
 * not read - see the limits in docs/why.md.
 */
function commandWhy(flags: CliFlags, positionals: string[]): void {
  const request = parseRationaleArgs(flags, positionals);
  const result = runRationale(request, new PolicyEngine());
  console.log(request.json ? JSON.stringify(result, null, 2) : formatRationaleReport(result));
  process.exit(rationaleExitCode(result));
}


async function main() {
  const [, , command = "help", ...args] = process.argv;
  const { flags, positionals } = parseFlags(args);

  switch (command) {
    case "help":
    case "--help":
    case "-h":
      printHelp();
      return;
    case "version":
    case "--version":
    case "-v":
      console.log(packageVersion);
      return;
    case "setup":
      commandSetup(flags);
      return;
    case "ui":
      await commandUi(flags);
      return;
    case "init":
      commandInit(flags);
      return;
    case "onboard":
      // Raw args: the profile is a positional and the onboard parser reads its own flags,
      // several of which (--allow, --agent-id) parseFlags() would have already consumed.
      process.exit(runOnboardCommand(args));
    case "start":
      runNodeScript([path.resolve(process.cwd(), "dist/index.js")]);
      return;
    case "dev":
      runNodeScript([path.resolve(process.cwd(), "node_modules/ts-node/dist/bin.js"), "src/index.ts"]);
      return;
    case "doctor":
      commandDoctor(flags);
      return;
    case "status":
      await commandStatus(flags);
      return;
    case "approval-mode":
      await commandApprovalMode(flags, positionals);
      return;
    case "shield":
      await commandShield(flags);
      return;
    case "normal":
      await commandNormal(flags);
      return;
    case "session-boost":
      await commandSessionBoost(flags, positionals);
      return;
    case "session-reset":
      await commandSessionReset(flags, positionals);
      return;
    case "pause":
      await commandSessionControl("pause", flags, positionals);
      return;
    case "resume":
      await commandSessionControl("resume", flags, positionals);
      return;
    case "terminate":
      await commandSessionControl("terminate", flags, positionals);
      return;
    case "fleet":
      // Raw args for the same reason `intercept` takes them: the subcommand is a positional,
      // and parseFlags() would read `--overlap 15m` as one of ours and hand back the rest in
      // an order the fleet parser cannot reconstruct.
      process.exit(runFleetCommand(args));
    case "anchor":
      await commandAnchor(flags);
      return;
    case "verify":
      await commandVerify(flags);
      return;
    case "verify-capture":
      // Raw args for the same reason `mcp` takes them: `--command '<cmd>'` carries the agent's
      // own command line, and parseFlags() splits on whitespace-free tokens in a way that would
      // hand the capture parser a command that is no longer the one the operator typed.
      process.exit(await runVerifyCaptureCommand(args));
    case "mcp":
      // Raw args, not the parsed flags: the wrapped server's own options are on this line and
      // parseFlags() has already read them as if they were ours.
      await commandMcp(args);
      return;
    case "perimeter":
      // Raw args for the same reason `mcp` takes them: the subcommand is a positional, and
      // everything after `run --` belongs to the contained command rather than to us.
      await commandPerimeter(args);
      return;
    case "sandbox":
      // Raw args for the same reason `perimeter` takes them: everything after `run --` belongs
      // to the sandboxed command, and parseFlags() would read those options as ours.
      process.exit(await runSandboxCommand(args));
    case "intercept":
      // Raw args for the same reason `perimeter` takes them: the subcommand is a positional, and
      // the path after `--ca-dir` belongs to the intercept parser rather than to us.
      await commandIntercept(args);
      return;
    case "decoy":
      // Raw args for the same reason `mcp` takes them: the subcommand is a positional that
      // parseFlags() would hand back stripped of the ordering the decoy parser needs.
      runDecoyCommand(args);
      return;
    case "why":
      commandWhy(flags, positionals);
      return;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
