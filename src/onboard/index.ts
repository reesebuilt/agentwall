/**
 * `agentwall onboard <profile>` - mint an identity, write it into config, and print the exact
 * environment the runtime needs.
 *
 * The one design rule this file follows, and the reason it exists at all: it NEVER reports
 * success. Onboarding writes configuration, and configuration is not protection. Three controls
 * in this repository shipped green and non-functional (a perimeter that never installed, a
 * secret scanner with no rules, a content inspector that saw zero bytes), and every one of them
 * would have been caught by making the tool refuse to congratulate itself. So the last thing
 * this command prints is the verify-capture invocation and the sentence "onboarding is not
 * complete until that passes", and the exit code says the same thing.
 *
 * Credential shape is load-bearing and easy to get subtly wrong. src/fleet/registry.ts
 * parseProxyCredential() returns, for a Basic header, the DECODED "user:pass" string, and the
 * only way to present a credential through an environment variable is proxy URL userinfo, which
 * every HTTP client encodes as exactly that. So the secret IS "<agentId>:<token>" and the stored
 * digest is sha256 of that whole string. Minting a bare token and hashing it would produce a
 * config that loads, an agent that presents a credential, and a registry that silently never
 * binds it, which is the precise failure this command exists to prevent.
 */

import * as fs from "fs";
import * as path from "path";
import { createHash, randomBytes } from "crypto";
import * as yaml from "js-yaml";
import {
  AGENT_PROFILES,
  AgentProfile,
  captureGrade,
  findProfile,
  interceptionGrade,
  profileGrade,
  profileIds,
} from "./profiles";

export const EXIT_OK = 0;
export const EXIT_USAGE = 2;

/**
 * Agent ids are restricted so the credential can ride a URL without encoding.
 *
 * A colon would make the Basic decode ambiguous (the registry splits on the first one), and
 * anything needing percent-encoding would mean the string the client sends is not the string we
 * hashed. Both fail as a silent non-binding rather than an error, so the constraint is enforced
 * at mint time where it can still be explained.
 */
const AGENT_ID_PATTERN = /^[A-Za-z0-9._-]+$/;

export interface MintedCredential {
  /** The full secret the operator pastes. Contains the agent id by construction. */
  secret: string;
  /** sha256 hex of `secret`, which is what goes in the config file. */
  digest: string;
}

/**
 * Mint a credential for one agent.
 *
 * 32 bytes from the CSPRNG, hex encoded, prefixed with the agent id and a colon. The result
 * works identically down both header paths the registry accepts: as URL userinfo it becomes
 * `Basic base64("<id>:<token>")` and decodes back to the secret, and as a manual
 * `Proxy-Authorization: Bearer <id>:<token>` it is the token verbatim. Same string, same digest.
 */
export function mintCredential(agentId: string): MintedCredential {
  if (!AGENT_ID_PATTERN.test(agentId)) {
    throw new Error(
      `agentwall: agent id "${agentId}" must match ${AGENT_ID_PATTERN.source}. The id travels in ` +
        `the userinfo of a proxy URL, so a colon or a character needing percent-encoding would ` +
        `change the string the proxy receives and the credential would silently never bind.`
    );
  }
  const secret = `${agentId}:${randomBytes(32).toString("hex")}`;
  return { secret, digest: createHash("sha256").update(secret, "utf8").digest("hex") };
}

export interface OnboardRequest {
  profileId: string;
  agentId: string;
  configPath: string;
  proxyHost: string;
  proxyPort: number;
  /** Overrides the profile's starter allowlist when non-empty. */
  allowedHosts: readonly string[];
  budgetWindowSeconds: number;
  budgetMaxRequests: number;
  /** Replace an existing agent of the same id instead of refusing. */
  force: boolean;
  json: boolean;
}

export interface OnboardResult {
  profile: AgentProfile;
  agentId: string;
  secret: string;
  digest: string;
  configPath: string;
  backupPath: string | null;
  allowedHosts: readonly string[];
  /** Literal `export KEY='value'` lines, ready to paste. */
  envLines: readonly string[];
  /** The interception lines, kept separate because interception is opt-in and off by default. */
  interceptionLines: readonly string[];
  /**
   * What the config ACTUALLY enforces, read back rather than assumed. Onboarding does not set
   * the mode, so claiming one would be a guess printed as a fact.
   */
  postureLines: readonly string[];
  replacedExisting: boolean;
}

/** The agent entry written into `fleet.agents`, matching FleetAgentSchema on the train base. */
interface FleetAgentEntry {
  id: string;
  label: string;
  match: { credential: string };
  egress?: { allowedHosts: string[] };
  budget: { windowSeconds: number; maxRequests: number };
}

function quoteForShell(value: string): string {
  // Single quotes with the standard close-escape-reopen dance. Credentials are hex and an agent
  // id cannot contain a quote, but the allowlist and paths are operator input and this output is
  // meant to be pasted into a shell verbatim.
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * The proxy URL an agent uses, credential included.
 *
 * The credential is the userinfo. That is not a shortcut, it is the only mechanism that works
 * through an environment variable, and it is why the secret was minted in `id:token` form.
 */
export function proxyUrlFor(secret: string, host: string, port: number): string {
  return `http://${secret}@${host}:${port}`;
}

/**
 * The environment a runtime needs, derived from what the profile MEASURED rather than from a
 * template.
 *
 * Only variables in `proxyEnv.honoured` are emitted. A variable the profile recorded as ignored
 * is not printed at all, because printing it would suggest it does something. Where a profile
 * measured an ignored spelling, the caller renders that as a warning instead.
 *
 * NO_PROXY is deliberately NOT set, even for runtimes measured to honour it. Every entry in
 * NO_PROXY is an address the agent reaches with no AgentWall in the path, so a default of
 * `localhost,127.0.0.1,::1` would ship a hole covering all of loopback: local databases, any
 * SSH tunnel forwarded there, and any local proxy that itself reaches the internet. It would
 * also pre-decide `verify-capture`, whose canary binds 127.0.0.1 by default, into either a
 * false bypass or an inconclusive result.
 *
 * The exemption is not needed anyway. None of these agents call AgentWall's own dashboard; the
 * operator reaches it from a browser or the CLI, and neither runs with the agent's proxy
 * environment. Where an agent genuinely must reach a local service, the answer is that agent's
 * egress allowlist, which is recorded in the chain, rather than a hole that is not.
 */
export function renderEnvLines(profile: AgentProfile, proxyUrl: string): string[] {
  const lines: string[] = [];
  for (const variable of profile.proxyEnv.honoured) {
    if (variable === "NO_PROXY" || variable === "no_proxy") continue;
    lines.push(`export ${variable}=${quoteForShell(proxyUrl)}`);
  }
  return lines;
}

/**
 * The note explaining the NO_PROXY that is deliberately absent.
 *
 * Printed rather than left silent: an operator who notices the omission should find the reason
 * next to it, not conclude the tool forgot.
 */
export function renderNoProxyNote(profile: AgentProfile): string[] {
  if (!profile.proxyEnv.honoured.some((v) => v === "NO_PROXY" || v === "no_proxy")) return [];
  return [
    "# NO_PROXY is deliberately NOT set, though this runtime honours it. Every entry in it is an",
    "# address the agent reaches with AgentWall out of the path, and it would pre-decide",
    "# verify-capture, whose canary binds loopback. If an agent must reach a local service, add",
    "# that host to its egress allowlist instead, where the decision is recorded.",
  ];
}

/**
 * The interception lines, or an explanation of why there are none.
 *
 * Semantics drive the text because they drive what the operator must actually do. A
 * "replacement" variable pointed at a bare CA file removes every public root and takes the agent
 * off the internet, so that case emits a bundle-building step rather than a bare path. An
 * "ignored" variable is printed as a warning so nobody reaches for it. An "unknown" one refuses
 * to emit a line at all.
 */
export function renderInterceptionLines(profile: AgentProfile, caPath: string): string[] {
  const lines: string[] = [];
  // One bundle per profile, built at most once even when several variables need it. python
  // requests reads REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE as aliases for the same thing, so
  // emitting the concatenation twice would just rewrite the same file mid-snippet.
  const bundlePath = path.join(process.env.HOME ?? "/root", ".agentwall", `${profile.id}-bundle.pem`);
  let bundleEmitted = false;

  for (const fact of profile.caTrust) {
    if (fact.semantics === "unknown") {
      lines.push(
        `# ${profile.label}: CA trust store UNVERIFIED. No line is emitted, deliberately.`,
        `#   ${fact.evidence}`
      );
      continue;
    }
    if (fact.semantics === "ignored") {
      lines.push(
        `# WARNING ${fact.variable} is IGNORED by this runtime. Setting it does nothing.`,
        `#   ${fact.evidence}`
      );
      continue;
    }
    if (fact.semantics === "replacement") {
      if (!bundleEmitted) {
        lines.push(
          `# This runtime REPLACES the public trust store with whatever the variable names, so`,
          `# the file has to carry the public roots too. Pointing it at the bare CA would make`,
          `# every public HTTPS call this agent attempts fail CERTIFICATE_VERIFY_FAILED.`,
          `mkdir -p ${quoteForShell(path.dirname(bundlePath))}`,
          `cat ${quoteForShell(caPath)} /etc/ssl/certs/ca-certificates.crt > ${quoteForShell(bundlePath)}`
        );
        bundleEmitted = true;
      }
      // Absolute, never "~": the path is single-quoted for the shell, and a quoted tilde is a
      // literal directory named "~" rather than $HOME. That would point the agent at a file
      // that does not exist while looking exactly like a working line.
      lines.push(`export ${fact.variable}=${quoteForShell(bundlePath)}`);
      continue;
    }
    lines.push(
      `# ${fact.variable} is additive: the public roots survive.`,
      `export ${fact.variable}=${quoteForShell(caPath)}`
    );
  }
  return lines;
}

/**
 * Report the posture the config ACTUALLY has, rather than the one onboarding wishes it had.
 *
 * `onboard` declares an agent; it does not set the enforcement mode, and it deliberately does
 * not change one it finds. So the report reads the document back. An operator who ran
 * `init --mode strict` and was then told "monitor, nothing will start failing because you ran
 * this command" would have been handed a reassuring falsehood by the one command in this
 * repository whose entire purpose is refusing to do that.
 *
 * Both keys matter and they are independent: `enforcement.mode` gates the runtime, and
 * `egress.defaultDeny` decides whether a host outside the allowlist is refused.
 */
export function renderPostureLines(document: Record<string, unknown>): string[] {
  const enforcement = document["enforcement"];
  let mode = "monitor";
  if (enforcement && typeof enforcement === "object" && "mode" in enforcement) {
    const raw = enforcement.mode;
    if (typeof raw === "string") mode = raw;
  }

  const egress = document["egress"];
  let defaultDeny = false;
  if (egress && typeof egress === "object" && "defaultDeny" in egress) {
    defaultDeny = egress.defaultDeny === true;
  }

  if (mode === "monitor" && !defaultDeny) {
    return [
      "Mode:       monitor, and egress is not default-deny. This agent is RECORDED, not",
      "            blocked. Nothing it does today starts failing because you ran this command.",
    ];
  }

  // Enforcing. Say what will actually happen, and name the allowlist as the thing to fix,
  // because the first symptom otherwise is the agent failing for reasons nobody connects
  // back to an onboarding step that printed a cheerful summary.
  return [
    `Mode:       ${mode}${defaultDeny ? ", egress is DEFAULT-DENY" : ""}. This config ENFORCES.`,
    "            WARNING: unlike the monitor default, this agent can be blocked immediately.",
    "            Anything outside the allowlist below is refused as soon as AgentWall reloads.",
    "            Widen the allowlist first, or run in monitor until verify-capture passes.",
  ];
}

/**
 * Load the config file as a plain object.
 *
 * Deliberately NOT loadConfig(): that applies defaults, resolves env credentials and validates
 * the whole document, and writing its output back would rewrite parts of the file the operator
 * never touched. Onboard edits one section and leaves the rest as it found it.
 */
function readConfigDocument(configPath: string): Record<string, unknown> {
  const raw = fs.readFileSync(configPath, "utf8");
  const parsed = yaml.load(raw);
  if (parsed === null || parsed === undefined) return {};
  if (typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`agentwall: ${configPath} is not a YAML mapping, so there is nowhere to add an agent.`);
  }
  return parsed as Record<string, unknown>;
}

/**
 * Insert or replace one agent in the fleet section, returning the new document.
 *
 * Pure so the round trip is testable without touching a disk. `unmatched` is only ever
 * initialised to "global" and never changed: switching a fleet to "deny" refuses every
 * connection that is not yet declared, and an onboarding command that quietly did that would
 * take the rest of the host's agents offline the moment the operator onboarded their first one.
 */
export function withAgent(
  document: Record<string, unknown>,
  entry: FleetAgentEntry,
  force: boolean
): { document: Record<string, unknown>; replacedExisting: boolean } {
  const next = { ...document };
  const existingFleet = (next["fleet"] ?? {}) as Record<string, unknown>;
  const agents = Array.isArray(existingFleet["agents"])
    ? [...(existingFleet["agents"] as FleetAgentEntry[])]
    : [];

  const index = agents.findIndex((agent) => agent && agent.id === entry.id);
  if (index >= 0 && !force) {
    throw new Error(
      `agentwall: an agent with id "${entry.id}" is already declared in this config. Re-run with ` +
        `--force to replace it, which mints a NEW credential and invalidates the old one, or pass ` +
        `--agent-id to onboard a second instance of this profile under a different id.`
    );
  }
  if (index >= 0) agents[index] = entry;
  else agents.push(entry);

  next["fleet"] = {
    ...existingFleet,
    unmatched: existingFleet["unmatched"] ?? "global",
    agents,
  };
  return { document: next, replacedExisting: index >= 0 };
}

/**
 * Do the onboarding: mint, write config, and compute the output.
 *
 * The credential digest is the only credential material that touches disk. The secret exists in
 * this process and in the printed output, and nowhere else; there is no file to forget to
 * delete and no recovery path other than minting a new one.
 */
export function runOnboard(request: OnboardRequest): OnboardResult {
  const profile = findProfile(request.profileId);
  if (!profile) {
    throw new Error(
      `agentwall: unknown profile "${request.profileId}". Available: ${profileIds().join(", ")}.`
    );
  }
  if (!fs.existsSync(request.configPath)) {
    throw new Error(
      `agentwall: no config at ${request.configPath}. Run \`agentwall init --mode monitor\` first, ` +
        `then onboard into it.`
    );
  }

  const credential = mintCredential(request.agentId);
  const allowedHosts =
    request.allowedHosts.length > 0 ? [...request.allowedHosts] : [...profile.starterHosts];

  const entry: FleetAgentEntry = {
    id: request.agentId,
    label: `${profile.label} (onboarded from profile ${profile.id})`,
    match: { credential: `sha256:${credential.digest}` },
    budget: {
      windowSeconds: request.budgetWindowSeconds,
      maxRequests: request.budgetMaxRequests,
    },
  };
  // An empty allowlist would fail AgentEgressSchema's refine, and it would also mean something
  // different from what the operator wants: omitting the block entirely leaves the agent judged
  // by the process-wide allowlist, which is the correct monitor-mode default for a profile
  // whose destinations we do not know.
  if (allowedHosts.length > 0) entry.egress = { allowedHosts };

  const document = readConfigDocument(request.configPath);
  const { document: updated, replacedExisting } = withAgent(document, entry, request.force);

  // Backup before the round trip. yaml.load + yaml.dump does not preserve comments, and an
  // operator who hand-annotated their config deserves to get it back rather than a lecture.
  const backupPath = `${request.configPath}.bak`;
  fs.copyFileSync(request.configPath, backupPath);
  fs.writeFileSync(request.configPath, yaml.dump(updated, { noRefs: true, lineWidth: 120 }));

  const proxyUrl = proxyUrlFor(credential.secret, request.proxyHost, request.proxyPort);
  const caPath = path.join(process.env.HOME ?? "/root", ".agentwall", "ca", "agentwall-ca.crt");

  // Read the posture back out of the document rather than asserting it. `onboard` writes an
  // agent, not a mode, and an operator who ran `init --mode strict` would otherwise be told
  // "monitor, nothing will start failing" by a command that had not looked. That is the same
  // class of untrue-but-reassuring output this whole command refuses to produce.
  const postureLines = renderPostureLines(updated);

  return {
    profile,
    agentId: request.agentId,
    secret: credential.secret,
    digest: credential.digest,
    configPath: request.configPath,
    backupPath,
    allowedHosts,
    envLines: renderEnvLines(profile, proxyUrl),
    interceptionLines: renderInterceptionLines(profile, caPath),
    postureLines,
    replacedExisting,
  };
}

function gradeBanner(label: string, grade: string): string {
  const suffix =
    grade === "verified"
      ? "measured end to end on the verification host"
      : grade === "partial"
        ? "mechanism observed, end-to-end path NOT observed"
        : "NOT VERIFIED, treat every line below as a guess";
  return `${label}: ${grade.toUpperCase()} (${suffix})`;
}

/**
 * Render the operator-facing report.
 *
 * Ordered by what someone acts on first, and it ends on the unfinished step rather than on a
 * summary, because the last thing on screen is the thing people do.
 */
export function renderReport(result: OnboardResult, request: OnboardRequest): string {
  const p = result.profile;
  const out: string[] = [];

  out.push(`Onboarded "${result.agentId}" from profile ${p.id} (${p.label}).`);
  if (result.replacedExisting) {
    out.push(`Replaced the existing declaration of "${result.agentId}". Its previous credential no longer works.`);
  }
  out.push("");
  out.push(`  ${gradeBanner("Capture (proxy env)", captureGrade(p))}`);
  out.push(`  ${gradeBanner("Interception (CA store)", interceptionGrade(p))}`);
  out.push(`  Runtime checked: ${p.verifiedAgainst ?? "none, nothing was checked against a real runtime"}`);
  out.push("");

  out.push("CREDENTIAL, PRINTED ONCE AND NEVER AGAIN");
  out.push("");
  out.push(`  ${result.secret}`);
  out.push("");
  out.push(`  AgentWall stored only its digest (sha256:${result.digest.slice(0, 16)}...).`);
  out.push("  The secret is not written to any file. If you lose it, re-run onboard with --force");
  out.push("  to mint a replacement; there is no recovery.");
  out.push("");

  out.push("CONFIG");
  out.push(`  Written:    ${result.configPath}`);
  out.push(`  Backup:     ${result.backupPath} (the YAML round trip does not preserve comments)`);
  for (const line of result.postureLines) out.push(`  ${line}`);
  out.push(
    `  Allowlist:  ${result.allowedHosts.length > 0 ? result.allowedHosts.join(", ") : "none set, the process-wide allowlist judges this agent"}`
  );
  out.push(`  Budget:     ${request.budgetMaxRequests} requests per ${request.budgetWindowSeconds}s`);
  out.push("");

  out.push(`ENVIRONMENT FOR ${p.label.toUpperCase()}`);
  out.push("");
  out.push(`  # AgentWall itself needs this, or nothing is listening on ${request.proxyPort}:`);
  out.push(`  export AGENTWALL_PROXY_PORT=${request.proxyPort}`);
  out.push("");
  out.push("  # The agent needs these. The credential is the userinfo in the URL.");
  for (const line of result.envLines) out.push(`  ${line}`);
  if (p.proxyEnv.ignored.length > 0) {
    out.push("");
    out.push(`  # MEASURED AND IGNORED by this runtime, do not bother: ${p.proxyEnv.ignored.join(", ")}`);
  }
  const noProxyNote = renderNoProxyNote(p);
  if (noProxyNote.length > 0) {
    out.push("");
    for (const line of noProxyNote) out.push(`  ${line}`);
  }
  out.push("");

  out.push("TLS INTERCEPTION (opt-in, off by default, not required for capture)");
  out.push("");
  for (const line of result.interceptionLines) out.push(`  ${line}`);
  out.push("");

  out.push("WHAT THIS RUNTIME DOES ON ITS OWN");
  out.push(`  MCP:          ${p.mcp}`);
  out.push(`  Subprocesses: ${p.subprocessEgress}`);
  out.push("");

  out.push("WHAT THIS PROFILE DOES NOT COVER");
  for (const limit of p.limits) out.push(`  - ${limit}`);
  out.push("");

  out.push("NOT DONE YET");
  out.push("");
  out.push("  Configuration is not capture. This command wrote config and printed an environment;");
  out.push("  it has proven nothing about whether this agent's traffic actually reaches AgentWall.");
  out.push("  Runtimes bypass proxies silently: bare Node 24 ignores HTTPS_PROXY entirely and still");
  out.push("  returns 200, so the agent looks fine while nothing is governed.");
  out.push("");
  out.push("  Export the environment above in the agent's own shell, then run:");
  out.push("");
  out.push(`      export AGENTWALL_AUDIT_FILE=<path to the audit chain>`);
  out.push(`      agentwall verify-capture --agent ${result.agentId}`);
  out.push("");
  out.push("  Exit 0 means captured. Exit 1 means NOT captured (no chain record, wrong agent, or a");
  out.push("  bypass). Exit 2 means the check could not run. Onboarding is complete when that");
  out.push("  command exits 0, and not before.");

  return out.join("\n");
}

const USAGE = `agentwall onboard <profile> [options]

Mint an identity for one agent runtime, write it into config, and print the environment that
runtime needs. Does NOT prove capture: finish with \`agentwall verify-capture --agent <id>\`.

Profiles:
${AGENT_PROFILES.map((p) => `  ${p.id.padEnd(14)} ${p.label} [${profileGrade(p)}]`).join("\n")}

Options:
  --agent-id <id>        Agent id to declare. Default: the profile id.
  --config <path>        Config to edit. Default: ./agentwall.config.yaml
  --proxy-host <host>    Proxy host the agent dials. Default: 127.0.0.1
  --proxy-port <port>    Proxy port. Default: 3128
  --allow <a,b>          Allowlist, comma separated. Default: the profile's starter hosts.
  --budget-requests <n>  Requests per window. Default: 2000
  --budget-window <s>    Window in seconds. Default: 3600
  --force                Replace an existing agent of the same id, minting a new credential.
  --json                 Emit the result as JSON. The secret is included; it is still printed once.
`;

function flagValue(args: string[], name: string): string | undefined {
  const index = args.indexOf(`--${name}`);
  if (index < 0) return undefined;
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) {
    throw new Error(`agentwall: --${name} needs a value.`);
  }
  return value;
}

function positiveInt(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`agentwall: --${name} must be a positive integer, got "${raw}".`);
  }
  return value;
}

/**
 * CLI entry. Returns an exit code rather than calling process.exit so it is testable.
 *
 * Note what it does NOT return: a success code that means "this agent is governed". Exit 0 here
 * means "config written and environment printed", and the printed text says so in those words.
 */
export function runOnboardCommand(argv: string[]): number {
  // argv arrives as the raw tail after `onboard`, so the profile is the first non-flag token.
  const positionals = argv.filter((token) => !token.startsWith("--"));
  const flagged = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    if (!argv[i].startsWith("--")) continue;
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) flagged.add(next);
  }
  const profileId = positionals.find((token) => !flagged.has(token));

  if (!profileId || profileId === "help") {
    console.log(USAGE);
    return profileId === "help" ? EXIT_OK : EXIT_USAGE;
  }

  const profile = findProfile(profileId);
  if (!profile) {
    console.error(`agentwall: unknown profile "${profileId}". Available: ${profileIds().join(", ")}.`);
    return EXIT_USAGE;
  }

  const request: OnboardRequest = {
    profileId,
    agentId: flagValue(argv, "agent-id") ?? profileId,
    configPath: path.resolve(process.cwd(), flagValue(argv, "config") ?? "agentwall.config.yaml"),
    proxyHost: flagValue(argv, "proxy-host") ?? "127.0.0.1",
    proxyPort: positiveInt(flagValue(argv, "proxy-port"), 3128, "proxy-port"),
    allowedHosts: (flagValue(argv, "allow") ?? "")
      .split(",")
      .map((host) => host.trim())
      .filter(Boolean),
    budgetWindowSeconds: positiveInt(flagValue(argv, "budget-window"), 3600, "budget-window"),
    budgetMaxRequests: positiveInt(flagValue(argv, "budget-requests"), 2000, "budget-requests"),
    force: argv.includes("--force"),
    json: argv.includes("--json"),
  };

  const result = runOnboard(request);

  if (request.json) {
    console.log(
      JSON.stringify(
        {
          agentId: result.agentId,
          profile: result.profile.id,
          captureGrade: captureGrade(result.profile),
          interceptionGrade: interceptionGrade(result.profile),
          secret: result.secret,
          credential: `sha256:${result.digest}`,
          configPath: result.configPath,
          backupPath: result.backupPath,
          allowedHosts: result.allowedHosts,
          env: result.envLines,
          interception: result.interceptionLines,
          onboardingComplete: false,
          nextStep: `agentwall verify-capture --agent ${result.agentId}`,
        },
        null,
        2
      )
    );
    return EXIT_OK;
  }

  console.log(renderReport(result, request));
  return EXIT_OK;
}
