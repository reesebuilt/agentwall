import { loadConfig, resolveConfigSource } from "../config";
import {
  CredentialStore,
  DEFAULT_OVERLAP_SECONDS,
  MAX_OVERLAP_SECONDS,
  credentialState,
  formatDuration,
  parseDurationSeconds,
  resolveCredentialStorePath,
} from "./credentials";
import type { CredentialState, StoredCredential } from "./credentials";
import { AgentRegistry } from "./registry";
import type { FleetAgentConfig, FleetConfig } from "./registry";

/**
 * `agentwall fleet` - the credential lifecycle an organisation needs and one host does not.
 *
 * On a single box a credential is a digest you write into a config file once and forget. On a
 * fleet it is an operational object with three moments that matter, and none of them are
 * served by editing YAML on every host:
 *
 *   issue    Mint a secret, record only its digest, print the secret once. The secret is
 *            never written anywhere by this command, so losing it means rotating rather than
 *            recovering it.
 *   rotate   Replace it while accepting the old one for a bounded, stated window. Without the
 *            window, rotation is an outage: the instant the new digest lands, every host
 *            still presenting the old secret is refused.
 *   revoke   End one credential without touching any other. Takes effect on the running proxy
 *            within a second, without a restart.
 *
 * None of these talk to a running instance. They are file operations against the credential
 * store, which the proxy re-reads on its own; see src/fleet/credentials.ts. That is a
 * deliberate choice about failure modes: an operator revoking a credential during an incident
 * should not need the thing they are containing to be healthy enough to accept an API call.
 */

const EXIT_OK = 0;
/** The command was understood and could not be carried out. */
const EXIT_FAIL = 1;
/** Bad arguments. */
const EXIT_USAGE = 2;

const VALUE_FLAGS = ["agent", "credential", "overlap", "reason", "config", "store"];

const USAGE = `Usage: agentwall fleet <subcommand> [options]

Subcommands:
  list                          Every issued credential, its agent, and its state
  issue    --agent <id>         Mint a credential for a declared agent. Prints the secret once
  rotate   --agent <id>         Replace an agent's credential, keeping the old one for a window
  revoke   --credential <id>    End one credential. Other agents are unaffected
  revoke   --agent <id>         End every credential an agent holds

Options:
  --overlap <duration>   rotate only: how long the old credential keeps working.
                         Default ${formatDuration(DEFAULT_OVERLAP_SECONDS)}, maximum ${formatDuration(MAX_OVERLAP_SECONDS)}, 0 for an immediate cutover.
                         Units: 90s, 15m, 2h, 1d. A bare number is seconds.
  --reason <text>        revoke only: recorded beside the tombstone and shown in the chain
  --config <path>        config file that declares the fleet (default: the usual search)
  --store <path>         credential store (default: fleet-credentials.json beside the config)
  --json                 machine-readable output

Exit codes: 0 ok, 1 the command could not be carried out, 2 bad usage.

The secret is printed once by \`issue\` and \`rotate\` and is stored nowhere. Only its sha256
digest is written. That is why there is no "show" subcommand: there is nothing to show.

When a change takes effect: an instance reading this store picks up \`revoke\` and \`rotate\` on its
next connection, within one second, with no restart and no signal. \`issue\` is the same, but an
agent still has to be given the new secret before it can present it. Whether the change is then
ENFORCED depends on \`enforcement.mode\`: monitor records and blocks nothing, including a
revocation. Each command reads that mode from your config and says which case you are in.

If the proxy cannot read the store at all (deleted, unreadable, corrupt), it keeps the last
copy it parsed and reports the failure in \`agentwall doctor\`. Enforcement continues; what is
lost is your ability to change it.`;

/** An operator mistake, not a failure of the host. Reported with usage and exit 2. */
class UsageError extends Error {}

interface ParsedArgs {
  subcommand: string;
  flags: Record<string, string>;
  json: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [subcommand = "", ...rest] = argv;
  const flags: Record<string, string> = {};
  let json = false;

  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index];
    if (!token.startsWith("--")) throw new UsageError(`unexpected argument "${token}"`);
    const key = token.slice(2);
    if (key === "json") {
      json = true;
      continue;
    }
    if (!VALUE_FLAGS.includes(key)) throw new UsageError(`unknown option "--${key}"`);
    const value = rest[index + 1];
    if (value === undefined || value.startsWith("--")) throw new UsageError(`--${key} needs a value`);
    flags[key] = value;
    index += 1;
  }

  return { subcommand, flags, json };
}

/** The declared fleet and the store that goes with it, resolved from the same config file. */
interface FleetContext {
  configPath: string;
  agents: readonly FleetAgentConfig[];
  minimumMatchTier: string;
  /** The parsed section itself, so doctor can build the same registry the server will. */
  fleet: FleetConfig;
  store: CredentialStore;
  /**
   * host:port of the forward proxy, or null when AGENTWALL_PROXY_PORT is not set here.
   *
   * Null rather than a placeholder. A previous version printed
   * `HTTPS_PROXY=http://<secret>@127.0.0.1:<AGENTWALL_PROXY_PORT>` when the port was unknown,
   * which is a line an operator pastes and which bash reads `<` as a redirect: a snippet that
   * cannot execute, shipped into someone else's terminal. If the port is not readable from
   * here, the line is not printed and the reason is.
   */
  proxyTarget: string | null;
  /**
   * `enforcement.mode`, read back out of the config rather than assumed.
   *
   * Every "this takes effect in one second" sentence this command prints is FALSE under
   * monitor, which gates nothing. Printing it unconditionally would be a confident, specific
   * promise about behaviour that the code never checked, which is the exact shape of the
   * three defects found across this batch today.
   */
  mode: string;
  /** True when --store pointed somewhere other than the path the config names. */
  storeOverridden: boolean;
}

function openFleet(flags: Record<string, string>): FleetContext {
  const configPath = resolveConfigSource(flags["config"]);
  if (!configPath) {
    throw new UsageError(
      "no agentwall.config.yaml found. Run this from the directory that holds it, pass --config <path>, or set AGENTWALL_CONFIG."
    );
  }
  const config = loadConfig(flags["config"]);
  if (!config.fleet || config.fleet.agents.length === 0) {
    throw new UsageError(
      `${configPath} declares no fleet agents. A credential identifies one of them, so there is nothing to issue it to. ` +
        `Add a fleet.agents entry first; see docs/fleet.md.`
    );
  }
  const proxyHost = process.env["AGENTWALL_PROXY_HOST"] ?? "127.0.0.1";
  const proxyPort = process.env["AGENTWALL_PROXY_PORT"];
  const declaredStore = resolveCredentialStorePath(configPath, config.fleet.credentialStore);
  const store = new CredentialStore(resolveCredentialStorePath(configPath, flags["store"] ?? config.fleet.credentialStore));
  return {
    configPath,
    agents: config.fleet.agents,
    minimumMatchTier: config.fleet.minimumMatchTier,
    fleet: config.fleet,
    store,
    proxyTarget: proxyPort ? `${proxyHost}:${proxyPort}` : null,
    // `enforcement` is optional in the type and defaulted by loadConfig, which throws on an
    // unrecognised mode. Absent therefore means the shipped default, which is monitor: the
    // conservative reading, and the one that makes this command UNDERstate what will happen
    // rather than promise enforcement that is not configured.
    mode: config.enforcement?.mode ?? "monitor",
    storeOverridden: store.filePath !== declaredStore,
  };
}

/**
 * Resolve `--agent` against the declaration.
 *
 * Refuses an id the config does not declare, rather than minting a credential nothing will
 * ever present. A typo here would otherwise produce a perfectly valid secret bound to an
 * agent that does not exist, and the operator would discover it when the deployment they just
 * shipped got refused.
 */
function requireDeclaredAgent(context: FleetContext, flags: Record<string, string>): FleetAgentConfig {
  const id = flags["agent"];
  if (!id) throw new UsageError("--agent <id> is required");
  const declared = context.agents.find((agent) => agent.id === id);
  if (!declared) {
    throw new UsageError(
      `${context.configPath} declares no agent "${id}". Declared agents: ${context.agents.map((agent) => agent.id).join(", ")}`
    );
  }
  // `issued` is the declaration that says the store owns this agent's digest, so it is the
  // one credential line issuance is allowed to see. A pinned `sha256:` or `env:` digest is
  // refused: minting beside it would leave two secrets that both bind, and revoking the
  // issued one would look like it worked while the config line kept letting the agent in.
  if (declared.match.credential !== undefined && declared.match.credential !== "issued") {
    throw new UsageError(
      `agent "${id}" pins match.credential in ${context.configPath}. A digest written into config has no ` +
        `lifecycle: it cannot be rotated with an overlap and cannot be revoked from here. Replace that line ` +
        `with "credential: issued", then issue.`
    );
  }
  return declared;
}

/** What one stored credential is doing, as `fleet list` prints it. */
function describeCredential(credential: StoredCredential, now: number = Date.now()): string {
  const state = credentialState(credential, now);
  if (state === "revoked") {
    return `revoked ${credential.revokedAt}${credential.revokedReason ? `: ${credential.revokedReason}` : ""}`;
  }
  if (state === "overlap") {
    const remaining = (Date.parse(credential.expiresAt ?? "") - now) / 1000;
    return `rotated out, still accepted for ${formatDuration(remaining)} (until ${credential.expiresAt})`;
  }
  if (state === "expired") return `overlap closed ${credential.expiresAt}, refused since`;
  return `issued ${credential.issuedAt}`;
}

/** One line an operator has to be able to act on, with a severity `doctor` renders. */
export interface FleetDoctorLine {
  level: "ok" | "warn" | "fail";
  text: string;
}

/**
 * What `agentwall doctor` says about fleet credentials.
 *
 * Lives here rather than in cli.ts so that the doctor line and `fleet list` cannot drift into
 * describing the same store differently, which is exactly the kind of divergence that has an
 * operator reading one screen and acting on the other.
 *
 * Empty when no fleet is declared. Doctor must stay silent on a single-agent install rather
 * than growing four lines about a feature nobody turned on.
 */
export function fleetDoctorLines(configPath?: string): FleetDoctorLine[] {
  let context: FleetContext;
  try {
    context = openFleet(configPath ? { config: configPath } : {});
  } catch (error) {
    // A missing config or an undeclared fleet is not a doctor finding: it is the default
    // single-agent install. A config that fails to PARSE is, and loadConfig throws a message
    // that names the file and the key.
    if (error instanceof UsageError) return [];
    return [{ level: "fail", text: `Fleet config could not be read: ${error instanceof Error ? error.message : String(error)}` }];
  }

  const lines: FleetDoctorLine[] = [];
  const store = context.store;
  if (store.error) {
    lines.push({
      level: "fail",
      text:
        `Credential store ${store.filePath} could not be parsed (${store.error.message}). ` +
        `A running proxy keeps the last copy it read, so issued credentials still work and can no longer be changed.`,
    });
    return lines;
  }

  const now = Date.now();
  const credentials = store.list();
  const byState = (state: CredentialState): StoredCredential[] =>
    credentials.filter((credential) => credentialState(credential, now) === state);

  const active = byState("active");
  const overlap = byState("overlap");
  const expired = byState("expired");
  const revoked = byState("revoked");

  lines.push({
    level: "ok",
    text:
      `Fleet credentials: ${active.length} active, ${overlap.length} mid-rotation, ${revoked.length} revoked ` +
      `(${store.absent ? "none issued yet" : store.filePath})`,
  });

  // The rotation windows, named individually. This is the number an operator needs during a
  // rotation and the one they will otherwise guess at: a window that closes in four minutes
  // and a window that closes tomorrow call for different behaviour in the next ten minutes.
  for (const credential of overlap) {
    const remaining = (Date.parse(credential.expiresAt ?? "") - now) / 1000;
    lines.push({
      level: "warn",
      text:
        `Rotation in progress: agent "${credential.agentId}" credential ${credential.credentialId} stops working in ` +
        `${formatDuration(remaining)} (${credential.expiresAt}). Both secrets are accepted until then.`,
    });
  }

  // "refused" only when the mode actually refuses. Under monitor these are recorded and let
  // through, and telling an operator otherwise is a specific, confident, unverified promise.
  const refused = context.mode === "monitor" ? "recorded and NOT blocked (enforcement.mode is monitor)" : "refused";
  for (const credential of expired) {
    lines.push({
      level: "ok",
      text:
        `Agent "${credential.agentId}" credential ${credential.credentialId} is past its overlap ` +
        `(${credential.expiresAt}); presenting it is ${refused}. The record is kept as the history of that rotation.`,
    });
  }

  // Declared agents that can never bind, from the SAME code the running proxy uses. Doctor
  // re-deriving this from the config would be a second implementation of the floor, and the
  // two would eventually disagree about which agents are refused, which is the worst
  // possible thing for the screen an operator reads when something is being refused.
  //
  // Constructing the registry also re-runs every boot-time refusal in it, so a fleet section
  // that would stop the server from starting is a doctor failure here instead of a surprise
  // on the next restart.
  try {
    for (const blocked of new AgentRegistry(context.fleet, store).unbindable()) {
      lines.push({
        level: "warn",
        text: `Agent "${blocked.id}" can never bind, so every connection it makes is ${refused}: ${blocked.reason}`,
      });
    }
  } catch (error) {
    lines.push({
      level: "fail",
      text: `Fleet section will not start: ${error instanceof Error ? error.message : String(error)}`,
    });
  }

  return lines;
}

/**
 * The one moment the secret exists outside the CSPRNG.
 *
 * Both presentation forms are printed because both are real and they are not interchangeable
 * knowledge: an operator who only learns the Bearer header will hand-roll a wrapper for
 * something that already speaks proxy URLs, and one who only learns the URL cannot configure
 * a client that takes an explicit header.
 */
function printSecret(secret: string, proxyTarget: string | null): void {
  console.log("");
  console.log(`  ${secret}`);
  console.log("");
  console.log("Printed once and stored nowhere. Only its sha256 digest is on disk. If it is lost,");
  console.log("rotate; there is nothing to recover.");
  console.log("");
  console.log("Present it either way. Both hash to the same digest:");
  console.log(`  Proxy-Authorization: Bearer ${secret}`);
  if (proxyTarget) {
    console.log(`  export HTTPS_PROXY=http://${secret}@${proxyTarget}`);
  } else {
    // Described in prose, NOT laid out as a command. The proxy port lives only in
    // AGENTWALL_PROXY_PORT, which is set for the server process and is not readable here, so
    // there is no real line to print. A template in the paste column would get pasted, and
    // `<proxy-port>` is a shell redirect: it would fail with "No such file or directory" and
    // send someone hunting a credential bug that does not exist.
    console.log("  For the URL form, set HTTPS_PROXY to http://SECRET@HOST:PORT using the secret above");
    console.log("  and the host and port the proxy listens on. AGENTWALL_PROXY_PORT is not set in this");
    console.log("  shell, so the exact line cannot be printed here.");
  }
  console.log("");
  console.log("Anything that can read this can be this agent. On a single-uid host that means it");
  console.log("separates cooperating agents and does not contain a hostile one.");
}

/**
 * What an operator can be told about when a store change starts being enforced.
 *
 * Read from `enforcement.mode` and from whether `--store` pointed away from the configured
 * path, rather than asserted. "In force on a running proxy within one second" is false under
 * monitor, which gates nothing, and false for any instance not reading this file.
 */
function effectNotes(context: FleetContext): string[] {
  const notes: string[] = [];
  if (context.storeOverridden) {
    notes.push(
      `--store pointed at ${context.store.filePath}, which is NOT the store ${context.configPath} names. ` +
        `An instance started from that config will not read this file, so nothing here changes what it enforces.`
    );
    return notes;
  }
  if (context.mode === "monitor") {
    notes.push(
      `enforcement.mode is "monitor" in ${context.configPath}. An instance reading this store picks the ` +
        `change up within one second and will RECORD it without blocking anything, with the projection in ` +
        `the record saying what guarded and strict would have done. Use the lockdown to actually stop traffic.`
    );
    return notes;
  }
  notes.push(
    `An instance started from ${context.configPath} (enforcement.mode "${context.mode}") picks this up on ` +
      `its next connection, within one second. No restart and no signal.`
  );
  return notes;
}

function commandIssue(context: FleetContext, flags: Record<string, string>, json: boolean): number {
  const declared = requireDeclaredAgent(context, flags);
  const { credential, secret } = context.store.issue(declared.id);
  if (json) {
    // The secret IS in the JSON. This output exists to be piped into a secret manager, and a
    // machine-readable form that omitted the one value the caller needs would just push
    // people back to scraping the human output.
    console.log(JSON.stringify({ agentId: credential.agentId, credentialId: credential.credentialId, secret, issuedAt: credential.issuedAt, store: context.store.filePath }, null, 2));
    return EXIT_OK;
  }
  console.log(`Issued credential ${credential.credentialId} for agent "${credential.agentId}".`);
  console.log(`Digest recorded in ${context.store.filePath}.`);
  printSecret(secret, context.proxyTarget);
  for (const note of effectNotes(context)) console.log(note);
  return EXIT_OK;
}

function commandRotate(context: FleetContext, flags: Record<string, string>, json: boolean): number {
  const declared = requireDeclaredAgent(context, flags);
  const overlapSeconds = flags["overlap"] === undefined ? DEFAULT_OVERLAP_SECONDS : parseDurationSeconds(flags["overlap"]);
  const { previous, credential, secret } = context.store.rotate(declared.id, overlapSeconds);
  if (json) {
    console.log(
      JSON.stringify(
        {
          agentId: credential.agentId,
          credentialId: credential.credentialId,
          secret,
          previousCredentialId: previous.credentialId,
          previousAcceptedUntil: previous.expiresAt,
          overlapSeconds,
          store: context.store.filePath,
        },
        null,
        2
      )
    );
    return EXIT_OK;
  }
  console.log(`Rotated agent "${credential.agentId}".`);
  console.log(`  new credential ${credential.credentialId}, active now`);
  if (overlapSeconds === 0) {
    console.log(`  old credential ${previous.credentialId} is refused as of ${previous.expiresAt}, immediately`);
  } else {
    console.log(
      `  old credential ${previous.credentialId} is accepted for another ${formatDuration(overlapSeconds)}, until ${previous.expiresAt}`
    );
  }
  printSecret(secret, context.proxyTarget);
  console.log("");
  if (overlapSeconds > 0) {
    console.log(`Both secrets are accepted until ${previous.expiresAt}. Deploy the new one before then;`);
    console.log("`agentwall doctor` prints the time remaining.");
  } else {
    console.log("There is no overlap: the old secret stops being accepted immediately.");
  }
  for (const note of effectNotes(context)) console.log(note);
  return EXIT_OK;
}

function commandRevoke(context: FleetContext, flags: Record<string, string>, json: boolean): number {
  const reason = flags["reason"];
  const credentialId = flags["credential"];
  const agentId = flags["agent"];
  if (!credentialId && !agentId) throw new UsageError("revoke needs --credential <id> or --agent <id>");
  if (credentialId && agentId) throw new UsageError("revoke takes --credential or --agent, not both");

  const revoked = credentialId
    ? [context.store.revoke(credentialId, reason)]
    : context.store.revokeAgent(agentId as string, reason);

  if (json) {
    console.log(
      JSON.stringify(
        { revoked: revoked.map((c) => ({ agentId: c.agentId, credentialId: c.credentialId, revokedAt: c.revokedAt, reason: c.revokedReason })), store: context.store.filePath },
        null,
        2
      )
    );
    return EXIT_OK;
  }
  for (const credential of revoked) {
    console.log(`Revoked ${credential.credentialId} for agent "${credential.agentId}" at ${credential.revokedAt}.`);
  }
  console.log("");
  // Verified rather than promised: this command tombstones the named records and writes back
  // every other one unchanged, which is what the store file now contains.
  console.log("Every other credential in the store is untouched.");
  console.log("The record is kept rather than deleted, so the refusal names this id in the audit chain.");
  for (const note of effectNotes(context)) console.log(note);
  return EXIT_OK;
}

function commandList(context: FleetContext, json: boolean): number {
  const now = Date.now();
  const credentials = context.store.list();
  if (json) {
    console.log(
      JSON.stringify(
        {
          store: context.store.filePath,
          minimumMatchTier: context.minimumMatchTier,
          credentials: credentials.map((credential) => ({
            agentId: credential.agentId,
            credentialId: credential.credentialId,
            state: credentialState(credential, now),
            issuedAt: credential.issuedAt,
            expiresAt: credential.expiresAt,
            revokedAt: credential.revokedAt,
            revokedReason: credential.revokedReason,
          })),
        },
        null,
        2
      )
    );
    return EXIT_OK;
  }

  console.log(`Credential store: ${context.store.filePath}`);
  console.log(`Fleet minimum binding tier: ${context.minimumMatchTier}`);
  console.log("");
  if (credentials.length === 0) {
    console.log("No credentials issued. `agentwall fleet issue --agent <id>` mints the first one.");
    return EXIT_OK;
  }

  const rows = credentials.map((credential) => ({
    agent: credential.agentId,
    id: credential.credentialId,
    state: credentialState(credential, now),
    detail: describeCredential(credential, now),
  }));
  const agentWidth = Math.max(5, ...rows.map((row) => row.agent.length));
  const idWidth = Math.max(10, ...rows.map((row) => row.id.length));
  console.log(`${"AGENT".padEnd(agentWidth)}  ${"CREDENTIAL".padEnd(idWidth)}  ${"STATE".padEnd(8)}  DETAIL`);
  for (const row of rows) {
    console.log(`${row.agent.padEnd(agentWidth)}  ${row.id.padEnd(idWidth)}  ${row.state.padEnd(8)}  ${row.detail}`);
  }

  // Agents with no credential at all. Named because the interesting question when reading
  // this list is usually "who is NOT on it".
  const uncovered = context.agents.filter(
    (agent) => agent.match.credential === undefined && context.store.listFor(agent.id).length === 0
  );
  if (uncovered.length > 0) {
    console.log("");
    console.log(`No issued credential: ${uncovered.map((agent) => agent.id).join(", ")}`);
    if (context.minimumMatchTier === "credential") {
      console.log(
        `fleet.minimumMatchTier is "credential", so every connection those agents make is ` +
          (context.mode === "monitor"
            ? `recorded and NOT blocked, because enforcement.mode is "monitor".`
            : `refused.`)
      );
    }
  }
  return EXIT_OK;
}

export function runFleetCommand(argv: string[]): number {
  // A bare `agentwall fleet` is somebody asking what this does, not a mistake.
  if (argv.length === 0) {
    console.log(USAGE);
    return EXIT_OK;
  }

  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (error) {
    console.error(`agentwall fleet: ${error instanceof Error ? error.message : String(error)}`);
    console.error("");
    console.error(USAGE);
    return EXIT_USAGE;
  }

  if (args.subcommand === "help" || args.subcommand === "--help" || args.subcommand === "-h") {
    console.log(USAGE);
    return EXIT_OK;
  }

  try {
    const context = openFleet(args.flags);
    switch (args.subcommand) {
      case "list":
        return commandList(context, args.json);
      case "issue":
        return commandIssue(context, args.flags, args.json);
      case "rotate":
        return commandRotate(context, args.flags, args.json);
      case "revoke":
        return commandRevoke(context, args.flags, args.json);
      default:
        throw new UsageError(`unknown subcommand "${args.subcommand}"`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    if (error instanceof UsageError) {
      console.error("");
      console.error(USAGE);
      return EXIT_USAGE;
    }
    return EXIT_FAIL;
  }
}
