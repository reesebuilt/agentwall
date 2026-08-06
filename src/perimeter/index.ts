import { spawnSync } from "child_process";
import { readFileSync } from "fs";
import { parsePerimeterStatus, renderNftables } from "./spec";
import type { PerimeterSpec } from "./spec";

/**
 * `agentwall perimeter` — the operator lifecycle for kernel-level containment.
 *
 * This file is the thin privileged half of the feature. All of the judgement lives in `./spec`,
 * which renders rules and reads status as pure functions with full test coverage; what is left
 * here is argument parsing, four `nft` invocations, and the refusals that keep an unprivileged run
 * from pretending it did something. That split is not tidiness. Applying firewall rules needs root,
 * this machine's tests do not run as root, and code that can only be exercised on a privileged host
 * is code that ships untested — so the untestable part is kept small enough to read.
 *
 * Every child process is spawned with `shell: false` and an argument array. A uid or a command line
 * that an operator typed is untrusted input the moment it reaches a shell, and a command-injection
 * hole in the tool that installs the security control would be a peculiar way to lose.
 *
 * The intended order is `plan`, read the output, `install`, `verify`, then `run`. `plan` is the only
 * subcommand that works unprivileged, and it is the only one that changes nothing.
 */

/** Placeholder uids for `plan` on a host where the accounts do not exist yet. */
const DEFAULT_AGENT_UID = 61001;
const DEFAULT_PROXY_UID = 61002;
const DEFAULT_PROXY_PORT = 8080;

const EXIT_OK = 0;
/** Not installed, refused, or nft failed. */
const EXIT_FAIL = 1;
/** Bad arguments or a spec that could never be installed. */
const EXIT_USAGE = 2;

const VALUE_FLAGS = ["agent-uid", "proxy-uid", "proxy-port", "dns-resolver", "agent-gid"];

/**
 * Proxy variables are removed from the environment `run` hands to the agent.
 *
 * The perimeter is transparent: the kernel rewrites the destination and the proxy reads the host
 * out of the stream. A client that still believes it has an HTTP proxy would send `CONNECT` to a
 * listener that expects a raw TLS ClientHello, and the operator would be left debugging a protocol
 * error that has nothing to do with their policy.
 */
const PROXY_ENV_KEYS = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"];

const USAGE = `Usage: agentwall perimeter <subcommand> [options]

Subcommands:
  plan                     Render the nftables ruleset and the resolved spec. Changes nothing.
  install                  Apply the ruleset via \`nft -f -\`. Requires root.
  status                   Report whether the perimeter is installed and correct.
  verify                   status, plus an explicit statement of what is and is not contained.
  rollback                 Delete the agentwall table. Requires root.
  run -- <command> [args]  Run a command as the agent uid, inside the perimeter. Requires root.

Options:
  --agent-uid <n>       uid the agent runs as (env AGENTWALL_AGENT_UID, default ${DEFAULT_AGENT_UID})
  --proxy-uid <n>       uid the proxy runs as (env AGENTWALL_PROXY_UID, default ${DEFAULT_PROXY_UID})
  --proxy-port <n>      port the proxy listens on (env AGENTWALL_PROXY_PORT, default ${DEFAULT_PROXY_PORT})
  --dns-resolver <ip>   the single resolver the agent may query; omitted means no DNS at all
  --allow-loopback      let the agent reach loopback services besides the proxy (default: off)
  --agent-gid <n>       gid for \`run\` (default: the agent uid's primary group from /etc/passwd)

Exit codes: 0 ok, 1 not installed or refused, 2 bad usage. \`run\` returns the command's own status.

Start with \`plan\`: it writes host firewall rules that will drop traffic, and an operator should
read them before they land. Apply with \`agentwall perimeter plan | sudo nft -f -\`, or
\`sudo agentwall perimeter install\` with the same options.`;

/** An operator mistake, not a failure of the host. Reported with usage and exit 2. */
class UsageError extends Error {}

interface ParsedArgs {
  subcommand: string;
  flags: Record<string, string>;
  allowLoopback: boolean;
  /** Everything after `--`, for `run`. */
  command: string[];
}

/** Where a resolved value came from, so `plan` can say so rather than presenting a guess as fact. */
type Origin = "flag" | "env" | "default";

interface ResolvedSpec {
  spec: PerimeterSpec;
  /** One `field  value  (source)` line per field, printed by `plan`. */
  provenance: string[];
  /** True when at least one uid is still the built-in placeholder. */
  placeholderUids: boolean;
  /** Explicit `--agent-gid`, or null to look the primary group up at `run` time. */
  agentGid: number | null;
}

export async function runPerimeterCommand(argv: string[]): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    return reportUsageError(err);
  }

  if (args.subcommand === "help" || args.subcommand === "--help" || args.subcommand === "-h") {
    console.log(USAGE);
    return EXIT_OK;
  }

  try {
    const resolved = resolveSpec(args);
    switch (args.subcommand) {
      case "plan":
        return commandPlan(resolved);
      case "install":
        return commandInstall(resolved);
      case "status":
        return commandStatus(resolved);
      case "verify":
        return commandVerify(resolved);
      case "rollback":
        return commandRollback();
      case "run":
        return commandRun(resolved, args.command);
      default:
        throw new UsageError(`unknown perimeter subcommand "${args.subcommand}".`);
    }
  } catch (err) {
    // renderNftables and parsePerimeterStatus reject a spec that could never be installed, naming
    // the field. That is an operator mistake, so it prints as usage rather than as a host failure.
    return reportUsageError(err);
  }
}

/**
 * `plan` — render and explain, touch nothing.
 *
 * Everything it prints is either a comment or a valid nft statement, so the whole of stdout pipes
 * into `nft -f -` unchanged. That matters: an operator who has just read the rules should be able
 * to apply exactly the bytes they read, rather than re-running a command and trusting that it
 * produced the same thing.
 */
function commandPlan(resolved: ResolvedSpec): number {
  const ruleset = renderNftables(resolved.spec);

  console.log("# agentwall perimeter plan — resolved spec");
  for (const line of resolved.provenance) console.log(`#   ${line}`);
  console.log("#");
  console.log("# Nothing has been applied. Review the rules below, then either");
  console.log("#   agentwall perimeter plan [same options] | sudo nft -f -");
  console.log("# or `sudo agentwall perimeter install` with the same options.");
  console.log("");
  console.log(ruleset.trimEnd());

  warnAboutPlaceholders(resolved);
  return EXIT_OK;
}

function commandInstall(resolved: ResolvedSpec): number {
  if (!isRoot()) {
    console.error("perimeter install needs root: it writes host firewall rules through `nft -f -`.");
    console.error("Run `agentwall perimeter plan` with the same options to print the exact ruleset");
    console.error("without privileges, read it, then apply it as root.");
    return EXIT_FAIL;
  }

  const ruleset = renderNftables(resolved.spec);
  warnAboutPlaceholders(resolved);

  const result = spawnSync("nft", ["-f", "-"], { input: ruleset, encoding: "utf8", shell: false });
  if (result.error !== undefined) {
    console.error(`could not run \`nft\`: ${result.error.message}`);
    console.error("The perimeter is nftables-based, so it exists on Linux only.");
    return EXIT_FAIL;
  }
  if (result.status !== 0) {
    console.error(`nft rejected the ruleset (exit ${result.status ?? "signal"}):`);
    console.error(result.stderr.trimEnd());
    console.error("Nothing was applied: nft loads a -f file as a single transaction.");
    return EXIT_FAIL;
  }

  console.log(`Perimeter installed. uid ${resolved.spec.agentUid} now reaches the network only through`);
  console.log(`the proxy on port ${resolved.spec.proxyPort}. Confirm with \`agentwall perimeter verify\`.`);
  return EXIT_OK;
}

function commandStatus(resolved: ResolvedSpec): number {
  const status = readStatus(resolved.spec);
  if (status === null) return EXIT_FAIL;

  if (status.installed) {
    console.log(`Perimeter installed: uid ${resolved.spec.agentUid} is redirected to port ${resolved.spec.proxyPort}`);
    console.log("and dropped by default. The proxy uid is exempt.");
    return EXIT_OK;
  }

  console.error("Perimeter NOT correctly installed.");
  console.error(`  redirect present: ${status.redirectPresent}`);
  console.error(`  default-drop present: ${status.dropPresent}`);
  for (const problem of status.problems) console.error(`  - ${problem}`);
  return EXIT_FAIL;
}

/**
 * `verify` — status, plus the boundary of the claim in writing.
 *
 * A containment control that is described only by what it blocks invites the reader to assume it
 * blocks everything else too. Printing the gaps next to the guarantees, every time, is the cheapest
 * defence against an operator building a threat model on top of a feature summary.
 */
function commandVerify(resolved: ResolvedSpec): number {
  const code = commandStatus(resolved);
  const { agentUid, proxyPort, dnsResolver, allowLoopback } = resolved.spec;

  console.log("");
  console.log("Contained:");
  console.log(`  - every TCP connection uid ${agentUid} opens to port 80 or 443 is redirected to the local`);
  console.log(`    proxy on port ${proxyPort}, whatever destination the process asked for and with no client`);
  console.log("    cooperation.");
  console.log(`  - everything else uid ${agentUid} sends is dropped by the kernel before it leaves the host:`);
  console.log("    UDP, QUIC, ICMP, raw sockets, and TCP to any other port. The capture is scoped to the");
  console.log("    ports whose destination the proxy can recover from the stream, so an unnameable");
  console.log("    destination is refused rather than policed as something it is not.");
  console.log(
    dnsResolver === undefined
      ? "  - DNS: no resolver is permitted, so name resolution fails rather than becoming a side channel."
      : `  - DNS: only ${dnsResolver} on port 53. Any other resolver is dropped.`
  );

  console.log("Not contained:");
  console.log(`  - any process running as a uid other than ${agentUid}. The perimeter is per-uid.`);
  console.log("  - root. Root can flush this table, so containment holds only while the agent is not root");
  console.log("    and cannot obtain it.");
  console.log("  - unix domain sockets, filesystem writes, and anything else that never reaches the");
  console.log("    network stack. Those are other planes' problem.");
  console.log("  - what is inside a TLS session. The proxy does not terminate TLS; it decides from the");
  console.log("    destination the stream names, and denies a stream that names none.");
  console.log("  - the port of a TLS stream sent to port 80. Ports are matched by the kernel, protocols are");
  console.log("    not, so such a stream is still attributed to 443 of the host its SNI names.");
  if (allowLoopback) {
    console.log(`  - loopback: uid ${agentUid} may reach other services on this host directly, and one of`);
    console.log("    them may be a route to the outside. You opened this with --allow-loopback.");
  }

  return code;
}

function commandRollback(): number {
  if (!isRoot()) {
    console.error("perimeter rollback needs root: removing the table is a host firewall change.");
    console.error("As root: `agentwall perimeter rollback`, or `nft delete table inet agentwall`.");
    return EXIT_FAIL;
  }

  const result = spawnSync("nft", ["delete", "table", "inet", "agentwall"], { encoding: "utf8", shell: false });
  if (result.error !== undefined) {
    console.error(`could not run \`nft\`: ${result.error.message}`);
    return EXIT_FAIL;
  }
  if (result.status !== 0) {
    // Removing a table that is not there is the state rollback wants, not a failure.
    if (/no such file or directory/i.test(result.stderr)) {
      console.log("No agentwall table present: nothing to roll back.");
      return EXIT_OK;
    }
    console.error(`nft could not delete the table (exit ${result.status ?? "signal"}):`);
    console.error(result.stderr.trimEnd());
    return EXIT_FAIL;
  }

  console.log("Perimeter removed. The agent uid now reaches the network directly.");
  return EXIT_OK;
}

/**
 * `run` — start a command as the agent uid, but only inside a perimeter that is actually there.
 *
 * The installation check is not a convenience. An agent that believes it is contained when it is
 * not is the worst thing this feature can produce: the operator has already decided it is safe to
 * hand it a broader task precisely because the box exists, and there is no failure signal anywhere
 * — traffic flows, the ledger fills with the subset that happens to reach the proxy, and the
 * unrestricted part is invisible. So an unverifiable perimeter refuses to start the agent rather
 * than starting it unprotected.
 */
function commandRun(resolved: ResolvedSpec, command: string[]): number {
  // Root check first, before anything reads host state: dropping privileges requires having them,
  // and an unprivileged invocation must not run the command at all rather than run it uncontained.
  if (!isRoot()) {
    console.error("perimeter run needs root: it drops to the agent uid, and only root may change uid.");
    console.error(`Without root this would run the command as you (uid ${process.getuid?.() ?? "unknown"}),`);
    console.error("which the perimeter does not contain. Refusing rather than running it unprotected.");
    return EXIT_FAIL;
  }

  if (command.length === 0) {
    throw new UsageError("perimeter run needs a command after `--`, e.g. `perimeter run -- npx my-agent`.");
  }

  const status = readStatus(resolved.spec);
  if (status === null) return EXIT_FAIL;
  if (!status.installed) {
    console.error("Refusing to start: the perimeter is not correctly installed, so this command would run");
    console.error("uncontained while looking contained.");
    for (const problem of status.problems) console.error(`  - ${problem}`);
    console.error("Install it first: `agentwall perimeter install`.");
    return EXIT_FAIL;
  }

  const gid = resolved.agentGid ?? primaryGidFor(resolved.spec.agentUid);
  if (gid === null) {
    console.error(`could not find a primary group for uid ${resolved.spec.agentUid} in /etc/passwd.`);
    console.error("Pass --agent-gid <n>. Running with root's group while dropping only the uid would");
    console.error("leave the command more privileged than the perimeter assumes.");
    return EXIT_FAIL;
  }

  const env = { ...process.env };
  for (const key of PROXY_ENV_KEYS) delete env[key];

  const result = spawnSync(command[0], command.slice(1), { stdio: "inherit", uid: resolved.spec.agentUid, gid, env, shell: false });
  if (result.error !== undefined) {
    console.error(`could not start ${command[0]}: ${result.error.message}`);
    return EXIT_FAIL;
  }
  if (result.status === null) {
    console.error(`${command[0]} was killed by signal ${result.signal ?? "unknown"}.`);
    return EXIT_FAIL;
  }
  return result.status;
}

/**
 * Read the live table and parse it, or print why that could not be done and return null.
 *
 * "Could not read" and "not installed" are kept apart deliberately. Reading nftables state needs
 * CAP_NET_ADMIN, so the common failure is a permission error, and reporting that as "not installed"
 * would push an operator into reinstalling — or, worse, into concluding an agent is unprotected
 * when it is fine.
 */
function readStatus(
  spec: PerimeterSpec
): { installed: boolean; redirectPresent: boolean; dropPresent: boolean; problems: string[] } | null {
  const result = spawnSync("nft", ["list", "table", "inet", "agentwall"], { encoding: "utf8", shell: false });

  if (result.error !== undefined) {
    console.error(`could not run \`nft\`: ${result.error.message}`);
    console.error("The perimeter is nftables-based, so it exists on Linux only. State unknown.");
    return null;
  }

  if (result.status !== 0) {
    const stderr = result.stderr.trim();
    // nft says exactly this when the table does not exist, which is a real answer, not a failure.
    if (!/no such file or directory/i.test(stderr)) {
      console.error(`could not read the nftables ruleset: ${stderr === "" ? `nft exited ${result.status}` : stderr}`);
      console.error("Listing a table needs CAP_NET_ADMIN — run status as root. State unknown, and an");
      console.error("unknown state is not the same as an absent one.");
      return null;
    }
    return parsePerimeterStatus("", spec);
  }

  return parsePerimeterStatus(result.stdout, spec);
}

function isRoot(): boolean {
  // getuid is absent on Windows, where there is no perimeter to install in the first place.
  return process.getuid?.() === 0;
}

/**
 * Find the primary group of a uid without a native module or an external lookup.
 *
 * Dropping only the uid would leave the command in root's group, which is not "running as the agent
 * user" in any sense a security control can rely on. Note the limit: Node sets uid and gid but does
 * not call initgroups(3), so supplementary groups inherited from the invoking process still apply.
 * On a stock host root has none beyond gid 0; on a host where root has been added to extra groups,
 * launch the agent from a systemd unit or a container instead of from here.
 */
function primaryGidFor(uid: number): number | null {
  let passwd: string;
  try {
    passwd = readFileSync("/etc/passwd", "utf8");
  } catch {
    return null;
  }

  for (const line of passwd.split("\n")) {
    const fields = line.split(":");
    if (fields.length < 4 || fields[2] === "") continue;
    if (Number(fields[2]) !== uid) continue;
    const gid = Number(fields[3]);
    return Number.isInteger(gid) ? gid : null;
  }
  return null;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [subcommand, ...rest] = argv;
  if (subcommand === undefined) throw new UsageError("perimeter needs a subcommand.");

  const flags: Record<string, string> = {};
  let allowLoopback = false;
  const command: string[] = [];

  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];

    if (arg === "--") {
      command.push(...rest.slice(i + 1));
      break;
    }
    if (arg === "--allow-loopback") {
      allowLoopback = true;
      continue;
    }
    if (!arg.startsWith("--")) throw new UsageError(`unexpected argument "${arg}".`);

    const name = arg.slice(2);
    if (!VALUE_FLAGS.includes(name)) throw new UsageError(`unknown flag "${arg}".`);

    const value = rest[i + 1];
    if (value === undefined || value.startsWith("--")) throw new UsageError(`${arg} needs a value.`);
    flags[name] = value;
    i += 1;
  }

  return { subcommand, flags, allowLoopback, command };
}

/**
 * Resolve flags, then environment, then built-in placeholder, recording which won.
 *
 * The placeholder uids exist so `plan` works on a host where the accounts have not been created
 * yet — reading the rules is the step that teaches an operator which accounts they need. They are
 * also exactly how somebody ends up installing a perimeter around a uid nothing runs as, so every
 * value carries its origin into the printed plan and a placeholder draws a warning on stderr.
 */
function resolveSpec(args: ParsedArgs): ResolvedSpec {
  const agentUid = resolveNumber(args.flags, "agent-uid", "AGENTWALL_AGENT_UID", DEFAULT_AGENT_UID);
  const proxyUid = resolveNumber(args.flags, "proxy-uid", "AGENTWALL_PROXY_UID", DEFAULT_PROXY_UID);
  const proxyPort = resolveNumber(args.flags, "proxy-port", "AGENTWALL_PROXY_PORT", DEFAULT_PROXY_PORT);
  const dnsResolver = args.flags["dns-resolver"];
  const agentGid = args.flags["agent-gid"] === undefined ? null : Number(args.flags["agent-gid"]);

  if (agentGid !== null && (!Number.isInteger(agentGid) || agentGid < 0)) {
    throw new UsageError(`--agent-gid: expected a non-negative integer, got "${args.flags["agent-gid"]}".`);
  }

  const spec: PerimeterSpec = {
    agentUid: agentUid.value,
    proxyUid: proxyUid.value,
    proxyPort: proxyPort.value,
    ...(dnsResolver === undefined ? {} : { dnsResolver }),
    allowLoopback: args.allowLoopback,
  };

  return {
    spec,
    provenance: [
      `agentUid       ${agentUid.value}  (${agentUid.origin})`,
      `proxyUid       ${proxyUid.value}  (${proxyUid.origin})`,
      `proxyPort      ${proxyPort.value}  (${proxyPort.origin})`,
      `dnsResolver    ${dnsResolver ?? "none"}  (${dnsResolver === undefined ? "default" : "flag"})`,
      `allowLoopback  ${args.allowLoopback}  (${args.allowLoopback ? "flag" : "default"})`,
    ],
    placeholderUids: agentUid.origin === "default" || proxyUid.origin === "default",
    agentGid,
  };
}

function resolveNumber(
  flags: Record<string, string>,
  flag: string,
  envKey: string,
  fallback: number
): { value: number; origin: Origin } {
  const raw = flags[flag] ?? process.env[envKey];
  if (raw === undefined || raw === "") return { value: fallback, origin: "default" };

  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new UsageError(
      `${flags[flag] === undefined ? envKey : `--${flag}`}: expected a number, got ${JSON.stringify(raw)}.`
    );
  }
  return { value, origin: flags[flag] === undefined ? "env" : "flag" };
}

function warnAboutPlaceholders(resolved: ResolvedSpec): void {
  if (!resolved.placeholderUids) return;
  console.error(
    `note: uid ${resolved.spec.agentUid}/${resolved.spec.proxyUid} are AgentWall's placeholder values. A perimeter ` +
      "around a uid nothing runs as contains nothing; pass --agent-uid/--proxy-uid, or set " +
      "AGENTWALL_AGENT_UID/AGENTWALL_PROXY_UID, with the accounts you actually created."
  );
}

function reportUsageError(err: unknown): number {
  console.error(err instanceof Error ? err.message : String(err));
  console.error("");
  console.error(USAGE);
  return EXIT_USAGE;
}
