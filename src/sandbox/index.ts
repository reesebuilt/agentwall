import { spawn, spawnSync } from "child_process";
import { existsSync, mkdirSync, statSync } from "fs";
import { join, resolve } from "path";
import {
  ABI_WITH_TCP,
  DEFAULT_REQUIRE_ABI,
  baseProfile,
  fitProfileToKernel,
  parseProbe,
  renderProfile,
} from "./profile";
import type { SandboxProbe, SandboxProfile, SeccompAction } from "./profile";

/**
 * `agentwall sandbox` - the operator lifecycle for per-process kernel confinement.
 *
 * The perimeter contains an agent's PACKETS. This contains the agent itself. They answer
 * different threat models and neither replaces the other: the perimeter assumes an agent that
 * will try to reach the network around your proxy, and the sandbox assumes an agent that has
 * been talked into reading a file it was never asked about. An agent that is untrusted at
 * runtime rather than only at policy time needs both.
 *
 * Everything here is unprivileged. Landlock and an unprivileged seccomp filter need no root, no
 * capability and no setuid bit, which is the single best property of this feature: `plan` and
 * `run` are both things an operator can try on their own laptop without being asked to trust a
 * privileged binary first. The launcher it drives is not setuid and never needs to be.
 *
 * The profile is handed to the launcher over a pipe on file descriptor 3 rather than a file. A
 * temporary file would be readable by anything else running as the same uid between the write
 * and the exec, and when this is composed with `perimeter run` the writer is root while the
 * reader has already dropped to the agent uid, so a root-owned temporary file would be
 * unreadable at exactly the moment it was needed. A pipe has neither problem.
 */

const EXIT_OK = 0;
/** Refused: the kernel cannot deliver what the profile asked for, or the launcher is missing. */
const EXIT_FAIL = 1;
/** Bad arguments. */
const EXIT_USAGE = 2;

/** Env var an operator can point at a launcher they built or vendored themselves. */
const HELPER_ENV = "AGENTWALL_SANDBOX_HELPER";

/**
 * A temporary directory inside the workdir, exported as TMPDIR.
 *
 * The alternative is granting the sandbox write access to /tmp, and /tmp is shared: a place to
 * drop an executable, and a place to read whatever another process on the host left behind. A
 * private temp inside the one directory the agent may already write costs nothing and removes
 * the whole category.
 */
const PRIVATE_TMP = ".agentwall-tmp";

const USAGE = `Usage: agentwall sandbox <subcommand> [options]

Subcommands:
  probe                    Measure this kernel's Landlock ABI and seccomp support. Changes nothing.
  plan                     Render the profile that would be applied, and its gaps. Changes nothing.
  build                    Compile the launcher from native/agentwall-sandbox.c.
  run -- <command> [args]  Apply the profile and exec the command. No root required.

Options:
  --workdir <path>      The one directory the agent may write to (default: the current directory)
  --allow-read <path>   Extra read-only path. Repeatable.
  --allow-write <path>  Extra writable path. Repeatable.
  --allow-exec <path>   Extra executable path. Repeatable. Needed if the runtime is outside /usr.
  --allow-tcp <port>    TCP port the agent may connect to. Repeatable. Implies --restrict-net.
  --allow-bind <port>   TCP port the agent may listen on. Repeatable. Implies --restrict-net.
  --restrict-net        Confine TCP to the ports above. Needs Landlock ABI ${ABI_WITH_TCP} (Linux 6.7).
  --seccomp <mode>      off, errno (default), or kill
  --require-abi <n>     Refuse to run below this Landlock ABI (default: ${DEFAULT_REQUIRE_ABI})
  --allow-degraded      Run even with no Landlock at all. Prints what is unprotected, every time.
  --json                Machine-readable output for probe and plan

Exit codes: 0 ok, 1 refused or unavailable, 2 bad usage. \`run\` returns the command's own status.

Read docs/sandbox.md before relying on this. It states which kernel versions are required and,
more importantly, what this does NOT confine.`;

class UsageError extends Error {}

interface ParsedArgs {
  subcommand: string;
  workdir?: string;
  read: string[];
  write: string[];
  exec: string[];
  connectTcp: number[];
  bindTcp: number[];
  restrictNet: boolean;
  seccomp?: SeccompAction;
  requireAbi?: number;
  allowDegraded: boolean;
  json: boolean;
  command: string[];
}

export async function runSandboxCommand(argv: string[]): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    return reportUsageError(err);
  }

  switch (args.subcommand) {
    case "probe":
      return commandProbe(args);
    case "plan":
      return commandPlan(args);
    case "build":
      return commandBuild();
    case "run":
      return commandRun(args);
    default:
      return reportUsageError(new UsageError(`Unknown sandbox subcommand: ${args.subcommand}`));
  }
}

/* ------------------------------------------------------------------ locating the launcher */

export interface HelperLocation {
  path: string | null;
  /** Every place that was looked, so a missing launcher is a fixable error rather than a mystery. */
  searched: string[];
}

/**
 * Find the compiled launcher.
 *
 * Compiling is a separate, explicit step rather than a postinstall hook. A postinstall that
 * silently invokes a C compiler is a supply-chain smell in any package and an especially poor
 * look in one whose whole pitch is that you can audit what it does. It is also the moment an
 * operator decides to trust a binary that will hold the filesystem boundary for their agent,
 * and that should be a command they typed.
 */
export function locateHelper(): HelperLocation {
  const searched: string[] = [];
  const override = process.env[HELPER_ENV];
  if (override !== undefined && override !== "") {
    searched.push(`${override} (from ${HELPER_ENV})`);
    return { path: existsSync(override) ? override : null, searched };
  }
  // Compiled layout (dist/sandbox/index.js), then the ts-node layout (src/sandbox/index.ts).
  for (const candidate of [
    resolve(__dirname, "..", "native", "agentwall-sandbox"),
    resolve(__dirname, "..", "..", "dist", "native", "agentwall-sandbox"),
  ]) {
    searched.push(candidate);
    if (existsSync(candidate)) return { path: candidate, searched };
  }
  return { path: null, searched };
}

function reportMissingHelper(location: HelperLocation): void {
  console.error("The sandbox launcher has not been built, so nothing can be confined.");
  console.error("Looked in:");
  for (const path of location.searched) console.error(`  - ${path}`);
  console.error("");
  console.error("Build it with `agentwall sandbox build`, or `npm run build:sandbox` in a checkout.");
  console.error(`Point ${HELPER_ENV} at a launcher you built elsewhere if you would rather not`);
  console.error("compile here. This command will not start your agent unconfined.");
}

/* ------------------------------------------------------------------------ probing */

export function probeKernel(helperPath: string): { probe: SandboxProbe; raw: string } | null {
  const result = spawnSync(helperPath, ["--probe"], { encoding: "utf8", shell: false });
  if (result.error !== undefined) {
    console.error(`could not run the launcher at ${helperPath}: ${result.error.message}`);
    return null;
  }
  if (result.status !== 0) {
    console.error(`the launcher at ${helperPath} exited ${result.status} during --probe.`);
    if (result.stderr) console.error(result.stderr.trim());
    return null;
  }
  return { probe: parseProbe(result.stdout), raw: result.stdout };
}

function commandProbe(args: ParsedArgs): number {
  const location = locateHelper();
  if (location.path === null) {
    if (args.json) {
      console.log(JSON.stringify({ helper: null, searched: location.searched, probe: null }, null, 2));
    } else {
      reportMissingHelper(location);
    }
    return EXIT_FAIL;
  }

  const probed = probeKernel(location.path);
  if (probed === null) return EXIT_FAIL;
  const { probe } = probed;

  if (args.json) {
    console.log(JSON.stringify({ helper: location.path, probe }, null, 2));
    return probe.landlockAbi > 0 ? EXIT_OK : EXIT_FAIL;
  }

  console.log(`launcher:        ${location.path}`);
  console.log(`kernel:          ${probe.kernelRelease}`);
  console.log(`landlock ABI:    ${probe.landlockAbi === 0 ? "none" : probe.landlockAbi}`);
  console.log(`  filesystem:    ${probe.landlockFs ? "yes" : "no"} (ABI 1, Linux 5.13)`);
  console.log(`  truncate:      ${probe.landlockTruncate ? "yes" : "no"} (ABI 3, Linux 6.2)`);
  console.log(`  tcp ports:     ${probe.landlockNetTcp ? "yes" : "no"} (ABI 4, Linux 6.7)`);
  console.log(`  device ioctl:  ${probe.landlockIoctlDev ? "yes" : "no"} (ABI 5, Linux 6.10)`);
  console.log(`seccomp filter:  ${probe.seccompFilter ? "yes" : "no"}`);
  console.log(`  denied calls:  ${probe.seccompDeniedSyscalls}`);
  console.log(`architecture:    ${probe.archSupported ? "supported" : "UNSUPPORTED by this build"}`);
  console.log("");

  if (probe.landlockAbi === 0) {
    console.log("This kernel offers NO filesystem confinement. `agentwall sandbox run` will refuse");
    console.log("to start a command here unless you pass --allow-degraded, and if you do, it will");
    console.log("tell you on every run that the filesystem is unprotected.");
    console.log("Check /sys/kernel/security/lsm: Landlock must be in the boot-time LSM list.");
    return EXIT_FAIL;
  }
  if (!probe.landlockNetTcp) {
    console.log(`TCP port confinement is unavailable below Landlock ABI ${ABI_WITH_TCP}. Filesystem`);
    console.log("confinement works normally; --restrict-net will report that it did not apply.");
  }
  return EXIT_OK;
}

/* -------------------------------------------------------------------------- plan */

function commandPlan(args: ParsedArgs): number {
  let profile: SandboxProfile;
  try {
    profile = profileFromArgs(args);
  } catch (err) {
    return reportUsageError(err);
  }
  const rendered = renderProfile(profile);

  const location = locateHelper();
  const probed = location.path === null ? null : probeKernel(location.path);
  const fit = probed === null ? null : fitProfileToKernel(profile, probed.probe);

  if (args.json) {
    console.log(
      JSON.stringify(
        { profile, rendered, helper: location.path, probe: probed?.probe ?? null, fit },
        null,
        2
      )
    );
    return fit !== null && fit.refusals.length > 0 ? EXIT_FAIL : EXIT_OK;
  }

  console.log(rendered.trimEnd());
  console.log("");
  console.log("Writable:");
  for (const rule of profile.fs.filter((r) => r.mode === "write")) console.log(`  ${rule.path}`);
  console.log("Everything else on this filesystem is refused by the kernel, including your home");
  console.log("directory, your SSH and cloud credentials, and every other checkout on this host.");
  console.log("");

  if (profile.restrictNet) {
    const connect = profile.net.filter((r) => r.kind === "connect-tcp").map((r) => r.port);
    const bind = profile.net.filter((r) => r.kind === "bind-tcp").map((r) => r.port);
    console.log(`Outbound TCP: ${connect.length > 0 ? connect.join(", ") : "none at all"}`);
    console.log(`Listening TCP: ${bind.length > 0 ? bind.join(", ") : "none at all"}`);
  } else {
    console.log("TCP is NOT confined by this profile. Pass --restrict-net, or rely on the");
    console.log("nftables perimeter (docs/perimeter.md), which contains a uid rather than a process.");
  }
  console.log("");

  if (location.path === null) {
    reportMissingHelper(location);
    return EXIT_FAIL;
  }
  if (fit === null) return EXIT_FAIL;

  for (const line of fit.degradations) console.log(`DEGRADED: ${line}`);
  for (const line of fit.refusals) console.log(`REFUSED:  ${line}`);
  if (fit.refusals.length === 0 && fit.degradations.length === 0) {
    console.log("This kernel can enforce every right in this profile.");
  }
  return fit.refusals.length > 0 ? EXIT_FAIL : EXIT_OK;
}

/* ------------------------------------------------------------------------- build */

function commandBuild(): number {
  const script = resolve(__dirname, "..", "..", "scripts", "build-sandbox-helper.sh");
  if (!existsSync(script)) {
    console.error(`could not find the build script at ${script}.`);
    console.error("This happens when the package was installed without its scripts/ directory.");
    console.error(`Build native/agentwall-sandbox.c yourself and point ${HELPER_ENV} at the result.`);
    return EXIT_FAIL;
  }
  const result = spawnSync("bash", [script], { stdio: "inherit", shell: false });
  if (result.error !== undefined) {
    console.error(`could not run ${script}: ${result.error.message}`);
    return EXIT_FAIL;
  }
  return result.status === 0 ? EXIT_OK : EXIT_FAIL;
}

/* --------------------------------------------------------------------------- run */

/**
 * `run` - apply the profile and become the command.
 *
 * The refusal path matters more than the success path. If the launcher is missing, or the kernel
 * cannot install what the profile asked for, this does not fall back to running the command
 * unconfined. That failure mode is the one that actually hurts: the operator has already widened
 * what they will let the agent attempt precisely because they believe it is boxed in, and an
 * unconfined run produces no signal anywhere. So the default is to refuse, and the only way past
 * it is an explicit flag whose effect is printed on every single run.
 */
async function commandRun(args: ParsedArgs): Promise<number> {
  if (args.command.length === 0) {
    return reportUsageError(
      new UsageError("sandbox run needs a command after `--`, e.g. `sandbox run -- node agent.js`.")
    );
  }

  let profile: SandboxProfile;
  try {
    profile = profileFromArgs(args);
  } catch (err) {
    return reportUsageError(err);
  }

  const location = locateHelper();
  if (location.path === null) {
    reportMissingHelper(location);
    return EXIT_FAIL;
  }

  const probed = probeKernel(location.path);
  if (probed === null) return EXIT_FAIL;
  const fit = fitProfileToKernel(profile, probed.probe);
  if (fit.refusals.length > 0) {
    console.error("Refusing to start: this kernel cannot enforce the profile, so the command would");
    console.error("run unconfined while looking confined.");
    for (const line of fit.refusals) console.error(`  - ${line}`);
    return EXIT_FAIL;
  }
  for (const line of fit.degradations) console.error(`agentwall sandbox: DEGRADED: ${line}`);

  const workdir = workdirFor(args);
  const tmp = join(workdir, PRIVATE_TMP);
  mkdirSync(tmp, { recursive: true, mode: 0o700 });

  const env = {
    ...process.env,
    TMPDIR: tmp,
    TMP: tmp,
    TEMP: tmp,
    /*
     * A marker the agent's own process tree can read. Something inside the sandbox that wants to
     * know whether it is sandboxed should not have to infer it from a failed syscall, and a
     * harness that logs this alongside its work makes an unconfined run visible in the record.
     */
    AGENTWALL_SANDBOX: `landlock-abi-${probed.probe.landlockAbi};seccomp-${profile.seccomp}`,
  };

  const rendered = renderProfile(profile);

  return await new Promise<number>((resolvePromise) => {
    const child = spawn(location.path as string, ["--", ...args.command], {
      stdio: ["inherit", "inherit", "inherit", "pipe"],
      env,
      cwd: workdir,
      shell: false,
    });

    const profilePipe = child.stdio[3];
    if (profilePipe === null || profilePipe === undefined || !("write" in profilePipe)) {
      child.kill("SIGKILL");
      console.error("could not open the profile pipe on fd 3, so the launcher would have read an");
      console.error("empty profile. Refusing rather than running the command unconfined.");
      resolvePromise(EXIT_FAIL);
      return;
    }
    /*
     * EPIPE here means the launcher exited before reading the profile, which it does when it
     * refuses. Its own message is already on stderr and the exit code carries the failure, so
     * this must not become an unhandled error event on top of it.
     */
    profilePipe.on("error", () => undefined);
    profilePipe.end(rendered);

    child.on("error", (err) => {
      console.error(`could not start the launcher: ${err.message}`);
      resolvePromise(EXIT_FAIL);
    });
    child.on("close", (code, signal) => {
      if (code === null) {
        console.error(`the command was killed by signal ${signal ?? "unknown"}.`);
        resolvePromise(EXIT_FAIL);
        return;
      }
      resolvePromise(code);
    });
  });
}

/* ---------------------------------------------------------------------- arguments */

const VALUE_FLAGS: Record<string, true> = {
  "--workdir": true,
  "--allow-read": true,
  "--allow-write": true,
  "--allow-exec": true,
  "--allow-tcp": true,
  "--allow-bind": true,
  "--seccomp": true,
  "--require-abi": true,
};

export function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = {
    subcommand: argv[0] ?? "",
    read: [],
    write: [],
    exec: [],
    connectTcp: [],
    bindTcp: [],
    restrictNet: false,
    allowDegraded: false,
    json: false,
    command: [],
  };
  if (parsed.subcommand === "" || parsed.subcommand.startsWith("-")) {
    throw new UsageError("sandbox needs a subcommand: probe, plan, build or run.");
  }

  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") {
      parsed.command = argv.slice(i + 1);
      break;
    }
    if (VALUE_FLAGS[arg] === true) {
      const value = argv[i + 1];
      if (value === undefined) throw new UsageError(`${arg} needs a value.`);
      i++;
      applyValueFlag(parsed, arg, value);
      continue;
    }
    switch (arg) {
      case "--restrict-net":
        parsed.restrictNet = true;
        break;
      case "--allow-degraded":
        parsed.allowDegraded = true;
        break;
      case "--json":
        parsed.json = true;
        break;
      default:
        throw new UsageError(`Unknown option: ${arg}`);
    }
  }
  return parsed;
}

function applyValueFlag(parsed: ParsedArgs, flag: string, value: string): void {
  switch (flag) {
    case "--workdir":
      parsed.workdir = value;
      return;
    case "--allow-read":
      parsed.read.push(value);
      return;
    case "--allow-write":
      parsed.write.push(value);
      return;
    case "--allow-exec":
      parsed.exec.push(value);
      return;
    case "--allow-tcp":
      parsed.connectTcp.push(parsePort(flag, value));
      parsed.restrictNet = true;
      return;
    case "--allow-bind":
      parsed.bindTcp.push(parsePort(flag, value));
      parsed.restrictNet = true;
      return;
    case "--seccomp":
      if (value !== "off" && value !== "errno" && value !== "kill") {
        throw new UsageError(`--seccomp must be off, errno or kill, got '${value}'.`);
      }
      parsed.seccomp = value;
      return;
    case "--require-abi": {
      const abi = Number.parseInt(value, 10);
      if (!Number.isInteger(abi) || abi < 0) {
        throw new UsageError(`--require-abi must be a non-negative integer, got '${value}'.`);
      }
      parsed.requireAbi = abi;
      return;
    }
    default:
      throw new UsageError(`Unknown option: ${flag}`);
  }
}

function parsePort(flag: string, value: string): number {
  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new UsageError(`${flag} must be a port in 0..65535, got '${value}'.`);
  }
  return port;
}

function workdirFor(args: ParsedArgs): string {
  const workdir = resolve(args.workdir ?? process.cwd());
  if (!existsSync(workdir) || !statSync(workdir).isDirectory()) {
    throw new UsageError(`--workdir ${workdir} is not a directory.`);
  }
  return workdir;
}

/**
 * Turn parsed flags into a profile.
 *
 * The workdir's private temp is granted explicitly rather than inherited from the workdir rule,
 * because `run` sets TMPDIR to it and a TMPDIR the process cannot write to is a failure mode that
 * shows up as a confusing error from whatever library happened to need a scratch file first.
 */
function profileFromArgs(args: ParsedArgs): SandboxProfile {
  const workdir = workdirFor(args);
  return baseProfile({
    workdir,
    read: args.read,
    write: [...args.write, join(workdir, PRIVATE_TMP)],
    exec: [...args.exec, ...runtimeExecPaths()],
    connectTcp: args.connectTcp,
    bindTcp: args.bindTcp,
    restrictNet: args.restrictNet,
    seccomp: args.seccomp,
    requireAbi: args.requireAbi,
    allowDegraded: args.allowDegraded,
  });
}

/**
 * The directory holding the running Node binary, when it is not already under a default path.
 *
 * Version managers put Node under the operator's home, which the base profile deliberately does
 * not grant. Without this, the single most common way to install Node produces a sandbox that
 * cannot exec the runtime it is supposed to confine, and the error (EACCES on exec) reads like a
 * permissions bug rather than a missing rule.
 */
function runtimeExecPaths(): string[] {
  const bin = process.execPath;
  if (bin === "" || bin.startsWith("/usr/") || bin.startsWith("/bin/") || bin.startsWith("/sbin/")) {
    return [];
  }
  return [bin];
}

function reportUsageError(err: unknown): number {
  const message = err instanceof Error ? err.message : String(err);
  console.error(message);
  console.error("");
  console.error(USAGE);
  return err instanceof UsageError ? EXIT_USAGE : EXIT_FAIL;
}
