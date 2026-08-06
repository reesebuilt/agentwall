import { isAbsolute, normalize, resolve } from "path";

/**
 * The sandbox profile: what an agent process is allowed to touch, decided as a pure function.
 *
 * This file never calls the kernel. It builds a profile, renders it to the line format the
 * `agentwall-sandbox` launcher reads, and parses the launcher's capability probe back into a
 * shape the CLI can reason about. Every judgement about what a default profile should contain
 * lives here, so it can be tested unprivileged, on any kernel, on any operating system, without
 * a compiler and without asking the host to enforce anything.
 *
 * The split mirrors `src/perimeter/spec.ts` and exists for the same reason: the part that needs
 * a specific kernel to exercise is the part that ships untested unless it is kept tiny. Here the
 * untestable-without-a-kernel part is four syscalls in `native/agentwall-sandbox.c`, and
 * everything above it is text.
 *
 * A warning that belongs at the top of this file rather than in a footnote. A rendered profile
 * is not enforcement. Asserting that `renderProfile` emitted `fs read /etc` proves the string
 * says so; it proves nothing about whether the kernel refused anything. The tests that speak to
 * enforcement run the real launcher against the real Landlock LSM and measure the difference,
 * and they are in `tests/sandbox-kernel.test.ts`, skipped by name and by reason when the host
 * cannot support them. Never let a rendering test stand in for one of those.
 */

/** Rights granted on a path. Each maps to a fixed Landlock right set inside the launcher. */
export type FsMode = "read" | "exec" | "write" | "rwdev";

export interface FsRule {
  mode: FsMode;
  /** Absolute path. Rights apply to this path and everything beneath it. */
  path: string;
}

export interface NetRule {
  kind: "connect-tcp" | "bind-tcp";
  port: number;
}

/**
 * What the filter does when a denied syscall is issued.
 *
 * `errno` returns EPERM and is the default. `kill` sends SIGSYS and takes the whole process down.
 * Killing is louder, and louder is usually right for a security control, but a false positive in
 * a denylist then becomes an agent that dies mid-task for reasons nobody can reproduce. EPERM
 * leaves a syscall that failed, an error the runtime can report, and a process still alive to
 * report it. Operators who want the harder failure can ask for it.
 */
export type SeccompAction = "off" | "errno" | "kill";

export interface SandboxProfile {
  fs: FsRule[];
  net: NetRule[];
  /**
   * Whether Landlock should handle TCP at all. When false, the launcher installs no network
   * rights and TCP is left to whatever else is containing the process. When true, the ports in
   * `net` are the only ones the kernel will permit, and an empty list means no TCP at all.
   */
  restrictNet: boolean;
  seccomp: SeccompAction;
  /** Refuse to run if the kernel's Landlock ABI is below this. 0 means take what the kernel has. */
  requireAbi: number;
  /** Run even with no Landlock at all. Off by default: the launcher refuses rather than pretend. */
  allowDegraded: boolean;
}

/**
 * Landlock ABI 1 is the floor for filesystem confinement to mean anything, so it is the default
 * floor. Raising this to 4 buys TCP port scoping and is the right call on a modern kernel, but
 * making it the default would refuse to run on every LTS kernel between 5.13 and 6.6 while
 * filesystem confinement there works perfectly well.
 */
export const DEFAULT_REQUIRE_ABI = 1;

/** The ABI that introduced LANDLOCK_ACCESS_NET_CONNECT_TCP and LANDLOCK_ACCESS_NET_BIND_TCP. */
export const ABI_WITH_TCP = 4;

/**
 * Paths the runtime itself needs, before any agent workload is considered.
 *
 * These are read and execute only. The list is deliberately coarse: an attempt to be surgical
 * about which of /usr/lib a given Node build dlopen's ends in a whack-a-mole that operators lose,
 * and the security value of splitting /usr into pieces is close to zero when every piece is
 * read-only and the interesting targets are all in $HOME.
 */
const RUNTIME_EXEC_PATHS = ["/usr", "/bin", "/sbin", "/lib", "/lib64"];

/**
 * Read-only host configuration a runtime reads during startup: the resolver configuration, the
 * CA bundle, locale and timezone data.
 */
const RUNTIME_READ_PATHS = [
  "/etc",
  /*
   * /proc is granted whole rather than as /proc/self, and that is a real widening worth naming.
   * Node reads /proc/stat and /proc/cpuinfo for os.cpus(), /proc/meminfo for the heap sizing
   * heuristics, and /proc/self/maps during stack setup, and denying any of them produces
   * failures that surface far from their cause. What this grants beyond /proc/self is the
   * ability to enumerate other processes running as the same uid and read their command lines.
   * Landlock cannot narrow that: procfs visibility is controlled by the hidepid= mount option,
   * not by path rules. Documented in docs/sandbox.md rather than quietly permitted.
   */
  "/proc",
  "/sys/devices/system/cpu",
];

/**
 * Character devices a runtime cannot start without. /dev as a whole is NOT granted: that would
 * hand over /dev/mem, every block device the agent's uid can open, and the rest of a directory
 * whose contents vary by host.
 */
const RUNTIME_DEVICES = [
  "/dev/null",
  "/dev/zero",
  "/dev/full",
  "/dev/random",
  "/dev/urandom",
  "/dev/tty",
];

export interface BaseProfileOptions {
  /** The one directory the agent may write to. Required: a sandbox with no writable path is a toy. */
  workdir: string;
  /** Extra read-only paths, from `--allow-read`. */
  read?: string[];
  /** Extra writable paths, from `--allow-write`. */
  write?: string[];
  /** Extra executable paths, from `--allow-exec`. Needed when the runtime lives outside /usr. */
  exec?: string[];
  /** TCP ports the agent may connect to. Empty with `restrictNet` on means no outbound TCP. */
  connectTcp?: number[];
  /** TCP ports the agent may bind. Empty with `restrictNet` on means it may not listen at all. */
  bindTcp?: number[];
  restrictNet?: boolean;
  seccomp?: SeccompAction;
  requireAbi?: number;
  allowDegraded?: boolean;
}

/**
 * Build the default profile for running an agent in a working directory.
 *
 * The shape of the default is the whole argument of this feature, so it is worth stating plainly
 * what it does NOT include. The operator's home directory is not readable. `~/.ssh` is not
 * readable. `~/.aws`, `~/.config`, `~/.kube`, the shell history, the browser profile, the other
 * repositories on the machine: none of them are readable, and none of them are listed anywhere
 * as an exclusion, because the profile is an allowlist and absence is the default. An agent that
 * is prompt-injected into reading a private key under this profile does not get a policy verdict
 * or a scanner hit. It gets EACCES from the kernel before any of AgentWall's own code is consulted.
 *
 * /tmp is not granted either. A shared /tmp is a place to drop a script and a place to read what
 * another process left behind, and almost everything that wants a temporary file is happy with
 * one somewhere else. The caller is expected to point TMPDIR inside the workdir.
 */
export function baseProfile(options: BaseProfileOptions): SandboxProfile {
  const workdir = requireAbsolute(options.workdir, "workdir");

  const fs: FsRule[] = [];
  for (const path of RUNTIME_EXEC_PATHS) fs.push({ mode: "exec", path });
  for (const path of options.exec ?? []) fs.push({ mode: "exec", path: requireAbsolute(path, "--allow-exec") });
  for (const path of RUNTIME_READ_PATHS) fs.push({ mode: "read", path });
  for (const path of options.read ?? []) fs.push({ mode: "read", path: requireAbsolute(path, "--allow-read") });
  fs.push({ mode: "write", path: workdir });
  for (const path of options.write ?? []) fs.push({ mode: "write", path: requireAbsolute(path, "--allow-write") });
  for (const path of RUNTIME_DEVICES) fs.push({ mode: "rwdev", path });

  const net: NetRule[] = [];
  for (const port of options.connectTcp ?? []) net.push({ kind: "connect-tcp", port: requirePort(port) });
  for (const port of options.bindTcp ?? []) net.push({ kind: "bind-tcp", port: requirePort(port) });

  return {
    fs: dedupe(fs),
    net,
    restrictNet: options.restrictNet ?? false,
    seccomp: options.seccomp ?? "errno",
    requireAbi: options.requireAbi ?? DEFAULT_REQUIRE_ABI,
    allowDegraded: options.allowDegraded ?? false,
  };
}

/**
 * Render a profile into the launcher's line format.
 *
 * The `end` line is not decoration. The launcher reads this off a pipe, and a pipe that closes
 * early yields a profile with some trailing lines missing. Losing an `fs` line only narrows the
 * sandbox, but losing the `seccomp` line silently widens it, so the launcher refuses any profile
 * that does not end with `end` rather than guessing whether it saw all of one.
 */
export function renderProfile(profile: SandboxProfile): string {
  const lines: string[] = [
    "# agentwall sandbox profile, generated. Rights not listed here are refused by the kernel.",
    "version 1",
  ];

  if (profile.requireAbi > 0) lines.push(`require-abi ${profile.requireAbi}`);
  if (profile.allowDegraded) lines.push("allow-degraded");

  for (const rule of profile.fs) {
    assertRenderable(rule.path);
    lines.push(`fs ${rule.mode} ${rule.path}`);
  }

  if (profile.restrictNet) {
    lines.push("net restrict");
    for (const rule of profile.net) lines.push(`net ${rule.kind} ${rule.port}`);
  }

  lines.push(`seccomp ${profile.seccomp}`);
  lines.push("end");
  return `${lines.join("\n")}\n`;
}

/**
 * What the launcher measured about this kernel. Every field comes from a syscall, not from a
 * version string: a distribution kernel can carry a 6.8 version number with Landlock disabled in
 * its boot-time LSM list, and uname would happily report a capability that is not there.
 */
export interface SandboxProbe {
  landlockAbi: number;
  landlockFs: boolean;
  landlockTruncate: boolean;
  landlockNetTcp: boolean;
  landlockIoctlDev: boolean;
  seccompFilter: boolean;
  seccompDeniedSyscalls: number;
  archSupported: boolean;
  kernelRelease: string;
}

/** Parse the `key=value` output of `agentwall-sandbox --probe`. */
export function parseProbe(text: string): SandboxProbe {
  const kv = new Map<string, string>();
  for (const line of text.split("\n")) {
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    kv.set(line.slice(0, eq).trim(), line.slice(eq + 1).trim());
  }
  const yes = (key: string) => kv.get(key) === "yes";
  const num = (key: string) => {
    const parsed = Number.parseInt(kv.get(key) ?? "", 10);
    return Number.isFinite(parsed) ? parsed : 0;
  };
  return {
    landlockAbi: num("landlock_abi"),
    landlockFs: yes("landlock_fs"),
    landlockTruncate: yes("landlock_truncate"),
    landlockNetTcp: yes("landlock_net_tcp"),
    landlockIoctlDev: yes("landlock_ioctl_dev"),
    seccompFilter: yes("seccomp_filter"),
    seccompDeniedSyscalls: num("seccomp_denied_syscalls"),
    archSupported: yes("arch_supported"),
    kernelRelease: kv.get("kernel_release") ?? "unknown",
  };
}

/**
 * The gap between what a profile asks for and what a measured kernel can deliver.
 *
 * `refusals` are conditions under which the launcher will not start the command at all.
 * `degradations` are rights the operator asked for that this kernel cannot enforce; the command
 * still starts, and the operator is told, every time, on stderr. Neither list is ever empty
 * because a check was skipped: a probe that could not be taken is itself a refusal.
 */
export interface ProfileFit {
  refusals: string[];
  degradations: string[];
}

export function fitProfileToKernel(profile: SandboxProfile, probe: SandboxProbe): ProfileFit {
  const refusals: string[] = [];
  const degradations: string[] = [];

  if (probe.landlockAbi === 0) {
    const message =
      "this kernel reports no Landlock, so no filesystem confinement can be installed. " +
      "Landlock needs Linux 5.13 or newer with CONFIG_SECURITY_LANDLOCK=y and `landlock` in the " +
      "boot-time LSM list (check /sys/kernel/security/lsm).";
    if (profile.requireAbi > 0 || !profile.allowDegraded) refusals.push(message);
    else degradations.push(`${message} Running anyway because --allow-degraded was passed.`);
  } else if (profile.requireAbi > probe.landlockAbi) {
    refusals.push(
      `profile requires Landlock ABI ${profile.requireAbi}, this kernel provides ${probe.landlockAbi}.`
    );
  }

  if (profile.restrictNet && probe.landlockAbi > 0 && !probe.landlockNetTcp) {
    degradations.push(
      `TCP port confinement needs Landlock ABI ${ABI_WITH_TCP} (Linux 6.7). This kernel reports ` +
        `ABI ${probe.landlockAbi}, so the ${profile.net.length} net rule(s) will NOT be installed ` +
        "and outbound TCP is unconfined by the sandbox."
    );
  }

  if (probe.landlockAbi > 0 && !probe.landlockTruncate) {
    degradations.push(
      `Landlock ABI ${probe.landlockAbi} has no TRUNCATE right (added in ABI 3, Linux 6.2), so a ` +
        "file under a read-only path can still be emptied with truncate(2)."
    );
  }

  if (profile.seccomp !== "off") {
    if (!probe.archSupported) {
      refusals.push(
        "the launcher was built for an architecture it has no AUDIT_ARCH constant for, so a " +
          "seccomp filter here could not tell one syscall ABI from another."
      );
    } else if (!probe.seccompFilter) {
      refusals.push(
        "seccomp filter mode is unavailable on this kernel (CONFIG_SECCOMP_FILTER). Pass " +
          "--seccomp off to run without it."
      );
    }
  }

  return { refusals, degradations };
}

function requireAbsolute(path: string, label: string): string {
  if (!isAbsolute(path)) {
    throw new Error(`${label} must be an absolute path, got '${path}'. Landlock rules key on a path the kernel resolves, and a relative one would depend on whatever directory the launcher happened to start in.`);
  }
  return normalize(resolve(path));
}

function requirePort(port: number): number {
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`tcp port must be an integer in 0..65535, got '${port}'.`);
  }
  return port;
}

/**
 * A path with a newline in it would end the rule and start a line the launcher would read as a
 * fresh directive. Refusing is the only safe answer: silently escaping it would let a path
 * chosen by something upstream inject `seccomp off` into a generated profile.
 */
function assertRenderable(path: string): void {
  if (/[\n\r]/.test(path)) {
    throw new Error(`path contains a newline and cannot be written to a line-oriented profile: ${JSON.stringify(path)}`);
  }
}

/**
 * Collapse duplicate rules, keeping the widest mode for a path.
 *
 * Duplicates are harmless to the kernel, which unions the rights, but a plan an operator reads
 * should not list /usr three times because three defaults happened to include it.
 */
function dedupe(rules: FsRule[]): FsRule[] {
  const rank: Record<FsMode, number> = { read: 0, rwdev: 1, exec: 2, write: 3 };
  const best = new Map<string, FsRule>();
  for (const rule of rules) {
    const existing = best.get(rule.path);
    if (existing === undefined || rank[rule.mode] > rank[existing.mode]) best.set(rule.path, rule);
  }
  return [...best.values()];
}
