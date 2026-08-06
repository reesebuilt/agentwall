import { afterAll, describe, expect, it } from "@jest/globals";
import { spawnSync } from "child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { parseProbe } from "../src/sandbox/profile";
import type { SandboxProbe } from "../src/sandbox/profile";

/**
 * Does the KERNEL actually refuse what the profile says it refuses?
 *
 * Everything in tests/sandbox-profile.test.ts asserts on text. Text cannot know whether Landlock
 * installed, whether a right was silently dropped, or whether landlock_add_rule rejected a rule
 * and left the process unconfined. That last one is not hypothetical: the first end-to-end run of
 * this feature failed because a rule naming a regular file carried READ_DIR, the kernel returned
 * EINVAL, and the launcher refused to start. A rendering test would have been green throughout.
 *
 * So this suite runs the real launcher against the real LSM and measures the difference between
 * a bare process and a sandboxed one. Every claim is a comparison: the same binary, the same
 * argument, run twice. A test that only checked the sandboxed half could pass because the file
 * was missing, the fixture was wrong, or the syscall was already denied by something else.
 *
 * None of it needs root. Landlock and an unprivileged seccomp filter are available to any uid on
 * a kernel that has them, which is the reason this can be a real enforcement test in CI rather
 * than a privileged test that gets skipped forever.
 *
 * When the host cannot support it, the suite says so by name and skips. It never substitutes a
 * weaker assertion for the one it could not make.
 */

interface Env {
  supported: boolean;
  reason: string;
  helper: string;
  syscallProbe: string;
  probe: SandboxProbe | null;
  dir: string;
}

const env: Env = {
  supported: false,
  reason: "",
  helper: "",
  syscallProbe: "",
  probe: null,
  dir: "",
};

/** Paths outside the sandbox that the fixtures use. Created in beforeAll, removed in afterAll. */
let secretFile = "";
let secretDir = "";
let workDir = "";

const PERMITTED_PORT = 47311;
const FORBIDDEN_PORT = 47312;

function run(command: string, args: string[]): { status: number; stdout: string; stderr: string } {
  const result = spawnSync(command, args, { encoding: "utf8", shell: false, timeout: 30_000 });
  return {
    status: result.status ?? -1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

/** Parse the probe fixture's `name=rc errno=N` output into a lookup of errno by name. */
function errnos(output: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const line of output.split("\n")) {
    const match = /^(\w+)=(-?\d+) errno=(\d+)$/.exec(line.trim());
    if (match !== null) out[match[1]] = Number.parseInt(match[3], 10);
  }
  return out;
}

const EACCES = 13;
const EPERM = 1;
const ECONNREFUSED = 111;

/** Write a launcher profile to a file and return the path. */
function profileFile(name: string, body: string): string {
  const path = join(env.dir, name);
  writeFileSync(path, body);
  return path;
}

/** The rights the sandboxed fixtures need in order to run at all, minus anything under test. */
function basePermits(): string[] {
  return [
    "fs exec /usr",
    "fs exec /bin",
    "fs exec /lib",
    "fs exec /lib64",
    `fs exec ${env.dir}`,
    `fs write ${workDir}`,
    "fs rwdev /dev/null",
  ];
}

/*
 * Detection runs at module load rather than in beforeAll, and that placement is load bearing.
 * Jest evaluates every describe body to collect tests BEFORE it runs any beforeAll hook, so a
 * gate computed in beforeAll is still false when `it` versus `it.skip` is chosen, and every
 * enforcement test silently skips on a host that could have run them. That is the precise
 * failure this suite exists to prevent, arrived at from the other direction.
 */
function detect(): void {
  if (process.platform !== "linux") {
    env.reason = `Landlock and seccomp are Linux kernel features and this host is ${process.platform}.`;
    return;
  }
  if (run("cc", ["--version"]).status !== 0) {
    env.reason = "no C compiler on PATH, so the launcher and the syscall probe cannot be built.";
    return;
  }

  env.dir = mkdtempSync(join(tmpdir(), "aw-sandbox-kernel-"));
  secretDir = mkdtempSync(join(tmpdir(), "aw-sandbox-secret-"));
  workDir = mkdtempSync(join(tmpdir(), "aw-sandbox-work-"));

  // A stand-in for the credential an injected agent would go looking for. Mode 0600 and owned by
  // this uid, so DAC permits the read and only Landlock can be the thing that refuses it.
  secretFile = join(secretDir, "id_ed25519");
  writeFileSync(secretFile, "PRIVATE-KEY-MATERIAL\n", { mode: 0o600 });
  chmodSync(secretFile, 0o600);

  const build = spawnSync("bash", [join(__dirname, "..", "scripts", "build-sandbox-helper.sh")], {
    encoding: "utf8",
    shell: false,
    timeout: 120_000,
    env: { ...process.env, AGENTWALL_SANDBOX_OUT_DIR: env.dir },
  });
  const candidate = join(env.dir, "agentwall-sandbox");
  if (build.status !== 0 || !existsSync(candidate)) {
    env.reason = `the launcher did not build: ${(build.stderr ?? "").trim() || "no output"}`;
    return;
  }
  env.helper = candidate;

  env.syscallProbe = join(env.dir, "sandbox-syscall-probe");
  const probeBuild = run("cc", [
    "-O2",
    "-o",
    env.syscallProbe,
    join(__dirname, "fixtures", "sandbox-syscall-probe.c"),
  ]);
  if (probeBuild.status !== 0 || !existsSync(env.syscallProbe)) {
    env.reason = `the syscall probe did not build: ${probeBuild.stderr.trim() || "no output"}`;
    return;
  }

  const probed = run(env.helper, ["--probe"]);
  if (probed.status !== 0) {
    env.reason = `the launcher could not probe this kernel: ${probed.stderr.trim()}`;
    return;
  }
  env.probe = parseProbe(probed.stdout);
  if (env.probe.landlockAbi === 0) {
    env.reason =
      "this kernel reports Landlock ABI 0, meaning Landlock is absent or not in the boot-time " +
      "LSM list. Filesystem enforcement cannot be measured here.";
    return;
  }
  env.supported = true;
}

detect();

afterAll(() => {
  for (const dir of [env.dir, secretDir, workDir]) {
    if (dir !== "") rmSync(dir, { recursive: true, force: true });
  }
});

const itKernel = () => (env.supported ? it : it.skip);

describe("sandbox kernel enforcement", () => {
  /**
   * Always runs. If the enforcement tests below were skipped, this is where the reason gets
   * recorded, so a green run on a kernel without Landlock cannot be mistaken for a green run
   * that proved something.
   */
  it("states whether kernel enforcement was exercised, and why not when it was not", () => {
    if (env.supported) {
      const probe = env.probe as SandboxProbe;
      console.log(
        `sandbox kernel tests: ACTIVE. kernel=${probe.kernelRelease} landlock_abi=${probe.landlockAbi} ` +
          `seccomp_filter=${probe.seccompFilter} denied_syscalls=${probe.seccompDeniedSyscalls}`
      );
      expect(probe.landlockAbi).toBeGreaterThanOrEqual(1);
      return;
    }
    console.log(`sandbox kernel tests: SKIPPED. ${env.reason}`);
    // A skip with no stated reason is the failure mode this whole file exists to avoid.
    expect(env.reason.length).toBeGreaterThan(20);
  });

  itKernel()("refuses a read the same process gets without the sandbox", () => {
    const bare = run("/usr/bin/cat", [secretFile]);
    expect(bare.status).toBe(0);
    expect(bare.stdout).toContain("PRIVATE-KEY-MATERIAL");

    const profile = profileFile(
      "deny-read.profile",
      [`version 1`, `require-abi 1`, ...basePermits(), "seccomp off", "end", ""].join("\n")
    );
    const sandboxed = run(env.helper, ["--quiet", "--profile-file", profile, "--", "/usr/bin/cat", secretFile]);

    expect(sandboxed.status).not.toBe(0);
    expect(sandboxed.stdout).not.toContain("PRIVATE-KEY-MATERIAL");
    expect(sandboxed.stderr).toMatch(/Permission denied/i);
    // The file is still there and still readable. Only the sandboxed process was refused.
    expect(readFileSync(secretFile, "utf8")).toContain("PRIVATE-KEY-MATERIAL");
  });

  itKernel()("permits a read the profile declared", () => {
    const allowed = join(workDir, "allowed.txt");
    writeFileSync(allowed, "declared-content\n");
    const profile = profileFile(
      "allow-read.profile",
      [`version 1`, `require-abi 1`, ...basePermits(), "seccomp off", "end", ""].join("\n")
    );
    const result = run(env.helper, ["--quiet", "--profile-file", profile, "--", "/usr/bin/cat", allowed]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("declared-content");
  });

  itKernel()("refuses a write outside the writable path", () => {
    const target = join(secretDir, "planted.sh");
    const bare = run("/usr/bin/touch", [target]);
    expect(bare.status).toBe(0);
    rmSync(target, { force: true });

    const profile = profileFile(
      "deny-write.profile",
      [`version 1`, `require-abi 1`, ...basePermits(), "seccomp off", "end", ""].join("\n")
    );
    const sandboxed = run(env.helper, ["--quiet", "--profile-file", profile, "--", "/usr/bin/touch", target]);
    expect(sandboxed.status).not.toBe(0);
    expect(existsSync(target)).toBe(false);
  });

  itKernel()("refuses to exec a binary no fs exec rule covers", () => {
    // The probe binary is in env.dir, which basePermits() grants. A copy in the secret dir is not.
    const outside = join(secretDir, "copied-probe");
    writeFileSync(outside, readFileSync(env.syscallProbe));
    chmodSync(outside, 0o755);
    expect(run(outside, []).status).toBe(0);

    const profile = profileFile(
      "deny-exec.profile",
      [`version 1`, `require-abi 1`, ...basePermits(), "seccomp off", "end", ""].join("\n")
    );
    const sandboxed = run(env.helper, ["--quiet", "--profile-file", profile, "--", outside]);
    expect(sandboxed.status).toBe(126);
    expect(sandboxed.stderr).toContain("fs exec");
  });

  itKernel()("denies the seccomp denylist while leaving ordinary syscalls alone", () => {
    const bare = errnos(run(env.syscallProbe, [secretFile, join(workDir, "w.txt")]).stdout);
    // Baseline sanity: these syscalls are reachable on this host, so a denial below is the filter.
    expect(bare.getpid).toBe(0);
    expect(bare.ptrace_traceme).toBe(0);
    expect(bare.io_uring_setup).not.toBe(EPERM);

    const profile = profileFile(
      "seccomp.profile",
      [
        `version 1`,
        `require-abi 1`,
        ...basePermits(),
        `fs read ${secretDir}`,
        "seccomp errno",
        "end",
        "",
      ].join("\n")
    );
    const sandboxed = errnos(
      run(env.helper, [
        "--quiet",
        "--profile-file",
        profile,
        "--",
        env.syscallProbe,
        secretFile,
        join(workDir, "w.txt"),
      ]).stdout
    );

    expect(sandboxed.ptrace_traceme).toBe(EPERM);
    expect(sandboxed.io_uring_setup).toBe(EPERM);
    expect(sandboxed.unshare_newuser).toBe(EPERM);
    // The control. A filter that broke getpid would break everything and prove nothing.
    expect(sandboxed.getpid).toBe(0);
  });

  itKernel()("confines outbound TCP to declared ports when the ABI supports it", () => {
    const probe = env.probe as SandboxProbe;
    if (!probe.landlockNetTcp) {
      console.log(
        `sandbox TCP confinement: NOT MEASURED. Landlock ABI ${probe.landlockAbi} is below 4 ` +
          "(Linux 6.7), so this kernel has no network hook to test."
      );
      expect(probe.landlockAbi).toBeLessThan(4);
      return;
    }

    const args = [
      secretFile,
      join(workDir, "w.txt"),
      String(PERMITTED_PORT),
      String(FORBIDDEN_PORT),
    ];
    const bare = errnos(run(env.syscallProbe, args).stdout);
    // Nothing is listening on either port, so both refuse at the transport layer, not the LSM.
    expect(bare.connect_permitted).toBe(ECONNREFUSED);
    expect(bare.connect_forbidden).toBe(ECONNREFUSED);
    expect(bare.bind_forbidden).toBe(0);

    const profile = profileFile(
      "net.profile",
      [
        `version 1`,
        `require-abi 4`,
        ...basePermits(),
        `fs read ${secretDir}`,
        "net restrict",
        `net connect-tcp ${PERMITTED_PORT}`,
        "seccomp off",
        "end",
        "",
      ].join("\n")
    );
    const sandboxed = errnos(
      run(env.helper, ["--quiet", "--profile-file", profile, "--", env.syscallProbe, ...args]).stdout
    );

    // Permitted port: unchanged from the bare run, so Landlock did not touch it.
    expect(sandboxed.connect_permitted).toBe(ECONNREFUSED);
    // Forbidden port: the kernel refused before the packet existed.
    expect(sandboxed.connect_forbidden).toBe(EACCES);
    expect(sandboxed.bind_forbidden).toBe(EACCES);
  });

  itKernel()("refuses to start when the profile requires an ABI this kernel does not have", () => {
    const marker = join(workDir, "must-not-exist.txt");
    rmSync(marker, { force: true });
    const profile = profileFile(
      "too-new.profile",
      [`version 1`, `require-abi 99`, ...basePermits(), "seccomp off", "end", ""].join("\n")
    );
    const result = run(env.helper, ["--profile-file", profile, "--", "/usr/bin/touch", marker]);
    expect(result.status).toBe(125);
    expect(result.stderr).toContain("requires Landlock ABI 99");
    // The refusal must be a refusal, not a warning followed by an unconfined run.
    expect(existsSync(marker)).toBe(false);
  });

  itKernel()("refuses a truncated profile rather than enforcing the part it received", () => {
    const marker = join(workDir, "truncated-must-not-run.txt");
    rmSync(marker, { force: true });
    // Everything except the `end` line, which is exactly what a closed pipe would deliver.
    const profile = profileFile(
      "truncated.profile",
      [`version 1`, ...basePermits(), "seccomp errno", ""].join("\n")
    );
    const result = run(env.helper, ["--profile-file", profile, "--", "/usr/bin/touch", marker]);
    expect(result.status).toBe(125);
    expect(result.stderr).toContain("truncated");
    expect(existsSync(marker)).toBe(false);
  });

  itKernel()("reports the rights it installed on stderr rather than running silently", () => {
    const profile = profileFile(
      "loud.profile",
      [`version 1`, `require-abi 1`, ...basePermits(), "seccomp errno", "end", ""].join("\n")
    );
    const result = run(env.helper, ["--profile-file", profile, "--", "/usr/bin/true"]);
    expect(result.status).toBe(0);
    expect(result.stderr).toMatch(/landlock abi=\d+ fs-rules=\d+/);
    expect(result.stderr).toContain("seccomp=errno");
  });

  /**
   * `--seccomp kill` is documented as the harder failure, so it has to actually be one. EPERM and
   * SIGSYS are very different outcomes for a caller, and a `kill` mode that quietly behaved like
   * `errno` would be a documented control that does not exist.
   */
  itKernel()("kills the process on a denied syscall in kill mode", () => {
    const profile = profileFile(
      "kill.profile",
      [
        `version 1`,
        `require-abi 1`,
        ...basePermits(),
        `fs read ${secretDir}`,
        "seccomp kill",
        "end",
        "",
      ].join("\n")
    );
    const result = spawnSync(
      env.helper,
      ["--quiet", "--profile-file", profile, "--", env.syscallProbe, secretFile, join(workDir, "w.txt")],
      { encoding: "utf8", shell: false, timeout: 30_000 }
    );
    // SIGSYS, not an exit code. The probe would otherwise exit 0 after printing every line.
    expect(result.signal).toBe("SIGSYS");
    expect(result.status).toBeNull();
    // It died at the first denied call, so the lines after it were never printed.
    expect(result.stdout ?? "").not.toContain("getpid=");
  });

  itKernel()("denies the syscalls --list-denied advertises, not a different set", () => {
    // The launcher's own inventory is what docs/sandbox.md is written against. If the two ever
    // drift, the documented denylist becomes a claim about a filter that does not exist.
    const listed = run(env.helper, ["--list-denied"]);
    expect(listed.status).toBe(0);
    const names = listed.stdout
      .split("\n")
      .map((line) => line.split("=")[0])
      .filter((name) => name.length > 0);
    for (const expected of [
      "unshare",
      "setns",
      "mount",
      "pivot_root",
      "init_module",
      "bpf",
      "perf_event_open",
      "ptrace",
      "process_vm_readv",
      "keyctl",
      "io_uring_setup",
      "clone3",
      "clone_newuser",
      "ioctl_tiocsti",
    ]) {
      expect(names).toContain(expected);
    }
    // clone3 must return ENOSYS, not EPERM: glibc only falls back to clone() on ENOSYS, and
    // anything else breaks pthread_create and therefore every Node worker thread.
    expect(listed.stdout).toMatch(/^clone3=\d+ errno=38$/m);
  });
});
