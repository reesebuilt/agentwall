import { describe, expect, it } from "@jest/globals";
import { homedir } from "os";
import {
  ABI_WITH_TCP,
  baseProfile,
  fitProfileToKernel,
  parseProbe,
  renderProfile,
} from "../src/sandbox/profile";
import type { SandboxProbe, SandboxProfile } from "../src/sandbox/profile";
import { locateHelper, parseArgs } from "../src/sandbox";

/**
 * What this suite defends, and what it deliberately cannot.
 *
 * Everything here is text: profiles built, profiles rendered, probe output parsed, the gap
 * between a profile and a measured kernel computed. None of it proves the kernel refuses
 * anything, and no assertion in this file should ever be read as if it did. Enforcement is
 * measured in tests/sandbox-kernel.test.ts by running a real process under the real LSM and
 * comparing it against the same process run bare.
 *
 * What these tests are for is the decisions. The default profile's contents ARE the security
 * posture of this feature: an operator who runs `agentwall sandbox run` gets whatever this
 * function returns, and a well-meaning edit that adds the home directory to the read list would
 * quietly undo the entire point while every kernel test stayed green. So the defaults are pinned
 * here, along with the two refusal paths that decide whether a command starts at all.
 *
 * Runs anywhere. No kernel, no compiler, no privilege, no Linux.
 */

const PROBE_ABI4: SandboxProbe = {
  landlockAbi: 4,
  landlockFs: true,
  landlockTruncate: true,
  landlockNetTcp: true,
  landlockIoctlDev: false,
  seccompFilter: true,
  seccompDeniedSyscalls: 50,
  archSupported: true,
  kernelRelease: "6.8.0-test",
};

const PROBE_NO_LANDLOCK: SandboxProbe = {
  ...PROBE_ABI4,
  landlockAbi: 0,
  landlockFs: false,
  landlockTruncate: false,
  landlockNetTcp: false,
};

function pathsFor(profile: SandboxProfile, mode: string): string[] {
  return profile.fs.filter((rule) => rule.mode === mode).map((rule) => rule.path);
}

describe("sandbox default profile", () => {
  it("grants exactly one writable path, the workdir", () => {
    const profile = baseProfile({ workdir: "/srv/agent/work" });
    expect(pathsFor(profile, "write")).toEqual(["/srv/agent/work"]);
  });

  /**
   * The claim this feature makes to an operator is that a prompt-injected agent cannot read their
   * credentials. That claim is only as good as the default profile, so the absences are asserted
   * rather than assumed.
   */
  it("grants no access to the home directory or the usual credential stores", () => {
    const profile = baseProfile({ workdir: "/srv/agent/work" });
    const granted = profile.fs.map((rule) => rule.path);
    for (const forbidden of [
      homedir(),
      `${homedir()}/.ssh`,
      `${homedir()}/.aws`,
      `${homedir()}/.config`,
      "/root",
      "/home",
      "/var",
      "/tmp",
    ]) {
      expect(granted).not.toContain(forbidden);
      // Nor as an ancestor: a rule on `/` would grant all of these by inheritance.
      expect(granted).not.toContain("/");
    }
  });

  /**
   * /tmp is shared between everything running as this uid: a place to drop an executable and a
   * place to read what another process left behind. The workdir gets a private temp instead, and
   * `run` points TMPDIR at it.
   */
  it("does not grant shared /tmp", () => {
    const profile = baseProfile({ workdir: "/srv/agent/work" });
    for (const rule of profile.fs) {
      expect(rule.path).not.toBe("/tmp");
      expect(rule.path.startsWith("/tmp/")).toBe(false);
    }
  });

  it("grants the runtime read and execute but never write", () => {
    const profile = baseProfile({ workdir: "/srv/agent/work" });
    expect(pathsFor(profile, "exec")).toEqual(expect.arrayContaining(["/usr", "/lib"]));
    for (const path of ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"]) {
      expect(pathsFor(profile, "write")).not.toContain(path);
    }
  });

  it("grants named character devices rather than all of /dev", () => {
    const profile = baseProfile({ workdir: "/srv/agent/work" });
    const devices = pathsFor(profile, "rwdev");
    expect(devices).toContain("/dev/null");
    expect(devices).toContain("/dev/urandom");
    expect(profile.fs.map((rule) => rule.path)).not.toContain("/dev");
  });

  it("leaves TCP unconfined unless the operator asks for it", () => {
    expect(baseProfile({ workdir: "/w" }).restrictNet).toBe(false);
    expect(baseProfile({ workdir: "/w", restrictNet: true }).restrictNet).toBe(true);
  });

  it("keeps the widest mode when a path is granted twice", () => {
    const profile = baseProfile({ workdir: "/srv/work", read: ["/srv/work"] });
    expect(pathsFor(profile, "write")).toContain("/srv/work");
    expect(pathsFor(profile, "read")).not.toContain("/srv/work");
  });

  it("refuses a relative path rather than resolving it against an unknown cwd", () => {
    expect(() => baseProfile({ workdir: "relative/dir" })).toThrow(/absolute path/);
    expect(() => baseProfile({ workdir: "/w", read: ["../escape"] })).toThrow(/absolute path/);
  });

  it("refuses a port outside 0..65535", () => {
    expect(() => baseProfile({ workdir: "/w", connectTcp: [70000] })).toThrow(/0\.\.65535/);
    expect(() => baseProfile({ workdir: "/w", bindTcp: [-1] })).toThrow(/0\.\.65535/);
  });
});

describe("sandbox profile rendering", () => {
  it("terminates the profile so the launcher can tell truncation from completeness", () => {
    const rendered = renderProfile(baseProfile({ workdir: "/w" }));
    expect(rendered.trimEnd().split("\n").pop()).toBe("end");
    expect(rendered).toContain("version 1");
  });

  /**
   * The launcher reads this off a pipe, line by line. A path containing a newline would end its
   * rule and begin a line the launcher reads as a fresh directive, so a path chosen anywhere
   * upstream could append `seccomp off` to a generated profile. Refusing is the only safe answer:
   * escaping would need the launcher to un-escape, and a parser is a worse place for this.
   */
  it("refuses a path containing a newline rather than emitting an injectable profile", () => {
    const profile = baseProfile({ workdir: "/w" });
    profile.fs.push({ mode: "read", path: "/evil\nseccomp off" });
    expect(() => renderProfile(profile)).toThrow(/newline/);
  });

  it("omits every net line when the profile does not restrict the network", () => {
    const profile = baseProfile({ workdir: "/w", connectTcp: [3128], restrictNet: false });
    const rendered = renderProfile(profile);
    expect(rendered).not.toContain("net restrict");
    expect(rendered).not.toContain("connect-tcp");
  });

  it("emits net restrict with no ports when the operator wants no TCP at all", () => {
    const rendered = renderProfile(baseProfile({ workdir: "/w", restrictNet: true }));
    expect(rendered).toContain("net restrict");
    expect(rendered).not.toContain("connect-tcp");
  });

  it("renders each granted path exactly once, with its mode", () => {
    const rendered = renderProfile(baseProfile({ workdir: "/srv/work", read: ["/data"] }));
    expect(rendered).toContain("fs write /srv/work\n");
    expect(rendered).toContain("fs read /data\n");
    expect(rendered.match(/^fs \w+ \/srv\/work$/gm)).toHaveLength(1);
  });
});

describe("sandbox probe parsing", () => {
  it("reads the launcher's key=value output", () => {
    const probe = parseProbe(
      [
        "landlock_abi=4",
        "landlock_fs=yes",
        "landlock_truncate=yes",
        "landlock_net_tcp=yes",
        "landlock_ioctl_dev=no",
        "seccomp_filter=yes",
        "seccomp_denied_syscalls=50",
        "arch_supported=yes",
        "kernel_release=6.8.0-136-generic",
      ].join("\n")
    );
    expect(probe.landlockAbi).toBe(4);
    expect(probe.landlockNetTcp).toBe(true);
    expect(probe.landlockIoctlDev).toBe(false);
    expect(probe.seccompDeniedSyscalls).toBe(50);
    expect(probe.kernelRelease).toBe("6.8.0-136-generic");
  });

  /**
   * Missing keys must read as absent capability, never as present. A truncated or unparseable
   * probe that defaulted to "yes" would report a sandbox nobody installed.
   */
  it("treats anything it could not read as absent", () => {
    const probe = parseProbe("landlock_abi=\ngarbage\n");
    expect(probe.landlockAbi).toBe(0);
    expect(probe.landlockFs).toBe(false);
    expect(probe.seccompFilter).toBe(false);
    expect(probe.archSupported).toBe(false);
    expect(probe.kernelRelease).toBe("unknown");
  });
});

describe("fitting a profile to a measured kernel", () => {
  it("passes a profile the kernel can enforce", () => {
    const fit = fitProfileToKernel(
      baseProfile({ workdir: "/w", restrictNet: true, connectTcp: [3128], requireAbi: 4 }),
      PROBE_ABI4
    );
    expect(fit.refusals).toEqual([]);
    expect(fit.degradations).toEqual([]);
  });

  /**
   * The refusal that matters most. An operator who believes a process is confined and is wrong
   * has already widened what they will let it attempt, and an unconfined run produces no signal
   * anywhere. So no Landlock means no start, and --allow-degraded is the only way past.
   */
  it("refuses on a kernel with no Landlock", () => {
    const fit = fitProfileToKernel(baseProfile({ workdir: "/w" }), PROBE_NO_LANDLOCK);
    expect(fit.refusals).toHaveLength(1);
    expect(fit.refusals[0]).toContain("no Landlock");
    expect(fit.refusals[0]).toContain("/sys/kernel/security/lsm");
  });

  it("runs degraded only when asked, and still says what is unprotected", () => {
    const profile = baseProfile({ workdir: "/w", allowDegraded: true, requireAbi: 0 });
    const fit = fitProfileToKernel(profile, PROBE_NO_LANDLOCK);
    expect(fit.refusals).toEqual([]);
    expect(fit.degradations).toHaveLength(1);
    expect(fit.degradations[0]).toContain("no Landlock");
  });

  /**
   * --allow-degraded is about a kernel with no Landlock at all. It must not also wave through a
   * kernel that has Landlock but not enough of it, because that is a different question the
   * operator answered with --require-abi.
   */
  it("still refuses an unmet --require-abi even with --allow-degraded", () => {
    const profile = baseProfile({ workdir: "/w", allowDegraded: true, requireAbi: 4 });
    const fit = fitProfileToKernel(profile, { ...PROBE_ABI4, landlockAbi: 2, landlockNetTcp: false });
    expect(fit.refusals[0]).toContain("requires Landlock ABI 4");
  });

  it("degrades rather than refuses when TCP scoping is asked for below ABI 4", () => {
    const profile = baseProfile({
      workdir: "/w",
      restrictNet: true,
      connectTcp: [3128],
      requireAbi: 1,
    });
    const fit = fitProfileToKernel(profile, {
      ...PROBE_ABI4,
      landlockAbi: 3,
      landlockNetTcp: false,
    });
    expect(fit.refusals).toEqual([]);
    expect(fit.degradations.join(" ")).toContain(`ABI ${ABI_WITH_TCP}`);
    expect(fit.degradations.join(" ")).toContain("unconfined");
  });

  it("names the truncate gap below ABI 3, where a read-only file can still be emptied", () => {
    const fit = fitProfileToKernel(baseProfile({ workdir: "/w" }), {
      ...PROBE_ABI4,
      landlockAbi: 2,
      landlockTruncate: false,
      landlockNetTcp: false,
    });
    expect(fit.degradations.join(" ")).toContain("truncate(2)");
  });

  it("refuses when seccomp was requested and the kernel has no filter mode", () => {
    const fit = fitProfileToKernel(baseProfile({ workdir: "/w", seccomp: "errno" }), {
      ...PROBE_ABI4,
      seccompFilter: false,
    });
    expect(fit.refusals.join(" ")).toContain("--seccomp off");
  });

  it("does not refuse for seccomp when the operator turned it off", () => {
    const fit = fitProfileToKernel(baseProfile({ workdir: "/w", seccomp: "off" }), {
      ...PROBE_ABI4,
      seccompFilter: false,
      archSupported: false,
    });
    expect(fit.refusals).toEqual([]);
  });
});

describe("sandbox argument parsing", () => {
  it("keeps everything after -- as the command, options included", () => {
    const args = parseArgs(["run", "--workdir", "/w", "--", "node", "--inspect", "agent.js"]);
    expect(args.subcommand).toBe("run");
    expect(args.workdir).toBe("/w");
    expect(args.command).toEqual(["node", "--inspect", "agent.js"]);
  });

  it("treats --allow-tcp as an implicit --restrict-net", () => {
    const args = parseArgs(["run", "--allow-tcp", "3128", "--", "true"]);
    expect(args.connectTcp).toEqual([3128]);
    expect(args.restrictNet).toBe(true);
  });

  it("accumulates repeated path flags", () => {
    const args = parseArgs(["plan", "--allow-read", "/a", "--allow-read", "/b", "--allow-write", "/c"]);
    expect(args.read).toEqual(["/a", "/b"]);
    expect(args.write).toEqual(["/c"]);
  });

  it("rejects an unknown option instead of ignoring it", () => {
    expect(() => parseArgs(["run", "--allow-everything", "--", "true"])).toThrow(/Unknown option/);
  });

  it("rejects a seccomp mode it does not implement", () => {
    expect(() => parseArgs(["run", "--seccomp", "paranoid"])).toThrow(/off, errno or kill/);
  });

  it("requires a subcommand", () => {
    expect(() => parseArgs([])).toThrow(/probe, plan, build or run/);
    expect(() => parseArgs(["--json"])).toThrow(/probe, plan, build or run/);
  });
});

describe("locating the launcher", () => {
  /**
   * A missing launcher must be a reported failure with the places that were searched, never a
   * silent fallback to running the command unconfined. The list is what turns "it did not work"
   * into something an operator can fix.
   */
  it("reports every path it searched when the launcher is absent", () => {
    const previous = process.env.AGENTWALL_SANDBOX_HELPER;
    process.env.AGENTWALL_SANDBOX_HELPER = "/nonexistent/agentwall-sandbox";
    try {
      const location = locateHelper();
      expect(location.path).toBeNull();
      expect(location.searched.join(" ")).toContain("/nonexistent/agentwall-sandbox");
      expect(location.searched.join(" ")).toContain("AGENTWALL_SANDBOX_HELPER");
    } finally {
      if (previous === undefined) delete process.env.AGENTWALL_SANDBOX_HELPER;
      else process.env.AGENTWALL_SANDBOX_HELPER = previous;
    }
  });
});
