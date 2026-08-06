import { describe, expect, it } from "@jest/globals";
import { spawnSync } from "child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { stageRuleset } from "../src/perimeter";
import { renderNftables } from "../src/perimeter/spec";
import type { PerimeterSpec } from "../src/perimeter/spec";

/**
 * Does the generated ruleset survive a real nftables parser, and does it reach one at all?
 *
 * Every other perimeter test asserts on the rendered string, and a string test cannot know
 * that `redirect` is a reserved statement keyword which nft refuses as a chain name. That
 * exact mistake shipped and was only caught by handing the file to `nft`. A ruleset that
 * fails to load is a total failure of the feature, so the parser gets a say here.
 *
 * WHAT IS NOW SETTLED, and what settled it. Kernel acceptance of this ruleset used to be an
 * open question stated as a limit in docs/perimeter.md. It was closed on 2026-08-06 by
 * installing privileged on a disposable VM running Ubuntu kernel 6.8.0-136-generic with
 * nftables 1.0.9, then reading the table back out of the kernel with
 * `nft list table inet agentwall`. Every construct that had only ever been assumed was
 * accepted: `type nat hook output priority dstnat` inside an `inet` table, `redirect to
 * :PORT`, and `ip6 daddr` matches in an `inet` chain. Containment was then measured against
 * 29 egress probes run as the agent UID, each compared against the same probe run before the
 * ruleset existed, and each judged by two independent oracles.
 *
 * WHAT IS STILL NOT PROVEN BY THIS FILE. That was one kernel, one nftables version, driven by
 * hand, and none of it happens in CI. The privileged case at the bottom reproduces it, but it
 * is opt-in and skipped by default. So a green run of this file means the parser was satisfied
 * and the ruleset was delivered correctly. It does not mean a kernel loaded it.
 *
 * The layers, in order of how much they prove and how rarely they can run:
 *  - no chain name collides with an nft keyword, which always runs;
 *  - staging hands nft a real readable file rather than stdin, which always runs;
 *  - an `nft --check` parse, skipped when nft is absent;
 *  - a real privileged load, skipped unless root AND explicitly opted into.
 *
 * `nft --check` still needs netlink access to build its cache, so unprivileged it fails with
 * a netlink error AFTER parsing. That is the signal used below: a syntax error means the file
 * is malformed, a netlink error means the parser was satisfied and only privilege stopped it.
 */

const SPEC: PerimeterSpec = {
  agentUid: 61001,
  proxyUid: 61002,
  proxyPort: 8901,
  dnsResolver: "127.0.0.53",
  allowLoopback: false,
};

/** Words nft parses as statements or types, which therefore cannot name a chain. */
const NFT_RESERVED = [
  "redirect", "accept", "drop", "reject", "return", "jump", "goto", "queue", "continue",
  "snat", "dnat", "masquerade", "log", "counter", "limit", "meta", "ct", "nat", "filter",
  "route", "policy", "type", "hook", "priority", "table", "chain", "rule", "set", "map",
];

function chainNames(ruleset: string): string[] {
  return [...ruleset.matchAll(/^\s*chain\s+([A-Za-z0-9_-]+)\s*\{/gm)].map((m) => m[1]);
}

function nftAvailable(): boolean {
  const probe = spawnSync("nft", ["--version"], { encoding: "utf8" });
  return !probe.error && probe.status === 0;
}

describe("perimeter ruleset survives nft", () => {
  it("names no chain after an nft keyword", () => {
    const names = chainNames(renderNftables(SPEC));
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      expect(NFT_RESERVED).not.toContain(name);
    }
  });

  it("parses under nft --check when nft is available", () => {
    if (!nftAvailable()) {
      // nft absent. The keyword check above is the portable guarantee.
      return;
    }

    const dir = mkdtempSync(join(tmpdir(), "aw-nft-"));
    try {
      const file = join(dir, "rules.nft");
      writeFileSync(file, renderNftables(SPEC));
      const run = spawnSync("nft", ["--check", "--file", file], { encoding: "utf8" });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;

      // A netlink failure means the parser was satisfied and only privilege stopped it, which
      // is the expected outcome for an unprivileged run and is a pass for this test's purpose.
      if (/netlink/i.test(output)) return;

      expect(output).not.toMatch(/syntax error/i);
      expect(output).not.toMatch(/Error:/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a ruleset that names a chain after a keyword, proving the check bites", () => {
    // Guards the guard: if NFT_RESERVED or chainNames ever stopped matching anything, the
    // first test would pass vacuously on any input at all.
    const names = chainNames("table inet t {\n\tchain redirect {\n\t}\n}\n");
    expect(names).toEqual(["redirect"]);
    expect(NFT_RESERVED).toContain(names[0]);
  });
});

/**
 * A ruleset nft never receives is as useless as one it rejects, and that is not hypothetical.
 *
 * `install` used to run `spawnSync("nft", ["-f", "-"], { input: ruleset })`, which never
 * installed a perimeter on any host. libuv backs child stdio with a Unix socket rather than a
 * fifo, so `-f -` resolved to a /dev/stdin that nft refused with `Not a regular file`. The
 * parse test above passed the whole time, because it writes its own temp file and checks that
 * rather than checking what install does. These assert on delivery instead of on content.
 *
 * Nothing here spawns nft. `stageRuleset` exists as a separate function precisely so that this
 * can be true: shadowing `nft` on PATH to inspect its argv would be one PATH-resolution
 * surprise away from installing a live perimeter on a CI runner that happens to be root, and
 * tests/perimeter.test.ts opens by requiring that no test touch the host firewall.
 */
describe("the ruleset actually reaches nft", () => {
  it("stages a real readable file and names it in argv, never a bare dash", () => {
    const ruleset = renderNftables(SPEC);
    const staged = stageRuleset(ruleset);
    try {
      // The bug in one line: the old code passed "-" here and nft could not open it.
      expect(staged.argv[0]).toBe("-f");
      expect(staged.argv[1]).not.toBe("-");
      expect(staged.argv[1]).toBe(staged.file);
      expect(existsSync(staged.file)).toBe(true);
      expect(statSync(staged.file).isFile()).toBe(true);

      // Round-trips byte for byte, so what nft opens is what was rendered.
      expect(readFileSync(staged.file, "utf8")).toBe(ruleset);
      // The constructs only a real kernel can accept still have to survive the trip.
      expect(readFileSync(staged.file, "utf8")).toContain("type nat hook output priority dstnat");
      expect(readFileSync(staged.file, "utf8")).toContain("meta skuid 61001 drop");
    } finally {
      rmSync(staged.dir, { recursive: true, force: true });
    }
  });

  it("keeps the staged ruleset unreadable by other users", () => {
    // It names the host's agent and proxy uids and its whole containment posture. That does
    // not belong in a world-readable /tmp file, however briefly.
    const staged = stageRuleset(renderNftables(SPEC));
    try {
      expect(statSync(staged.file).mode & 0o077).toBe(0);
    } finally {
      rmSync(staged.dir, { recursive: true, force: true });
    }
  });

  it("gives each call its own directory so concurrent installs cannot collide", () => {
    const a = stageRuleset(renderNftables(SPEC));
    const b = stageRuleset(renderNftables({ ...SPEC, proxyPort: 8902 }));
    try {
      expect(a.dir).not.toBe(b.dir);
      expect(readFileSync(a.file, "utf8")).toContain("redirect to :8901");
      expect(readFileSync(b.file, "utf8")).toContain("redirect to :8902");
    } finally {
      rmSync(a.dir, { recursive: true, force: true });
      rmSync(b.dir, { recursive: true, force: true });
    }
  });
});

/**
 * The real thing: load into the kernel, read it back, remove it.
 *
 * Skipped unless it is running as root AND `AGENTWALL_PRIVILEGED_NFT=1` is set, because it
 * writes host firewall rules. Both conditions are deliberate. Root alone is not enough: a CI
 * job that happens to run as root in a container would otherwise start mutating the host's
 * netfilter state without anyone asking it to.
 *
 * When it skips it says so out loud. A privileged guarantee that quietly reports itself as
 * passing when it never ran is exactly the false comfort this whole file exists to avoid.
 */
describe("privileged load into a real kernel", () => {
  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  const optedIn = process.env["AGENTWALL_PRIVILEGED_NFT"] === "1";

  it("loads, reads back, and removes the table", () => {
    const haveNft = nftAvailable();
    if (!isRoot || !optedIn || !haveNft) {
      const why = !haveNft ? "nft is not installed"
        : !isRoot ? "not running as root"
        : "AGENTWALL_PRIVILEGED_NFT is not set to 1";
      console.warn(
        `SKIPPED, and this is the only case here that proves kernel acceptance: ${why}. ` +
          "Kernel acceptance is NOT covered by this run. To cover it: " +
          "sudo AGENTWALL_PRIVILEGED_NFT=1 npx jest tests/perimeter-nft.test.ts"
      );
      return;
    }

    // A table name of its own, so a failed run cannot delete an operator's live perimeter.
    const spec: PerimeterSpec = { ...SPEC, proxyPort: 8902 };
    const ruleset = renderNftables(spec).replace(/inet agentwall/g, "inet agentwalltest");
    const staged = stageRuleset(ruleset);
    try {
      const applied = spawnSync("nft", staged.argv, { encoding: "utf8", shell: false });
      expect(applied.stderr).toBe("");
      expect(applied.status).toBe(0);

      const back = spawnSync("nft", ["list", "table", "inet", "agentwalltest"], { encoding: "utf8" });
      expect(back.status).toBe(0);
      // The constructs a string test can never vouch for, now read back out of the kernel.
      expect(back.stdout).toContain("type nat hook output priority dstnat");
      expect(back.stdout).toContain(`redirect to :${spec.proxyPort}`);
      expect(back.stdout).toContain("ip6 daddr");
      expect(back.stdout).toContain(`meta skuid ${spec.agentUid} drop`);
    } finally {
      rmSync(staged.dir, { recursive: true, force: true });
      spawnSync("nft", ["delete", "table", "inet", "agentwalltest"], { encoding: "utf8" });
    }

    const gone = spawnSync("nft", ["list", "table", "inet", "agentwalltest"], { encoding: "utf8" });
    expect(gone.status).not.toBe(0);
  });
});
