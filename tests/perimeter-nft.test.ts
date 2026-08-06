import { describe, expect, it } from "@jest/globals";
import { spawnSync } from "child_process";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { renderNftables } from "../src/perimeter/spec";
import type { PerimeterSpec } from "../src/perimeter/spec";

/**
 * Does the generated ruleset survive a real nftables parser?
 *
 * Every other perimeter test asserts on the rendered string, and a string test cannot know
 * that `redirect` is a reserved statement keyword which nft refuses as a chain name. That
 * exact mistake shipped and was only caught by handing the file to `nft`. A ruleset that
 * fails to load is a total failure of the feature — the agent runs uncontained while the
 * operator believes otherwise — so the parser gets a say here.
 *
 * Two layers, because CI may not have nft:
 *  - a pure check that no chain name collides with an nft keyword, which always runs;
 *  - an `nft --check` pass, skipped when nft is absent.
 *
 * `nft --check` still needs netlink access to build its cache, so unprivileged it fails with
 * a netlink error AFTER parsing. That is the signal used below: a syntax error means the file
 * is malformed, a netlink error means the parser was satisfied and only privilege stopped it.
 * Kernel acceptance of the chain types, hooks and inet-family nat support is NOT proven here;
 * that needs a privileged load and is stated as a limit in docs/perimeter.md.
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

describe("perimeter ruleset survives nft", () => {
  it("names no chain after an nft keyword", () => {
    const names = chainNames(renderNftables(SPEC));
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      expect(NFT_RESERVED).not.toContain(name);
    }
  });

  it("parses under nft --check when nft is available", () => {
    const probe = spawnSync("nft", ["--version"], { encoding: "utf8" });
    if (probe.error || probe.status !== 0) {
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
