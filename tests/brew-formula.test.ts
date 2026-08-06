// The Homebrew formula is generated, so these tests defend the generator's refusals rather than
// its happy path. A formula that installs the wrong bytes is not a build failure: it is a green
// release followed by `brew install` telling a stranger our download is corrupt. Every case below
// is a way that could happen silently.

import { describe, expect, it } from "@jest/globals";

// The generator is a plain CommonJS script with no build step, deliberately: it has to run from a
// bare checkout during a release. requiring it keeps the test against the shipped file.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { parseChecksums, buildFormula, PLATFORMS } = require("../scripts/brew-formula.js");

// Digests are distinct per asset so a test can tell "used the right line" from "used any line".
const DIGESTS: Record<string, string> = {
  "agentwall-verify-darwin-arm64": "a".repeat(64),
  "agentwall-verify-darwin-amd64": "b".repeat(64),
  "agentwall-verify-linux-arm64": "c".repeat(64),
  "agentwall-verify-linux-amd64": "d".repeat(64),
  "agentwall-verify-windows-amd64.exe": "e".repeat(64),
};

function manifest(entries: Record<string, string> = DIGESTS): string {
  return (
    Object.entries(entries)
      .map(([name, digest]) => `${digest}  ${name}`)
      .join("\n") + "\n"
  );
}

describe("parseChecksums", () => {
  it("reads sha256sum text mode and binary mode", () => {
    // sha256sum writes two spaces in text mode and " *" in binary mode. A manifest produced with
    // `sha256sum -b` is still a manifest, and rejecting it would fail a correct release.
    const parsed = parseChecksums(`${"a".repeat(64)}  text-mode\n${"b".repeat(64)} *binary-mode\n`);
    expect(parsed.get("text-mode")).toBe("a".repeat(64));
    expect(parsed.get("binary-mode")).toBe("b".repeat(64));
  });

  it("strips directory prefixes so a manifest written from a parent directory resolves", () => {
    const parsed = parseChecksums(`${"a".repeat(64)}  dist-release/agentwall-verify-linux-amd64\n`);
    expect(parsed.get("agentwall-verify-linux-amd64")).toBe("a".repeat(64));
  });

  it("rejects a line that is not sha256sum format instead of skipping it", () => {
    // Skipping would turn a truncated or reformatted manifest into a formula with a missing
    // platform, which is the failure this whole module exists to prevent.
    expect(() => parseChecksums("md5-or-something  agentwall-verify-linux-amd64\n")).toThrow(
      /not sha256sum format/
    );
  });

  it("rejects a digest that is not 64 hex characters", () => {
    expect(() => parseChecksums(`${"a".repeat(63)}  agentwall-verify-linux-amd64\n`)).toThrow(
      /not sha256sum format/
    );
  });

  it("rejects an empty manifest", () => {
    expect(() => parseChecksums("\n\n")).toThrow(/lists no files/);
  });
});

describe("buildFormula", () => {
  it("emits one url and the matching digest for every supported platform", () => {
    const formula = buildFormula({ version: "1.2.3", digests: parseChecksums(manifest()) });

    for (const platform of PLATFORMS) {
      expect(formula).toContain(
        `url "https://github.com/repsecure/agentwall/releases/download/v1.2.3/${platform.asset}"`
      );
      expect(formula).toContain(`sha256 "${DIGESTS[platform.asset]}"`);
    }
  });

  it("pairs each digest with its own asset rather than merely mentioning both", () => {
    // Guards against a generator that emits the right set of URLs and the right set of digests
    // while crossing them, which every "contains" assertion above would pass.
    const formula: string = buildFormula({
      version: "1.2.3",
      digests: parseChecksums(manifest()),
    });

    for (const platform of PLATFORMS) {
      const block = new RegExp(
        `url "[^"]*/${platform.asset.replace(/\./g, "\\.")}"\\s*\\n\\s*sha256 "${
          DIGESTS[platform.asset]
        }"`
      );
      expect(formula).toMatch(block);
    }
  });

  it("refuses to emit a formula when a platform's binary is absent from the manifest", () => {
    // A missing on_ block is not a syntax error. Homebrew would install nothing on that platform
    // and exit zero, so this has to fail at generation time.
    const partial = { ...DIGESTS };
    delete partial["agentwall-verify-darwin-arm64"];

    expect(() => buildFormula({ version: "1.2.3", digests: parseChecksums(manifest(partial)) })).toThrow(
      /agentwall-verify-darwin-arm64/
    );
  });

  it("names every missing platform, not just the first", () => {
    const onlyLinux = {
      "agentwall-verify-linux-amd64": DIGESTS["agentwall-verify-linux-amd64"],
      "agentwall-verify-linux-arm64": DIGESTS["agentwall-verify-linux-arm64"],
    };
    let message = "";
    try {
      buildFormula({ version: "1.2.3", digests: parseChecksums(manifest(onlyLinux)) });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("agentwall-verify-darwin-arm64");
    expect(message).toContain("agentwall-verify-darwin-amd64");
  });

  it("declares no sha256 that is absent from the manifest", () => {
    // This is the property a reader can check by hand against checksums.txt, and the release
    // workflow enforces the same thing on the real artifact. Asserted here so a generator change
    // cannot break it without a test failing first.
    //
    // Scoped to `sha256 "..."` rather than to any 64-character hex run, because the formula's own
    // test block embeds an all-zero prevHash in its sample audit record. Matching bare hex found
    // that string and called it an invented digest; the first version of the release-side check
    // had the same bug and would have failed every release. Checking the values the formula
    // actually declares is both narrower and the thing we mean.
    const formula: string = buildFormula({
      version: "1.2.3",
      digests: parseChecksums(manifest()),
    });
    const declared = [...formula.matchAll(/sha256 "([0-9a-f]{64})"/g)].map((m) => m[1]);
    expect(declared).toHaveLength(PLATFORMS.length);
    for (const digest of declared) {
      expect(Object.values(DIGESTS)).toContain(digest);
    }
  });

  it("declares the version explicitly, because the asset URLs carry none", () => {
    // The assets are bare executables, so Homebrew cannot infer a version from the URL. Without
    // an explicit declaration the formula fails to load, and `version` is also what the formula's
    // own test block asserts the binary reports.
    const formula: string = buildFormula({ version: "9.9.9", digests: parseChecksums(manifest()) });
    expect(formula).toMatch(/^\s*version "9\.9\.9"$/m);
  });

  it("does not offer the windows binary through Homebrew", () => {
    // Homebrew has no Windows support. The asset exists in the manifest and is deliberately not
    // referenced; a formula that mapped it would be an unusable download.
    const formula: string = buildFormula({ version: "1.2.3", digests: parseChecksums(manifest()) });
    expect(formula).not.toContain("windows");
    expect(formula).not.toContain(DIGESTS["agentwall-verify-windows-amd64.exe"]);
  });

  it("makes the staged binary executable before installing it", () => {
    // Homebrew stages a plain HTTP download non-executable. Losing this chmod produces an install
    // that succeeds and a binary that cannot run, which no checksum or provenance check catches.
    const formula: string = buildFormula({ version: "1.2.3", digests: parseChecksums(manifest()) });
    expect(formula).toMatch(/chmod 0755, binary/);
  });
});
