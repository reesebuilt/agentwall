import { afterEach, describe, expect, it } from "@jest/globals";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { spawnSync } from "child_process";

// The release check is plain CommonJS so it can run before a build.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { scanText } = require("../scripts/check-public-copy.js") as {
  scanText: (
    text: string,
    file?: string
  ) => Array<{ file: string; rule: string; match: string; line: number; column: number }>;
};

const temporaryDirectories: string[] = [];
const checker = resolve(__dirname, "..", "scripts", "check-public-copy.js");

function temporaryFile(content: string): string {
  const directory = mkdtempSync(join(tmpdir(), "agentwall-public-copy-"));
  temporaryDirectories.push(directory);
  const file = join(directory, "copy.md");
  writeFileSync(file, content, "utf8");
  return file;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("public copy scanner", () => {
  it("accepts complete plain public copy", () => {
    expect(scanText("AgentWall checks local actions.\n", "copy.md")).toEqual([]);
  });

  it("detects competitor names and competitor URLs", () => {
    const findings = scanText(
      "PipeLock has a comparison at https://pipelock.ai/compare.\n",
      "copy.md"
    );

    expect(findings.map((finding) => finding.rule)).toContain("competitor-name");
    expect(findings.map((finding) => finding.rule)).toContain("competitor-url");
  });

  it("detects an em dash", () => {
    expect(scanText("Setup is local—it does not need the service.\n", "copy.md")).toEqual([
      expect.objectContaining({ rule: "em-dash", line: 1 }),
    ]);
  });

  it("detects unfinished copy markers", () => {
    const findings = scanText(
      "TODO: replace copy here. TBD. FIXME. Lorem ipsum. Coming soon.\n",
      "copy.md"
    );

    expect(findings).not.toHaveLength(0);
    expect(findings.every((finding) => finding.rule === "placeholder")).toBe(true);
  });

  it("returns exit code 1 when a supplied file contains banned copy", () => {
    const file = temporaryFile("AgentWall checks requests—then records the result.\n");
    const result = spawnSync(process.execPath, [checker, file], { encoding: "utf8" });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("em-dash");
  });

  it("returns exit code 0 when a supplied file is clean", () => {
    const file = temporaryFile("AgentWall checks requests and records the result.\n");
    const result = spawnSync(process.execPath, [checker, file], { encoding: "utf8" });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Public copy check passed");
  });
});
