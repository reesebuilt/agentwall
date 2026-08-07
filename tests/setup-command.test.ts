import { afterEach, describe, expect, it } from "@jest/globals";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { dirname, join } from "path";
import { createLocalOperatorFiles, loadGeneratedEnvironment, type LocalSetupOptions } from "../src/setup";

const options: LocalSetupOptions = {
  mode: "monitor",
  host: "127.0.0.1",
  port: 3000,
  allowedHosts: [],
  lanAccess: false,
  force: false,
};

const directories: string[] = [];
const previousProxyPort = process.env.AGENTWALL_PROXY_PORT;

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "agentwall-setup-"));
  directories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
  if (previousProxyPort === undefined) {
    delete process.env.AGENTWALL_PROXY_PORT;
  } else {
    process.env.AGENTWALL_PROXY_PORT = previousProxyPort;
  }
});

describe("guided local setup", () => {
  it("creates safe local files and a mode-0600 operator environment", () => {
    const result = createLocalOperatorFiles(temporaryDirectory(), options);

    expect(result.environmentPath).toContain(join(".agentwall", "operator.env"));
    expect(statSync(result.environmentPath).mode & 0o777).toBe(0o600);
    expect(statSync(dirname(result.environmentPath)).mode & 0o777).toBe(0o700);

    const environment = readFileSync(result.environmentPath, "utf8");
    expect(environment).toContain("AGENTWALL_OPERATOR_TOKEN=");
    expect(environment).toContain(`AGENTWALL_AUDIT_FILE=${result.auditPath}`);
    expect(result.dashboardUrl).toBe("http://127.0.0.1:3000");
    expect(result.created).toBe(true);
  });

  it("does not replace an existing config without force", () => {
    const directory = temporaryDirectory();
    const configPath = join(directory, "agentwall.config.yaml");
    writeFileSync(configPath, "existing\n");

    expect(() => createLocalOperatorFiles(directory, options)).toThrow(/overwrite/i);
    expect(readFileSync(configPath, "utf8")).toBe("existing\n");
  });

  it("overwrites generated setup files only when force is explicit", () => {
    const directory = temporaryDirectory();
    const first = createLocalOperatorFiles(directory, options);
    const firstEnvironment = readFileSync(first.environmentPath, "utf8");

    const second = createLocalOperatorFiles(directory, { ...options, mode: "strict", force: true });

    expect(readFileSync(second.environmentPath, "utf8")).not.toBe(firstEnvironment);
    expect(readFileSync(second.configPath, "utf8")).toContain("mode: always");
  });

  it("preserves existing gitignore rules and adds each generated path once", () => {
    const directory = temporaryDirectory();
    const gitignorePath = join(directory, ".gitignore");
    writeFileSync(gitignorePath, "node_modules/\n.agentwall/\n");

    createLocalOperatorFiles(directory, options);
    createLocalOperatorFiles(directory, { ...options, force: true });

    const lines = readFileSync(gitignorePath, "utf8").trim().split("\n");
    expect(lines[0]).toBe("node_modules/");
    expect(lines.filter((line) => line === ".agentwall/")).toHaveLength(1);
    expect(lines.filter((line) => line === "agentwall-approvals.json")).toHaveLength(1);
    expect(lines.filter((line) => line === "audit.jsonl")).toHaveLength(1);
  });

  it("gives an explicit environment variable priority over the generated file", () => {
    const directory = temporaryDirectory();
    createLocalOperatorFiles(directory, options);
    process.env.AGENTWALL_PROXY_PORT = "9999";

    expect(loadGeneratedEnvironment(directory).AGENTWALL_PROXY_PORT).toBe("9999");
  });

  it("parses known values without evaluating shell text", () => {
    const directory = temporaryDirectory();
    const agentwallDirectory = join(directory, ".agentwall");
    createLocalOperatorFiles(directory, options);
    writeFileSync(
      join(agentwallDirectory, "operator.env"),
      [
        "AGENTWALL_PROXY_PORT=8899",
        "AGENTWALL_AUDIT_FILE=$(touch /tmp/agentwall-unsafe)",
        "UNRELATED_VALUE=ignored",
        "export AGENTWALL_PROXY_HOST=0.0.0.0",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );

    const loaded = loadGeneratedEnvironment(directory);
    expect(loaded.AGENTWALL_PROXY_PORT).toBe("8899");
    expect(loaded.AGENTWALL_AUDIT_FILE).toBe("$(touch /tmp/agentwall-unsafe)");
    expect(loaded).not.toHaveProperty("UNRELATED_VALUE");
    expect(loaded).not.toHaveProperty("AGENTWALL_PROXY_HOST");
  });
});
