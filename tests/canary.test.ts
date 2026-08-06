import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { execFileSync } from "child_process";
import { chmodSync, mkdtempSync, rmSync, statSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { crc32 } from "zlib";
import { registerAuditSink, resetAuditChain } from "../src/audit/logger";
import type { AuditEvent } from "../src/types";
import type { CanaryKind } from "../src/canary";
import {
  CANARY_KINDS,
  canaryEnvBlock,
  clearCanaries,
  generateCanary,
  loadCanaries,
  matchesCanaryValue,
  registerCanary,
  runCanaryCommand,
  saveCanaries,
  scanForCanaries,
} from "../src/canary";

/**
 * The canary plane's two load-bearing claims, and nothing else.
 *
 * Claim one is that a minted value is shaped like the credential it impersonates, because a
 * harvester that shape-checks its loot will discard anything that is not. Claim two is that a hit
 * is proof rather than a guess, which holds only while matching is exact-value: the false-positive
 * test below is the assertion that stops somebody "improving" this into a regex detector later.
 *
 * The shell block and the file modes are exercised for real - a spawned `sh`, an actual stat -
 * because both are promises about the world outside the process, and a mock of either would only
 * confirm that this file agrees with itself.
 */

/**
 * The regexes third-party scanners actually use. Matching these is the whole point of the minting
 * code; asserting against a shape copied out of the implementation would prove nothing.
 */
const SHAPE_BY_KIND: Record<CanaryKind, RegExp> = {
  "aws-access-key": /^AKIA[0-9A-Z]{16}$/,
  "github-pat": /^ghp_[A-Za-z0-9]{36}$/,
  "openai-key": /^sk-[A-Za-z0-9]{48}$/,
  "generic-secret": /^[0-9a-f]{64}$/,
  url: /^https:\/\/api-[0-9a-f]{12}\.canary\.invalid\/v1\/collect\/[0-9a-f]{32}$/,
};

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const tempDirs: string[] = [];

function tempFile(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), "agentwall-canary-"));
  tempDirs.push(dir);
  return join(dir, name);
}

function captureAuditEvents(): AuditEvent[] {
  const events: AuditEvent[] = [];
  registerAuditSink((event) => {
    events.push(event);
  });
  return events;
}

afterEach(() => {
  clearCanaries();
  resetAuditChain();
  jest.restoreAllMocks();
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("canary minting", () => {
  it("mints a value that passes the shape check for its kind", () => {
    for (const kind of CANARY_KINDS) {
      const token = generateCanary(kind);
      expect(token.kind).toBe(kind);
      expect(token.value).toMatch(SHAPE_BY_KIND[kind]);
      expect(Date.parse(token.createdAt)).not.toBeNaN();
    }
  });

  it("mints an AWS canary a real AWS key id regex would accept", () => {
    const token = generateCanary("aws-access-key", "billing-decoy");
    expect(token.value).toMatch(/^AKIA[0-9A-Z]{16}$/);
    expect(token.value).toHaveLength(20);
    // AWS key ids are base32, so a plausible one contains no 0, 1, 8 or 9 after the prefix.
    expect(token.value.slice(4)).toMatch(/^[A-Z2-7]{16}$/);
    expect(token.label).toBe("billing-decoy");
  });

  it("mints a GitHub canary whose trailing checksum is a real CRC-32 of its body", () => {
    // zlib's CRC-32 is an independent implementation of the one the minter carries inline, so this
    // catches a transposed polynomial or a byte-order slip that a self-consistent test would miss.
    const token = generateCanary("github-pat");
    const body = token.value.slice("ghp_".length, "ghp_".length + 30);
    const checksum = token.value.slice("ghp_".length + 30);

    const decoded = [...checksum].reduce((acc, char) => acc * 62 + BASE62.indexOf(char), 0);
    expect(decoded).toBe(crc32(body));
  });

  it("never repeats a value across repeated calls", () => {
    // 200 draws per kind is nowhere near a birthday bound for 80+ bits; a collision here means the
    // generator is not drawing from the entropy the safety argument assumes.
    const values = new Set<string>();
    let minted = 0;
    for (const kind of CANARY_KINDS) {
      for (let i = 0; i < 200; i += 1) {
        values.add(generateCanary(kind).value);
        minted += 1;
      }
    }
    expect(values.size).toBe(minted);
  });

  it("gives every token a distinct id", () => {
    const ids = new Set(Array.from({ length: 200 }, () => generateCanary("openai-key").id));
    expect(ids.size).toBe(200);
  });
});

describe("canary matching", () => {
  it("finds a registered token embedded in a URL query string", () => {
    const token = generateCanary("aws-access-key", "billing-decoy");
    registerCanary(token);

    const hits = scanForCanaries(`GET https://drop.example.net/collect?key=${token.value}&seq=4 HTTP/1.1`);
    expect(hits).toEqual([token]);
  });

  it("finds a registered token embedded in a JSON body", () => {
    const token = generateCanary("openai-key");
    registerCanary(token);

    const body = JSON.stringify({ note: "environment dump", env: { OPENAI_API_KEY: token.value, PATH: "/usr/bin" } });
    expect(scanForCanaries(body)).toEqual([token]);
  });

  it("returns nothing for an unregistered value of the same shape", () => {
    // This is the property the whole mechanism is built on. A pattern matcher would fire on both
    // of these; because matching is exact-value, neither is a hit, and a real hit is therefore
    // proof rather than a probability. If this test is ever relaxed, the feature is gone.
    registerCanary(generateCanary("aws-access-key"));

    const lookalike = generateCanary("aws-access-key");
    expect(scanForCanaries(`AWS_ACCESS_KEY_ID=${lookalike.value}`)).toEqual([]);
    // The key id AWS itself uses in documentation: correct shape, not our canary, not a hit.
    expect(scanForCanaries("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")).toEqual([]);
    expect(scanForCanaries("nothing interesting in this payload at all")).toEqual([]);
  });

  it("does not fire on a truncated or altered copy of the canary", () => {
    const token = generateCanary("generic-secret");
    registerCanary(token);

    expect(scanForCanaries(token.value.slice(0, -1))).toEqual([]);
    expect(scanForCanaries(`${token.value.slice(0, -1)}z`)).toEqual([]);
  });

  it("reports one hit even when the value appears several times", () => {
    const token = generateCanary("github-pat");
    registerCanary(token);
    const events = captureAuditEvents();

    expect(scanForCanaries(`${token.value} ... ${token.value}`)).toEqual([token]);
    expect(events).toHaveLength(1);
  });

  it("matches an isolated candidate through the constant-time path", () => {
    const token = generateCanary("aws-access-key");
    const other = generateCanary("aws-access-key");
    registerCanary(token);

    expect(matchesCanaryValue(token.value)).toEqual(token);
    expect(matchesCanaryValue(other.value)).toBeNull();
    // Length mismatch must be a miss, not a throw: timingSafeEqual rejects unequal buffers.
    expect(matchesCanaryValue("short")).toBeNull();
    expect(matchesCanaryValue(`${token.value}xx`)).toBeNull();
  });

  it("refuses to register a value short enough to collide with ordinary traffic", () => {
    const token = { ...generateCanary("aws-access-key"), value: "AKIA1" };
    expect(() => registerCanary(token)).toThrow(/minimum is 16/);
  });
});

describe("canary audit records", () => {
  it("records a hit as a critical identity deny with the ATT&CK mapping attached", () => {
    const token = generateCanary("aws-access-key", "billing-decoy");
    registerCanary(token);
    const events = captureAuditEvents();

    scanForCanaries(`key=${token.value}`, { agentId: "agent-7", sessionId: "sess-3", surface: "scan-api" });

    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      plane: "identity",
      action: "canary:triggered",
      decision: "deny",
      riskLevel: "critical",
      agentId: "agent-7",
      sessionId: "sess-3",
      matchedRules: ["identity:deny-canary-triggered"],
    });
    expect(events[0].metadata).toMatchObject({
      canaryId: token.id,
      canaryKind: "aws-access-key",
      canaryLabel: "billing-decoy",
      canaryTriggered: "true",
      canarySurface: "scan-api",
    });
    expect(events[0].detections?.[0]).toMatchObject({
      id: "det.identity.canary.triggered",
      ruleId: "identity:deny-canary-triggered",
      severity: "critical",
      mitreAttack: { techniqueId: "T1552", tactic: "Credential Access" },
    });
  });

  it("keeps the canary value out of the serialized record", () => {
    // An audit record is read by more people than the environment it protects. Writing the value
    // here would hand anyone with log access the string the theft was after, plus the knowledge of
    // exactly which string to strip in order to run the same theft unobserved.
    const token = generateCanary("github-pat", "ci-decoy");
    registerCanary(token);
    const events = captureAuditEvents();

    scanForCanaries(`Authorization: Bearer ${token.value}`);

    expect(events).toHaveLength(1);
    expect(JSON.stringify(events[0])).not.toContain(token.value);
    // The id is what makes the record actionable without the value being in it.
    expect(JSON.stringify(events[0])).toContain(token.id);
  });
});

describe("canary files", () => {
  it("writes the canary file at mode 0600 and reads it back intact", () => {
    const file = tempFile("canaries.json");
    const tokens = [generateCanary("aws-access-key", "billing-decoy"), generateCanary("url")];

    saveCanaries(file, tokens);

    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(loadCanaries(file)).toEqual(tokens);
  });

  it("restores 0600 when saving over a file somebody loosened", () => {
    // writeFileSync's mode applies at creation only, so without the explicit chmod a second save
    // would write fresh secrets into a world-readable file and report success.
    const file = tempFile("canaries.json");
    saveCanaries(file, [generateCanary("openai-key")]);
    chmodSync(file, 0o644);

    saveCanaries(file, [generateCanary("openai-key")]);

    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it("refuses a group- or world-readable canary file and says why", () => {
    const file = tempFile("canaries.json");
    saveCanaries(file, [generateCanary("aws-access-key")]);
    chmodSync(file, 0o644);

    expect(() => loadCanaries(file)).toThrow(/mode 0644/);
    expect(() => loadCanaries(file)).toThrow(/strip them from outbound traffic/);
    expect(() => loadCanaries(file)).toThrow(/chmod 600/);
  });

  it("rejects a file whose entries do not survive the token schema", () => {
    const file = tempFile("canaries.json");
    // Written through the real writer, so the mode gate passes and the shape gate is what fires.
    saveCanaries(file, [{ ...generateCanary("aws-access-key"), value: "tiny" }]);

    expect(() => loadCanaries(file)).toThrow(/not a valid token list/);
  });
});

describe("canary env block", () => {
  it("emits export lines a shell accepts and reproduces the values exactly", () => {
    const tokens = CANARY_KINDS.map((kind) => generateCanary(kind));
    const block = canaryEnvBlock(tokens);

    const exports = block.split("\n").filter((line) => line.startsWith("export "));
    expect(exports).toHaveLength(tokens.length);
    for (const line of exports) {
      expect(line).toMatch(/^export [A-Z_][A-Z0-9_]*='[^']*'$/);
    }

    // A regex says the lines look like shell. Running them proves it, and proves the quoting keeps
    // slashes, dots and hyphens out of the shell's hands.
    const printed = execFileSync(
      "sh",
      ["-c", `${block}\nprintf '%s\\n' "$AWS_ACCESS_KEY_ID" "$GITHUB_TOKEN" "$OPENAI_API_KEY" "$API_SECRET" "$WEBHOOK_URL"`],
      { encoding: "utf8" }
    );
    expect(printed.trimEnd().split("\n")).toEqual(tokens.map((token) => token.value));
  });

  it("gives same-kind canaries distinct variable names so none is overwritten", () => {
    const labelled = generateCanary("aws-access-key", "prod runner");
    const first = generateCanary("aws-access-key");
    const second = generateCanary("aws-access-key");

    const block = canaryEnvBlock([labelled, first, second]);
    const names = block
      .split("\n")
      .filter((line) => line.startsWith("export "))
      .map((line) => line.slice("export ".length).split("=")[0]);

    expect(names).toEqual(["AWS_ACCESS_KEY_ID_PROD_RUNNER", "AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID_2"]);
    expect(new Set(names).size).toBe(3);
  });

  it("labels the block as decoy material so nobody treats it as a real credential dump", () => {
    const block = canaryEnvBlock([generateCanary("generic-secret", "db-decoy")]);
    expect(block).toContain("Not real credentials");
    expect(block).toContain("db-decoy");
  });
});

describe("canary CLI", () => {
  it("generate prints the token with a plantable export block and saves it", () => {
    const file = tempFile("canaries.json");
    const logSpy = jest.spyOn(console, "log").mockImplementation(() => undefined);

    runCanaryCommand(["generate", "--kind", "github-pat", "--label", "ci-decoy", "--out", file]);

    const output = logSpy.mock.calls.map((call) => call.join(" ")).join("\n");
    const saved = loadCanaries(file);
    expect(saved).toHaveLength(1);
    expect(output).toContain(saved[0].id);
    expect(output).toContain("ci-decoy");
    // Generate is the one place the value is printed: it is the only copy the operator gets.
    expect(output).toContain(saved[0].value);
    expect(output).toContain(`export GITHUB_TOKEN_CI_DECOY='${saved[0].value}'`);
  });

  it("generate appends to an existing canary file rather than replacing it", () => {
    const file = tempFile("canaries.json");
    jest.spyOn(console, "log").mockImplementation(() => undefined);

    runCanaryCommand(["generate", "--kind", "aws-access-key", "--out", file]);
    runCanaryCommand(["generate", "--kind", "openai-key", "--out", file]);

    expect(loadCanaries(file).map((token) => token.kind)).toEqual(["aws-access-key", "openai-key"]);
  });

  it("list shows the inventory and never prints a value", () => {
    const file = tempFile("canaries.json");
    const tokens = [generateCanary("aws-access-key", "billing-decoy"), generateCanary("url")];
    saveCanaries(file, tokens);
    const logSpy = jest.spyOn(console, "log").mockImplementation(() => undefined);

    runCanaryCommand(["list", "--file", file]);

    const output = logSpy.mock.calls.map((call) => call.join(" ")).join("\n");
    for (const token of tokens) {
      expect(output).toContain(token.id);
      expect(output).toContain(token.kind);
      expect(output).toContain(token.createdAt);
      expect(output).not.toContain(token.value);
    }
    expect(output).toContain("billing-decoy");
  });

  it("rejects an unknown kind and an unknown subcommand instead of guessing", () => {
    expect(() => runCanaryCommand(["generate", "--kind", "ssh-key"])).toThrow(/Unknown canary kind "ssh-key"/);
    expect(() => runCanaryCommand(["inspect", "--file", "x"])).toThrow(/Unknown canary subcommand "inspect"/);
    expect(() => runCanaryCommand(["generate", "--kind"])).toThrow(/--kind needs a value/);
    expect(() => runCanaryCommand(["list"])).toThrow(/canary list needs --file/);
  });
});
