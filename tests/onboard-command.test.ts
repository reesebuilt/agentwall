import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { createHash } from "crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import * as yaml from "js-yaml";

import {
  mintCredential,
  proxyUrlFor,
  renderEnvLines,
  renderNoProxyNote,
  renderInterceptionLines,
  runOnboard,
  withAgent,
  OnboardRequest,
} from "../src/onboard";
import { AGENT_PROFILES, findProfile } from "../src/onboard/profiles";
import { AgentRegistry, parseProxyCredential } from "../src/fleet/registry";
import { loadConfig } from "../src/config";

/**
 * What onboarding has to actually deliver, as opposed to what it prints.
 *
 * The load-bearing test in this file is "the emitted proxy URL binds at the credential tier".
 * Everything else in the command could be correct while that one thing is wrong, and the
 * failure is silent: the config loads, the agent presents a credential, and the registry never
 * matches it, so every connection quietly falls back to the process-wide allowlist with nothing
 * on screen to say the per-agent policy is not in force. That is the shape of the three
 * controls this repository has already shipped green and non-functional.
 */

let dir: string;
let configPath: string;

function baseRequest(overrides: Partial<OnboardRequest> = {}): OnboardRequest {
  return {
    profileId: "claude-code",
    agentId: "claude-code",
    configPath,
    proxyHost: "127.0.0.1",
    proxyPort: 3128,
    allowedHosts: [],
    budgetWindowSeconds: 3600,
    budgetMaxRequests: 2000,
    force: false,
    json: false,
    ...overrides,
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "aw-onboard-"));
  configPath = join(dir, "agentwall.config.yaml");
  writeFileSync(
    configPath,
    yaml.dump({
      port: 3000,
      host: "127.0.0.1",
      logLevel: "info",
      egress: { defaultDeny: false, allowedHosts: ["api.openai.com"], allowedPorts: [443] },
    })
  );
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("credential minting", () => {
  it("hashes the whole id:token string, which is what the proxy will actually present", () => {
    // The registry's Basic path returns the DECODED "user:pass", so a digest taken over the
    // bare token would never match what arrives. This is the silent non-binding bug.
    const { secret, digest } = mintCredential("claude-code");
    expect(secret.startsWith("claude-code:")).toBe(true);
    expect(digest).toBe(createHash("sha256").update(secret, "utf8").digest("hex"));
    expect(digest).not.toBe(
      createHash("sha256").update(secret.slice("claude-code:".length), "utf8").digest("hex")
    );
  });

  it("mints 32 bytes of entropy and never repeats", () => {
    const a = mintCredential("agent-one");
    const b = mintCredential("agent-one");
    expect(a.secret.slice("agent-one:".length)).toHaveLength(64);
    expect(a.secret).not.toBe(b.secret);
  });

  it("refuses an agent id that would change shape inside a proxy URL", () => {
    // A colon makes the Basic decode ambiguous; anything needing percent-encoding means the
    // string the proxy receives is not the string we hashed. Both fail as a silent non-match,
    // so they are refused where the refusal can still be explained.
    expect(() => mintCredential("agent:two")).toThrow(/must match/);
    expect(() => mintCredential("agent two")).toThrow(/must match/);
    expect(() => mintCredential("agent@host")).toThrow(/must match/);
    expect(() => mintCredential("fine.agent_1-x")).not.toThrow();
  });
});

describe("the config onboard writes", () => {
  it("loads through the real loader and binds the agent at the credential tier", () => {
    const result = runOnboard(baseRequest());

    const config = loadConfig(configPath);
    expect(config.fleet?.agents.map((agent) => agent.id)).toEqual(["claude-code"]);

    // Rebuild the header exactly as an HTTP client does from the emitted proxy URL: userinfo
    // out of the URL, base64 as Basic. Nothing here trusts the mint; it goes through the URL.
    const url = new URL(proxyUrlFor(result.secret, "127.0.0.1", 3128));
    const userinfo = `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`;
    const presented = parseProxyCredential(`Basic ${Buffer.from(userinfo, "utf8").toString("base64")}`);

    const registry = new AgentRegistry(config.fleet!);
    const resolved = registry.resolve({ uid: null, comm: null, credential: presented });

    expect(resolved.id).toBe("claude-code");
    expect(resolved.matchedOn).toBe("credential");
    expect(resolved.declared).toBe(true);
    expect(resolved.agent?.egress?.allowedHosts).toEqual(["api.anthropic.com", "platform.claude.com"]);
    expect(resolved.agent?.budget).toEqual({ windowSeconds: 3600, maxRequests: 2000 });
  });

  it("binds identically through the Bearer form, since both hash the same string", () => {
    const result = runOnboard(baseRequest());
    const registry = new AgentRegistry(loadConfig(configPath).fleet!);
    const presented = parseProxyCredential(`Bearer ${result.secret}`);
    expect(registry.resolve({ uid: null, comm: null, credential: presented }).matchedOn).toBe("credential");
  });

  it("does not bind a credential that was not issued", () => {
    runOnboard(baseRequest());
    const registry = new AgentRegistry(loadConfig(configPath).fleet!);
    const resolved = registry.resolve({
      uid: null,
      comm: null,
      credential: `claude-code:${"0".repeat(64)}`,
    });
    expect(resolved.matchedOn).toBe("none");
    expect(resolved.declared).toBe(false);
    expect(resolved.id).toBe("unattributed");
  });

  it("stores the digest and never the secret", () => {
    const result = runOnboard(baseRequest());
    const onDisk = readFileSync(configPath, "utf8");
    expect(onDisk).toContain(`sha256:${result.digest}`);
    expect(onDisk).not.toContain(result.secret);
    // The token half alone must not be there either.
    expect(onDisk).not.toContain(result.secret.split(":")[1]);
  });

  it("leaves the rest of the config exactly as it found it", () => {
    // Onboard edits one section. A round trip that rewrote egress or port would change
    // enforcement behaviour as a side effect of adding an agent.
    runOnboard(baseRequest());
    const config = loadConfig(configPath);
    expect(config.port).toBe(3000);
    expect(config.egress.allowedHosts).toEqual(["api.openai.com"]);
    expect(config.egress.defaultDeny).toBe(false);
  });

  it("keeps the fleet open so onboarding one agent cannot strand the others", () => {
    // fleet.unmatched "deny" refuses every connection no declared agent claims. An onboarding
    // command that set it would take the rest of the host offline on first use.
    runOnboard(baseRequest());
    expect(loadConfig(configPath).fleet?.unmatched).toBe("global");
  });

  it("backs the config up before the comment-losing round trip", () => {
    const before = readFileSync(configPath, "utf8");
    const result = runOnboard(baseRequest());
    expect(readFileSync(result.backupPath!, "utf8")).toBe(before);
  });
});

describe("declaring more than one agent", () => {
  it("adds a second agent without disturbing the first", () => {
    const first = runOnboard(baseRequest());
    const second = runOnboard(baseRequest({ profileId: "codex", agentId: "codex" }));

    const config = loadConfig(configPath);
    expect(config.fleet?.agents.map((agent) => agent.id)).toEqual(["claude-code", "codex"]);

    const registry = new AgentRegistry(config.fleet!);
    expect(registry.resolve({ credential: first.secret }).id).toBe("claude-code");
    expect(registry.resolve({ credential: second.secret }).id).toBe("codex");
  });

  it("refuses to silently replace an existing agent", () => {
    runOnboard(baseRequest());
    expect(() => runOnboard(baseRequest())).toThrow(/already declared/);
  });

  it("replaces on --force and invalidates the previous credential", () => {
    const first = runOnboard(baseRequest());
    const second = runOnboard(baseRequest({ force: true }));
    expect(second.replacedExisting).toBe(true);

    const registry = new AgentRegistry(loadConfig(configPath).fleet!);
    expect(registry.resolve({ credential: second.secret }).matchedOn).toBe("credential");
    expect(registry.resolve({ credential: first.secret }).matchedOn).toBe("none");
  });

  it("onboards the same profile twice under different ids", () => {
    runOnboard(baseRequest());
    const second = runOnboard(baseRequest({ agentId: "claude-code-review" }));
    const registry = new AgentRegistry(loadConfig(configPath).fleet!);
    expect(registry.resolve({ credential: second.secret }).id).toBe("claude-code-review");
  });
});

describe("the emitted environment reflects what was measured", () => {
  it("never emits a variable the profile measured as ignored", () => {
    // Claude Code ignores the lowercase spelling. Emitting it would hand the operator a line
    // that does nothing and looks like it does something.
    const claude = findProfile("claude-code")!;
    const lines = renderEnvLines(claude, "http://secret@127.0.0.1:3128");
    expect(lines.some((line) => line.startsWith("export no_proxy="))).toBe(false);
  });

  it("carries the credential in the proxy URL, which is the only env-var mechanism there is", () => {
    const result = runOnboard(baseRequest());
    const httpsLine = result.envLines.find((line) => line.startsWith("export HTTPS_PROXY="));
    expect(httpsLine).toContain(result.secret);
    expect(httpsLine).toContain("@127.0.0.1:3128");
  });

  it("never punches a NO_PROXY hole, even for a runtime measured to honour it", () => {
    // Every entry in NO_PROXY is an address the agent reaches with AgentWall out of the path,
    // so a default of localhost,127.0.0.1,::1 would ship an un-governed route to all of
    // loopback: local databases, forwarded SSH tunnels, any local proxy that itself egresses.
    // It would also pre-decide verify-capture, whose canary binds 127.0.0.1 by default, making
    // every onboarded agent either a false bypass or an inconclusive result.
    const claude = findProfile("claude-code")!;
    expect(claude.proxyEnv.honoured).toContain("NO_PROXY");

    const result = runOnboard(baseRequest());
    expect(result.envLines.some((line) => line.startsWith("export NO_PROXY="))).toBe(false);
    expect(result.envLines.every((line) => line.includes("@127.0.0.1:3128"))).toBe(true);
  });

  it("explains the absent NO_PROXY rather than leaving the operator to wonder", () => {
    const note = renderNoProxyNote(findProfile("claude-code")!).join("\n");
    expect(note).toMatch(/deliberately NOT set/);
    expect(note).toMatch(/egress allowlist/);
    // Every line must be a shell comment: this block sits inside a paste-ready snippet.
    for (const line of renderNoProxyNote(findProfile("claude-code")!)) {
      expect(line.startsWith("#")).toBe(true);
    }
  });

  it("emits no such note for a runtime that was never measured to honour NO_PROXY", () => {
    expect(renderNoProxyNote(findProfile("openclaw")!)).toEqual([]);
  });

  it("honours an explicit allowlist over the profile's starter hosts", () => {
    const result = runOnboard(baseRequest({ allowedHosts: ["api.example.test"] }));
    expect(result.allowedHosts).toEqual(["api.example.test"]);
    const registry = new AgentRegistry(loadConfig(configPath).fleet!);
    expect(registry.resolve({ credential: result.secret }).agent?.egress?.allowedHosts).toEqual([
      "api.example.test",
    ]);
  });

  it("omits the per-agent allowlist entirely when a profile has no starter hosts", () => {
    // An empty allowlist would fail the schema's refine, and it means something different from
    // "no per-agent list": generic falls back to the process-wide allowlist, which is correct
    // for a runtime whose destinations nobody has measured.
    const result = runOnboard(baseRequest({ profileId: "generic", agentId: "mystery" }));
    expect(result.allowedHosts).toEqual([]);
    const registry = new AgentRegistry(loadConfig(configPath).fleet!);
    expect(registry.resolve({ credential: result.secret }).agent?.egress).toBeUndefined();
  });
});

describe("interception output refuses to break the agent it is configuring", () => {
  it("builds a full bundle for a replacement variable instead of pointing at the bare CA", () => {
    // Measured: REQUESTS_CA_BUNDLE pointed at a lone CA file made every public HTTPS call fail.
    // The emitted snippet must concatenate the system roots or it takes the agent offline.
    const hermes = findProfile("hermes-agent")!;
    const lines = renderInterceptionLines(hermes, "/ca/agentwall-ca.crt");
    const joined = lines.join("\n");
    expect(joined).toContain("ca-certificates.crt");
    expect(joined).toMatch(/REPLACES the public trust store/);
    // The export must point at the bundle it just built, never at the raw CA.
    const exportLine = lines.find((line) => line.startsWith("export REQUESTS_CA_BUNDLE="));
    expect(exportLine).toContain("bundle.pem");
    expect(exportLine).not.toContain("/ca/agentwall-ca.crt");
  });

  it("never emits a quoted tilde, which the shell does not expand", () => {
    // A single-quoted '~/.agentwall/x.pem' is a literal directory named "~", so the variable
    // would point at a file that does not exist while looking exactly like a working line.
    // Every path in a paste-ready snippet has to be absolute.
    for (const profile of AGENT_PROFILES) {
      for (const line of renderInterceptionLines(profile, "/ca/agentwall-ca.crt")) {
        if (line.startsWith("#")) continue;
        expect(line).not.toContain("'~");
      }
    }
  });

  it("builds the shared bundle once even when two aliased variables need it", () => {
    // requests reads CURL_CA_BUNDLE as an alias for REQUESTS_CA_BUNDLE, so both facts want the
    // same file. Emitting the concatenation twice rewrites it mid-snippet for no reason.
    const hermes = findProfile("hermes-agent")!;
    const lines = renderInterceptionLines(hermes, "/ca/agentwall-ca.crt");
    expect(lines.filter((line) => line.startsWith("cat "))).toHaveLength(1);
    // Both variables must still be exported, and both at the same bundle.
    const exports = lines.filter((line) => line.startsWith("export "));
    expect(exports).toHaveLength(2);
    expect(new Set(exports.map((line) => line.split("=")[1])).size).toBe(1);
  });

  it("emits a plain export for an additive variable", () => {
    const pi = findProfile("pi-agent")!;
    const lines = renderInterceptionLines(pi, "/ca/agentwall-ca.crt");
    expect(lines).toContain("export NODE_EXTRA_CA_CERTS='/ca/agentwall-ca.crt'");
  });

  it("warns rather than exports for a variable measured as ignored", () => {
    const hermes = findProfile("hermes-agent")!;
    const lines = renderInterceptionLines(hermes, "/ca/agentwall-ca.crt");
    expect(lines.some((line) => line.startsWith("export SSL_CERT_FILE="))).toBe(false);
    expect(lines.join("\n")).toMatch(/SSL_CERT_FILE is IGNORED/);
  });

  it("emits no export at all when the trust store was never determined", () => {
    // Codex runs a native binary nobody tested. A guessed variable here is the failure mode
    // this profile set exists to avoid.
    const codex = findProfile("codex")!;
    const lines = renderInterceptionLines(codex, "/ca/agentwall-ca.crt");
    expect(lines.some((line) => line.startsWith("export "))).toBe(false);
    expect(lines.join("\n")).toMatch(/UNVERIFIED/);
  });
});

describe("refusals", () => {
  it("refuses an unknown profile instead of guessing one", () => {
    expect(() => runOnboard(baseRequest({ profileId: "gemini-cli" }))).toThrow(/unknown profile/);
  });

  it("refuses to invent a config file that does not exist", () => {
    expect(() =>
      runOnboard(baseRequest({ configPath: join(dir, "absent.yaml") }))
    ).toThrow(/agentwall init/);
  });

  it("refuses a config whose top level is not a mapping", () => {
    writeFileSync(configPath, yaml.dump(["not", "a", "mapping"]));
    expect(() => runOnboard(baseRequest())).toThrow(/not a YAML mapping/);
  });
});

describe("withAgent is a pure edit of the fleet section", () => {
  it("creates the fleet section when the config has none", () => {
    const { document } = withAgent({ port: 3000 }, { id: "a", label: "A", match: { credential: "sha256:x" }, budget: { windowSeconds: 60, maxRequests: 1 } }, false);
    expect(document).toEqual({
      port: 3000,
      fleet: { unmatched: "global", agents: [{ id: "a", label: "A", match: { credential: "sha256:x" }, budget: { windowSeconds: 60, maxRequests: 1 } }] },
    });
  });

  it("preserves an operator's existing unmatched posture", () => {
    // Someone who deliberately closed their fleet must not have it reopened by onboarding.
    const { document } = withAgent(
      { fleet: { unmatched: "deny", agents: [{ id: "existing", label: "E", match: { credential: "sha256:y" }, budget: { windowSeconds: 60, maxRequests: 1 } }] } },
      { id: "new", label: "N", match: { credential: "sha256:z" }, budget: { windowSeconds: 60, maxRequests: 1 } },
      false
    );
    // Asserted whole rather than by casting a property off an untyped document: the shape is
    // the contract here, and comparing it entire also proves nothing else was disturbed.
    expect(document.fleet).toEqual({
      unmatched: "deny",
      agents: [
        { id: "existing", label: "E", match: { credential: "sha256:y" }, budget: { windowSeconds: 60, maxRequests: 1 } },
        { id: "new", label: "N", match: { credential: "sha256:z" }, budget: { windowSeconds: 60, maxRequests: 1 } },
      ],
    });
  });
});
