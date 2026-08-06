import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as yaml from "js-yaml";
import { buildServer } from "../src/server";
import { AgentwallConfig, loadConfig } from "../src/config";
import { PolicyEngine } from "../src/policy/engine";
import { registerAuditSink, resetAuditChain, seedAuditChain, stdoutSink } from "../src/audit/logger";
import { AuditEvent } from "../src/types";

/**
 * Config and policy hot-reload.
 *
 * What already worked before this suite existed: policy rules reloaded from three triggers, and
 * a policy file that failed to parse was rejected whole with the previous ruleset left
 * enforcing. tests/policy-runtime.test.ts covers that and is not duplicated here.
 *
 * What these tests defend is the part that did not exist: one atomic action across BOTH files,
 * a request that cannot straddle a swap, an audit record carrying both file hashes and the
 * rule-level diff, and an honest account of the config keys a running process cannot change.
 */

const ALLOW_RULE = `
version: "1"
rules:
  - id: "custom:allow-openai"
    description: "Allow OpenAI"
    plane: "network"
    match:
      type: "hostname-equals"
      values: ["api.openai.com"]
    decision: "allow"
    riskLevel: "low"
    reason: "OpenAI host allowed"
`;

const DENY_RULE = `
version: "1"
rules:
  - id: "custom:deny-openai"
    description: "Deny OpenAI"
    plane: "network"
    match:
      type: "hostname-equals"
      values: ["api.openai.com"]
    decision: "deny"
    riskLevel: "high"
    reason: "OpenAI host denied"
`;

const OPENAI_REQUEST = {
  agentId: "agent-reload",
  plane: "network" as const,
  action: "http_request",
  payload: { url: "https://api.openai.com/v1/chat/completions" },
};

const tempDirs: string[] = [];

function makeDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-hot-reload-"));
  tempDirs.push(dir);
  return dir;
}

function baseConfigObject(policyPath: string): Record<string, unknown> {
  return {
    port: 0,
    host: "127.0.0.1",
    logLevel: "silent",
    approval: { mode: "auto", timeoutMs: 30_000, backend: "memory" },
    policy: { defaultDecision: "deny", configPath: policyPath },
    dlp: { enabled: true, redactSecrets: true },
    egress: {
      enabled: true,
      defaultDeny: true,
      allowPrivateRanges: false,
      allowedHosts: [],
      allowedSchemes: ["https"],
      allowedPorts: [443],
    },
    manifestIntegrity: { enabled: true },
    watchdog: { enabled: true, staleAfterMs: 15_000, timeoutMs: 30_000, killSwitchMode: "deny_all" },
  };
}

/**
 * A policy file plus a config file on disk, and the config loaded THROUGH loadConfig so it
 * carries `sourcePath`. Reload re-reads the file that path names, so a hand-built literal would
 * exercise a different code path than the one operators use.
 *
 * `watch: false` is not available through buildServer, so these servers do carry the real file
 * watcher. Every assertion here drives an explicit trigger and none writes the policy file while
 * a server is open except the test that is specifically about a rejected file, so the watcher
 * cannot race the assertions.
 */
function setup(policyContents: string, configOverrides: Record<string, unknown> = {}) {
  const dir = makeDir();
  const policyPath = path.join(dir, "policy.yaml");
  const configPath = path.join(dir, "agentwall.config.yaml");
  fs.writeFileSync(policyPath, policyContents);
  fs.writeFileSync(configPath, yaml.dump({ ...baseConfigObject(policyPath), ...configOverrides }));
  return { dir, policyPath, configPath, config: loadConfig(configPath) };
}

function writeConfig(configPath: string, policyPath: string, overrides: Record<string, unknown>): void {
  fs.writeFileSync(configPath, yaml.dump({ ...baseConfigObject(policyPath), ...overrides }));
}

/** Records the chain accepted, in order. */
function captureAudit(): AuditEvent[] {
  const captured: AuditEvent[] = [];
  resetAuditChain();
  seedAuditChain({ chainIndex: 0, previousHash: null });
  // Durable, because emit() only commits a record once a durable sink accepts it. Without one
  // registered, every record is counted as dropped and nothing joins the chain.
  registerAuditSink((event) => captured.push(event), { durable: true });
  return captured;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  resetAuditChain();
  registerAuditSink(stdoutSink);
});

describe("policy reload takes effect and is rejected atomically", () => {
  it("serves the new ruleset on the next request after a valid reload", async () => {
    const { policyPath, config } = setup(ALLOW_RULE);
    const { app, reloadCoordinator } = await buildServer(config);

    try {
      const before = await app.inject({ method: "POST", url: "/evaluate", payload: OPENAI_REQUEST });
      expect(before.json().decision).toBe("allow");

      fs.writeFileSync(policyPath, DENY_RULE);
      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });

      expect(report.ok).toBe(true);
      expect(report.policy.applied).toBe(true);
      expect(report.policy.diff).toEqual({
        added: ["custom:deny-openai"],
        removed: ["custom:allow-openai"],
        modified: [],
      });

      const after = await app.inject({ method: "POST", url: "/evaluate", payload: OPENAI_REQUEST });
      expect(after.json().decision).toBe("deny");
      expect(after.json().matchedRules).toContain("custom:deny-openai");
    } finally {
      await app.close();
    }
  });

  it("keeps the previous policy enforcing when the new policy file is invalid", async () => {
    const { policyPath, config } = setup(DENY_RULE);
    const { app, reloadCoordinator } = await buildServer(config);

    try {
      // Not merely unparseable: a rule that names a private host, which the loader refuses on
      // purpose. A YAML syntax error is already covered in tests/policy-runtime.test.ts, and this
      // proves the semantic validation stage rejects just as completely.
      fs.writeFileSync(
        policyPath,
        `
version: "1"
rules:
  - id: "custom:allow-localhost"
    description: "Allow localhost"
    plane: "network"
    match:
      type: "hostname-equals"
      values: ["127.0.0.1"]
    decision: "allow"
    riskLevel: "low"
    reason: "should be refused"
`
      );

      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });
      expect(report.ok).toBe(false);
      expect(report.policy.applied).toBe(false);
      expect(report.policy.error).toContain("cannot allow private or local hosts");

      // The whole point: still enforcing the ruleset from before the refused file.
      const after = await app.inject({ method: "POST", url: "/evaluate", payload: OPENAI_REQUEST });
      expect(after.json().decision).toBe("deny");
      expect(after.json().matchedRules).toContain("custom:deny-openai");
    } finally {
      await app.close();
    }
  });

  it("refuses the whole reload when the config file is invalid, without touching the policy", async () => {
    const { policyPath, configPath, config } = setup(DENY_RULE);
    const { app, reloadCoordinator } = await buildServer(config);

    try {
      // Both files change. The config is invalid, so neither may be applied: a reload that took
      // the policy half would be the partial outcome the two-phase order exists to prevent.
      fs.writeFileSync(policyPath, ALLOW_RULE);
      writeConfig(configPath, policyPath, { enforcement: { mode: "strct" } });

      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });
      expect(report.ok).toBe(false);
      expect(report.config.error).toContain("invalid enforcement.mode");
      expect(report.policy.applied).toBe(false);
      expect(report.policy.diff).toEqual({ added: [], removed: [], modified: [] });

      const after = await app.inject({ method: "POST", url: "/evaluate", payload: OPENAI_REQUEST });
      expect(after.json().decision).toBe("deny");
    } finally {
      await app.close();
    }
  });

  it("refuses a defaultDecision that would make the engine fail open", async () => {
    // Regression guard. `policy.defaultDecision` is typed "allow" | "deny" but arrives from
    // yaml.load, and nothing checked it at runtime. An unrecognised value became the decision
    // returned for every unmatched request, and src/runtime/enforcement.ts gates on
    // `decision === "deny"`, so a typo here failed OPEN rather than closed.
    const { policyPath, configPath, config } = setup(DENY_RULE);
    const { app, reloadCoordinator } = await buildServer(config);

    try {
      writeConfig(configPath, policyPath, { policy: { defaultDecision: "yolo", configPath: policyPath } });

      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });
      expect(report.ok).toBe(false);
      expect(report.config.error).toContain("invalid policy.defaultDecision");

      // The unmatched default is still deny, not the garbage value.
      const unmatched = await app.inject({
        method: "POST",
        url: "/evaluate",
        payload: { ...OPENAI_REQUEST, payload: { url: "https://unmatched.example.com/" } },
      });
      expect(unmatched.json().decision).toBe("deny");
    } finally {
      await app.close();
    }
  });

  it("refuses a config file loadConfig cannot parse at all", () => {
    const { configPath } = setup(DENY_RULE);
    fs.writeFileSync(configPath, "port: [unclosed\n");
    expect(() => loadConfig(configPath)).toThrow();
  });
});

describe("in-flight requests keep the policy they started with", () => {
  it("does not swap the ruleset under a request that is already being served", async () => {
    const { policyPath, config } = setup(ALLOW_RULE);
    const { app, reloadCoordinator } = await buildServer(config);

    // Hold the request AFTER the onRequest hook pinned its snapshot and BEFORE the handler
    // evaluates. preHandler runs between the two, so this is the real in-flight window.
    // Executor form: Promise.withResolvers reads better but is ES2024, and this project's lib is
    // ES2022. Same reasoning as tests/enforcement.test.ts and tests/spill-watch.test.ts.
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    app.addHook("preHandler", async (req) => {
      if (req.headers["x-test-hold"] === "1") {
        await held;
      }
    });

    try {
      const inFlight = app.inject({
        method: "POST",
        url: "/evaluate",
        headers: { "x-test-hold": "1" },
        payload: OPENAI_REQUEST,
      });

      // Let the held request reach the preHandler before anything reloads.
      await new Promise<void>((resolve) => setImmediate(resolve));

      fs.writeFileSync(policyPath, DENY_RULE);
      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });
      expect(report.ok).toBe(true);
      expect(report.policy.applied).toBe(true);

      release();
      const response = await inFlight;

      // Started under the allow ruleset, so it finishes under it.
      expect(response.json().decision).toBe("allow");
      expect(response.json().matchedRules).toContain("custom:allow-openai");

      // And the very next request gets the new one, so this is isolation and not a stuck engine.
      const next = await app.inject({ method: "POST", url: "/evaluate", payload: OPENAI_REQUEST });
      expect(next.json().decision).toBe("deny");
    } finally {
      release();
      await app.close();
    }
  });

  it("holds a captured snapshot across a reload while the engine moves on", () => {
    const engine = new PolicyEngine([], "deny");
    const pinned = engine.snapshot();

    engine.replaceRules([
      {
        id: "later:allow-all",
        description: "Allow",
        plane: "all",
        match: () => true,
        decision: "allow",
        riskLevel: "low",
        reason: "added after the snapshot was taken",
      },
    ]);

    const ctx = { agentId: "a", plane: "network" as const, action: "http_request", payload: {} };
    expect(pinned.evaluate(ctx).decision).toBe("deny");
    expect(engine.evaluate(ctx).decision).toBe("allow");
    expect(engine.snapshot().version).toBeGreaterThan(pinned.version);
  });

  it("bumps the snapshot version when only defaultDecision changes", async () => {
    const { policyPath, configPath, config } = setup(ALLOW_RULE);
    const { app, engine, reloadCoordinator } = await buildServer(config);

    try {
      const versionBefore = engine.snapshot().version;
      // Same policy path, so defaultDecision is the ONLY thing that changed.
      writeConfig(configPath, policyPath, { policy: { defaultDecision: "allow", configPath: policyPath } });

      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });
      expect(report.ok).toBe(true);
      expect(report.config.applied).toContain("policy.defaultDecision");
      // A request that matches no rule now gets a different answer, so it is a different policy
      // even though no rule moved.
      expect(engine.snapshot().version).toBeGreaterThan(versionBefore);

      const unmatched = await app.inject({
        method: "POST",
        url: "/evaluate",
        payload: { ...OPENAI_REQUEST, payload: { url: "https://unmatched.example.com/" } },
      });
      expect(unmatched.json().decision).toBe("allow");
    } finally {
      await app.close();
    }
  });
});

describe("reload is recorded on the audit chain", () => {
  it("chains a record carrying both file hashes, the rule diff, and who triggered it", async () => {
    const { policyPath, config } = setup(ALLOW_RULE);
    const { app, reloadCoordinator } = await buildServer(config);
    const captured = captureAudit();

    try {
      fs.writeFileSync(policyPath, DENY_RULE);
      const report = reloadCoordinator.reload({
        source: "api",
        operatorId: "op-42",
        reason: "rotating the openai rule",
      });
      expect(report.ok).toBe(true);
      expect(report.audit.recorded).toBe(true);

      const records = captured.filter((event) => event.action === "config:reload");
      expect(records).toHaveLength(1);
      const record = records[0];

      // Who.
      expect(record.metadata?.reloadSource).toBe("api");
      expect(record.metadata?.reloadOperator).toBe("op-42");
      expect(record.metadata?.reloadReason).toBe("rotating the openai rule");

      // What changed, at the rule level.
      expect(record.metadata?.policyRulesAdded).toBe("custom:deny-openai");
      expect(record.metadata?.policyRulesRemoved).toBe("custom:allow-openai");
      expect(record.metadata?.policyRulesModified).toBe("none");

      // Old and new hash, for both files, and they are real digests of the real bytes.
      const policyHashAfter = record.metadata?.policyHashAfter;
      expect(policyHashAfter).toMatch(/^[0-9a-f]{64}$/);
      expect(record.metadata?.policyHashBefore).toMatch(/^[0-9a-f]{64}$/);
      expect(record.metadata?.policyHashBefore).not.toBe(policyHashAfter);
      expect(policyHashAfter).toBe(report.policy.hashAfter);
      expect(record.metadata?.configHashBefore).toMatch(/^[0-9a-f]{64}$/);
      // This reload did not touch the config file, so its two hashes agree. The test below proves
      // they DIVERGE when it does change, which is the assertion that matters: hashing the file
      // twice at reload time would satisfy this line and be wrong.
      expect(record.metadata?.configHashAfter).toBe(record.metadata?.configHashBefore);

      // It is chained, not merely emitted.
      expect(record.integrity).toBeDefined();
      expect(record.plane).toBe("governance");
      expect(record.decision).toBe("allow");
    } finally {
      await app.close();
    }
  });

  it("reports the previously adopted config hash, not the edited file hashed twice", async () => {
    // Regression guard, found by driving a real process rather than by this suite. An operator
    // edits the config file and THEN triggers a reload, so reading the file at reload time to
    // fill both slots put the NEW hash in `configHashBefore` and reported a change as if nothing
    // had moved. The before-hash has to be remembered from when the values went into force.
    const { policyPath, configPath, config } = setup(ALLOW_RULE);
    const { app, reloadCoordinator } = await buildServer(config);
    const captured = captureAudit();

    try {
      const hashAtBoot = reloadCoordinator.state().config.hash;
      writeConfig(configPath, policyPath, { logLevel: "warn" });

      // Saved but not reloaded: in force and on disk now disagree, and GET /reload says so.
      const pending = reloadCoordinator.state().config;
      expect(pending.hash).toBe(hashAtBoot);
      expect(pending.hashOnDisk).not.toBe(hashAtBoot);

      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });
      expect(report.ok).toBe(true);
      expect(report.config.hashBefore).toBe(hashAtBoot);
      expect(report.config.hashAfter).not.toBe(hashAtBoot);

      const record = captured.filter((event) => event.action === "config:reload")[0];
      expect(record.metadata?.configHashBefore).toBe(hashAtBoot);
      expect(record.metadata?.configHashAfter).not.toBe(hashAtBoot);
      expect(record.metadata?.configHashAfter).toMatch(/^[0-9a-f]{64}$/);

      // Adopted, so the next reload's before-hash is this one and the two views agree again.
      const settled = reloadCoordinator.state().config;
      expect(settled.hash).toBe(report.config.hashAfter);
      expect(settled.hashOnDisk).toBe(settled.hash);
    } finally {
      await app.close();
    }
  });

  it("records a rejected reload as a denied change and keeps the refused hash out of the after slot", async () => {
    const { policyPath, config } = setup(DENY_RULE);
    const { app, reloadCoordinator } = await buildServer(config);
    const captured = captureAudit();

    try {
      fs.writeFileSync(policyPath, "rules: [ this is not valid\n");
      const report = reloadCoordinator.reload({ source: "sighup" });
      expect(report.ok).toBe(false);

      const records = captured.filter((event) => event.action === "config:reload");
      expect(records).toHaveLength(1);
      expect(records[0].decision).toBe("deny");
      expect(records[0].riskLevel).toBe("high");
      expect(records[0].metadata?.reloadOutcome).toBe("rejected");
      // No identity is invented for a signal.
      expect(records[0].metadata?.reloadOperator).toBe("none");
      expect(records[0].metadata?.policyError).toBeDefined();
    } finally {
      await app.close();
    }
  });

  it("reports loudly instead of silently when the durable sink refuses the record", async () => {
    const { policyPath, config } = setup(ALLOW_RULE);
    const { app, reloadCoordinator } = await buildServer(config);

    resetAuditChain();
    seedAuditChain({ chainIndex: 0, previousHash: null });
    // A durable sink that refuses everything, standing in for a full partition.
    registerAuditSink(() => {
      throw new Error("no space left on device");
    }, { durable: true });

    try {
      fs.writeFileSync(policyPath, DENY_RULE);
      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });

      // The reload still happened: evidence is not a precondition for an operator fixing policy.
      expect(report.ok).toBe(true);
      expect(report.policy.applied).toBe(true);
      const after = await app.inject({ method: "POST", url: "/evaluate", payload: OPENAI_REQUEST });
      expect(after.json().decision).toBe("deny");

      // And it says so, in the response, where a caller cannot miss it.
      expect(report.audit.recorded).toBe(false);
      expect(report.audit.eventId).toBeNull();
      expect(report.warnings.some((warning) => warning.includes("NOT on the audit chain"))).toBe(true);
    } finally {
      await app.close();
    }
  });
});

describe("config keys a running process cannot apply are named, not pretended", () => {
  it("applies logLevel and reports egress and enforcement changes as restart-required", async () => {
    const { policyPath, configPath, config } = setup(ALLOW_RULE);
    const { app, reloadCoordinator } = await buildServer(config);

    try {
      writeConfig(configPath, policyPath, {
        logLevel: "warn",
        enforcement: { mode: "strict" },
        egress: {
          enabled: true,
          defaultDeny: true,
          allowPrivateRanges: false,
          allowedHosts: ["api.anthropic.com"],
          allowedSchemes: ["https"],
          allowedPorts: [443],
        },
      });

      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });
      expect(report.ok).toBe(true);
      expect(report.config.applied).toEqual(["logLevel"]);
      expect(app.log.level).toBe("warn");
      // Named, not applied. These are captured at boot by the proxies.
      expect(report.config.restartRequired).toContain("enforcement.mode");
      expect(report.config.restartRequired).toContain("egress.allowedHosts");
      expect(report.warnings.some((warning) => warning.includes("cannot apply"))).toBe(true);
      // The live config still reports what is actually in force, not what the file says.
      expect(config.enforcement?.mode).not.toBe("strict");
    } finally {
      await app.close();
    }
  });

  it("refuses a log level pino would throw on, before the policy is touched", async () => {
    const { policyPath, configPath, config } = setup(ALLOW_RULE);
    const { app, reloadCoordinator } = await buildServer(config);

    try {
      fs.writeFileSync(policyPath, DENY_RULE);
      writeConfig(configPath, policyPath, { logLevel: "chatty" });

      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });
      expect(report.ok).toBe(false);
      expect(report.config.error).toContain("invalid logLevel");
      expect(report.policy.applied).toBe(false);

      // The policy file changed on disk and was NOT applied, because phase 1 refused first.
      const after = await app.inject({ method: "POST", url: "/evaluate", payload: OPENAI_REQUEST });
      expect(after.json().decision).toBe("allow");
    } finally {
      await app.close();
    }
  });

  it("reports an unchanged reload as unchanged rather than as a change", async () => {
    const { config } = setup(ALLOW_RULE);
    const { app, reloadCoordinator } = await buildServer(config);
    const captured = captureAudit();

    try {
      const report = reloadCoordinator.reload({ source: "api", operatorId: "op-1" });
      expect(report.ok).toBe(true);
      expect(report.policy.applied).toBe(false);
      expect(report.config.applied).toEqual([]);
      expect(report.config.restartRequired).toEqual([]);

      const records = captured.filter((event) => event.action === "config:reload");
      expect(records[0].metadata?.reloadOutcome).toBe("unchanged");
      expect(records[0].riskLevel).toBe("low");
    } finally {
      await app.close();
    }
  });
});

describe("reload API surface", () => {
  let savedLoopback: string | undefined;
  let savedToken: string | undefined;

  beforeEach(() => {
    savedLoopback = process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
    savedToken = process.env.AGENTWALL_OPERATOR_TOKEN;
  });

  afterEach(() => {
    if (savedLoopback === undefined) delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
    else process.env.AGENTWALL_ALLOW_LOOPBACK_DEV = savedLoopback;
    if (savedToken === undefined) delete process.env.AGENTWALL_OPERATOR_TOKEN;
    else process.env.AGENTWALL_OPERATOR_TOKEN = savedToken;
  });

  it("reloads through POST /reload and records the authenticated operator", async () => {
    const { policyPath, config } = setup(ALLOW_RULE);
    const { app } = await buildServer(config);
    const captured = captureAudit();

    try {
      fs.writeFileSync(policyPath, DENY_RULE);
      const response = await app.inject({
        method: "POST",
        url: "/reload",
        payload: { reason: "swapping the openai rule" },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json().ok).toBe(true);
      expect(response.json().policy.diff.added).toEqual(["custom:deny-openai"]);

      const records = captured.filter((event) => event.action === "config:reload");
      expect(records).toHaveLength(1);
      expect(records[0].metadata?.reloadSource).toBe("api");
      // tests/setup-env.ts enables loopback dev, so the principal is the loopback identity
      // rather than a token subject. Either way it is the auth layer's id, never a body field.
      expect(records[0].metadata?.reloadOperator).not.toBe("none");

      const after = await app.inject({ method: "POST", url: "/evaluate", payload: OPENAI_REQUEST });
      expect(after.json().decision).toBe("deny");
    } finally {
      await app.close();
    }
  });

  it("answers 400 with the full report when the file on disk is refused", async () => {
    const { policyPath, config } = setup(DENY_RULE);
    const { app } = await buildServer(config);

    try {
      fs.writeFileSync(policyPath, "rules: [ broken\n");
      const response = await app.inject({ method: "POST", url: "/reload", payload: {} });

      expect(response.statusCode).toBe(400);
      expect(response.json().ok).toBe(false);
      expect(response.json().policy.error).toBeDefined();
      expect(response.json().policy.applied).toBe(false);
    } finally {
      await app.close();
    }
  });

  it("rejects a body field it does not implement rather than ignoring it", async () => {
    const { config } = setup(ALLOW_RULE);
    const { app } = await buildServer(config);

    try {
      // An operator asking for a partial reload must be told it is not a thing, not handed a 200
      // for something else.
      const response = await app.inject({ method: "POST", url: "/reload", payload: { policyOnly: true } });
      expect(response.statusCode).toBe(400);
      expect(response.json().error).toBe("Invalid reload request");
    } finally {
      await app.close();
    }
  });

  it("reports what a reload can and cannot change through GET /reload", async () => {
    const { policyPath, configPath, config } = setup(ALLOW_RULE);
    const { app } = await buildServer(config);

    try {
      const response = await app.inject({ method: "GET", url: "/reload" });
      expect(response.statusCode).toBe(200);
      const state = response.json();
      expect(state.policy.path).toBe(policyPath);
      expect(state.policy.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(state.policy.ruleCount).toBeGreaterThan(0);
      expect(state.config.path).toBe(configPath);
      expect(state.config.liveAppliableKeys).toEqual(["logLevel", "policy.defaultDecision"]);
    } finally {
      await app.close();
    }
  });

  it("requires the operator token", async () => {
    delete process.env.AGENTWALL_ALLOW_LOOPBACK_DEV;
    process.env.AGENTWALL_OPERATOR_TOKEN = "reload-suite-token";

    const { config } = setup(ALLOW_RULE);
    const { app } = await buildServer(config);

    try {
      const anonymous = await app.inject({ method: "POST", url: "/reload", payload: {} });
      expect(anonymous.statusCode).toBe(401);

      const authenticated = await app.inject({
        method: "POST",
        url: "/reload",
        headers: { authorization: "Bearer reload-suite-token" },
        payload: {},
      });
      expect(authenticated.statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });
});

describe("SIGHUP", () => {
  it("reloads on the signal and removes its handler on dispose", async () => {
    const { policyPath, config } = setup(ALLOW_RULE);
    const { app, reloadCoordinator } = await buildServer(config);
    const before = process.listenerCount("SIGHUP");

    try {
      reloadCoordinator.installSignalHandler();
      expect(process.listenerCount("SIGHUP")).toBe(before + 1);
      // Idempotent: a second call must not stack a listener that would reload twice per signal.
      reloadCoordinator.installSignalHandler();
      expect(process.listenerCount("SIGHUP")).toBe(before + 1);

      fs.writeFileSync(policyPath, DENY_RULE);
      process.emit("SIGHUP");

      const report = reloadCoordinator.getLastReport();
      expect(report?.source).toBe("sighup");
      expect(report?.ok).toBe(true);
      expect(report?.policy.diff.added).toEqual(["custom:deny-openai"]);

      const after = await app.inject({ method: "POST", url: "/evaluate", payload: OPENAI_REQUEST });
      expect(after.json().decision).toBe("deny");
    } finally {
      await app.close();
      // buildServer's onClose disposes the coordinator, so the listener must be gone.
      expect(process.listenerCount("SIGHUP")).toBe(before);
    }
  });
});
