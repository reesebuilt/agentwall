import { afterAll, describe, expect, it } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { AgentwallConfig } from "../src/config";
import { buildServer } from "../src/server";
import { analyzeCommand } from "../src/integrations/damage-control/command-firewall";

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-damage-control-"));
const policyPath = path.join(tempDir, "policy.yaml");
fs.writeFileSync(policyPath, "version: '1'\nrules: []\n");

const config: AgentwallConfig = {
  port: 3000,
  host: "127.0.0.1",
  logLevel: "silent",
  dashboard: {},
  approval: {
    mode: "auto",
    timeoutMs: 30_000,
    backend: "memory",
  },
  policy: {
    defaultDecision: "deny",
    configPath: policyPath,
  },
  dlp: {
    enabled: true,
    redactSecrets: true,
  },
  egress: {
    enabled: true,
    defaultDeny: true,
    allowPrivateRanges: false,
    allowedHosts: [],
    allowedSchemes: ["https"],
    allowedPorts: [443],
  },
  manifestIntegrity: {
    enabled: true,
  },
  watchdog: {
    enabled: false,
    staleAfterMs: 15_000,
    timeoutMs: 30_000,
    killSwitchMode: "deny_all",
  },
};

describe("damage-control command-firewall analyzer", () => {
  it("allows an exact safe whitelist command (git status)", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "git status", mode: "whitelist" });
    expect(analysis.decision).toBe("allow");
    expect(analysis.matchedSignals).toContain("whitelist:exact-match");
    expect(analysis.recommendedLevel).toBe("L4");
  });

  it("denies rm -rf in whitelist mode", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "rm -rf /", mode: "whitelist" });
    expect(analysis.decision).toBe("deny");
    expect(analysis.matchedSignals.some((sig) => sig.startsWith("destructive:rm-rf"))).toBe(true);
    expect(analysis.riskLevel).toBe("critical");
  });

  it("denies split recursive force rm flags in blacklist mode", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "rm -r -f /tmp/agentwall", mode: "blacklist" });
    expect(analysis.decision).toBe("deny");
    expect(analysis.matchedSignals).toContain("destructive:rm-rf");
    expect(analysis.riskLevel).toBe("critical");
  });

  it("denies long recursive force rm flags in blacklist mode", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "rm --recursive --force /tmp/agentwall", mode: "blacklist" });
    expect(analysis.decision).toBe("deny");
    expect(analysis.matchedSignals).toContain("destructive:rm-rf");
    expect(analysis.riskLevel).toBe("critical");
  });

  it("denies compound operator in whitelist mode", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "git status && rm -rf .", mode: "whitelist" });
    expect(analysis.decision).toBe("deny");
    expect(analysis.matchedSignals).toContain("compound:and");
    expect(analysis.bypassNotes.join(" ")).toContain("compound");
  });

  it("denies python script as a write-code-then-execute bypass in whitelist mode", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "python cleanup.py", mode: "whitelist" });
    expect(analysis.decision).toBe("deny");
    expect(analysis.matchedSignals).toContain("interpreter:script");
    expect(analysis.bypassNotes.join(" ")).toMatch(/write-code-then-execute/i);
  });

  it("denies obvious destructive commands in blacklist mode", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "terraform destroy", mode: "blacklist" });
    expect(analysis.decision).toBe("deny");
    expect(analysis.matchedSignals).toContain("destructive:terraform-destroy");
    expect(analysis.bypassNotes.join(" ")).toMatch(/bypassable/i);
  });

  it("approves ambiguous interpreter use in blacklist mode", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "node script.js", mode: "blacklist" });
    expect(analysis.decision).toBe("approve");
    expect(analysis.matchedSignals).toContain("interpreter:script");
  });

  it("denies everything in no_bash mode", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "ls", mode: "no_bash" });
    expect(analysis.decision).toBe("deny");
    expect(analysis.recommendedLevel).toBe("L5");
    expect(analysis.matchedSignals).toContain("mode:no-bash");
  });

  it("monitor mode reports but allows", () => {
    const analysis = analyzeCommand({ agentId: "test", command: "rm -rf /", mode: "monitor" });
    expect(analysis.decision).toBe("allow");
    expect(analysis.matchedSignals.some((sig) => sig.startsWith("destructive:"))).toBe(true);
    expect(analysis.reasons.join(" ")).toMatch(/whitelist mode would have returned 'deny'/i);
  });

  it("honors custom allowedCommands list", () => {
    const analysis = analyzeCommand({
      agentId: "test",
      command: "ls -la",
      mode: "whitelist",
      allowedCommands: ["ls -la"],
    });
    expect(analysis.decision).toBe("allow");
    expect(analysis.reasons.join(" ")).not.toContain("ls -la");
  });
});

describe("damage-control route + dashboard", () => {
  const serverPromise = buildServer(config);

  afterAll(async () => {
    const { app } = await serverPromise;
    await app.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("preflight emits an audit and surfaces analysis + combined decision", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/integrations/damage-control/command-preflight",
      payload: {
        agentId: "dashboard-damage-control",
        command: "rm -rf /",
        mode: "whitelist",
      },
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.ok).toBe(true);
    expect(body.analysis.decision).toBe("deny");
    expect(body.combined.decision).toBe("deny");
    expect(body.delivery.executionAllowed).toBe(false);
    expect(body.audit?.eventId).toBeTruthy();
    expect(body.policy).toBeDefined();
  });

  it("combines analyzer + policy by most restrictive decision (monitor allow stays gated by policy approve)", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/integrations/damage-control/command-preflight",
      payload: {
        agentId: "dashboard-damage-control",
        command: "rm -rf /",
        mode: "monitor",
      },
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.analysis.decision).toBe("allow");
    expect(["approve", "deny"]).toContain(body.combined.decision);
    expect(body.delivery.executionAllowed).toBe(false);
  });

  it("returns 400 on invalid input", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/integrations/damage-control/command-preflight",
      payload: { command: "" },
    });
    expect(response.statusCode).toBe(400);
  });

  it("/api/dashboard/state exposes the damageControl ladder and endpoint", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({ method: "GET", url: "/api/dashboard/state" });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.damageControl).toBeDefined();
    expect(body.damageControl.endpoint).toBe("/integrations/damage-control/command-preflight");
    expect(body.damageControl.recommendedLevel).toBe("L4");
    const levels = body.damageControl.ladder.map((entry: { level: string }) => entry.level);
    expect(levels).toEqual(["L1", "L2", "L3", "L4", "L5"]);
    expect(Array.isArray(body.damageControl.recentAudits)).toBe(true);
  });

  it("dashboard shell exposes the operator and evidence surfaces", async () => {
    const { app } = await serverPromise;
    const html = await app.inject({ method: "GET", url: "/" });
    expect(html.statusCode).toBe(200);
    expect(html.body).toContain("Agentwall status");
    expect(html.body).toContain("Evidence");
    expect(html.body).toContain("Operations");
    expect(html.body).toContain('aria-live="polite"');

    const js = await app.inject({ method: "GET", url: "/app.js" });
    expect(js.statusCode).toBe(200);
    expect(js.body).toContain("function renderEvidence");
    expect(js.body).toContain("/api/operator/actions");
    expect(js.body).toContain("function renderOperatorAction");
  });
});
