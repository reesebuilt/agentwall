import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { buildServer } from "../src/server";
import { AgentwallConfig } from "../src/config";
import { HarnessPreflightAdapter } from "../src/integrations/agent-harness/preflight";

const baseConfig: AgentwallConfig = {
  port: 0,
  host: "127.0.0.1",
  logLevel: "silent",
  approval: { mode: "never", timeoutMs: 1000, backend: "memory" },
  policy: { defaultDecision: "deny" },
  dlp: { enabled: true, redactSecrets: true },
  egress: {
    enabled: true,
    defaultDeny: true,
    allowPrivateRanges: false,
    allowedHosts: ["api.openai.com"],
    allowedSchemes: ["https"],
    allowedPorts: [443],
  },
  manifestIntegrity: { enabled: true },
  watchdog: { enabled: false, staleAfterMs: 5000, timeoutMs: 5000, killSwitchMode: "monitor" },
};

describe("agent-harness preflight adapter (monitor-first)", () => {
  const started: Array<Awaited<ReturnType<typeof buildServer>>["app"]> = [];

  afterEach(async () => {
    await Promise.all(started.splice(0).map((app) => app.close()));
  });

  it("observes deny responses but still executes in observe mode", async () => {
    const { app } = await buildServer(baseConfig);
    started.push(app);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    if (!address || typeof address === "string") {
      throw new Error("Unexpected listen address");
    }

    const adapter = new HarnessPreflightAdapter({
      agentwallUrl: `http://127.0.0.1:${address.port}`,
      rolloutMode: "observe",
    });

    const execute = jest.fn(async () => "ok");
    const output = await adapter.runOutbound({
      networkRequest: { url: "http://169.254.169.254/latest/meta-data/" },
      context: {
        agentId: "agent-1",
        sessionId: "s1",
        plane: "tool",
        action: "exec",
        payload: { command: "curl http://169.254.169.254/latest/meta-data/" },
      },
      execute,
    });

    expect(output.blocked).toBe(false);
    expect(output.result).toBe("ok");
    expect(execute).toHaveBeenCalledTimes(1);
    expect(output.network.inspection?.allowed).toBe(false);
    expect(output.network.failOpen).toBe(false);
    expect(output.policy.evaluation?.decision).toBe("approve");
  });

  it("fails open when Agentwall is unavailable", async () => {
    const adapter = new HarnessPreflightAdapter({
      agentwallUrl: "http://127.0.0.1:1",
      rolloutMode: "observe",
      timeoutMs: 50,
    });

    const execute = jest.fn(async () => "still-runs");
    const output = await adapter.runOutbound({
      networkRequest: { url: "https://api.openai.com/v1/chat/completions" },
      context: {
        agentId: "agent-1",
        plane: "network",
        action: "web_fetch",
        payload: { url: "https://api.openai.com/v1/chat/completions" },
      },
      execute,
    });

    expect(output.blocked).toBe(false);
    expect(output.result).toBe("still-runs");
    expect(output.network.failOpen).toBe(true);
    expect(output.policy.failOpen).toBe(true);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("can enforce critical network blocks when rolloutMode=enforce_critical", async () => {
    const { app } = await buildServer(baseConfig);
    started.push(app);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    if (!address || typeof address === "string") {
      throw new Error("Unexpected listen address");
    }

    const adapter = new HarnessPreflightAdapter({
      agentwallUrl: `http://127.0.0.1:${address.port}`,
      rolloutMode: "enforce_critical",
    });

    const execute = jest.fn(async () => "should-not-run");
    const output = await adapter.runOutbound({
      networkRequest: { url: "http://169.254.169.254/latest/meta-data/" },
      context: {
        agentId: "agent-1",
        plane: "network",
        action: "web_fetch",
        payload: { url: "http://169.254.169.254/latest/meta-data/" },
      },
      execute,
    });

    expect(output.blocked).toBe(true);
    expect(output.result).toBeUndefined();
    expect(execute).not.toHaveBeenCalled();
    expect(output.network.reason).toContain("Blocked by Agentwall critical network preflight");
  });
});
