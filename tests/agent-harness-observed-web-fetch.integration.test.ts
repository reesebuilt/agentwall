import * as http from "http";
import { afterEach, describe, expect, it } from "@jest/globals";
import { buildServer } from "../src/server";
import { AgentwallConfig } from "../src/config";
import { createObservedWebFetch, HarnessPreflightEvent } from "../src/integrations/agent-harness/web-fetch-egress";

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
    allowedHosts: ["127.0.0.1", "api.openai.com"],
    allowedSchemes: ["http", "https"],
    allowedPorts: [80, 443],
  },
  manifestIntegrity: { enabled: true },
  watchdog: { enabled: false, staleAfterMs: 5000, timeoutMs: 5000, killSwitchMode: "monitor" },
};

describe("agent-harness observed web fetch egress wiring", () => {
  const started: Array<Awaited<ReturnType<typeof buildServer>>["app"]> = [];
  const rawServers: http.Server[] = [];

  afterEach(async () => {
    await Promise.all(started.splice(0).map((app) => app.close()));
    await Promise.all(
      rawServers.splice(0).map(
        (server) =>
          new Promise<void>((resolve, reject) => {
            server.close((error) => (error ? reject(error) : resolve()));
          })
      )
    );
  });

  it("runs real outbound HTTP through preflight in observe mode (fail-open safe)", async () => {
    const events: HarnessPreflightEvent[] = [];

    const targetServer = http.createServer((_, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hello-observe");
    });
    rawServers.push(targetServer);
    await new Promise<void>((resolve) => targetServer.listen(0, "127.0.0.1", () => resolve()));
    const targetAddress = targetServer.address();
    if (!targetAddress || typeof targetAddress === "string") {
      throw new Error("Unexpected target server address");
    }

    const { app } = await buildServer(baseConfig);
    started.push(app);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    if (!address || typeof address === "string") {
      throw new Error("Unexpected Agentwall listen address");
    }

    const observedFetch = createObservedWebFetch({
      agentwallUrl: `http://127.0.0.1:${address.port}`,
      rolloutMode: "observe",
      actor: { agentId: "agent-1", sessionId: "session-observe" },
      onEvent: (event) => events.push(event),
    });

    const result = await observedFetch.fetch(`http://127.0.0.1:${targetAddress.port}/hello`);

    expect(result.status).toBe(200);
    expect(result.text).toBe("hello-observe");
    expect(result.preflight.networkFailOpen).toBe(false);
    expect(result.preflight.policyFailOpen).toBe(false);
    expect(events.some((event) => event.kind === "network.inspect")).toBe(true);
    expect(events.some((event) => event.kind === "policy.evaluate")).toBe(true);
    expect(
      events.some((event) => event.kind === "outbound.execute" && String(event.payload.phase) === "allow")
    ).toBe(true);
  });

  it("preserves fail-open behavior when Agentwall is unavailable", async () => {
    const targetServer = http.createServer((_, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hello-fail-open");
    });
    rawServers.push(targetServer);
    await new Promise<void>((resolve) => targetServer.listen(0, "127.0.0.1", () => resolve()));
    const targetAddress = targetServer.address();
    if (!targetAddress || typeof targetAddress === "string") {
      throw new Error("Unexpected target server address");
    }

    const observedFetch = createObservedWebFetch({
      agentwallUrl: "http://127.0.0.1:1",
      rolloutMode: "observe",
      timeoutMs: 50,
      actor: { agentId: "agent-1", sessionId: "session-fail-open" },
    });

    const result = await observedFetch.fetch(`http://127.0.0.1:${targetAddress.port}/hello`);

    expect(result.status).toBe(200);
    expect(result.text).toBe("hello-fail-open");
    expect(result.preflight.networkFailOpen).toBe(true);
    expect(result.preflight.policyFailOpen).toBe(true);
  });
});
