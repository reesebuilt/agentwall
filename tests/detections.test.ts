import { afterAll, describe, expect, it } from "@jest/globals";
import { buildServer } from "../src/server";
import { AgentwallConfig } from "../src/config";

const config: AgentwallConfig = {
  port: 3000,
  host: "127.0.0.1",
  logLevel: "silent",
  approval: {
    mode: "auto",
    timeoutMs: 5_000,
    backend: "memory",
  },
  policy: {
    defaultDecision: "deny",
  },
  dlp: {
    enabled: true,
    redactSecrets: true,
  },
  egress: {
    enabled: true,
    defaultDeny: true,
    allowPrivateRanges: false,
    allowedHosts: ["api.openai.com"],
    allowedSchemes: ["https"],
    allowedPorts: [443],
  },
  manifestIntegrity: {
    enabled: true,
  },
  watchdog: {
    enabled: true,
    staleAfterMs: 15_000,
    timeoutMs: 30_000,
    killSwitchMode: "deny_all",
  },
};

describe("Detection surfaces", () => {
  const serverPromise = buildServer(config);

  afterAll(async () => {
    const { app } = await serverPromise;
    await app.close();
  });

  it("returns mapped detection metadata via /detections", async () => {
    const { app } = await serverPromise;

    const response = await app.inject({ method: "GET", url: "/detections" });
    expect(response.statusCode).toBe(200);

    const payload = response.json();
    expect(payload.count).toBeGreaterThan(0);
    expect(payload.detections.some((d: { ruleId: string }) => d.ruleId === "net:block-ssrf-private")).toBe(true);
    expect(payload.detections.some((d: { mitreAttack?: { techniqueId?: string } }) => Boolean(d.mitreAttack?.techniqueId))).toBe(true);
  });

  it("returns detections in /evaluate responses for matched rules", async () => {
    const { app } = await serverPromise;

    const response = await app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "det-agent",
        plane: "network",
        action: "http_request",
        payload: { url: "http://127.0.0.1/admin" },
      },
    });

    expect(response.statusCode).toBe(200);
    const payload = response.json();
    expect(Array.isArray(payload.detections)).toBe(true);
    expect(payload.detections.length).toBeGreaterThan(0);
  });
});
