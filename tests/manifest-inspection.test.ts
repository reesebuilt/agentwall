import { afterEach, describe, expect, it } from "@jest/globals";
import { AgentwallConfig } from "../src/config";
import { createManifestAttestation, hashManifest } from "../src/integrity/manifest";
import { buildServer } from "../src/server";

const config: AgentwallConfig = {
  port: 3019,
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

describe("Manifest inspection route", () => {
  let server: Awaited<ReturnType<typeof buildServer>> | undefined;

  afterEach(async () => {
    if (server) {
      await server.app.close();
      server = undefined;
    }
  });

  it("returns trust state and records manifest inspection evidence for operators", async () => {
    server = await buildServer(config);

    const subjectId = "tool:write_file";
    const subjectType = "tool" as const;
    const manifest = {
      name: "write_file",
      description: "Write a file to disk",
      inputs: ["path", "content"],
    };
    const approvedFingerprint = hashManifest(manifest, "operator-registry");
    approvedFingerprint.approvedAt = new Date().toISOString();
    approvedFingerprint.attestation = createManifestAttestation({
      subjectId,
      subjectType,
      fingerprint: approvedFingerprint,
      signer: "agentwall-operator",
    });

    const response = await server.app.inject({
      method: "POST",
      url: "/inspect/manifest",
      payload: {
        subjectId,
        subjectType,
        manifest,
        approvedFingerprint,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(
      expect.objectContaining({
        subjectId,
        subjectType,
        status: "approved",
        trustState: "trusted",
        attestation: expect.objectContaining({
          status: "valid",
          signer: "agentwall-operator",
        }),
      })
    );

    const dashboard = await server.app.inject({ method: "GET", url: "/api/dashboard/state" });
    const state = dashboard.json();

    expect(
      state.eventFeed.some(
        (item: { title?: string; detail?: { subjectId?: string; trustState?: string; attestationStatus?: string } }) =>
          item.title === "Manifest trust inspection" &&
          item.detail?.subjectId === subjectId &&
          item.detail?.trustState === "trusted" &&
          item.detail?.attestationStatus === "valid"
      )
    ).toBe(true);
    expect(
      state.evidenceLedger.some(
        (item: { title?: string; attributes?: { subjectId?: string; trustState?: string; attestationStatus?: string } }) =>
          item.title === "Manifest trust inspection" &&
          item.attributes?.subjectId === subjectId &&
          item.attributes?.trustState === "trusted" &&
          item.attributes?.attestationStatus === "valid"
      )
    ).toBe(true);
  });
});
