import { describe, expect, it } from "@jest/globals";
import {
  buildGatewayId,
  buildOrganizationControlPlaneSnapshot,
  buildOrganizationFederationSummaryPayload,
  inferGatewayKind,
} from "../src/org/control-plane";
import {
  mergeOrganizationControlPlaneSnapshots,
  pollOrganizationPeerSummaries,
  validateOrganizationFederationSummaryPayload,
} from "../src/org/federation";

const now = "2026-04-30T14:20:00.000Z";

describe("organization control plane", () => {
  it("infers gateway kind from normalized channel ids", () => {
    expect(inferGatewayKind("telegram:-100:1199")).toBe("telegram");
    expect(inferGatewayKind("slack:T123:C456")).toBe("slack");
    expect(inferGatewayKind("discord:guild:channel")).toBe("discord");
    expect(inferGatewayKind("api:tenant:gateway")).toBe("api");
    expect(inferGatewayKind("custom:lane")).toBe("unknown");
    expect(buildGatewayId("instance-a", "slack")).toBe("instance-a:slack");
  });

  it("summarizes one single-pane view across agents, gateways, and channels", () => {
    const snapshot = buildOrganizationControlPlaneSnapshot({
      now,
      localInstance: {
        id: "instance-a-agentwall",
        name: "Instance A Agentwall",
        url: "http://127.0.0.1:3015",
        environment: "local",
      },
      configuredInstances: [
        {
          id: "prod-east",
          name: "Prod East Agentwall",
          url: "https://agentwall-prod-east.example.com",
          role: "remote",
          status: "unknown",
          environment: "prod",
        },
      ],
      observedChannels: [
        {
          agentId: "sales-agent",
          channelId: "slack:T123:C456",
          lastSeenAt: "2026-04-30T14:10:00.000Z",
          lastPlane: "tool",
          lastAction: "crm_update",
          riskLevel: "medium",
          sessionIds: ["session-sales"],
          userIds: ["slack:U111"],
          roleIds: ["sales"],
        },
        {
          agentId: "soc-agent",
          channelId: "telegram:-100:593",
          lastSeenAt: "2026-04-30T14:11:00.000Z",
          lastPlane: "identity",
          lastAction: "credential_lookup",
          riskLevel: "critical",
          sessionIds: ["session-soc"],
          userIds: ["telegram:123456789"],
          roleIds: ["operator"],
        },
      ],
    });

    expect(snapshot.summary).toEqual({
      instances: 2,
      gateways: 2,
      agents: 2,
      channels: 2,
      configuredInstances: 1,
      observedChannels: 2,
    });
    expect(snapshot.instances[0]).toEqual(expect.objectContaining({ id: "instance-a-agentwall", role: "local", status: "online" }));
    expect(snapshot.gateways).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "instance-a-agentwall:slack", kind: "slack", channelCount: 1, agentCount: 1 }),
        expect.objectContaining({ id: "instance-a-agentwall:telegram", kind: "telegram", channelCount: 1, agentCount: 1 }),
      ])
    );
    expect(snapshot.agents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ agentId: "soc-agent", highestRisk: "critical", channelIds: ["telegram:-100:593"] }),
        expect.objectContaining({ agentId: "sales-agent", highestRisk: "medium", channelIds: ["slack:T123:C456"] }),
      ])
    );
  });

  it("builds a safe federation summary payload around the local org snapshot", () => {
    const snapshot = buildOrganizationControlPlaneSnapshot({
      now,
      localInstance: {
        id: "local-agentwall",
        name: "Local Agentwall",
        url: "http://operator:secret@127.0.0.1:3015?token=hidden#fragment",
      },
      observedChannels: [
        {
          agentId: "ops-agent",
          channelId: "telegram:-100:42",
          lastSeenAt: now,
          lastPlane: "tool",
          lastAction: "status_check",
          riskLevel: "low",
          sessionIds: ["session-ops"],
          userIds: ["telegram:operator"],
          roleIds: ["operator"],
        },
      ],
    });

    const payload = buildOrganizationFederationSummaryPayload(now, snapshot);

    expect(payload).toMatchObject({
      schemaVersion: "agentwall.org.summary.v1",
      generatedAt: now,
      instance: { id: "local-agentwall", role: "local", status: "online", url: "http://127.0.0.1:3015" },
      capabilities: expect.arrayContaining(["org-summary-read", "redacted-federation-export", "channel-inventory"]),
      summary: { instances: 1, gateways: 1, agents: 1, channels: 1 },
      controlPlane: {
        summary: { instances: 1, gateways: 1, agents: 1, channels: 1 },
      },
    });
    expect(payload.controlPlane.instances[0].id).toBe("local-agentwall");
    expect(payload.controlPlane.channels[0]).toEqual(expect.objectContaining({ sessionIds: [], userIds: [], roleIds: [] }));
    expect(JSON.stringify(payload)).not.toContain("operator");
    expect(JSON.stringify(payload)).not.toContain("token=");
    expect(JSON.stringify(payload)).not.toContain("#fragment");
  });

  it("merges local control-plane snapshots with validated remote federation summaries", () => {
    const local = buildOrganizationControlPlaneSnapshot({
      now,
      localInstance: {
        id: "local-agentwall",
        name: "Local Agentwall",
        url: "http://127.0.0.1:3015",
      },
      configuredInstances: [
        {
          id: "remote-west",
          name: "Remote West",
          url: "https://remote-west.example.com?token=hidden",
          role: "remote",
          status: "unknown",
        },
      ],
      observedChannels: [
        {
          agentId: "local-agent",
          channelId: "telegram:-100:local",
          lastSeenAt: now,
          lastPlane: "tool",
          lastAction: "status_check",
          riskLevel: "low",
          sessionIds: ["local-session"],
          userIds: ["local-user"],
          roleIds: ["operator"],
        },
      ],
    });
    const remoteSnapshot = buildOrganizationControlPlaneSnapshot({
      now: "2026-04-30T14:21:00.000Z",
      localInstance: {
        id: "remote-west",
        name: "Remote West",
        url: "https://remote-west.example.com",
      },
      configuredInstances: [
        {
          id: "local-agentwall",
          name: "Local as seen remotely",
          url: "https://local.example.com",
          role: "remote",
          status: "unknown",
        },
      ],
      observedChannels: [
        {
          agentId: "remote-agent",
          channelId: "slack:T999:C888",
          lastSeenAt: "2026-04-30T14:21:00.000Z",
          lastPlane: "network",
          lastAction: "http_request",
          riskLevel: "high",
          sessionIds: ["remote-session"],
          userIds: ["remote-user"],
          roleIds: ["analyst"],
        },
      ],
    });
    const remotePayload = buildOrganizationFederationSummaryPayload("2026-04-30T14:21:30.000Z", remoteSnapshot);

    const merged = mergeOrganizationControlPlaneSnapshots(local, [validateOrganizationFederationSummaryPayload({ ok: true, ...remotePayload })], [
      {
        id: "remote-west",
        name: "Remote West",
        url: "https://remote-west.example.com",
        summaryUrl: "https://remote-west.example.com/api/org/summary",
        ok: true,
        status: "online",
        generatedAt: remotePayload.generatedAt,
      },
    ]);

    expect(merged.summary).toMatchObject({
      instances: 2,
      gateways: 2,
      agents: 2,
      channels: 2,
      configuredInstances: 1,
      observedChannels: 2,
    });
    expect(merged.instances.filter((instance) => instance.role === "local")).toHaveLength(1);
    expect(merged.instances.find((instance) => instance.id === "remote-west")).toEqual(
      expect.objectContaining({ role: "remote", status: "online", url: "https://remote-west.example.com" })
    );
    expect(merged.instances.find((instance) => instance.id === "local-agentwall")?.name).toBe("Local Agentwall");
    expect(merged.channels.map((channel) => channel.id)).toEqual(
      expect.arrayContaining(["local-agentwall:local-agent:telegram:-100:local", "remote-west:remote-agent:slack:T999:C888"])
    );
  });

  it("generates authenticated peer polling headers and redacts token values from errors", async () => {
    const seenHeaders: Record<string, string>[] = [];
    const result = await pollOrganizationPeerSummaries({
      env: { AGENTWALL_TEST_TOKEN: "test-token" },
      instances: [
        {
          id: "peer-auth",
          name: "Peer Auth",
          url: "https://user:password@peer.example.com/base?token=hidden",
          summaryUrl: "https://peer.example.com/api/org/summary?token=hidden",
          role: "remote",
          status: "unknown",
          authTokenEnv: "AGENTWALL_TEST_TOKEN",
          pollTimeoutMs: 100,
        },
        {
          id: "peer-custom-auth",
          name: "Peer Custom Auth",
          url: "https://peer-custom.example.com",
          role: "remote",
          status: "unknown",
          authTokenEnv: "AGENTWALL_TEST_TOKEN",
          authHeaderName: "X-Agentwall-Token",
          pollTimeoutMs: 100,
        },
      ],
      fetchImpl: async (_url, init) => {
        seenHeaders.push(init?.headers ?? {});
        throw new Error("custom auth failure X-Agentwall-Token: test-token and https://user:test-token@peer.example.com/?token=test-token&api_key=api-secret&access_token=access-secret&refresh_token=refresh-secret");
      },
    });

    expect(result.payloads).toHaveLength(0);
    expect(seenHeaders[0].Authorization).toBe("Bearer test-token");
    expect(seenHeaders[1]["X-Agentwall-Token"]).toBe("test-token");
    expect(JSON.stringify(result.peers)).not.toContain("test-token");
    expect(JSON.stringify(result.peers)).not.toContain("api-secret");
    expect(JSON.stringify(result.peers)).not.toContain("access-secret");
    expect(JSON.stringify(result.peers)).not.toContain("refresh-secret");
    expect(result.peers[0].url).toBe("https://peer.example.com/base");
    expect(result.peers[0].summaryUrl).toBe("https://peer.example.com/api/org/summary");
    expect(result.peers.every((peer) => peer.ok === false)).toBe(true);
  });

  it("rejects malformed remote federation payloads before merge", () => {
    const valid = buildOrganizationFederationSummaryPayload(now, buildOrganizationControlPlaneSnapshot({
      now,
      localInstance: {
        id: "peer-valid",
        name: "Peer Valid",
        url: "https://peer-valid.example.com",
      },
      observedChannels: [],
    }));
    const malformed = {
      ok: true,
      ...valid,
      controlPlane: {
        ...valid.controlPlane,
        channels: [
          {
            id: "peer-valid:agent:slack:T:C",
            instanceId: "peer-valid",
            gatewayId: "peer-valid:slack",
            gatewayKind: "slack",
            agentId: "agent",
            channelId: "slack:T:C",
            lastSeenAt: now,
            lastPlane: "tool",
            lastAction: "status_check",
            riskLevel: "low",
          },
        ],
      },
    };

    expect(() => validateOrganizationFederationSummaryPayload(malformed)).toThrow(/sessionIds/);
  });

  it("rejects peer summaries whose instance identity does not match the configured peer", async () => {
    const wrongPayload = buildOrganizationFederationSummaryPayload(now, buildOrganizationControlPlaneSnapshot({
      now,
      localInstance: {
        id: "wrong-peer",
        name: "Wrong Peer",
        url: "https://wrong-peer.example.com",
      },
      observedChannels: [],
    }));

    const result = await pollOrganizationPeerSummaries({
      instances: [
        {
          id: "expected-peer",
          name: "Expected Peer",
          url: "https://expected-peer.example.com",
          role: "remote",
          status: "unknown",
          pollTimeoutMs: 100,
        },
      ],
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({ ok: true, ...wrongPayload }),
      }),
    });

    expect(result.payloads).toHaveLength(0);
    expect(result.peers[0]).toEqual(expect.objectContaining({ id: "expected-peer", ok: false, status: "degraded" }));
    expect(result.peers[0].error).toContain("identity mismatch");
  });
});
