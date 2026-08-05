import { afterEach, describe, expect, it } from "@jest/globals";
import * as http from "http";
import { AddressInfo } from "net";
import { AgentwallConfig } from "../src/config";
import { createManifestAttestation, hashManifest } from "../src/integrity/manifest";
import { buildServer } from "../src/server";

type CollectorPayload = Record<string, unknown>;
type SpanPayload = {
  traceId: string;
  spanId: string;
  name: string;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes?: Array<{ key: string; value: Record<string, boolean | number | string> }>;
  status?: { code?: number; message?: string };
};

const baseConfig: AgentwallConfig = {
  port: 3022,
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

describe("OTLP-style decision trace export", () => {
  let collector: Awaited<ReturnType<typeof startCollector>> | undefined;
  let server: Awaited<ReturnType<typeof buildServer>> | undefined;

  afterEach(async () => {
    if (server) {
      await server.app.close();
      server = undefined;
    }

    if (collector) {
      await collector.close();
      collector = undefined;
    }
  });

  it("emits OTLP-style spans for evaluate and inspection routes when telemetry is enabled", async () => {
    collector = await startCollector();
    server = await buildServer({
      ...baseConfig,
      telemetry: {
        enabled: true,
        endpoint: collector.endpoint,
        serviceName: "agentwall-test",
        timeoutMs: 2_000,
      },
    });

    const evaluateResponse = await server.app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "trace-agent",
        sessionId: "trace-session",
        plane: "network",
        action: "http_request",
        payload: { url: "http://127.0.0.1/admin" },
      },
    });
    const networkResponse = await server.app.inject({
      method: "POST",
      url: "/inspect/network",
      payload: { url: "http://127.0.0.1/admin" },
    });
    const contentResponse = await server.app.inject({
      method: "POST",
      url: "/inspect/content",
      payload: {
        text: "Customer secret is sk-test-1234567890 and SSN 123-45-6789",
        source: "user",
        trustLabel: "untrusted",
      },
    });

    const manifest = {
      name: "write_file",
      description: "Write a file to disk",
      inputs: ["path", "content"],
    };
    const approvedFingerprint = hashManifest(manifest, "operator-registry");
    approvedFingerprint.attestation = createManifestAttestation({
      subjectId: "tool:write_file",
      subjectType: "tool",
      fingerprint: approvedFingerprint,
      signer: "agentwall-operator",
    });
    const manifestResponse = await server.app.inject({
      method: "POST",
      url: "/inspect/manifest",
      payload: {
        subjectId: "tool:write_file",
        subjectType: "tool",
        manifest,
        approvedFingerprint,
      },
    });

    expect(evaluateResponse.statusCode).toBe(200);
    expect(networkResponse.statusCode).toBe(200);
    expect(contentResponse.statusCode).toBe(200);
    expect(manifestResponse.statusCode).toBe(200);
    expect(contentResponse.json()).toEqual(expect.objectContaining({ riskLevel: expect.any(String) }));
    expect(manifestResponse.json()).toEqual(expect.objectContaining({ trustState: "trusted" }));

    await waitFor(() => collector!.exports.length === 4);

    const spans = flattenSpans(collector.exports);
    expect(spans).toHaveLength(4);

    const spansByName = new Map(spans.map((span) => [span.name, span]));
    expect(Array.from(spansByName.keys()).sort()).toEqual(
      ["inspect.content", "inspect.manifest", "inspect.network", "policy.evaluate"].sort()
    );

    const evaluateSpan = spansByName.get("policy.evaluate") as SpanPayload;
    const evaluateAttributes = attributeMap(evaluateSpan.attributes ?? []);
    expect(evaluateSpan.traceId).toMatch(/^[a-f0-9]{32}$/);
    expect(evaluateSpan.spanId).toMatch(/^[a-f0-9]{16}$/);
    expect(BigInt(evaluateSpan.endTimeUnixNano)).toBeGreaterThan(BigInt(evaluateSpan.startTimeUnixNano));
    expect(evaluateSpan.status).toEqual(expect.objectContaining({ code: 1 }));
    expect(evaluateAttributes).toEqual(
      expect.objectContaining({
        "agentwall.route_name": "policy.evaluate",
        "agentwall.route_path": "/evaluate",
        "agentwall.plane": "network",
        "agentwall.action": "http_request",
        "agentwall.decision": "deny",
        "agentwall.result_status": "deny",
        "agentwall.risk_level": "critical",
        "agentwall.agent_id": "trace-agent",
        "agentwall.session_id": "trace-session",
        "agentwall.audit_event_id": expect.any(String),
      })
    );

    const networkAttributes = attributeMap((spansByName.get("inspect.network") as SpanPayload).attributes ?? []);
    expect(networkAttributes).toEqual(
      expect.objectContaining({
        "agentwall.route_name": "inspect.network",
        "agentwall.plane": "network",
        "agentwall.action": "inspect_network",
        "agentwall.decision": "deny",
        "agentwall.result_status": "blocked",
        "agentwall.risk_level": expect.any(String),
        "agentwall.network_ssrf": true,
      })
    );

    const contentAttributes = attributeMap((spansByName.get("inspect.content") as SpanPayload).attributes ?? []);
    expect(contentAttributes).toEqual(
      expect.objectContaining({
        "agentwall.route_name": "inspect.content",
        "agentwall.plane": "content",
        "agentwall.action": "inspect_content",
        "agentwall.decision": "redact",
        "agentwall.result_status": "sensitive_content_detected",
        "agentwall.content_contains_pii": true,
        "agentwall.content_redacted": true,
      })
    );

    const manifestAttributes = attributeMap((spansByName.get("inspect.manifest") as SpanPayload).attributes ?? []);
    expect(manifestAttributes).toEqual(
      expect.objectContaining({
        "agentwall.route_name": "inspect.manifest",
        "agentwall.plane": "governance",
        "agentwall.action": "inspect_manifest",
        "agentwall.decision": "allow",
        "agentwall.result_status": "approved",
        "agentwall.risk_level": "low",
        "agentwall.subject_id": "tool:write_file",
        "agentwall.manifest_trust_state": "trusted",
      })
    );

    for (const payload of collector.exports) {
      const serviceName = resourceAttribute(payload, "service.name");
      expect(serviceName).toBe("agentwall-test");
    }
  });

  it("does not export spans when telemetry is left at its default disabled state", async () => {
    collector = await startCollector();
    server = await buildServer(baseConfig);

    const response = await server.app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "trace-agent",
        sessionId: "trace-session",
        plane: "network",
        action: "http_request",
        payload: { url: "http://127.0.0.1/admin" },
      },
    });

    expect(response.statusCode).toBe(200);

    await sleep(150);
    expect(collector.exports).toHaveLength(0);
  });
});

async function startCollector(): Promise<{
  endpoint: string;
  exports: CollectorPayload[];
  close: () => Promise<void>;
}> {
  const exports: CollectorPayload[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer | string) => {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    });
    req.on("end", () => {
      exports.push(JSON.parse(Buffer.concat(chunks).toString("utf-8")) as CollectorPayload);
      res.statusCode = 202;
      res.end("accepted");
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;

  return {
    endpoint: `http://127.0.0.1:${address.port}/v1/traces`,
    exports,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function flattenSpans(payloads: CollectorPayload[]): SpanPayload[] {
  return payloads.flatMap((payload) => {
    const resourceSpans = (payload["resourceSpans"] ?? []) as Array<Record<string, unknown>>;
    return resourceSpans.flatMap((resourceSpan) => {
      const scopeSpans = (resourceSpan["scopeSpans"] ?? []) as Array<Record<string, unknown>>;
      return scopeSpans.flatMap((scopeSpan) => ((scopeSpan["spans"] ?? []) as SpanPayload[]));
    });
  });
}

function attributeMap(attributes: Array<{ key: string; value: Record<string, boolean | number | string> }>): Record<string, boolean | number | string> {
  return attributes.reduce<Record<string, boolean | number | string>>((accumulator, attribute) => {
    const value =
      attribute.value["stringValue"] ??
      attribute.value["boolValue"] ??
      attribute.value["intValue"] ??
      attribute.value["doubleValue"];
    if (value !== undefined) {
      accumulator[attribute.key] = value;
    }
    return accumulator;
  }, {});
}

function resourceAttribute(payload: CollectorPayload, key: string): boolean | number | string | undefined {
  const resourceSpans = (payload["resourceSpans"] ?? []) as Array<Record<string, unknown>>;
  const firstResource = resourceSpans[0]?.["resource"] as Record<string, unknown> | undefined;
  const attributes = (firstResource?.["attributes"] ?? []) as Array<{ key: string; value: Record<string, boolean | number | string> }>;
  return attributeMap(attributes)[key];
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const startedAt = Date.now();
  while (!predicate()) {
    if (Date.now() - startedAt > timeoutMs) {
      throw new Error(`Condition not met within ${timeoutMs}ms`);
    }

    await sleep(25);
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, ms));
}
