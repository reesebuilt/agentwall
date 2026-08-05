import { afterAll, beforeAll, describe, expect, it } from "@jest/globals";
import { buildServer } from "../src/server";
import type { AgentwallServer } from "../src/server";
import { resetAuditChain } from "../src/audit/logger";
import type { AgentwallConfig } from "../src/config";

/**
 * Pins the wire contract of the 400 that routes return when body validation fails.
 *
 * /evaluate and /approval/:id/respond parse untrusted request bodies, so the validation
 * error is a public output of this service: dashboards and callers read
 * details.fieldErrors[field] and render it. That makes the envelope an API surface, and a
 * validator upgrade that quietly reshapes it breaks consumers without breaking any other
 * test in this suite. These assertions describe the envelope, not the validator's wording:
 * the key sets, where field-level problems land, where whole-body problems land, and the
 * types of every leaf. Message text belongs to the validation library and is not promised
 * to callers.
 */

const config: AgentwallConfig = {
  port: 0,
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

interface FlattenedErrorBody {
  error: string;
  details: {
    formErrors: unknown;
    fieldErrors: Record<string, unknown>;
  };
}

function expectStringArray(value: unknown): string[] {
  expect(Array.isArray(value)).toBe(true);
  const list = value as unknown[];
  for (const item of list) {
    expect(typeof item).toBe("string");
    expect((item as string).length).toBeGreaterThan(0);
  }
  return list as string[];
}

describe("validation failure response shape", () => {
  let server: AgentwallServer;

  beforeAll(async () => {
    resetAuditChain();
    server = await buildServer(config);
  });

  afterAll(async () => {
    await server.app.close();
    resetAuditChain();
  });

  async function postInvalid(url: string, payload: unknown): Promise<FlattenedErrorBody> {
    const response = await server.app.inject({ method: "POST", url, payload: payload as never });
    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain("application/json");

    const body = response.json() as FlattenedErrorBody;
    // Exactly two members. An extra member (raw issues, a stack, the received body) would
    // be new output flowing back to an unauthenticated caller, which is why the key set is
    // asserted rather than the two members being spot-checked.
    expect(Object.keys(body).sort()).toEqual(["details", "error"]);
    expect(body.error).toBe("Invalid request body");
    expect(Object.keys(body.details).sort()).toEqual(["fieldErrors", "formErrors"]);
    return body;
  }

  it("reports per-field problems on /evaluate under details.fieldErrors keyed by field name", async () => {
    const body = await postInvalid("/evaluate", { plane: 12, action: "read", payload: {} });

    expect(body.details.formErrors).toEqual([]);
    expect(Object.keys(body.details.fieldErrors).sort()).toEqual(["agentId", "plane"]);
    for (const messages of Object.values(body.details.fieldErrors)) {
      expect(expectStringArray(messages).length).toBeGreaterThan(0);
    }
  });

  it("attributes a nested problem to its top-level field and nothing deeper", async () => {
    const body = await postInvalid("/evaluate", {
      agentId: "agent-1",
      plane: "network",
      action: "http_request",
      payload: {},
      actor: { roleIds: "not-an-array" },
    });

    // Callers index fieldErrors by top-level member. A nested failure collapsing to the
    // parent name is the behaviour they are written against, so a change to per-path keys
    // would silently empty every dashboard field it feeds.
    expect(body.details.formErrors).toEqual([]);
    expect(Object.keys(body.details.fieldErrors)).toEqual(["actor"]);
    expect(expectStringArray(body.details.fieldErrors.actor).length).toBeGreaterThan(0);
  });

  it("reports a whole-body type problem under details.formErrors with no field attribution", async () => {
    const body = await postInvalid("/evaluate", [1, 2, 3]);

    expect(expectStringArray(body.details.formErrors).length).toBeGreaterThan(0);
    expect(body.details.fieldErrors).toEqual({});
  });

  it("returns the same envelope from /approval/:id/respond for a rejected enum value", async () => {
    const body = await postInvalid("/approval/req-does-not-exist/respond", { decision: "yes" });

    // The body is parsed before the operator identity is resolved, so this envelope is what
    // an unauthenticated caller sees. It must stay as narrow as the authenticated one.
    expect(body.details.formErrors).toEqual([]);
    expect(Object.keys(body.details.fieldErrors)).toEqual(["decision"]);
    expect(expectStringArray(body.details.fieldErrors.decision).length).toBeGreaterThan(0);
  });

  it("does not echo the submitted value back when a field has the wrong type", async () => {
    // The 400 is rendered by the dashboard and returned to whoever posted the body, so
    // reflecting attacker-controlled content turns a validation error into a delivery
    // channel for it. A type mismatch is reported by type, never by value.
    const response = await server.app.inject({
      method: "POST",
      url: "/evaluate",
      payload: { agentId: 909909909, plane: "network", action: "http_request", payload: {} },
    });

    expect(response.statusCode).toBe(400);
    expect(response.payload).not.toContain("909909909");
  });

  it("strips unknown members instead of rejecting the request", async () => {
    // Callers send bodies with fields this version does not know about. Rejecting them
    // would turn every additive change on the caller side into a 400 here.
    const response = await server.app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-1",
        plane: "network",
        action: "http_request",
        payload: {},
        unknownMemberFromANewerCaller: "ignored",
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toHaveProperty("decision");
  });
});
