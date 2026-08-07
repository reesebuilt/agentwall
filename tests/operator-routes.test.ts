import { mkdtempSync, rmSync } from "fs";
import { createServer } from "http";
import { tmpdir } from "os";
import { join } from "path";
import { afterAll, describe, expect, it } from "@jest/globals";
import type { AgentwallConfig } from "../src/config";
import { buildServer } from "../src/server";
import {
  MUTATING_OPERATOR_ACTIONS,
  READ_ONLY_OPERATOR_ACTIONS,
  operatorActionCatalog,
} from "../src/operator/action-catalog";
import { resolveTypedCommandAction } from "../src/operator/command-allowlist";
import { BOOTSTRAP_ACTIONS } from "../src/bootstrap";

const config: AgentwallConfig = {
  port: 0,
  host: "127.0.0.1",
  logLevel: "silent",
  dashboard: {},
  approval: {
    mode: "always",
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

const expectedMutating = [
  "approval-mode",
  "shield",
  "normal",
  "session-boost",
  "session-reset",
  "pause",
  "resume",
  "terminate",
  "fleet-issue",
  "fleet-rotate",
  "fleet-revoke",
  "anchor",
  "verify-capture",
  "mcp-wrap",
  "mcp-http-wrap",
  "mcp-http-stop",
  "perimeter-install",
  "perimeter-rollback",
  "perimeter-run",
  "sandbox-build",
  "sandbox-run",
  "intercept-init",
  "intercept-trust",
  "decoy-generate",
] as const;

const expectedReadOnly = [
  "doctor",
  "status",
  "verify",
  "fleet-list",
  "mcp-http-list",
  "perimeter-plan",
  "perimeter-status",
  "perimeter-verify",
  "sandbox-probe",
  "sandbox-plan",
  "intercept-status",
  "decoy-list",
  "why",
  "version",
  "help",
] as const;

const serverPromise = buildServer(config);

afterAll(async () => {
  const { app } = await serverPromise;
  await app.close();
});

describe("running-service operator action catalog", () => {
  it("returns the complete typed catalog without an arbitrary shell action", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({ method: "GET", url: "/api/operator/actions" });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.actions.map((action: { id: string }) => action.id)).toEqual([
      ...expectedMutating,
      ...expectedReadOnly,
    ]);
    expect(body.actions.find((action: { id: string }) => action.id === "shell")).toBeUndefined();
    expect(body.actions[0]).toEqual(expect.objectContaining({
      id: expect.any(String),
      label: expect.any(String),
      group: expect.any(String),
      mutating: expect.any(Boolean),
      confirmation: expect.any(Boolean),
      description: expect.any(String),
      cli: expect.any(String),
      fields: expect.any(Array),
    }));
    const commandFields = body.actions
      .flatMap((action: { fields: Array<{ name: string; options?: string[] }> }) => action.fields)
      .filter((field: { name: string }) => field.name === "command");
    expect(commandFields.length).toBeGreaterThan(0);
    expect(commandFields.every((field: { options?: string[] }) => field.options?.includes("agentwall"))).toBe(true);
  });

  it("keeps bootstrap actions separate from running-service actions", () => {
    expect(MUTATING_OPERATOR_ACTIONS).toEqual(expectedMutating);
    expect(READ_ONLY_OPERATOR_ACTIONS).toEqual(expectedReadOnly);
    expect(BOOTSTRAP_ACTIONS).toEqual(["setup", "init", "onboard", "start", "dev", "stop"]);

    const runningIds = operatorActionCatalog.map((action) => action.id);
    for (const action of BOOTSTRAP_ACTIONS) {
      expect(runningIds).not.toContain(action);
    }
  });

  it("gives each mutation a confirmation contract and each read-only action an output path", () => {
    for (const action of operatorActionCatalog) {
      expect(action.cli.startsWith("agentwall ")).toBe(true);
      expect(action.confirmation).toBe(action.mutating);
    }
  });
});

describe("operator action route behavior", () => {
  it("rejects an unknown action before execution", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/api/operator/actions",
      payload: { action: "shell" },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual(expect.objectContaining({
      ok: false,
      action: "shell",
      status: "invalid",
      next: expect.stringMatching(/catalog/i),
    }));
  });

  it("requires confirmation before every mutation", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/api/operator/actions",
      payload: { action: "terminate", sessionId: "session-1" },
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual(expect.objectContaining({
      ok: false,
      action: "terminate",
      status: "confirmation-required",
      next: expect.stringMatching(/confirm/i),
    }));
  });

  it("rejects a cross-origin mutation", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/api/operator/actions",
      headers: { origin: "https://example.invalid", host: "127.0.0.1:3000" },
      payload: { action: "approval-mode", mode: "auto", confirm: true },
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual(expect.objectContaining({
      ok: false,
      action: "approval-mode",
      status: "forbidden",
    }));
  });

  it("applies a confirmed dashboard control and returns a structured result", async () => {
    const { app, gate } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/api/operator/actions",
      payload: { action: "approval-mode", mode: "auto", confirm: true },
    });

    expect(response.statusCode).toBe(200);
    expect(gate.getMode()).toBe("auto");
    expect(response.json()).toEqual(expect.objectContaining({
      ok: true,
      action: "approval-mode",
      status: "completed",
      message: "Approval mode is auto.",
      next: "Review pending approvals.",
      data: { mode: "auto" },
    }));
  });

  it("keeps a read-only status action available without confirmation", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/api/operator/actions",
      payload: { action: "status" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(expect.objectContaining({
      ok: true,
      action: "status",
      status: "completed",
      data: expect.objectContaining({ output: expect.any(String) }),
    }));
  });

  it("returns a failure status when a read-only command reports failure", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/api/operator/actions",
      payload: { action: "perimeter-status" },
    });

    expect(response.statusCode).toBeGreaterThanOrEqual(400);
    expect(response.json()).toEqual(expect.objectContaining({
      ok: false,
      action: "perimeter-status",
      status: "failed",
    }));
  });
  it("accepts the required subject for a read-only policy explanation", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/api/operator/actions",
      payload: { action: "why", subject: "https://example.com", kind: "url" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual(expect.objectContaining({
      ok: true,
      action: "why",
      status: "completed",
      data: expect.objectContaining({ output: expect.any(String) }),
    }));
  });

  it("starts, lists, and stops a managed MCP HTTP wrapper", async () => {
    const upstream = createServer((_request, reply) => {
      reply.writeHead(200, { "content-type": "application/json" });
      reply.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
    });
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
    const address = upstream.address();
    if (!address || typeof address === "string") throw new Error("The upstream did not bind to a TCP address.");
    const upstreamPort = address.port;
    const { app } = await serverPromise;

    try {
      const started = await app.inject({
        method: "POST",
        url: "/api/operator/actions",
        payload: {
          action: "mcp-http-wrap",
          upstreamUrl: `http://127.0.0.1:${upstreamPort}/mcp`,
          listenPort: 0,
          serverName: "route-test",
          agentId: "route-agent",
          confirm: true,
        },
      });

      expect(started.statusCode).toBe(200);
      const startBody = started.json();
      expect(startBody).toEqual(expect.objectContaining({
        ok: true,
        action: "mcp-http-wrap",
        status: "completed",
        data: expect.objectContaining({
          wrapId: expect.any(String),
          endpoint: expect.stringMatching(/^http:\/\/127\.0\.0\.1:\d+\/mcp$/),
        }),
      }));

      const listed = await app.inject({
        method: "POST",
        url: "/api/operator/actions",
        payload: { action: "mcp-http-list" },
      });
      expect(listed.statusCode).toBe(200);
      expect(listed.json().data.wrappers).toEqual([
        expect.objectContaining({
          wrapId: startBody.data.wrapId,
          endpoint: expect.stringMatching(/^http:\/\/127\.0\.0\.1:\d+\/mcp$/),
          serverName: "route-test",
        }),
      ]);

      const stopped = await app.inject({
        method: "POST",
        url: "/api/operator/actions",
        payload: { action: "mcp-http-stop", wrapId: startBody.data.wrapId, confirm: true },
      });
      expect(stopped.statusCode).toBe(200);
      expect(stopped.json()).toEqual(expect.objectContaining({
        ok: true,
        action: "mcp-http-stop",
        status: "completed",
      }));

      const empty = await app.inject({
        method: "POST",
        url: "/api/operator/actions",
        payload: { action: "mcp-http-list" },
      });
      expect(empty.statusCode).toBe(200);
      expect(empty.json().data.output).toBe("No MCP HTTP wrappers are running.");
    } finally {
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  });
  it("uses the declared decoy file for generation and listing", async () => {
    const root = mkdtempSync(join(tmpdir(), "agentwall-operator-"));
    const decoyFile = join(root, "decoys.json");
    const { app } = await serverPromise;

    try {
      const generated = await app.inject({
        method: "POST",
        url: "/api/operator/actions",
        payload: { action: "decoy-generate", kind: "generic-secret", out: decoyFile, confirm: true },
      });

      expect(generated.statusCode).toBe(200);
      expect(generated.json()).toEqual(expect.objectContaining({
        ok: true,
        action: "decoy-generate",
        status: "completed",
        data: expect.objectContaining({ path: decoyFile, id: expect.any(String) }),
      }));

      const listed = await app.inject({
        method: "POST",
        url: "/api/operator/actions",
        payload: { action: "decoy-list", file: decoyFile },
      });

      expect(listed.statusCode).toBe(200);
      expect(listed.json().data.decoys).toEqual([
        expect.objectContaining({ id: generated.json().data.id, kind: "generic-secret" }),
      ]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });


  it("formats the fleet doctor result with the stable line fields", async () => {
    const { app } = await serverPromise;
    const response = await app.inject({
      method: "POST",
      url: "/api/operator/actions",
      payload: { action: "doctor" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().data.output).toBe("No fleet credential problems were found.");
  });
});

describe("typed command allowlist", () => {
  const allowlist = {
    workingDirectoryRoot: "/srv/agentwall",
    agentwallBinary: "/srv/agentwall/dist/index.js",
    sandboxLauncher: "/srv/agentwall/dist/native/agentwall-sandbox",
    mcpBinaries: { node: "/usr/bin/node" },
  };

  it("resolves only a declared binary and a contained working directory", () => {
    expect(resolveTypedCommandAction({
      command: "node",
      args: ["server.js"],
      confirm: true,
      workingDirectory: "services",
    }, allowlist)).toEqual({
      command: "/usr/bin/node",
      args: ["server.js"],
      confirm: true,
      workingDirectory: "/srv/agentwall/services",
    });
  });

  it.each([
    [{ command: "node; touch /tmp/unsafe", args: [], confirm: true }, /shell syntax/i],
    [{ command: "/usr/bin/node", args: [], confirm: true }, /executable name/i],
    [{ command: "../node", args: [], confirm: true }, /executable name/i],
    [{ command: "python", args: [], confirm: true }, /not declared/i],
    [{ command: "node", args: ["$(id)"], confirm: true }, /shell syntax/i],
    [{ command: "node", args: [], confirm: true, workingDirectory: "../outside" }, /working directory/i],
  ])("rejects unsafe typed command input %#", (input, expected) => {
    expect(() => resolveTypedCommandAction(input, allowlist)).toThrow(expected);
  });
});
