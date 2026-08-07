import { afterEach, describe, expect, it, jest } from "@jest/globals";
import Fastify from "fastify";
import { EventEmitter } from "events";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { createBootstrapApp, type BootstrapApp, type BootstrapSpawn } from "../src/bootstrap";
import { createLocalOperatorFiles, loadGeneratedEnvironment } from "../src/setup";
import { registerOperatorAuth } from "../src/auth/operator";

const directories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "agentwall-bootstrap-"));
  directories.push(directory);
  return directory;
}

async function localSession(app: BootstrapApp): Promise<Record<string, string>> {
  const page = await app.inject({ method: "GET", url: "/", headers: { host: "127.0.0.1:3001" } });
  const setCookie = page.headers["set-cookie"];
  const cookie = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  if (!cookie) throw new Error("Bootstrap page did not set its local session cookie.");
  return {
    host: "127.0.0.1:3001",
    origin: "http://127.0.0.1:3001",
    cookie: cookie.split(";", 1)[0],
  };
}

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
  jest.restoreAllMocks();
});

describe("bootstrap UI", () => {
  it("serves setup status while the AgentWall service is stopped", async () => {
    const app = createBootstrapApp({
      baseDir: temporaryDirectory(),
      host: "127.0.0.1",
      port: 3001,
      servicePort: 3000,
    });

    try {
      const response = await app.inject({
        method: "GET",
        url: "/api/bootstrap/status",
        headers: { host: "127.0.0.1:3001" },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ service: "stopped", setup: "missing" });
    } finally {
      await app.close();
    }
  });

  it("does not set cookies for an unrecognized Host header", async () => {
    const app = createBootstrapApp({
      baseDir: temporaryDirectory(),
      host: "127.0.0.1",
      port: 3001,
      servicePort: 3000,
    });

    try {
      const response = await app.inject({
        method: "GET",
        url: "/api/bootstrap/status",
        headers: { host: "attacker.example" },
      });
      expect(response.statusCode).toBe(421);
      expect(response.headers["set-cookie"]).toBeUndefined();
    } finally {
      await app.close();
    }
  });

  it("hands the operator token to the service through an HttpOnly cookie only", async () => {
    const directory = temporaryDirectory();
    createLocalOperatorFiles(directory, {
      mode: "monitor",
      host: "127.0.0.1",
      port: 3000,
      allowedHosts: [],
      lanAccess: false,
      force: false,
    });
    const token = loadGeneratedEnvironment(directory).AGENTWALL_OPERATOR_TOKEN;
    const app = createBootstrapApp({ baseDir: directory, host: "127.0.0.1", port: 3001, servicePort: 3000 });

    try {
      const response = await app.inject({
        method: "GET",
        url: "/api/bootstrap/status",
        headers: { host: "127.0.0.1:3001" },
      });
      const setCookie = String(response.headers["set-cookie"]);
      expect(setCookie).toContain(`agentwall_operator=${token}`);
      expect(setCookie).toContain("HttpOnly");
      expect(setCookie).toContain("SameSite=Strict");
      expect(response.body).not.toContain(token);
    } finally {
      await app.close();
    }
  });

  it("lets the main service accept the handoff cookie only for same-origin changes", async () => {
    const directory = temporaryDirectory();
    createLocalOperatorFiles(directory, {
      mode: "monitor",
      host: "127.0.0.1",
      port: 3000,
      allowedHosts: [],
      lanAccess: false,
      force: false,
    });
    const token = loadGeneratedEnvironment(directory).AGENTWALL_OPERATOR_TOKEN;
    if (!token) throw new Error("Setup did not create an operator token.");
    const previousToken = process.env.AGENTWALL_OPERATOR_TOKEN;
    process.env.AGENTWALL_OPERATOR_TOKEN = token;
    const bootstrap = createBootstrapApp({ baseDir: directory, host: "127.0.0.1", port: 3001, servicePort: 3000 });
    const service = Fastify();
    registerOperatorAuth(service, { allowLoopbackDev: false }, []);
    service.post("/control", async () => ({ ok: true }));

    try {
      const status = await bootstrap.inject({
        method: "GET",
        url: "/api/bootstrap/status",
        headers: { host: "127.0.0.1:3001" },
      });
      const operatorCookie = String(status.headers["set-cookie"]).match(/agentwall_operator=[^;,]+/)?.[0];
      if (!operatorCookie) throw new Error("Bootstrap did not set the operator handoff cookie.");

      const allowed = await service.inject({
        method: "POST",
        url: "/control",
        headers: { cookie: operatorCookie, host: "127.0.0.1:3000", origin: "http://127.0.0.1:3000" },
      });
      const crossPort = await service.inject({
        method: "POST",
        url: "/control",
        headers: { cookie: operatorCookie, host: "127.0.0.1:3000", origin: "http://127.0.0.1:3001" },
      });

      expect(allowed.statusCode).toBe(200);
      expect(crossPort.statusCode).toBe(403);
    } finally {
      await bootstrap.close();
      await service.close();
      if (previousToken === undefined) delete process.env.AGENTWALL_OPERATOR_TOKEN;
      else process.env.AGENTWALL_OPERATOR_TOKEN = previousToken;
    }
  });

  it("starts only the fixed AgentWall production entry point", async () => {
    const directory = temporaryDirectory();
    const child = Object.assign(new EventEmitter(), {
      pid: 4242,
      kill: jest.fn(() => true),
    });
    const spawnMock = jest.fn(() => child) as unknown as BootstrapSpawn;
    const app = createBootstrapApp({
      baseDir: directory,
      host: "127.0.0.1",
      port: 3001,
      servicePort: 3000,
      spawnChild: spawnMock,
    });

    try {
      const headers = await localSession(app);
      const response = await app.inject({ method: "POST", url: "/api/bootstrap/start", headers, payload: {} });

      expect(response.statusCode).toBe(202);
      expect(spawnMock).toHaveBeenCalledWith(
        process.execPath,
        [join(directory, "dist", "index.js")],
        expect.objectContaining({ cwd: directory, stdio: "inherit" }),
      );
      expect(JSON.stringify(response.json())).not.toContain("AGENTWALL_OPERATOR_TOKEN");
    } finally {
      await app.close();
    }
  });

  it("starts development only through the fixed local ts-node entry point", async () => {
    const directory = temporaryDirectory();
    const child = Object.assign(new EventEmitter(), {
      pid: 4243,
      kill: jest.fn(() => true),
    });
    const spawnMock = jest.fn(() => child) as unknown as BootstrapSpawn;
    const app = createBootstrapApp({
      baseDir: directory,
      host: "127.0.0.1",
      port: 3001,
      servicePort: 3000,
      spawnChild: spawnMock,
    });

    try {
      const headers = await localSession(app);
      const response = await app.inject({ method: "POST", url: "/api/bootstrap/dev", headers, payload: {} });

      expect(response.statusCode).toBe(202);
      expect(spawnMock).toHaveBeenCalledWith(
        process.execPath,
        [join(directory, "node_modules", "ts-node", "dist", "bin.js"), "src/index.ts"],
        expect.objectContaining({ cwd: directory, stdio: "inherit" }),
      );
    } finally {
      await app.close();
    }
  });

  it("rejects command input instead of forwarding it to a child", async () => {
    const spawnMock = jest.fn() as unknown as BootstrapSpawn;
    const app = createBootstrapApp({
      baseDir: temporaryDirectory(),
      host: "127.0.0.1",
      port: 3001,
      servicePort: 3000,
      spawnChild: spawnMock,
    });

    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/bootstrap/start",
        headers: { host: "127.0.0.1:3001" },
        payload: { command: "node; touch /tmp/unsafe" },
      });
      expect(response.statusCode).toBe(400);
      expect(spawnMock).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });

  it("rejects a cross-origin bootstrap mutation", async () => {
    const app = createBootstrapApp({
      baseDir: temporaryDirectory(),
      host: "127.0.0.1",
      port: 3001,
      servicePort: 3000,
    });

    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/bootstrap/setup",
        headers: { origin: "https://example.invalid", host: "127.0.0.1:3001" },
        payload: {
          mode: "monitor",
          host: "127.0.0.1",
          port: 3000,
          allowedHosts: [],
          lanAccess: false,
          force: false,
        },
      });
      expect(response.statusCode).toBe(403);
    } finally {
      await app.close();
    }
  });

  it("requires the one-time local session cookie for a mutation", async () => {
    const app = createBootstrapApp({
      baseDir: temporaryDirectory(),
      host: "127.0.0.1",
      port: 3001,
      servicePort: 3000,
    });

    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/bootstrap/stop",
        headers: { origin: "http://127.0.0.1:3001", host: "127.0.0.1:3001" },
        payload: { confirm: true },
      });
      expect(response.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it("returns a new agent environment once without putting the credential in later status", async () => {
    const directory = temporaryDirectory();
    createLocalOperatorFiles(directory, {
      mode: "monitor",
      host: "127.0.0.1",
      port: 3000,
      allowedHosts: [],
      lanAccess: false,
      force: false,
    });
    const app = createBootstrapApp({ baseDir: directory, host: "127.0.0.1", port: 3001, servicePort: 3000 });

    try {
      const headers = await localSession(app);
      const response = await app.inject({
        method: "POST",
        url: "/api/bootstrap/onboard",
        headers,
        payload: { profileId: "generic", agentId: "generic" },
      });

      expect(response.statusCode).toBe(200);
      const body = response.json();
      expect(body.warning).toMatch(/copy.*now/i);
      expect(body.env).toEqual(expect.arrayContaining([expect.stringContaining("HTTP_PROXY=")]));

      const status = await app.inject({
        method: "GET",
        url: "/api/bootstrap/status",
        headers: { host: "127.0.0.1:3001" },
      });
      expect(status.body).not.toContain(body.env.join("\n"));
      expect(status.body).not.toContain("generic:");
    } finally {
      await app.close();
    }
  });

  it("rejects shell-like agent names before onboarding", async () => {
    const app = createBootstrapApp({
      baseDir: temporaryDirectory(),
      host: "127.0.0.1",
      port: 3001,
      servicePort: 3000,
    });

    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/bootstrap/onboard",
        headers: { host: "127.0.0.1:3001" },
        payload: { profileId: "generic", agentId: "generic; touch /tmp/unsafe" },
      });
      expect(response.statusCode).toBe(400);
    } finally {
      await app.close();
    }
  });
});
