import { randomBytes, timingSafeEqual } from "crypto";
import { type ChildProcess, type SpawnOptions, spawn as nodeSpawn } from "child_process";
import * as fs from "fs";
import * as path from "path";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import rateLimit from "@fastify/rate-limit";
import { z, type ZodType } from "zod";
import { OPERATOR_COOKIE_NAME } from "./auth/operator";
import { runOnboard } from "./onboard";
import { writeStarterFiles } from "./onboarding";
import { createLocalOperatorFiles, loadGeneratedEnvironment } from "./setup";

export const BOOTSTRAP_ACTIONS = ["setup", "init", "onboard", "start", "dev", "stop"] as const;

export type BootstrapServiceState = "stopped" | "starting" | "running" | "failed";
export type BootstrapApp = FastifyInstance;
export type BootstrapSpawn = (command: string, args: string[], options: SpawnOptions) => ChildProcess;

export interface BootstrapUiOptions {
  baseDir: string;
  host: string;
  port: number;
  servicePort: number;
  spawnChild?: BootstrapSpawn;
}

const BOOTSTRAP_COOKIE_NAME = "agentwall_bootstrap";
const SAFE_NAME = /^[A-Za-z0-9._-]+$/;
const SAFE_HOST = /^[A-Za-z0-9.*:[\]_-]+$/;
const STOP_ACTION_SCHEMA = z.object({ confirm: z.literal(true) }).strict();
const EMPTY_ACTION_SCHEMA = z.object({}).strict();
const SETUP_ACTION_SCHEMA = z.object({
  mode: z.enum(["monitor", "guarded", "strict"]).default("monitor"),
  host: z.string().min(1).regex(SAFE_HOST).default("127.0.0.1"),
  port: z.number().int().min(1).max(65535).default(3000),
  allowedHosts: z.array(z.string().min(1).regex(SAFE_HOST)).default([]),
  lanAccess: z.boolean().default(false),
  force: z.boolean().default(false),
}).strict();
const INIT_ACTION_SCHEMA = z.object({
  mode: z.enum(["monitor", "guarded", "strict"]).default("guarded"),
  host: z.string().min(1).regex(SAFE_HOST).default("127.0.0.1"),
  port: z.number().int().min(1).max(65535).default(3000),
  allowedHosts: z.array(z.string().min(1).regex(SAFE_HOST)).default(["api.openai.com"]),
  lanAccess: z.boolean().default(false),
  force: z.boolean().default(false),
}).strict();
const ONBOARD_ACTION_SCHEMA = z.object({
  profileId: z.string().min(1).max(80).regex(SAFE_NAME).default("generic"),
  agentId: z.string().min(1).max(80).regex(SAFE_NAME).default("generic"),
}).strict();

interface ChildState {
  service: BootstrapServiceState;
  mode: "production" | "development" | null;
  pid: number | null;
  lastExitCode: number | null;
  error: string | null;
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.toLowerCase();
  if (normalized === "localhost" || normalized === "::1" || normalized === "[::1]") return true;
  const octets = normalized.split(".");
  return octets.length === 4 && octets[0] === "127" && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function listenerHostHeaders(host: string, port: number): Set<string> {
  const normalized = host.toLowerCase();
  const address = normalized.includes(":") && !normalized.startsWith("[") ? `[${normalized}]` : normalized;
  const headers = new Set([`${address}:${port}`]);
  if (port === 80) headers.add(address);
  return headers;
}

function cookiesFromRequest(request: FastifyRequest): Map<string, string> {
  const result = new Map<string, string>();
  const header = request.headers.cookie;
  if (typeof header !== "string") return result;
  for (const field of header.split(";")) {
    const separator = field.indexOf("=");
    if (separator < 0) continue;
    result.set(field.slice(0, separator).trim(), field.slice(separator + 1).trim());
  }
  return result;
}

function tokensMatch(presented: string, expected: string): boolean {
  const presentedBytes = Buffer.from(presented, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (presentedBytes.length !== expectedBytes.length) {
    timingSafeEqual(expectedBytes, expectedBytes);
    return false;
  }
  return timingSafeEqual(presentedBytes, expectedBytes);
}

function cookie(name: string, value: string): string {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict`;
}

function setBrowserCookies(reply: FastifyReply, baseDir: string, bootstrapToken: string): void {
  const values = [cookie(BOOTSTRAP_COOKIE_NAME, bootstrapToken)];
  const operatorToken = loadGeneratedEnvironment(baseDir).AGENTWALL_OPERATOR_TOKEN;
  if (operatorToken) values.push(cookie(OPERATOR_COOKIE_NAME, operatorToken));
  reply.header("Set-Cookie", values);
}

function validationHook(schema: ZodType) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const parsed = schema.safeParse(request.body ?? {});
    if (parsed.success) {
      request.body = parsed.data;
      return;
    }
    await reply.status(400).send({
      error: "Invalid bootstrap action",
      issues: parsed.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })),
    });
  };
}

function allowedMutationOrigin(request: FastifyRequest): boolean {
  const origin = request.headers.origin;
  const host = request.headers.host;
  if (typeof origin !== "string" || typeof host !== "string") return false;
  try {
    const parsed = new URL(origin);
    return (parsed.protocol === "http:" || parsed.protocol === "https:")
      && parsed.host === host
      && isLoopbackHost(parsed.hostname);
  } catch {
    return false;
  }
}

function mutationGuard(bootstrapToken: string) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!allowedMutationOrigin(request)) {
      await reply.status(403).send({ error: "Bootstrap actions must originate from this local AgentWall page." });
      return;
    }
    const presented = cookiesFromRequest(request).get(BOOTSTRAP_COOKIE_NAME);
    if (!presented || !tokensMatch(presented, encodeURIComponent(bootstrapToken))) {
      await reply.status(401).send({ error: "Open the local AgentWall setup page before you use a bootstrap action." });
    }
  };
}

function setupState(baseDir: string): "missing" | "ready" {
  const required = [
    path.join(baseDir, "agentwall.config.yaml"),
    path.join(baseDir, "policy.yaml"),
    path.join(baseDir, ".agentwall", "operator.env"),
  ];
  return required.every((filePath) => fs.existsSync(filePath)) ? "ready" : "missing";
}

type BootstrapAsset = "bootstrap.html" | "bootstrap.js" | "styles.css" | "assets/brand/favicon.svg" | "assets/brand/agentwall-logo-mark.svg";

function staticAssetPath(fileName: BootstrapAsset): string {
  return path.resolve(__dirname, "..", "public", fileName);
}

function sendStaticAsset(reply: FastifyReply, fileName: BootstrapAsset): void {
  const assetPath = staticAssetPath(fileName);
  const contentType = fileName.endsWith(".html")
    ? "text/html; charset=utf-8"
    : fileName.endsWith(".js")
      ? "application/javascript; charset=utf-8"
      : fileName.endsWith(".css")
        ? "text/css; charset=utf-8"
        : "image/svg+xml";
  try {
    const content = fs.readFileSync(assetPath);
    reply.type(contentType).send(content);
  } catch {
    reply.status(404).type("text/plain; charset=utf-8").send("AgentWall bootstrap asset not found.\n");
  }
}

export function createBootstrapApp(options: BootstrapUiOptions): BootstrapApp {
  if (!isLoopbackHost(options.host)) {
    throw new Error("The AgentWall bootstrap UI can bind only to a loopback host.");
  }
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    throw new Error("The AgentWall bootstrap UI port must be between 1 and 65535.");
  }
  if (!Number.isInteger(options.servicePort) || options.servicePort < 1 || options.servicePort > 65535) {
    throw new Error("The AgentWall service port must be between 1 and 65535.");
  }

  const baseDir = path.resolve(options.baseDir);
  const spawnChild = options.spawnChild ?? nodeSpawn;
  const bootstrapToken = randomBytes(32).toString("hex");
  const app = Fastify({ logger: false });
  const allowedHostHeaders = listenerHostHeaders(options.host, options.port);
  let child: ChildProcess | null = null;
  let stopRequested = false;
  const childState: ChildState = {
    service: "stopped",
    mode: null,
    pid: null,
    lastExitCode: null,
    error: null,
  };

  app.addHook("onRequest", async (request, reply) => {
    const requestHost = request.headers.host?.toLowerCase();
    if (!requestHost || !allowedHostHeaders.has(requestHost)) {
      await reply.status(421).send({ error: "Use the configured local AgentWall bootstrap address." });
      return;
    }
    reply.header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  });

  app.get("/", async (_request, reply) => {
    setBrowserCookies(reply, baseDir, bootstrapToken);
    sendStaticAsset(reply, "bootstrap.html");
  });

  app.get("/bootstrap.js", async (_request, reply) => {
    sendStaticAsset(reply, "bootstrap.js");
  });

  app.get("/styles.css", async (_request, reply) => {
    sendStaticAsset(reply, "styles.css");
  });

  app.get("/assets/brand/favicon.svg", async (_request, reply) => {
    sendStaticAsset(reply, "assets/brand/favicon.svg");
  });

  app.get("/assets/brand/agentwall-logo-mark.svg", async (_request, reply) => {
    sendStaticAsset(reply, "assets/brand/agentwall-logo-mark.svg");
  });

  app.get("/api/bootstrap/status", async (_request, reply) => {
    setBrowserCookies(reply, baseDir, bootstrapToken);
    return reply.send({
      setup: setupState(baseDir),
      service: childState.service,
      mode: childState.mode,
      pid: childState.pid,
      lastExitCode: childState.lastExitCode,
      error: childState.error,
      dashboardUrl: `http://127.0.0.1:${options.servicePort}`,
    });
  });

  app.register(async (scope) => {
    await scope.register(rateLimit, { global: false });
    const guard = mutationGuard(bootstrapToken);

    scope.post("/api/bootstrap/setup", {
      config: { rateLimit: { max: 60, timeWindow: "1 minute" } },
      preValidation: validationHook(SETUP_ACTION_SCHEMA),
      preHandler: guard,
    }, async (request, reply) => {
      try {
        const result = createLocalOperatorFiles(baseDir, request.body as z.infer<typeof SETUP_ACTION_SCHEMA>);
        setBrowserCookies(reply, baseDir, bootstrapToken);
        return reply.send({
          ok: true,
          action: "setup",
          created: result.created,
          configPath: result.configPath,
          policyPath: result.policyPath,
          environmentPath: result.environmentPath,
          auditPath: result.auditPath,
          dashboardUrl: result.dashboardUrl,
        });
      } catch (error) {
        return reply.status(409).send({ error: error instanceof Error ? error.message : "AgentWall setup failed." });
      }
    });

    scope.post("/api/bootstrap/init", {
      config: { rateLimit: { max: 60, timeWindow: "1 minute" } },
      preValidation: validationHook(INIT_ACTION_SCHEMA),
      preHandler: guard,
    }, async (request, reply) => {
      const input = request.body as z.infer<typeof INIT_ACTION_SCHEMA>;
      const configPath = path.join(baseDir, "agentwall.config.yaml");
      const policyPath = path.join(baseDir, "policy.yaml");
      if (!input.force && (fs.existsSync(configPath) || fs.existsSync(policyPath))) {
        return reply.status(409).send({ error: "Refusing to overwrite existing AgentWall starter files. Set force to replace them." });
      }
      const result = writeStarterFiles(baseDir, input);
      setBrowserCookies(reply, baseDir, bootstrapToken);
      return reply.send({ ok: true, action: "init", configPath: result.configPath, policyPath: result.policyPath });
    });

    scope.post("/api/bootstrap/onboard", {
      config: { rateLimit: { max: 60, timeWindow: "1 minute" } },
      preValidation: validationHook(ONBOARD_ACTION_SCHEMA),
      preHandler: guard,
    }, async (request, reply) => {
      const input = request.body as z.infer<typeof ONBOARD_ACTION_SCHEMA>;
      try {
        const generatedEnvironment = loadGeneratedEnvironment(baseDir);
        const proxyPort = Number(generatedEnvironment.AGENTWALL_PROXY_PORT ?? 8899);
        const result = runOnboard({
          profileId: input.profileId,
          agentId: input.agentId,
          configPath: path.join(baseDir, "agentwall.config.yaml"),
          proxyHost: generatedEnvironment.AGENTWALL_PROXY_HOST ?? "127.0.0.1",
          proxyPort: Number.isInteger(proxyPort) && proxyPort > 0 && proxyPort <= 65535 ? proxyPort : 8899,
          allowedHosts: [],
          budgetWindowSeconds: 3600,
          budgetMaxRequests: 2000,
          force: false,
          json: false,
        });
        return reply.send({
          ok: true,
          action: "onboard",
          agentId: result.agentId,
          profileId: result.profile.id,
          env: result.envLines,
          warning: "Copy this environment now. AgentWall does not store the credential.",
          nextAction: `agentwall verify-capture --agent ${result.agentId}`,
        });
      } catch (error) {
        return reply.status(400).send({ error: error instanceof Error ? error.message : "AgentWall onboarding failed." });
      }
    });

    const startService = (mode: "production" | "development", reply: FastifyReply) => {
      if (child && (childState.service === "starting" || childState.service === "running")) {
        return reply.status(409).send({ error: "AgentWall is already active in this bootstrap session." });
      }

      const args = mode === "production"
        ? [path.join(baseDir, "dist", "index.js")]
        : [path.join(baseDir, "node_modules", "ts-node", "dist", "bin.js"), "src/index.ts"];
      childState.service = "starting";
      childState.mode = mode;
      childState.pid = null;
      childState.lastExitCode = null;
      childState.error = null;
      stopRequested = false;

      try {
        const nextChild = spawnChild(process.execPath, args, {
          cwd: baseDir,
          env: { ...process.env, ...loadGeneratedEnvironment(baseDir) },
          stdio: "inherit",
        });
        child = nextChild;
        childState.pid = nextChild.pid ?? null;
        nextChild.once("spawn", () => {
          if (child !== nextChild) return;
          childState.service = "running";
          childState.pid = nextChild.pid ?? null;
        });
        nextChild.once("error", (error) => {
          if (child !== nextChild) return;
          childState.service = "failed";
          childState.error = error.message;
          childState.pid = null;
          child = null;
        });
        nextChild.once("exit", (code) => {
          if (child !== nextChild) return;
          childState.service = stopRequested || code === 0 ? "stopped" : "failed";
          childState.lastExitCode = code;
          childState.error = stopRequested || code === 0 ? null : `AgentWall exited with status ${code ?? "unknown"}.`;
          childState.pid = null;
          child = null;
          stopRequested = false;
        });
        setBrowserCookies(reply, baseDir, bootstrapToken);
        return reply.status(202).send({ ok: true, action: mode === "production" ? "start" : "dev", service: childState.service, pid: childState.pid });
      } catch (error) {
        child = null;
        childState.service = "failed";
        childState.error = error instanceof Error ? error.message : "AgentWall could not start.";
        return reply.status(500).send({ error: childState.error });
      }
    };

    scope.post("/api/bootstrap/start", {
      config: { rateLimit: { max: 60, timeWindow: "1 minute" } },
      preValidation: validationHook(EMPTY_ACTION_SCHEMA),
      preHandler: guard,
    }, async (_request, reply) => startService("production", reply));

    scope.post("/api/bootstrap/dev", {
      config: { rateLimit: { max: 60, timeWindow: "1 minute" } },
      preValidation: validationHook(EMPTY_ACTION_SCHEMA),
      preHandler: guard,
    }, async (_request, reply) => startService("development", reply));

    scope.post("/api/bootstrap/stop", {
      config: { rateLimit: { max: 60, timeWindow: "1 minute" } },
      preValidation: validationHook(STOP_ACTION_SCHEMA),
      preHandler: guard,
    }, async (_request, reply) => {
      if (!child || (childState.service !== "starting" && childState.service !== "running")) {
        childState.service = "stopped";
        childState.pid = null;
        return reply.send({ ok: true, action: "stop", service: "stopped", message: "AgentWall is already stopped." });
      }
      stopRequested = true;
      const stopped = child.kill("SIGTERM");
      if (!stopped) {
        stopRequested = false;
        return reply.status(500).send({ error: "AgentWall did not accept the stop signal." });
      }
      return reply.send({ ok: true, action: "stop", service: childState.service, message: "The stop signal was sent." });
    });
  });
  app.addHook("onClose", async () => {
    if (child && (childState.service === "starting" || childState.service === "running")) {
      stopRequested = true;
      child.kill("SIGTERM");
    }
  });

  return app;

}

export async function runBootstrapUi(options: BootstrapUiOptions): Promise<void> {
  const app = createBootstrapApp(options);
  await app.listen({ host: options.host, port: options.port });
  console.log(`AgentWall setup UI: http://${options.host}:${options.port}`);
}
