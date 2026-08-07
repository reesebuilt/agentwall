import { randomUUID } from "crypto";
import { existsSync } from "fs";
import { basename, resolve } from "path";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AgentwallConfig } from "../config";
import type { ApprovalGate } from "../approval/gate";
import type { PolicyEngine } from "../policy/engine";
import type { RuntimeState } from "../dashboard/state";
import type { RuntimeFloodGuard } from "../runtime/floodguard";
import { isSameOriginRequest } from "../auth/operator";
import { operatorActionCatalog } from "../operator/action-catalog";
import type { OperatorActionId } from "../operator/action-catalog";
import { resolveTypedCommandAction } from "../operator/command-allowlist";
import type { CommandAllowlistOptions } from "../operator/command-allowlist";
import { runFleetAction, fleetDoctorLines } from "../fleet/command";
import { runAnchorPass, runVerify } from "../audit/anchor-service";
import { runVerifyCapture } from "../capture/verify";
import { runMcpHttpWrap } from "../mcp/wrap";
import type { McpHttpHandle } from "../mcp/http";
import { runPerimeterCommand } from "../perimeter";
import { runSandboxCommand } from "../sandbox";
import { runInterceptCommand } from "../intercept";
import { DECOY_KINDS, generateDecoy, loadDecoys, saveDecoys } from "../decoy";
import { formatRationaleReport, parseRationaleArgs, runRationale } from "../rationale";
import { packageVersion } from "../version";
import { scanText } from "../planes/identity/dlp";

const confirm = z.boolean().optional();
const commandFields = {
  command: z.string().min(1).max(128),
  args: z.array(z.string().max(8_192)).max(256).default([]),
  workingDirectory: z.string().min(1).max(4_096).optional(),
};
const sessionFields = {
  sessionId: z.string().min(1).max(256),
  note: z.string().max(2_000).optional(),
  confirm,
};
const perimeterFields = {
  agentUid: z.number().int().nonnegative().optional(),
  proxyUid: z.number().int().nonnegative().optional(),
  proxyPort: z.number().int().min(1).max(65_535).optional(),
  dnsResolver: z.string().min(1).max(255).optional(),
  agentGid: z.number().int().nonnegative().optional(),
  allowLoopback: z.boolean().optional(),
};
const mcpHttpFields = {
  upstreamUrl: z.string().min(1).max(2_048).url(),
  listenPort: z.number().int().min(0).max(65_535).default(0),
  listenHost: z.enum(["127.0.0.1", "localhost", "::1"]).default("127.0.0.1"),
  serverName: z.string().min(1).max(256).optional(),
  agentId: z.string().min(1).max(256).optional(),
  baselineMode: z.enum(["off", "learn", "lock"]).default("off"),
  baselineFile: z.string().min(1).max(4_096).optional(),
};

export const OperatorActionSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("approval-mode"), mode: z.enum(["auto", "always", "never"]), confirm }).strict(),
  z.object({ action: z.literal("shield"), durationMs: z.number().int().positive().optional(), confirm }).strict(),
  z.object({ action: z.literal("normal"), confirm }).strict(),
  z.object({ action: z.literal("session-boost"), sessionId: z.string().min(1), multiplier: z.number().min(1).max(100).optional(), durationMs: z.number().int().positive().optional(), confirm }).strict(),
  z.object({ action: z.literal("session-reset"), sessionId: z.string().min(1), confirm }).strict(),
  z.object({ action: z.literal("mcp-http-wrap"), ...mcpHttpFields, confirm }).strict(),
  z.object({ action: z.literal("mcp-http-stop"), wrapId: z.string().min(1).max(128), confirm }).strict(),
  z.object({ action: z.literal("pause"), ...sessionFields }).strict(),
  z.object({ action: z.literal("resume"), ...sessionFields }).strict(),
  z.object({ action: z.literal("terminate"), ...sessionFields }).strict(),
  z.object({ action: z.literal("fleet-issue"), agentId: z.string().min(1), confirm }).strict(),
  z.object({ action: z.literal("fleet-rotate"), agentId: z.string().min(1), overlapSeconds: z.number().int().nonnegative().optional(), confirm }).strict(),
  z.object({ action: z.literal("fleet-revoke"), agentId: z.string().min(1).optional(), credentialId: z.string().min(1).optional(), reason: z.string().max(2_000).optional(), confirm }).strict(),
  z.object({ action: z.literal("anchor"), confirm }).strict(),
  z.object({ action: z.literal("verify-capture"), agentId: z.string().min(1), host: z.string().min(1).max(255).optional(), timeoutMs: z.number().int().positive().optional(), ...commandFields, confirm }).strict(),
  z.object({ action: z.literal("mcp-wrap"), serverName: z.string().min(1).max(256).optional(), agentId: z.string().min(1).max(256).optional(), ...commandFields, confirm }).strict(),
  z.object({ action: z.literal("perimeter-install"), ...perimeterFields, confirm }).strict(),
  z.object({ action: z.literal("perimeter-rollback"), confirm }).strict(),
  z.object({ action: z.literal("perimeter-run"), ...perimeterFields, ...commandFields, confirm }).strict(),
  z.object({ action: z.literal("sandbox-build"), confirm }).strict(),
  z.object({ action: z.literal("sandbox-run"), ...commandFields, confirm }).strict(),
  z.object({ action: z.literal("intercept-init"), caDir: z.string().min(1).max(4_096).optional(), days: z.number().int().positive().max(3_650).optional(), confirm }).strict(),
  z.object({ action: z.literal("intercept-trust"), caDir: z.string().min(1).max(4_096).optional(), confirm }).strict(),
  z.object({ action: z.literal("decoy-generate"), kind: z.enum(DECOY_KINDS), label: z.string().min(1).max(256).optional(), out: z.string().min(1).max(4_096).optional(), confirm }).strict(),
  z.object({ action: z.literal("doctor") }).strict(),
  z.object({ action: z.literal("status") }).strict(),
  z.object({ action: z.literal("verify") }).strict(),
  z.object({ action: z.literal("fleet-list") }).strict(),
  z.object({ action: z.literal("mcp-http-list") }).strict(),
  z.object({ action: z.literal("perimeter-plan"), ...perimeterFields }).strict(),
  z.object({ action: z.literal("perimeter-status"), ...perimeterFields }).strict(),
  z.object({ action: z.literal("perimeter-verify"), ...perimeterFields }).strict(),
  z.object({ action: z.literal("sandbox-probe") }).strict(),
  z.object({ action: z.literal("sandbox-plan") }).strict(),
  z.object({ action: z.literal("intercept-status"), caDir: z.string().min(1).max(4_096).optional() }).strict(),
  z.object({ action: z.literal("decoy-list"), file: z.string().min(1).max(4_096).optional() }).strict(),
  z.object({ action: z.literal("why"), subject: z.string().min(1).max(100_000), kind: z.enum(["url", "text", "tool"]).optional(), tool: z.string().min(1).max(256).optional(), toolArgs: z.string().max(100_000).optional() }).strict(),
  z.object({ action: z.literal("version") }).strict(),
  z.object({ action: z.literal("help") }).strict(),
]);

export type OperatorAction = z.infer<typeof OperatorActionSchema>;

export interface OperatorActionResult {
  ok: boolean;
  action: string;
  status: string;
  message: string;
  next: string;
  data?: unknown;
}

export interface OperatorRouteContext {
  config: AgentwallConfig;
  engine: PolicyEngine;
  gate: ApprovalGate;
  runtime: RuntimeState;
  floodGuard: RuntimeFloodGuard;
  auditPath?: string;
  commandAllowlist: CommandAllowlistOptions;
  decoyPath?: string;
}

interface ManagedMcpHttpWrap {
  handle: McpHttpHandle;
  endpoint: string;
  upstream: string;
  serverName: string;
  agentId: string;
  baselineMode: "off" | "learn" | "lock";
  startedAt: string;
}

function result(
  action: string,
  ok: boolean,
  status: string,
  message: string,
  next: string,
  data?: unknown,
): OperatorActionResult {
  return { ok, action, status, message, next, ...(data === undefined ? {} : { data }) };
}

function perimeterArgs(input: {
  agentUid?: number;
  proxyUid?: number;
  proxyPort?: number;
  dnsResolver?: string;
  agentGid?: number;
  allowLoopback?: boolean;
}): string[] {
  const args: string[] = [];
  if (input.agentUid !== undefined) args.push("--agent-uid", String(input.agentUid));
  if (input.proxyUid !== undefined) args.push("--proxy-uid", String(input.proxyUid));
  if (input.proxyPort !== undefined) args.push("--proxy-port", String(input.proxyPort));
  if (input.dnsResolver !== undefined) args.push("--dns-resolver", input.dnsResolver);
  if (input.agentGid !== undefined) args.push("--agent-gid", String(input.agentGid));
  if (input.allowLoopback === true) args.push("--allow-loopback");
  return args;
}

async function commandResult(
  action: OperatorActionId,
  runner: () => number | Promise<number>,
  successMessage: string,
  next: string,
): Promise<OperatorActionResult> {
  const exitCode = await runner();
  return result(
    action,
    exitCode === 0,
    exitCode === 0 ? "completed" : "failed",
    exitCode === 0 ? successMessage : `${successMessage.replace(/\.$/, "")} failed with exit code ${exitCode}.`,
    next,
    { output: `Command exited with status ${exitCode}.`, exitCode },
  );
}

async function executeAction(
  action: OperatorAction,
  context: OperatorRouteContext,
  managedMcpHttpWraps: Map<string, ManagedMcpHttpWrap>,
): Promise<OperatorActionResult> {
  const configPath = context.config.sourcePath;
  switch (action.action) {
    case "approval-mode": {
      context.gate.setMode(action.mode);
      context.runtime.updateApprovalMode(action.mode);
      return result(action.action, true, "completed", `Approval mode is ${action.mode}.`, "Review pending approvals.", { mode: action.mode });
    }
    case "shield": {
      const durationMs = action.durationMs ?? context.config.runtimeGuards?.shield?.defaultDurationMs ?? 600_000;
      const state = context.floodGuard.setShieldMode(true, Date.now(), durationMs);
      return result(action.action, true, "completed", "FloodGuard shield mode is active.", "Review the hottest session.", { mode: state.mode, shieldUntil: state.shieldUntil });
    }
    case "normal": {
      const state = context.floodGuard.setShieldMode(false, Date.now());
      return result(action.action, true, "completed", "FloodGuard normal mode is active.", "Review runtime status.", { mode: state.mode });
    }
    case "session-boost": {
      const durationMs = action.durationMs ?? context.config.runtimeGuards?.shield?.defaultDurationMs ?? 600_000;
      const override = context.floodGuard.setSessionOverride(action.sessionId, action.multiplier ?? 1.5, Date.now(), durationMs);
      return result(action.action, true, "completed", `Session ${action.sessionId} has higher limits.`, "Review the session before the override expires.", { override });
    }
    case "session-reset": {
      const cleared = context.floodGuard.clearSessionOverride(action.sessionId);
      return result(action.action, true, "completed", `Session ${action.sessionId} uses normal limits.`, "Review the session status.", { cleared: cleared.cleared });
    }
    case "pause":
    case "resume":
    case "terminate": {
      const controlled = context.runtime.controlSession(action.sessionId, action.action, action.note);
      if (!controlled.ok) return result(action.action, false, "failed", controlled.message, "Refresh status and select an active session.");
      return result(action.action, true, "completed", `Session ${action.sessionId} is ${controlled.session.status}.`, "Review the session status.", { session: controlled.session });
    }
    case "fleet-issue":
    case "fleet-rotate":
    case "fleet-revoke": {
      const fleet = action.action === "fleet-issue"
        ? runFleetAction({ operation: "issue", agentId: action.agentId, configPath })
        : action.action === "fleet-rotate"
          ? runFleetAction({ operation: "rotate", agentId: action.agentId, overlapSeconds: action.overlapSeconds, configPath })
          : runFleetAction({ operation: "revoke", agentId: action.agentId, credentialId: action.credentialId, reason: action.reason, configPath });
      const message = action.action === "fleet-issue"
        ? `Credential ${fleet.credentialId} is issued for ${fleet.agentId}.`
        : action.action === "fleet-rotate"
          ? `Credential ${fleet.credentialId} replaces ${fleet.previousCredentialId}.`
          : `${fleet.credentials?.length ?? 0} credential record is revoked.`;
      return result(action.action, true, "completed", message, fleet.notes[0] ?? "Review the fleet credential list.", fleet);
    }
    case "anchor": {
      if (!context.auditPath) throw new Error("No audit file is configured.");
      const anchored = await runAnchorPass({ auditPath: context.auditPath });
      if (!anchored.anchored) return result(action.action, false, "failed", `No checkpoint was created: ${anchored.reason}.`, "Write audit records and try again.");
      return result(action.action, true, "completed", "The audit checkpoint is created.", "Run audit verification after the anchor confirms.", { checkpoint: anchored.checkpoint, covered: anchored.covered, segments: anchored.segments });
    }
    case "verify-capture": {
      if (!context.auditPath) throw new Error("No audit file is configured.");
      const command = resolveTypedCommandAction({ command: action.command, args: action.args, confirm: true, workingDirectory: action.workingDirectory }, context.commandAllowlist);
      const report = await runVerifyCapture({
        agentId: action.agentId,
        auditPath: context.auditPath,
        configPath,
        commandArgv: [command.command, ...command.args],
        host: action.host ?? "127.0.0.1",
        timeoutMs: action.timeoutMs ?? 30_000,
        settleMs: 1_000,
      });
      const data = { agentId: report.agentId, captured: report.captured, outcome: report.outcome, declaredTier: report.declaredTier, observedTier: report.observedTier, assertions: report.assertions, limits: report.limits };
      return result(action.action, report.captured, "completed", report.captured ? "The selected request appears in the audit chain." : "The selected request is not proven in the audit chain.", "Run audit verification for chain integrity.", data);
    }
    case "mcp-wrap": {
      const command = resolveTypedCommandAction(
        { command: action.command, args: action.args, confirm: true, workingDirectory: action.workingDirectory },
        context.commandAllowlist,
      );
      const argv = [
        "agentwall",
        "mcp",
        "wrap",
        ...(action.serverName === undefined ? [] : ["--server-name", action.serverName]),
        ...(action.agentId === undefined ? [] : ["--agent-id", action.agentId]),
        "--",
        command.command,
        ...command.args,
      ];
      return result(
        action.action,
        true,
        "planned",
        "The MCP stdio wrapper plan is ready.",
        "Copy the command details into the client-owned MCP configuration.",
        { output: JSON.stringify({ argv, workingDirectory: command.workingDirectory }, null, 2), argv, workingDirectory: command.workingDirectory },
      );
    }
    case "mcp-http-wrap": {
      const upstream = new URL(action.upstreamUrl);
      const handle = await runMcpHttpWrap({
        upstreamUrl: action.upstreamUrl,
        listenPort: action.listenPort,
        listenHost: action.listenHost,
        serverName: action.serverName,
        agentId: action.agentId,
        baselineMode: action.baselineMode,
        baselineFile: action.baselineFile ?? resolve(process.cwd(), ".agentwall", "mcp-baselines.json"),
        engine: context.engine,
        durableAudit: false,
      });
      const endpointHost = action.listenHost.includes(":") ? `[${action.listenHost}]` : action.listenHost;
      const endpoint = `http://${endpointHost}:${handle.port}/mcp`;
      const wrapId = randomUUID();
      managedMcpHttpWraps.set(wrapId, {
        handle,
        endpoint,
        upstream: `${upstream.protocol}//${upstream.host}${upstream.pathname}`,
        serverName: action.serverName ?? upstream.host,
        agentId: action.agentId ?? "unattributed",
        baselineMode: action.baselineMode,
        startedAt: new Date().toISOString(),
      });
      return result(
        action.action,
        true,
        "completed",
        "The MCP HTTP wrapper is running.",
        "Point the MCP client at the local wrapper URL.",
        { wrapId, endpoint, upstream: `${upstream.protocol}//${upstream.host}${upstream.pathname}`, baselineMode: action.baselineMode },
      );
    }
    case "mcp-http-stop": {
      const managed = managedMcpHttpWraps.get(action.wrapId);
      if (!managed) return result(action.action, false, "not-found", "The MCP HTTP wrapper was not found.", "List the active MCP HTTP wrappers and select one.");
      await managed.handle.close();
      managedMcpHttpWraps.delete(action.wrapId);
      return result(action.action, true, "completed", "The MCP HTTP wrapper is stopped.", "List the active MCP HTTP wrappers to confirm the state.", { wrapId: action.wrapId, endpoint: managed.endpoint });
    }
    case "perimeter-install":
      return commandResult(action.action, () => runPerimeterCommand(["install", ...perimeterArgs(action)]), "The host network perimeter is installed.", "Run perimeter verification.");
    case "perimeter-rollback":
      return commandResult(action.action, () => runPerimeterCommand(["rollback"]), "The host network perimeter is removed.", "Review perimeter status.");
    case "perimeter-run": {
      const command = resolveTypedCommandAction({ command: action.command, args: action.args, confirm: true, workingDirectory: action.workingDirectory }, context.commandAllowlist);
      return commandResult(action.action, () => runPerimeterCommand(["run", ...perimeterArgs(action), "--", command.command, ...command.args]), "The declared command completed inside the perimeter.", "Review perimeter status and audit evidence.");
    }
    case "sandbox-build":
      return commandResult(action.action, () => runSandboxCommand(["build"]), "The sandbox launcher is built.", "Run the sandbox probe.");
    case "sandbox-run": {
      const command = resolveTypedCommandAction({ command: action.command, args: action.args, confirm: true, workingDirectory: action.workingDirectory }, context.commandAllowlist);
      return commandResult(action.action, () => runSandboxCommand(["run", "--workdir", command.workingDirectory, "--", command.command, ...command.args]), "The declared command completed in the sandbox.", "Review the command output and sandbox limits.");
    }
    case "intercept-init": {
      const args = ["init", ...(action.caDir ? ["--ca-dir", action.caDir] : []), ...(action.days ? ["--days", String(action.days)] : [])];
      return commandResult(action.action, () => runInterceptCommand(args), "The interception certificate authority is created.", "Review trust steps before host changes.");
    }
    case "intercept-trust": {
      const args = ["trust", ...(action.caDir ? ["--ca-dir", action.caDir] : [])];
      return commandResult(action.action, () => runInterceptCommand(args), "The certificate trust plan is ready.", "Apply only the trust steps that match this host.");
    }
    case "decoy-generate": {
      const path = action.out ?? context.decoyPath ?? resolve(process.cwd(), ".agentwall", "decoys.json");
      const tokens = existsSync(path) ? loadDecoys(path) : [];
      const token = generateDecoy(action.kind, action.label);
      saveDecoys(path, [...tokens, token]);
      return result(action.action, true, "completed", `Decoy ${token.id} is stored.`, "Plant the decoy in the selected agent environment.", { id: token.id, kind: token.kind, label: token.label, path });
    }
    case "doctor": {
      const lines = fleetDoctorLines(configPath);
      const output = lines.length === 0 ? "No fleet credential problems were found." : lines.map((line) => `${line.level}: ${line.text}`).join("\n");
      return result(action.action, true, "completed", "The local checks are complete.", "Fix each reported problem, then run doctor again.", { output });
    }
    case "status": {
      const ruleCount = context.engine.snapshot().getRules().length;
      const snapshot = context.runtime.getSnapshot(ruleCount);
      const output = `Service ${snapshot.service.status}; approval mode ${context.gate.getMode()}.`;
      return result(action.action, true, "completed", "Runtime status is ready.", "Review sessions and pending approvals.", { output, service: snapshot.service, approvalMode: context.gate.getMode(), floodGuard: context.floodGuard.getTelemetrySnapshot() });
    }
    case "verify": {
      if (!context.auditPath) throw new Error("No audit file is configured.");
      const report = runVerify({ auditPath: context.auditPath });
      return result(action.action, report.ok, "completed", report.ok ? "All audit integrity layers pass." : "One or more audit integrity layers fail.", "Review each failed layer before you trust the evidence.", { output: report.layers.map((layer) => `${layer.ok ? "PASS" : "FAIL"} ${layer.name}: ${layer.detail}`).join("\n"), report });
    }
    case "fleet-list": {
      const fleet = runFleetAction({ operation: "list", configPath });
      return result(action.action, true, "completed", "Fleet credential status is ready.", "Rotate or revoke credentials that need attention.", { ...fleet, output: `${fleet.credentials?.length ?? 0} credential records.` });
    }
    case "mcp-http-list": {
      const wrappers = [...managedMcpHttpWraps.entries()].map(([wrapId, managed]) => ({
        wrapId,
        endpoint: managed.endpoint,
        upstream: managed.upstream,
        serverName: managed.serverName,
        agentId: managed.agentId,
        baselineMode: managed.baselineMode,
        startedAt: managed.startedAt,
      }));
      const output = wrappers.length === 0
        ? "No MCP HTTP wrappers are running."
        : wrappers.map((wrapper) => [
            `Wrapper ID: ${wrapper.wrapId}`,
            `Server: ${wrapper.serverName}`,
            `Agent: ${wrapper.agentId}`,
            `Endpoint: ${wrapper.endpoint}`,
            `Upstream: ${wrapper.upstream}`,
            `Inventory mode: ${wrapper.baselineMode}`,
            `Started: ${wrapper.startedAt}`,
          ].join("\n")).join("\n\n");
      return result(action.action, true, "completed", "The MCP HTTP wrapper list is ready.", "Stop a wrapper when the client no longer needs it.", { wrappers, output });
    }
    case "perimeter-plan":
    case "perimeter-status":
    case "perimeter-verify": {
      const operation = action.action.slice("perimeter-".length);
      return commandResult(action.action, () => runPerimeterCommand([operation, ...perimeterArgs(action)]), `The perimeter ${operation} check is complete.`, "Review the reported host boundary.");
    }
    case "sandbox-probe":
      return commandResult(action.action, () => runSandboxCommand(["probe"]), "The sandbox capability probe is complete.", "Review each refusal and limit.");
    case "sandbox-plan":
      return commandResult(action.action, () => runSandboxCommand(["plan"]), "The sandbox plan is ready.", "Review the plan before a sandbox run.");
    case "intercept-status": {
      const args = ["status", ...(action.caDir ? ["--ca-dir", action.caDir] : [])];
      return commandResult(action.action, () => runInterceptCommand(args), "The interception status is ready.", "Review certificate age and key permissions.");
    }
    case "decoy-list": {
      const path = action.file ?? context.decoyPath ?? resolve(process.cwd(), ".agentwall", "decoys.json");
      const tokens = existsSync(path) ? loadDecoys(path) : [];
      const decoys = tokens.map(({ id, kind, label, createdAt }) => ({ id, kind, label, createdAt }));
      return result(action.action, true, "completed", "The decoy list is ready.", "Generate a decoy when the list is empty.", { output: `${decoys.length} decoys.`, decoys, path });
    }
    case "why": {
      const flags: Record<string, string> = {};
      if (action.kind) flags.kind = action.kind;
      if (action.tool) flags.tool = action.tool;
      if (action.toolArgs) flags.args = action.toolArgs;
      const request = parseRationaleArgs(flags, [action.subject]);
      const rationale = runRationale(request, context.engine);
      const report = formatRationaleReport(rationale);
      const output = scanText(report, true).redactedText ?? report;
      return result(action.action, true, "completed", "The policy explanation is ready.", "Change only the narrow control named by the explanation.", { output, decision: rationale.decision, findingCount: rationale.findings.length });
    }
    case "version":
      return result(action.action, true, "completed", `AgentWall version ${packageVersion} is running.`, "Check release notes before an upgrade.", { output: packageVersion, version: packageVersion });
    case "help":
      return result(action.action, true, "completed", "The operator command list is ready.", "Select one action from the catalog.", { output: operatorActionCatalog.map((entry) => entry.cli).join("\n") });
  }
}

function rejectCrossOriginMutation(req: FastifyRequest, entry: { mutating: boolean }, reply: FastifyReply, action: string): boolean {
  if (!entry.mutating || req.headers.origin === undefined || isSameOriginRequest(req)) return false;
  void reply.status(403).send(result(action, false, "forbidden", "This change came from a different origin.", "Use the local AgentWall operator page."));
  return true;
}
function operatorActionCatalogFor(context: CommandAllowlistOptions): readonly typeof operatorActionCatalog[number][] {
  const commandNames = new Set<string>();
  if (context.agentwallBinary) commandNames.add("agentwall");
  if (context.sandboxLauncher) commandNames.add(basename(context.sandboxLauncher));
  for (const name of Object.keys(context.mcpBinaries ?? {})) commandNames.add(name);
  const commandOptions = [...commandNames].sort();

  return operatorActionCatalog.map((entry) => ({
    ...entry,
    fields: entry.fields.map((field) =>
      field.name === "command" ? { ...field, options: [...commandOptions] } : field
    ),
  }));
}


export async function operatorRoutes(app: FastifyInstance, context: OperatorRouteContext): Promise<void> {
  const managedMcpHttpWraps = new Map<string, ManagedMcpHttpWrap>();
  app.addHook("onClose", async () => {
    const handles = [...managedMcpHttpWraps.values()].map((managed) => managed.handle);
    managedMcpHttpWraps.clear();
    await Promise.allSettled(handles.map((handle) => handle.close()));
  });
  app.get("/api/operator/actions", async (_req, reply) => reply.send({ actions: operatorActionCatalogFor(context.commandAllowlist) }));

  app.post("/api/operator/actions", async (req, reply) => {
    let requested = "invalid";
    if (req.body !== null && typeof req.body === "object" && "action" in req.body && typeof req.body.action === "string") {
      requested = req.body.action.slice(0, 128);
    }
    const parsed = OperatorActionSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send(result(requested, false, "invalid", "The operator action fields are invalid.", "Refresh the action catalog and correct the named fields."));
    }

    const entry = operatorActionCatalog.find((candidate) => candidate.id === parsed.data.action);
    if (!entry) {
      return reply.status(400).send(result(parsed.data.action, false, "invalid", "The operator action is not allowlisted.", "Refresh the action catalog and select a listed action."));
    }
    if (rejectCrossOriginMutation(req, entry, reply, parsed.data.action)) return;
    const confirmed = "confirm" in parsed.data ? parsed.data.confirm : undefined;
    if (entry.mutating && confirmed !== true) {
      return reply.status(409).send(result(parsed.data.action, false, "confirmation-required", `Confirm the ${entry.label.toLowerCase()} action before execution.`, "Set confirm to true after you review the plan.", { plan: entry.cli }));
    }

    try {
      const actionResult = await executeAction(parsed.data, context, managedMcpHttpWraps);
      return reply.status(actionResult.ok || !entry.mutating ? 200 : 409).send(actionResult);
    } catch (error) {
      const message = error instanceof Error ? error.message : "The operator action failed.";
      return reply.status(400).send(result(parsed.data.action, false, "failed", message.endsWith(".") ? message : `${message}.`, "Correct the action fields or review local status before you try again."));
    }
  });
}
