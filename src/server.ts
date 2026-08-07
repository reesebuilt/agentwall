import Fastify, { FastifyInstance } from "fastify";
import { PolicyEngine } from "./policy/engine";
import { builtinRules } from "./policy/rules";
import { ApprovalGate } from "./approval/gate";
import { healthRoutes } from "./routes/health";
import { policyRoutes } from "./routes/policy";
import { inspectRoutes } from "./routes/inspect";
import { approvalRoutes } from "./routes/approval";
import { registerAuditSink, seedAuditChain, stdoutSink } from "./audit/logger";
import { createFileSink, resumeChainState } from "./audit/file-sink";
import { startAnchorSchedule } from "./audit/anchor-service";
import { AgentwallConfig, defaultRuntimeGuards } from "./config";
import { RuntimeState } from "./dashboard/state";
import { registerOperatorAuth, operatorAuthConfigured } from "./auth/operator";
import { dashboardRoutes } from "./routes/dashboard";
import { uiRoutes } from "./routes/ui";
import { telegramTestBotRoutes } from "./routes/telegram";
import { communicationChannelRoutes } from "./routes/communication-channel";
import { damageControlRoutes } from "./routes/damage-control";
import { lockdownRoutes } from "./routes/lockdown";
import { initLockdown } from "./runtime/lockdown";
import { probeRoutes } from "./routes/probe";
import { fleetRoutes } from "./routes/fleet";
import { evidenceRoutes } from "./routes/evidence";
import { fleetEvidenceRoutes } from "./routes/fleet-evidence";
import { FileBackedPolicyRuntime, ReloadResult } from "./policy/runtime";
import { PolicySnapshot } from "./policy/engine";
import { ReloadCoordinator } from "./runtime/reload";
import { reloadRoutes } from "./routes/reload";
import { RuntimeFloodGuard } from "./runtime/floodguard";
import { createDecisionTraceExporter } from "./telemetry/otel";
import { basename, resolve } from "path";
import { operatorRoutes } from "./routes/operator";
import { locateHelper } from "./sandbox";

function configuredMcpBinaries(value: string | undefined): Record<string, string> {
  const binaries: Record<string, string> = {};
  for (const entry of value?.split(",") ?? []) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf("=");
    const executable = separator < 0 ? trimmed : trimmed.slice(separator + 1).trim();
    const name = separator < 0 ? basename(executable) : trimmed.slice(0, separator).trim();
    if (name && executable) binaries[name] = executable;
  }
  return binaries;
}

declare module "fastify" {
  interface FastifyRequest {
    /**
     * The ruleset this request is being served under, pinned once when it arrived.
     *
     * A reload during the request swaps the engine's pointer and leaves this one alone, so a
     * request cannot straddle two rulesets no matter how many times it evaluates or what it
     * awaits in between.
     */
    policySnapshot?: PolicySnapshot;
  }
}

export interface AgentwallServer {
  app: FastifyInstance;
  engine: PolicyEngine;
  gate: ApprovalGate;
  runtime: RuntimeState;
  policyRuntime?: FileBackedPolicyRuntime;
  /**
   * Config and policy reload. Replaces the previous `reloadPolicy` closure, which reloaded
   * rules only, recorded nothing on the chain, and had no caller outside a test.
   */
  reloadCoordinator: ReloadCoordinator;
}

export async function buildServer(config: AgentwallConfig): Promise<AgentwallServer> {
  const app = Fastify({
    logger: { level: config.logLevel },
  });

  app.addHook("onRequest", async (_req, reply) => {
    reply.header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    reply.header("Cross-Origin-Opener-Policy", "same-origin");
  });

  // Audit: stdout stays the ops stream; the chain gets its own file that nothing else
  // writes to. The path is EXPLICIT with no default: a server must not invent a location
  // in $HOME for security-critical data, and a default here caused the test suite to write
  // 589 records into the operator's real chain and then resume from it. Unset means
  // stdout-only, the prior behaviour.
  const auditPath = process.env.AGENTWALL_AUDIT_FILE;
  if (auditPath) {
    const resumed = resumeChainState(auditPath);
    seedAuditChain(resumed.state);
    // Durable: this file is what `verify` walks, so a record it refuses is a record that
    // does not exist and the chain must not link across it.
    registerAuditSink(createFileSink(auditPath), { durable: true });
    if (resumed.discontinuity) {
      app.log.warn({ auditPath, reason: resumed.discontinuity },
        "audit chain discontinuity: starting a NEW chain");
    } else if (resumed.state.chainIndex > 0) {
      app.log.info({ auditPath, resumedAt: resumed.state.chainIndex },
        "audit chain resumed from prior run");
    }
  }
  registerAuditSink(stdoutSink);

  // Emergency stop: wired here so the signal and sentinel channels exist as early as the
  // audit stream that records them. Idempotent, so rebuilding a server does not stack a
  // second SIGUSR1 listener or a second poll timer. No path in the environment simply
  // leaves the sentinel channel off; the other three sources are unaffected.
  initLockdown({ sentinelPath: process.env.AGENTWALL_LOCKDOWN_FILE });

  const policyRuntime = config.policy.configPath
    ? new FileBackedPolicyRuntime(config.policy.configPath, { logger: app.log })
    : undefined;
  const engine = new PolicyEngine(
    [...builtinRules, ...(policyRuntime?.getRules() ?? [])],
    config.policy.defaultDecision
  );
  const gate = new ApprovalGate(
    config.approval.mode,
    config.approval.timeoutMs,
    config.approval.backend,
    config.approval.persistencePath,
    {
      webhookUrl: config.approval.webhookUrl,
      logger: app.log,
    }
  );
  const runtime = new RuntimeState(config);
  const floodGuard = new RuntimeFloodGuard(config.runtimeGuards ?? defaultRuntimeGuards);
  const telemetry = createDecisionTraceExporter(config.telemetry, app.log);
  runtime.hydrateApprovalQueue(gate.getPersistedPending());


  // Pin the ruleset for the life of the request, before anything can evaluate against it.
  //
  // A reload replaces the engine's snapshot pointer; it does not mutate the snapshot this holds,
  // so a request that started under one policy finishes under it. Before this hook the
  // guarantee was incidental: PolicyEngine.evaluate is synchronous and reads the rules array
  // once, so no single evaluation could tear, but nothing stopped a handler that evaluates
  // twice, or awaits before evaluating, from straddling a swap. That is a property that
  // survives only until somebody makes a handler async, which is not a guarantee.
  //
  // Costs one property assignment and no allocation: snapshot() hands back the current object.
  app.addHook("onRequest", async (req) => {
    req.policySnapshot = engine.snapshot();
  });

  const reloadCoordinator = new ReloadCoordinator({
    engine,
    config,
    policyRuntime,
    logger: app.log,
    // Pino accepts a level assignment at runtime. Routed through a closure so the coordinator
    // does not need the Fastify instance, and validated before it is called: an unrecognised
    // level makes this throw.
    setLogLevel: (level: string) => {
      app.log.level = level;
    },
  });

  // The pre-existing policy-file watcher. It validates and reloads inside the runtime and hands
  // the result here, so the only thing added is moving the engine and getting the change on the
  // chain, which this path previously did not do. The before-state for the diff comes from the
  // coordinator's own cache, because the runtime has already swapped by the time this fires.
  //
  // Deliberately NOT extended to the config file: an explicit trigger is the right shape for a
  // policy surface, and a config change that needs a restart cannot be honoured by a watcher.
  policyRuntime?.start((result: ReloadResult) => {
    reloadCoordinator.applyExternalReload(result, { source: "watch" });
  });

  app.addHook("onClose", async () => {
    policyRuntime?.stop();
    reloadCoordinator.dispose();
    gate.close();
  });

  // Auth BEFORE any route registers. Allowlist model: everything is protected
  // unless named public, so a route added later is guarded by default rather than
  // silently open until somebody remembers. Health stays public so a liveness probe
  // does not need a credential.
  const authCfg = { allowLoopbackDev: process.env.AGENTWALL_ALLOW_LOOPBACK_DEV === "1" };
  registerOperatorAuth(app, authCfg);
  if (!operatorAuthConfigured(authCfg)) {
    // Loud, because the failure mode is a service that refuses every request and
    // an operator who cannot tell why.
    app.log.warn(
      "No operator auth configured: set AGENTWALL_OPERATOR_TOKEN, or AGENTWALL_ALLOW_LOOPBACK_DEV=1 for local development. All non-health routes will return 401.",
    );
  }

  await healthRoutes(app);
  await policyRoutes(app, engine, runtime, floodGuard, telemetry);
  await inspectRoutes(app, config, runtime, telemetry);
  await approvalRoutes(app, gate, runtime, floodGuard);
  await telegramTestBotRoutes(app, engine, runtime);
  await communicationChannelRoutes(app, engine, runtime);
  await damageControlRoutes(app, engine, runtime);
  await dashboardRoutes(app, config, engine, gate, runtime, floodGuard, policyRuntime, reloadCoordinator);
  await operatorRoutes(app, {
    config,
    engine,
    gate,
    runtime,
    floodGuard,
    auditPath,
    commandAllowlist: {
      workingDirectoryRoot: process.cwd(),
      agentwallBinary: resolve(process.argv[1] ?? process.execPath),
      sandboxLauncher: locateHelper().path ?? undefined,
      mcpBinaries: configuredMcpBinaries(process.env.AGENTWALL_OPERATOR_MCP_BINARIES),
    },
    decoyPath: process.env.AGENTWALL_DECOY_FILE,
  });
  await uiRoutes(app);
  await lockdownRoutes(app);
  await probeRoutes(app, engine, runtime);
  await reloadRoutes(app, reloadCoordinator);
  await fleetRoutes(app);
  await evidenceRoutes(app, auditPath);
  // Registered after the single-host viewer so its `/evidence/*` mutating block is already in
  // place. The fleet surface installs its own 405s over its own paths regardless, because a
  // read-only contract that depends on another module having been registered first is not a
  // contract. The sources file is separate from the audit file on purpose: an aggregator is
  // usually not a host that runs agents, and requiring it to have a local chain to show
  // somebody else's would be a coupling with nothing behind it.
  await fleetEvidenceRoutes(app, process.env.AGENTWALL_FLEET_EVIDENCE);

  return { app, engine, gate, runtime, policyRuntime, reloadCoordinator };
}
