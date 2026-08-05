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
import { FileBackedPolicyRuntime, ReloadResult } from "./policy/runtime";
import { RuntimeFloodGuard } from "./runtime/floodguard";
import { createDecisionTraceExporter } from "./telemetry/otel";

export interface AgentwallServer {
  app: FastifyInstance;
  engine: PolicyEngine;
  gate: ApprovalGate;
  runtime: RuntimeState;
  policyRuntime?: FileBackedPolicyRuntime;
  reloadPolicy: () => ReloadResult | undefined;
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
  // writes to. The path is EXPLICIT with no default — a server must not invent a location
  // in $HOME for security-critical data, and a default here caused the test suite to write
  // 589 records into the operator's real chain and then resume from it. Unset means
  // stdout-only, the prior behaviour.
  const auditPath = process.env.AGENTWALL_AUDIT_FILE;
  if (auditPath) {
    const resumed = resumeChainState(auditPath);
    seedAuditChain(resumed.state);
    registerAuditSink(createFileSink(auditPath));
    if (resumed.discontinuity) {
      app.log.warn({ auditPath, reason: resumed.discontinuity },
        "audit chain discontinuity: starting a NEW chain");
    } else if (resumed.state.chainIndex > 0) {
      app.log.info({ auditPath, resumedAt: resumed.state.chainIndex },
        "audit chain resumed from prior run");
    }
  }
  registerAuditSink(stdoutSink);

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


  const applyReload = (result: ReloadResult) => {
    if (!result.reloaded) {
      return;
    }

    engine.replaceRules([...builtinRules, ...result.rules]);
    app.log.info(
      { policyPath: config.policy.configPath, ruleCount: engine.getRules().length },
      "Reloaded declarative policy rules"
    );
  };

  const reloadPolicy = (): ReloadResult | undefined => {
    if (!policyRuntime) {
      return undefined;
    }

    const result = policyRuntime.reload();
    applyReload(result);
    return result;
  };

  policyRuntime?.start(applyReload);

  app.addHook("onClose", async () => {
    policyRuntime?.stop();
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
  await dashboardRoutes(app, config, engine, gate, runtime, floodGuard, policyRuntime);
  await uiRoutes(app);

  return { app, engine, gate, runtime, policyRuntime, reloadPolicy };
}
