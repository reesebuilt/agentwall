import { afterAll, describe, expect, it } from "@jest/globals";
import { buildServer } from "../src/server";
import { AgentwallConfig } from "../src/config";
import { buildOrganizationControlPlaneSnapshot, buildOrganizationFederationSummaryPayload } from "../src/org/control-plane";

async function waitForPendingApproval(
  app: Awaited<ReturnType<typeof buildServer>>["app"],
  attempts = 20
): Promise<Array<{ requestId: string }>> {
  for (let index = 0; index < attempts; index += 1) {
    const pendingResponse = await app.inject({ method: "GET", url: "/approval/pending" });
    const pending = pendingResponse.json().pending;
    if (pending.length > 0) {
      return pending;
    }

    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  return [];
}

async function waitForPendingCount(
  app: Awaited<ReturnType<typeof buildServer>>["app"],
  count: number,
  attempts = 20
): Promise<Array<{ requestId: string; sessionId?: string; action?: string }>> {
  for (let index = 0; index < attempts; index += 1) {
    const pendingResponse = await app.inject({ method: "GET", url: "/approval/pending" });
    const pending = pendingResponse.json().pending;
    if (pending.length >= count) {
      return pending;
    }

    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  return [];
}

const config: AgentwallConfig = {
  port: 3000,
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

describe("Dashboard routes", () => {
  const serverPromise = buildServer(config);

  afterAll(async () => {
    const { app } = await serverPromise;
    await app.close();
  });

  it("serves the Agentwall dashboard shell and seeded runtime state", async () => {
    const { app } = await serverPromise;
    const html = await app.inject({ method: "GET", url: "/" });
    expect(html.statusCode).toBe(200);
    expect(html.body).toContain("Telegram Guardrails");
    expect(html.body).toContain("Configure one Telegram channel, prove the deny path");
    expect(html.body).toContain("Operator Investigation");
    expect(html.body).toContain("Detection Timeline");
    expect(html.body).toContain("Command Deck");
    expect(html.body).toContain("Organization Control Plane");
    expect(html.body).toContain("Advanced User");
    expect(html.body).toContain("Simple by default. Enable Advanced User for granular controls.");
    expect(html.body).toContain("role=\"switch\"");
    expect(html.body).toContain("data-console-mode-toggle");
    expect(html.body).toContain("Today, Waiting, Risks, Approvals, Auto-handled");
    expect(html.body).toContain("Knowledge Base");
    expect(html.body).toContain("/dashboard/knowledge-base");

    const dashboardRoute = await app.inject({ method: "GET", url: "/dashboard" });
    expect(dashboardRoute.statusCode).toBe(200);
    expect(dashboardRoute.body).toContain("Dashboard");

    const knowledgeBaseRoute = await app.inject({ method: "GET", url: "/dashboard/knowledge-base" });
    expect(knowledgeBaseRoute.statusCode).toBe(200);
    expect(knowledgeBaseRoute.body).toContain("Agentwall Mission Control Reference");
    expect(knowledgeBaseRoute.body).toContain("Canonical Access");

    const shellScript = await app.inject({ method: "GET", url: "/app.js" });
    expect(shellScript.statusCode).toBe(200);
    expect(shellScript.body).toContain("node.closest(\".advanced-panel\")");
    expect(shellScript.body).toContain("if (advancedContainer && currentConsoleMode !== \"advanced\")");
    expect(shellScript.body).toContain("applyConsoleMode(\"advanced\")");
    expect(shellScript.body).toContain("function confirmDangerousPolicySave");
    expect(shellScript.body).toContain("Advanced User confirmation: this save");
    expect(shellScript.body).toContain("Guardrail save cancelled. Advanced User confirmation is required");
    expect(shellScript.body).toContain("Advanced User confirmation: NEVER mode auto-approves approval-required requests.");
    expect(shellScript.body).toContain("${[\"auto\", \"always\"]");
    expect(shellScript.body).toContain("function installConsoleModeSwitch");
    expect(shellScript.body).toContain("data-console-mode-toggle");
    expect(shellScript.body).toContain("Granular controls are visible: policies, federation, evidence, audit, and raw runtime telemetry.");
    expect(shellScript.body).toContain("liveSessions > 0 ? getTopSessionTarget(state) : null");
    expect(shellScript.body).toContain("Enable Advanced User when you need policy, federation, or diagnostic detail.");
    expect(shellScript.body).toContain("Pending Decisions");
    expect(shellScript.body).toContain("Recent Decisions");
    expect(shellScript.body).toContain("Add a short operator note");
    expect(shellScript.body).toContain("Decision saved");
    expect(shellScript.body).toContain("pending remain");
    expect(shellScript.body).toContain("critical still pending");
    expect(shellScript.body).toContain("Next up:");
    expect(shellScript.body).toContain("Session lane:");
    expect(shellScript.body).toContain("Open top pending");
    expect(shellScript.body).toContain("Open knowledge base");
    expect(shellScript.body).toContain("System truth");
    expect(shellScript.body).toContain("Inspect risk posture");
    expect(shellScript.body).toContain("blocked work item(s) waiting");
    expect(shellScript.body).toContain("Telegram channel guardrails");
    expect(shellScript.body).toContain("Run Telegram proof check");
    expect(shellScript.body).toContain("data-telegram-proof");
    expect(shellScript.body).toContain("write_file from Telegram must deny");
    expect(shellScript.body).toContain("Scoped Guardrails");
    expect(shellScript.body).toContain("Guardrail editor");
    expect(shellScript.body).toContain("Communication Channels");
    expect(shellScript.body).toContain("Control channel");
    expect(shellScript.body).toContain("function renderOrganizationControlPlane");
    expect(shellScript.body).toContain("Single pane of glass");
    expect(shellScript.body).toContain("Peer Federation");
    expect(shellScript.body).toContain("No peers configured");
    expect(shellScript.body).toContain("Peer summary");
    expect(shellScript.body).toContain("Organization Channels");
    expect(shellScript.body).toContain("Save guardrail");
    expect(shellScript.body).toContain("Edit guardrail");
    expect(shellScript.body).toContain("Hotkeys now target");
    expect(shellScript.body).toContain("result?.queue?.nextRequestId");
    expect(shellScript.body).toContain("Back to core console.");
    expect(shellScript.body).toContain("clearDrilldownSelection()");
    expect(shellScript.body).toContain("applyConsoleMode(\"core\")");
    expect(shellScript.body).toContain("Alt+A");
    expect(shellScript.body).toContain("Alt+D");
    expect(shellScript.body).toContain("Alt+O");
    expect(shellScript.body).toContain("Alt+←");
    expect(shellScript.body).toContain("Alt+→");
    expect(shellScript.body).toContain("Approve top pending");
    expect(shellScript.body).toContain("Deny top pending");
    expect(shellScript.body).toContain("Open top pending");
    expect(shellScript.body).toContain("Top pending");
    expect(shellScript.body).toContain("loadDrilldown(\"approval\", topPendingId)");
    expect(shellScript.body).toContain("Why first");
    expect(shellScript.body).toContain("Rule hit");
    expect(shellScript.body).toContain("queueRank");
    expect(shellScript.body).toContain("item.queuePositionLabel");
    expect(shellScript.body).toContain("item.sessionLaneLabel");
    expect(shellScript.body).toContain("Approve in drilldown");
    expect(shellScript.body).toContain("Deny in drilldown");
    expect(shellScript.body).toContain("Previous pending");
    expect(shellScript.body).toContain("Next pending");
    expect(shellScript.body).toContain("queueNavigation.previousDetail");
    expect(shellScript.body).toContain("queueNavigation.nextDetail");
    expect(shellScript.body).toContain("queueNavigation.previousRule");
    expect(shellScript.body).toContain("queueNavigation.nextRule");
    expect(shellScript.body).toContain("currentDrilldown.kind === \"approval\" && currentDrilldown.status === \"pending\"");
    expect(shellScript.body).toContain("currentDrilldown?.kind === \"approval\" && currentDrilldown?.status === \"pending\"");
    expect(shellScript.body).toContain("currentDrilldown.id");
    expect(shellScript.body).toContain("queueNavigation.previousRequestId");
    expect(shellScript.body).toContain("queueNavigation.nextRequestId");
    expect(shellScript.body).toContain("handleMissingDrilldownAfterRefresh");
    expect(shellScript.body).toContain("Approval already resolved elsewhere.");
    expect(shellScript.body).toContain("Moved to next pending:");
    expect(shellScript.body).toContain("currentDrilldownRef?.kind === \"approval\"");
    expect(shellScript.body).toContain("currentState?.approvals?.queueHealth?.reviewRequestId");
    expect(shellScript.body).toContain("function getTopPendingApprovalTarget()");
    expect(shellScript.body).toContain("await openTopPendingApproval(getTopPendingApprovalTarget())");
    expect(shellScript.body).toContain("handoffToNextPendingApproval");
    expect(shellScript.body).toContain("currentState?.approvals?.pending?.[0]?.requestId");
    expect(shellScript.body).toContain("Queue shifted while you were deciding");
    expect(shellScript.body).toContain("function buildApprovalDecisionNoteDefault");
    expect(shellScript.body).toContain("findApprovalDecisionContext");
    expect(shellScript.body).toContain("matchedRule");
    expect(shellScript.body).toContain("escapeApprovalNoteSegment");
    expect(shellScript.body).toContain("Decision ${decision} from console");
    expect(shellScript.body).toContain("function renderCommandDeck");
    expect(shellScript.body).toContain("Today");
    expect(shellScript.body).toContain("Waiting");
    expect(shellScript.body).toContain("Risks");
    expect(shellScript.body).toContain("Approvals");
    expect(shellScript.body).toContain("Auto-handled");
    expect(shellScript.body).toContain("function renderKnowledgeBase");
    expect(shellScript.body).toContain("data-kb-filter");
    expect(shellScript.body).toContain("data-kb-section");
    expect(shellScript.body).toContain("navigateKnowledgeBaseFilter");
    expect(shellScript.body).toContain("kb-clear-search");
    expect(shellScript.body).toContain("Runtime Context");
    expect(shellScript.body).toContain("kb-runtime-context");
    expect(shellScript.body).toContain("missing/not configured");
    expect(shellScript.body).toContain("Agentwall Control Room Knowledge Base");
    expect(shellScript.body).toContain("function renderControlRoom");
    expect(shellScript.body).toContain("data-local-service-action");
    expect(shellScript.body).toContain("/api/dashboard/control/local-service");

    const stateResponse = await app.inject({ method: "GET", url: "/api/dashboard/state" });
    expect(stateResponse.statusCode).toBe(200);
    const state = stateResponse.json();
    expect(state.brand).toBe("Agentwall");
    expect(state.localControl).toBeDefined();
    expect(state.localControl.serviceName).toBe("agentwall-live.service");
    expect(state.localControl.manager).toBe("systemd-user");
    expect(state.eventFeed.length).toBeGreaterThan(0);
    expect(Array.isArray(state.operatorTimeline)).toBe(true);
    expect(Array.isArray(state.runtimeFlows)).toBe(true);
    expect(Array.isArray(state.evidenceLedger)).toBe(true);
    expect(state.commandDeck).toBeDefined();
    expect(state.commandDeck.today.title).toBe("Today");
    expect(state.commandDeck.waiting.title).toBe("Waiting");
    expect(state.commandDeck.risks.title).toBe("Risks");
    expect(state.commandDeck.approvals.title).toBe("Approvals");
    expect(state.commandDeck.autoHandled.title).toBe("Auto-handled");
    expect(state.commandDeck.today.items[0].title).toContain("Send a test evaluation");
    expect(state.commandDeck.today.items[0].actionLabel).toBe("Seed telemetry");
    expect(state.commandDeck.risks.items[0].title).toContain("No live runtime risk");
    expect(state.commandDeck.autoHandled.items[0].title).toContain("No auto-handled work yet");
    expect(state.organizationControlPlane).toBeDefined();
    expect(state.organizationControlPlane.summary.instances).toBeGreaterThanOrEqual(1);
    expect(Array.isArray(state.organizationControlPlane.instances)).toBe(true);
    expect(Array.isArray(state.organizationControlPlane.gateways)).toBe(true);
    expect(Array.isArray(state.organizationControlPlane.channels)).toBe(true);

    const localServiceResponse = await app.inject({ method: "GET", url: "/api/dashboard/local-service" });
    expect(localServiceResponse.statusCode).toBe(200);
    expect(localServiceResponse.json().localControl.serviceName).toBe("agentwall-live.service");

    const crossOriginControl = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/approval-mode",
      headers: { origin: "https://evil.example", host: "127.0.0.1:3000" },
      payload: { mode: "always" },
    });
    expect(crossOriginControl.statusCode).toBe(403);

    const orgSummaryResponse = await app.inject({ method: "GET", url: "/api/org/summary" });
    expect(orgSummaryResponse.statusCode).toBe(200);
    const orgSummary = orgSummaryResponse.json();
    expect(orgSummary.ok).toBe(true);
    expect(orgSummary.schemaVersion).toBe("agentwall.org.summary.v1");
    expect(orgSummary.capabilities).toEqual(expect.arrayContaining(["org-summary-read", "redacted-federation-export"]));
    expect(orgSummary.generatedAt).toBeDefined();
    expect(orgSummary.instance).toEqual(expect.objectContaining({ id: "127.0.0.1:3000", name: "Local Agentwall", role: "local" }));
    expect(orgSummary.summary.instances).toBeGreaterThanOrEqual(1);
    expect(orgSummary.controlPlane.summary).toEqual(orgSummary.summary);
    expect(Array.isArray(orgSummary.controlPlane.instances)).toBe(true);
    expect(Array.isArray(orgSummary.controlPlane.channels)).toBe(true);

    expect(state.knowledgeBase).toBeDefined();
    expect(state.knowledgeBase.access.baseUrl).toBe("http://127.0.0.1:3000");
    expect(state.knowledgeBase.access.dashboardUrl).toBe("http://127.0.0.1:3000/dashboard");
    expect(state.knowledgeBase.access.knowledgeBaseUrl).toBe("http://127.0.0.1:3000/dashboard/knowledge-base");
    expect(state.knowledgeBase.access.lastVerifiedStatus).toBe("seeded");
    expect(state.knowledgeBase.sections.map((item: { id: string }) => item.id)).toEqual(
      expect.arrayContaining(["sources", "concepts", "articles", "open_questions", "file_structure", "runtime_context"])
    );
    expect(state.knowledgeBase.entries.some((item: { title: string }) => item.title === "Dashboard state API")).toBe(true);
    expect(state.knowledgeBase.entries.some((item: { category: string; title: string }) => item.category === "file_structure" && item.title === "docs/ path summary")).toBe(true);
    expect(state.knowledgeBase.entries.some((item: { category: string; title: string }) => item.category === "file_structure" && item.title === "src/ path summary")).toBe(true);
    expect(state.knowledgeBase.entries.some((item: { category: string; title: string }) => item.category === "file_structure" && item.title === "public/ path summary")).toBe(true);
    expect(state.knowledgeBase.entries.some((item: { category: string; title: string }) => item.category === "file_structure" && item.title === "tests/ path summary")).toBe(true);
    expect(Array.isArray(state.knowledgeBase.runtimeContext)).toBe(true);
    expect(state.knowledgeBase.runtimeContext.map((item: { id: string }) => item.id)).toEqual(
      expect.arrayContaining(["soul", "memory", "user_profile", "system_environment"])
    );
    const soulContext = state.knowledgeBase.runtimeContext.find((item: { id: string }) => item.id === "soul");
    expect(soulContext).toMatchObject({
      status: "available",
      value: "configured",
      excerpt: "[runtime prompt excerpt withheld]",
    });
    // The fixture's own text, so this fails if the probe ever echoes SOUL.md contents
    // instead of just presence/size. Asserting on a name no fixture contains would pass
    // vacuously forever.
    expect(JSON.stringify(soulContext)).not.toContain("Test Agent Behaviour Contract");
    expect(JSON.stringify(soulContext)).not.toContain("Fixture only");
    expect(JSON.stringify(soulContext)).not.toContain("/home/");
    expect(
      state.knowledgeBase.runtimeContext.find((item: { id: string }) => item.id === "memory")
    ).toMatchObject({
      status: "missing",
      value: "missing/not configured",
    });
    const userProfileContext = state.knowledgeBase.runtimeContext.find((item: { id: string }) => item.id === "user_profile");
    expect(["missing", "available"]).toContain(userProfileContext?.status);
    if (userProfileContext?.status === "missing") {
      expect(userProfileContext.value).toBe("missing/not configured");
    } else {
      expect(String(userProfileContext?.value ?? "").length).toBeGreaterThan(0);
    }
    expect(
      state.knowledgeBase.runtimeContext.find((item: { id: string }) => item.id === "system_environment")
    ).toMatchObject({
      status: "available",
      facts: expect.arrayContaining([
        expect.objectContaining({ label: "Agent home" }),
        expect.objectContaining({ label: "Config file" }),
        expect.objectContaining({ label: "Skills collections" }),
      ]),
    });
    expect(state.freshness.hasLiveActivity).toBe(false);
    expect(state.service.operatorSummary).toContain("Awaiting first live agent activity");
    expect(state.service.recommendedActions).toContain("Send a test evaluation or approval request to confirm live telemetry end to end.");
    expect(state.health.watchdogStates[0].status).toBe("healthy");
    expect(state.policyCatalog).toBeDefined();
    expect(state.policyCatalog.editable).toBe(false);
    expect(Array.isArray(state.policyCatalog.scopedRules)).toBe(true);
    expect(state.channelInventory).toBeDefined();
    expect(state.channelInventory.total).toBe(0);
    expect(Array.isArray(state.channelInventory.byAgent)).toBe(true);

    // Telegram first-run onboarding DTO
    expect(state.product).toBeDefined();
    expect(state.product.telegramFirstRun).toBeDefined();
    const firstRun = state.product.telegramFirstRun;
    expect(firstRun.webhookEndpointPath).toBe("/integrations/telegram/generic-test-bot/webhook");
    expect(typeof firstRun.webhookSecretConfigured).toBe("boolean");
    expect(typeof firstRun.botTokenConfigured).toBe("boolean");
    expect(typeof firstRun.liveSendEnabled).toBe("boolean");
    expect(typeof firstRun.observedLaneCount).toBe("number");
    expect(typeof firstRun.recommendedNextAction).toBe("string");
    expect(Array.isArray(firstRun.checklist)).toBe(true);
    expect(firstRun.checklist.length).toBeGreaterThan(0);
    firstRun.checklist.forEach((step: { id: string; label: string; status: string; detail: string }) => {
      expect(step.id).toBeTruthy();
      expect(step.label).toBeTruthy();
      expect(["done", "current", "blocked", "pending"]).toContain(step.status);
    });
    // No secrets must appear in the DTO
    const firstRunJson = JSON.stringify(firstRun);
    expect(firstRunJson).not.toMatch(/AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET/);
    expect(firstRunJson).not.toMatch(/AGENTWALL_TELEGRAM_TEST_BOT_TOKEN/);
    // primaryLane should be null when no channels observed
    expect(firstRun.primaryLane).toBeNull();

    // Same-origin rejection on the proof endpoint
    const crossOriginProof = await app.inject({
      method: "POST",
      url: "/api/dashboard/proof/communication-channel",
      headers: { origin: "https://evil.example", host: "127.0.0.1:3000" },
      payload: { agentId: "test-agent", platform: "telegram", channelId: "telegram:-1001234567890:4242" },
    });
    expect(crossOriginProof.statusCode).toBe(403);
  });

  it("polls authenticated org peers for dashboard state without expanding the local org summary export", async () => {
    const originalFetch = globalThis.fetch;
    const previousToken = process.env.AGENTWALL_DASHBOARD_TEST_TOKEN;
    process.env.AGENTWALL_DASHBOARD_TEST_TOKEN = "test-token";
    const remoteSnapshot = buildOrganizationControlPlaneSnapshot({
      now: "2026-04-30T15:00:00.000Z",
      localInstance: {
        id: "remote-dashboard-peer",
        name: "Remote Dashboard Peer",
        url: "https://remote-dashboard.example.com",
      },
      observedChannels: [
        {
          agentId: "remote-dashboard-agent",
          channelId: "slack:TREM:CPEER",
          lastSeenAt: "2026-04-30T15:00:00.000Z",
          lastPlane: "tool",
          lastAction: "peer_status",
          riskLevel: "medium",
          sessionIds: ["remote-session"],
          userIds: ["remote-user"],
          roleIds: ["remote-role"],
        },
      ],
    });
    const remotePayload = buildOrganizationFederationSummaryPayload("2026-04-30T15:00:05.000Z", remoteSnapshot);
    const seenRequests: Array<{ url: string; headers?: Record<string, string> }> = [];
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      seenRequests.push({ url: String(url), headers: init?.headers as Record<string, string> | undefined });
      return {
        ok: true,
        status: 200,
        json: async () => ({ ok: true, ...remotePayload }),
      } as Response;
    }) as typeof fetch;

    const isolated = await buildServer({
      ...config,
      port: 3020,
      approval: {
        ...config.approval,
        backend: "memory",
      },
      organization: {
        instanceId: "local-dashboard-peer-test",
        instanceName: "Local Dashboard Peer Test",
        instances: [
          {
            id: "remote-dashboard-peer",
            name: "Remote Dashboard Peer",
            url: "https://remote-dashboard.example.com/root?token=hidden",
            role: "remote",
            status: "unknown",
            authTokenEnv: "AGENTWALL_DASHBOARD_TEST_TOKEN",
            pollTimeoutMs: 100,
          },
        ],
      },
    });

    try {
      const state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
      expect(seenRequests[0].url).toBe("https://remote-dashboard.example.com/root/api/org/summary");
      expect(seenRequests[0].headers?.Authorization).toBe("Bearer test-token");
      expect(state.organizationFederation.peers).toEqual([
        expect.objectContaining({ id: "remote-dashboard-peer", ok: true, status: "online" }),
      ]);
      expect(state.organizationFederation.peers[0].summaryUrl).toBe("https://remote-dashboard.example.com/root/api/org/summary");
      expect(state.organizationFederation.peers[0].summaryUrl).not.toContain("?");
      expect(JSON.stringify(state.organizationFederation.peers[0])).not.toContain("authTokenEnv");
      expect(JSON.stringify(state.organizationFederation.peers[0])).not.toContain("authHeaderName");
      expect(JSON.stringify(state.organizationFederation.peers[0])).not.toContain("token=");
      expect(JSON.stringify(state.organizationFederation.peers[0])).not.toContain("api_key=");
      expect(JSON.stringify(state.organizationFederation.peers[0])).not.toContain("access_token=");
      const peerBundle = await isolated.app.inject({ method: "GET", url: "/app.js" });
      expect(peerBundle.statusCode).toBe(200);
      expect(peerBundle.body).toContain("Peer Federation");
      expect(peerBundle.body).toContain("Peer summary");
      expect(state.organizationControlPlane.summary.channels).toBe(1);
      expect(state.organizationControlPlane.summary.configuredInstances).toBe(1);
      expect(state.organizationControlPlane.instances.find((item: { id: string }) => item.id === "remote-dashboard-peer")).toEqual(
        expect.objectContaining({ role: "remote", status: "online", url: "https://remote-dashboard.example.com/root" })
      );
      expect(state.organizationControlPlane.channels.some((item: { agentId: string }) => item.agentId === "remote-dashboard-agent")).toBe(true);
      expect(JSON.stringify(state.organizationControlPlane)).not.toContain("AGENTWALL_DASHBOARD_TEST_TOKEN");
      expect(JSON.stringify(state.organizationControlPlane)).not.toContain("token=hidden");

      const orgSummary = (await isolated.app.inject({ method: "GET", url: "/api/org/summary" })).json();
      expect(orgSummary.ok).toBe(true);
      expect(orgSummary.controlPlane.channels.some((item: { agentId: string }) => item.agentId === "remote-dashboard-agent")).toBe(false);
    } finally {
      await isolated.app.close();
      globalThis.fetch = originalFetch;
      if (previousToken === undefined) {
        delete process.env.AGENTWALL_DASHBOARD_TEST_TOKEN;
      } else {
        process.env.AGENTWALL_DASHBOARD_TEST_TOKEN = previousToken;
      }
    }
  });

  it("degrades malformed org peers without breaking dashboard state", async () => {
    const originalFetch = globalThis.fetch;
    const valid = buildOrganizationFederationSummaryPayload("2026-04-30T15:10:00.000Z", buildOrganizationControlPlaneSnapshot({
      now: "2026-04-30T15:10:00.000Z",
      localInstance: {
        id: "malformed-peer",
        name: "Malformed Peer",
        url: "https://malformed-peer.example.com",
      },
      observedChannels: [],
    }));
    globalThis.fetch = (async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        ok: true,
        ...valid,
        controlPlane: {
          ...valid.controlPlane,
          channels: [
            {
              id: "malformed-peer:agent:slack:T:C",
              instanceId: "malformed-peer",
              gatewayId: "malformed-peer:slack",
              gatewayKind: "slack",
              agentId: "agent",
              channelId: "slack:T:C",
              lastSeenAt: "2026-04-30T15:10:00.000Z",
              lastPlane: "tool",
              lastAction: "status_check",
              riskLevel: "low",
            },
          ],
        },
      }),
    }) as Response) as typeof fetch;

    const isolated = await buildServer({
      ...config,
      port: 3021,
      approval: {
        ...config.approval,
        backend: "memory",
      },
      organization: {
        instanceId: "local-dashboard-malformed-peer-test",
        instanceName: "Local Dashboard Malformed Peer Test",
        instances: [
          {
            id: "malformed-peer",
            name: "Malformed Peer",
            url: "https://malformed-peer.example.com",
            role: "remote",
            status: "unknown",
            pollTimeoutMs: 100,
          },
        ],
      },
    });

    try {
      const response = await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" });
      expect(response.statusCode).toBe(200);
      const state = response.json();
      expect(state.organizationFederation.peers[0]).toEqual(
        expect.objectContaining({ id: "malformed-peer", ok: false, status: "degraded" })
      );
      expect(state.organizationFederation.peers[0].error).toContain("sessionIds");
      expect(JSON.stringify(state.organizationFederation.peers[0])).not.toContain("authTokenEnv");
      expect(JSON.stringify(state.organizationFederation.peers[0])).not.toContain("authHeaderName");
      expect(JSON.stringify(state.organizationFederation.peers[0])).not.toContain("Bearer");
      expect(JSON.stringify(state.organizationFederation.peers[0])).not.toContain("token=");
      expect(state.organizationControlPlane.instances.find((item: { id: string }) => item.id === "local-dashboard-malformed-peer-test")).toBeDefined();
      expect(state.organizationControlPlane.channels.some((item: { id: string }) => item.id.includes("malformed-peer"))).toBe(false);
    } finally {
      await isolated.app.close();
      globalThis.fetch = originalFetch;
    }
  });

  it("keeps operator-only control changes out of live activity freshness", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3001,
      approval: {
        ...config.approval,
        backend: "memory",
      },
    });

    try {
      await isolated.app.inject({
        method: "POST",
        url: "/api/dashboard/control/approval-mode",
        payload: { mode: "never" },
      });

      const state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
      expect(state.freshness.hasLiveActivity).toBe(false);
      expect(state.freshness.lastLiveEventAt).toBeNull();
      expect(state.service.operatorSummary).toContain("Awaiting first live agent activity");
    } finally {
      await isolated.app.close();
    }
  });

  it("uses dashboard.publicBaseUrl for canonical knowledge base access when configured", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3016,
      dashboard: {
        publicBaseUrl: "https://mission-control.example.com/",
      },
      approval: {
        ...config.approval,
        backend: "memory",
      },
    });

    try {
      const state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
      expect(state.knowledgeBase.access.baseUrl).toBe("https://mission-control.example.com");
      expect(state.knowledgeBase.access.dashboardUrl).toBe("https://mission-control.example.com/dashboard");
      expect(state.knowledgeBase.access.knowledgeBaseUrl).toBe("https://mission-control.example.com/dashboard/knowledge-base");
      expect(state.knowledgeBase.runtimeContext.find((item: { id: string }) => item.id === "system_environment")?.excerpt).toContain(
        "https://mission-control.example.com"
      );
      expect(
        state.knowledgeBase.runtimeContext.find((item: { id: string }) => item.id === "system_environment")?.facts
      ).toEqual(
        expect.arrayContaining([expect.objectContaining({ label: "Base URL", value: "https://mission-control.example.com" })])
      );
    } finally {
      await isolated.app.close();
    }
  });

  it("drops contained sessions out of the active-agents-now tally without erasing agent history", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3006,
      approval: {
        ...config.approval,
        backend: "memory",
      },
    });

    try {
      await isolated.app.inject({
        method: "POST",
        url: "/evaluate",
        payload: {
          agentId: "agent-contained",
          sessionId: "session-contained",
          plane: "tool",
          action: "bash_exec",
          payload: { command: "pwd" },
          provenance: [{ source: "user", trustLabel: "trusted" }],
          flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
        },
      });

      const activeState = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
      expect(activeState.posture.activeAgents).toBe(1);
      expect(activeState.posture.activeAgentsNow).toBe(1);

      await isolated.app.inject({
        method: "POST",
        url: "/api/dashboard/control/session/session-contained",
        payload: { action: "terminate", confirm: true, note: "Containment" },
      });

      const terminatedState = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
      expect(terminatedState.posture.activeAgents).toBe(1);
      expect(terminatedState.posture.activeAgentsNow).toBe(0);
      expect(terminatedState.stats.sessionCounts.terminated).toBe(1);
      expect(terminatedState.service.recommendedActions).toContain("Inspect terminated sessions and capture audit evidence before normalizing controls.");
    } finally {
      await isolated.app.close();
    }
  });

  it("keeps terminated sessions counted even after they fall out of the recent-session slice", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3002,
      approval: {
        ...config.approval,
        backend: "memory",
      },
    });

    try {
      await isolated.app.inject({
        method: "POST",
        url: "/evaluate",
        payload: {
          agentId: "agent-0",
          sessionId: "session-0",
          plane: "tool",
          action: "bash_exec",
          payload: { command: "pwd" },
          provenance: [{ source: "user", trustLabel: "trusted" }],
          flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
        },
      });
      await isolated.app.inject({
        method: "POST",
        url: "/api/dashboard/control/session/session-0",
        payload: { action: "terminate", confirm: true, note: "Containment" },
      });

      for (let index = 1; index <= 12; index += 1) {
        await isolated.app.inject({
          method: "POST",
          url: "/evaluate",
          payload: {
            agentId: `agent-${index}`,
            sessionId: `session-${index}`,
            plane: "tool",
            action: "bash_exec",
            payload: { command: `echo ${index}` },
            provenance: [{ source: "user", trustLabel: "trusted" }],
            flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
          },
        });
      }

      const state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
      expect(state.stats.sessionCounts.terminated).toBe(1);
      expect(state.posture.criticalSignals).toBeGreaterThan(0);
      expect(state.service.attentionRequired).toBe(true);
      expect(state.service.operatorSummary).toContain("terminated");
      expect(state.sessions.recent.some((item: { sessionId: string }) => item.sessionId === "session-0")).toBe(false);
      expect(state.sessions.statusById["session-0"]).toBe("terminated");
    } finally {
      await isolated.app.close();
    }
  });

  it("reflects live policy, inspection, and approval activity", async () => {
    const { app } = await serverPromise;

    await app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-ops",
        plane: "network",
        action: "http_request",
        payload: { url: "https://api.openai.com/v1/chat/completions" },
        provenance: [{ source: "web", trustLabel: "untrusted" }],
        flow: { direction: "egress", labels: ["external_egress"], highRisk: true, crossesBoundary: true },
      },
    });

    await app.inject({
      method: "POST",
      url: "/inspect/network",
      payload: { url: "http://169.254.169.254/latest/meta-data/" },
    });

    await app.inject({
      method: "POST",
      url: "/inspect/network",
      payload: { url: "https://user:pass@example.com/data" },
    });

    await app.inject({
      method: "POST",
      url: "/inspect/content",
      payload: { text: "Reach me at alice@example.com" },
    });

    const approvalRequest = app.inject({
      method: "POST",
      url: "/approval/request",
      payload: {
        context: {
          agentId: "agent-ops",
          plane: "tool",
          action: "bash_exec",
          payload: { command: "rm -rf /tmp/example" },
        },
        policyResult: {
          decision: "approve",
          riskLevel: "high",
          matchedRules: ["tool:require-approval-shell"],
          reasons: ["Shell execution requires human approval"],
          requiresApproval: true,
          highRiskFlow: false,
        },
      },
    });
    const pending = await waitForPendingApproval(app);
    expect(pending.length).toBeGreaterThan(0);

    await app.inject({
      method: "POST",
      url: `/approval/${pending[0].requestId}/respond`,
      payload: {
        decision: "approved",
        note: "Reviewed in dashboard test",
      },
    });

    const resolvedApproval = await approvalRequest;
    expect(resolvedApproval.statusCode).toBe(200);

    const stateResponse = await app.inject({ method: "GET", url: "/api/dashboard/state" });
    const state = stateResponse.json();

    expect(state.auditFeed.some((item: { agentId: string }) => item.agentId === "agent-ops")).toBe(true);
    expect(
      state.auditFeed.some(
        (item: { agentId: string; integrity?: { chainIndex: number; hash: string; previousHash: string | null } }) =>
          item.agentId === "agent-ops" &&
          typeof item.integrity?.chainIndex === "number" &&
          typeof item.integrity?.hash === "string" &&
          ["string", "object"].includes(typeof item.integrity?.previousHash)
      )
    ).toBe(true);
    expect(state.inspectionActivity.length).toBeGreaterThan(0);
    expect(state.approvals.recent.some((item: { status: string }) => item.status === "approved")).toBe(true);
    expect(state.approvals.summary).toBeDefined();
    expect(Array.isArray(state.approvals.pending)).toBe(true);
    expect(Array.isArray(state.approvals.recent)).toBe(true);
    expect(state.approvals.pending.length).toBe(0);
    expect(state.approvals.summary.headline).toContain("Last decision");
    expect(state.approvals.summary.headline).toContain("bash_exec");
    expect(state.approvals.summary.reason).toContain("Reviewed in dashboard test");
    // The approver is the authenticated principal, not a caller-supplied string.
    // Before 2026-08-04 a client could name itself anything here.
    expect(state.approvals.recent.find((item: { status: string }) => item.status === "approved")?.triageDetail).toContain("loopback-dev");
    expect(Array.isArray(state.approvals.recent.find((item: { status: string }) => item.status === "approved")?.matchedRules)).toBe(true);
    expect(state.commandDeck.today.items.length).toBeGreaterThan(0);
    expect(state.commandDeck.waiting.items.length).toBeGreaterThan(0);
    expect(state.commandDeck.risks.items.length).toBeGreaterThan(0);
    expect(state.commandDeck.approvals.items.length).toBeGreaterThan(0);
    expect(state.commandDeck.autoHandled.items.length).toBeGreaterThan(0);
    expect(
      state.commandDeck.today.items.some(
        (item: { title: string }) => item.title.includes("Review") || item.title.includes("Inspect") || item.title.includes("Open")
      )
    ).toBe(true);
    expect(state.commandDeck.approvals.items[0].title).toContain("Pending approvals");
    expect(state.priorityQueue.length).toBeGreaterThan(0);

    expect(state.floodGuard).toBeDefined();
    expect(state.knowledgeBase.access.lastVerifiedStatus).toBe("fresh");
    expect(state.service.recommendedActions.some((item: string) => item.includes("critical signal") || item.includes("pending approval queue"))).toBe(true);
    expect(state.operatorTimeline.length).toBeGreaterThan(0);
    expect(state.operatorTimeline.some((item: { category: string }) => item.category === "approval")).toBe(true);
    expect(state.evidenceLedger.length).toBeGreaterThan(0);
    expect(state.taskGraph.nodes.length).toBeGreaterThan(0);
    expect(
      state.eventFeed.some(
        (item: { detail?: { blockedCategory?: string; detectionId?: string } }) =>
          item.detail?.blockedCategory === "embedded-credentials" && item.detail?.detectionId === "det.net.embedded.credentials"
      )
    ).toBe(true);
  });



  it("adds FloodGuard blocks and queue items into the operator timeline so the default console shows what changed first", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3007,
      approval: {
        ...config.approval,
        mode: "always",
        timeoutMs: 200,
        backend: "memory",
      },
      runtimeGuards: {
        enabled: true,
        requestPerMinutePerSession: 60,
        toolActionPerMinutePerSession: 60,
        approvalRequestsPerMinutePerSession: 1,
        approvalResponsesPerMinutePerActor: 60,
        maxPendingApprovalsGlobal: 10,
        maxPendingApprovalsPerSession: 10,
        costBudgetPerHourPerSession: 1200,
        costWeights: {
          evaluateBase: 1,
          approvalRequest: 4,
          approvalRequiresManual: 2,
          toolActionMultiplier: 3,
          highRiskMultiplier: 2,
          criticalRiskMultiplier: 3,
        },
        shield: {
          requestRateMultiplier: 0.5,
          toolActionRateMultiplier: 0.5,
          approvalRequestRateMultiplier: 0.5,
          approvalResponseRateMultiplier: 0.5,
          maxPendingGlobalMultiplier: 0.6,
          maxPendingSessionMultiplier: 0.6,
          costBudgetMultiplier: 0.75,
          defaultDurationMs: 10 * 60_000,
        },
      },
    });

    try {
      const first = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-queue",
            sessionId: "session-queue",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "whoami" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "critical",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["manual review required"],
            requiresApproval: true,
            highRiskFlow: false,
          },
        },
      });
      const pending = await waitForPendingApproval(isolated.app, 10);
      expect(pending.length).toBeGreaterThan(0);

      const second = await isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-queue",
            sessionId: "session-queue",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "id" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "critical",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["manual review required"],
            requiresApproval: true,
            highRiskFlow: false,
          },
        },
      });
      expect(second.statusCode).toBe(429);

      const state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
      expect(state.approvals.summary.headline).toContain("Review");
      expect(state.approvals.summary.headline).toContain("bash_exec");
      expect(state.approvals.summary.reason).toContain("manual review required");
      expect(state.approvals.pending.length).toBeGreaterThan(0);
      expect(state.approvals.queueHealth).toBeDefined();
      expect(state.approvals.queueHealth.pendingCount).toBeGreaterThan(0);
      expect(state.approvals.queueHealth.criticalCount).toBeGreaterThan(0);
      expect(state.approvals.queueHealth.reviewRequestId).toBe(state.approvals.pending[0].requestId);
      expect(state.approvals.queueHealth.reviewTarget).toContain("bash_exec");
      expect(state.approvals.queueHealth.reviewTarget).toContain("session-queue");
      expect(state.approvals.queueHealth.reviewDetail).toContain("waiting");
      expect(state.approvals.queueHealth.reviewDetail).toContain("manual review required");
      expect(state.approvals.queueHealth.reviewRule).toBe("tool:require-approval-shell");
      expect(state.approvals.queueHealth.reviewLane).toContain("session-queue");
      expect(state.approvals.queueHealth.reviewLane).toContain("1 pending");
      expect(state.approvals.pending[0].priorityLabel).toBe("critical");
      expect(state.approvals.pending[0].action).toBe("bash_exec");
      expect(state.approvals.pending[0].triageDetail).toContain("waiting");
      expect(state.operatorTimeline.some((item: { category: string; title: string }) => item.category === "approval" && item.title.includes("awaiting decision"))).toBe(true);
      expect(state.operatorTimeline.some((item: { category: string; title: string }) => item.category === "floodguard" && item.title.includes("FloodGuard blocked"))).toBe(true);
      expect((await first).statusCode).toBe(200);
    } finally {
      await isolated.app.close();
    }
  });

  it("returns the next pending target after a decision so the console can keep operators moving", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3011,
      approval: {
        ...config.approval,
        backend: "memory",
      },
    });

    try {
      const first = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-speed",
            sessionId: "session-first",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "whoami" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["manual review required"],
            requiresApproval: true,
            highRiskFlow: false,
          },
        },
      });

      const second = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-speed",
            sessionId: "session-second",
            plane: "tool",
            action: "http_request",
            payload: { url: "https://api.openai.com/v1/models" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "critical",
            matchedRules: ["network:require-approval-egress"],
            reasons: ["operator confirmation required"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });

      const pending = await waitForPendingCount(isolated.app, 2, 30);
      expect(pending).toHaveLength(2);

      const response = await isolated.app.inject({
        method: "POST",
        url: `/approval/${pending[0].requestId}/respond`,
        payload: {
          decision: "approved",
          note: "Move to the next one",
        },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({
        ok: true,
        queue: {
          pendingCount: 1,
          criticalCount: 1,
          nextRequestId: pending[1].requestId,
          nextTarget: expect.stringContaining("session-second"),
          nextTargetDetail: expect.stringContaining("operator confirmation required"),
          nextRule: "network:require-approval-egress",
          nextLane: expect.stringContaining("session-second"),
        },
      });

      await isolated.app.inject({
        method: "POST",
        url: `/approval/${pending[1].requestId}/respond`,
        payload: {
          decision: "approved",
          note: "Done",
        },
      });

      expect((await first).statusCode).toBe(200);
      expect((await second).statusCode).toBe(200);
    } finally {
      await isolated.app.close();
    }
  });

  it("orders pending approvals by risk first and oldest wait next so the hottest decision stays pinned", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3008,
      approval: {
        ...config.approval,
        mode: "always",
        timeoutMs: 200,
        backend: "memory",
      },
    });

    try {
      const first = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-low",
            sessionId: "session-low",
            plane: "tool",
            action: "safe_tool",
            payload: {},
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["tool:review-safe-tool"],
            reasons: ["High-risk tool request"],
            requiresApproval: true,
            highRiskFlow: false,
          },
        },
      });
      await waitForPendingApproval(isolated.app, 10);
      await new Promise((resolve) => setTimeout(resolve, 25));

      const second = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-critical",
            sessionId: "session-critical",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "rm -rf /tmp/demo" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "critical",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Critical shell execution requires approval"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });

      let state;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
        if (state.approvals.pending.length >= 2) break;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      expect(state.approvals.pending.length).toBeGreaterThanOrEqual(2);
      expect(state.approvals.pending[0].action).toBe("bash_exec");
      expect(state.approvals.pending[0].priorityLabel).toBe("critical");
      await Promise.all([first, second]);
    } finally {
      await isolated.app.close();
    }
  });

  it("keeps queue health and rendered pending order aligned when FloodGuard pressure breaks same-risk ties", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3010,
      approval: {
        ...config.approval,
        mode: "always",
        timeoutMs: 400,
        backend: "memory",
      },
      runtimeGuards: {
        enabled: true,
        requestPerMinutePerSession: 3,
        toolActionPerMinutePerSession: 3,
        approvalRequestsPerMinutePerSession: 10,
        approvalResponsesPerMinutePerActor: 60,
        maxPendingApprovalsGlobal: 10,
        maxPendingApprovalsPerSession: 10,
        costBudgetPerHourPerSession: 1200,
        costWeights: {
          evaluateBase: 1,
          approvalRequest: 4,
          approvalRequiresManual: 2,
          toolActionMultiplier: 3,
          highRiskMultiplier: 2,
          criticalRiskMultiplier: 3,
        },
        shield: {
          requestRateMultiplier: 0.5,
          toolActionRateMultiplier: 0.5,
          approvalRequestRateMultiplier: 0.5,
          approvalResponseRateMultiplier: 0.5,
          maxPendingGlobalMultiplier: 0.6,
          maxPendingSessionMultiplier: 0.6,
          costBudgetMultiplier: 0.75,
          defaultDurationMs: 10 * 60_000,
        },
      },
    });

    try {
      const coolApproval = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-cool",
            sessionId: "session-cool",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "pwd" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Human review required"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });
      await waitForPendingApproval(isolated.app, 10);
      await new Promise((resolve) => setTimeout(resolve, 25));

      for (let attempt = 0; attempt < 2; attempt += 1) {
        const evaluate = await isolated.app.inject({
          method: "POST",
          url: "/evaluate",
          payload: {
            agentId: "agent-hot",
            sessionId: "session-hot",
            plane: "tool",
            action: "bash_exec",
            payload: { command: `echo ${attempt}` },
            provenance: [{ source: "user", trustLabel: "trusted" }],
            flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
          },
        });
        expect(evaluate.statusCode).toBe(200);
      }

      const hotApproval = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-hot",
            sessionId: "session-hot",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "whoami" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Human review required"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });

      let state;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
        if (state.approvals.pending.length >= 2) break;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }

      expect(state.approvals.pending.length).toBeGreaterThanOrEqual(2);
      expect(state.approvals.queueHealth.reviewTarget).toContain("session-hot");
      expect(state.approvals.queueHealth.reviewDetail).toContain("Human review required");
      expect(state.approvals.pending[0].sessionId).toBe("session-hot");
      expect(state.approvals.pending[0].queueRank).toBe(1);
      expect(state.approvals.pending[1].queueRank).toBe(2);

      await Promise.all([coolApproval, hotApproval]);
    } finally {
      await isolated.app.close();
    }
  });

  it("keeps approval response handoff aligned with the prioritized dashboard queue", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3013,
      approval: {
        ...config.approval,
        mode: "always",
        timeoutMs: 400,
        backend: "memory",
      },
      runtimeGuards: {
        enabled: true,
        requestPerMinutePerSession: 3,
        toolActionPerMinutePerSession: 3,
        approvalRequestsPerMinutePerSession: 10,
        approvalResponsesPerMinutePerActor: 60,
        maxPendingApprovalsGlobal: 10,
        maxPendingApprovalsPerSession: 10,
        costBudgetPerHourPerSession: 1200,
        costWeights: {
          evaluateBase: 1,
          approvalRequest: 4,
          approvalRequiresManual: 2,
          toolActionMultiplier: 3,
          highRiskMultiplier: 2,
          criticalRiskMultiplier: 3,
        },
        shield: {
          requestRateMultiplier: 0.5,
          toolActionRateMultiplier: 0.5,
          approvalRequestRateMultiplier: 0.5,
          approvalResponseRateMultiplier: 0.5,
          maxPendingGlobalMultiplier: 0.6,
          maxPendingSessionMultiplier: 0.6,
          costBudgetMultiplier: 0.75,
          defaultDurationMs: 10 * 60_000,
        },
      },
    });

    try {
      const coolApproval = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-cool-handoff",
            sessionId: "session-cool-handoff",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "pwd" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Human review required"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });
      await waitForPendingApproval(isolated.app, 10);
      await new Promise((resolve) => setTimeout(resolve, 25));

      for (let attempt = 0; attempt < 2; attempt += 1) {
        const evaluate = await isolated.app.inject({
          method: "POST",
          url: "/evaluate",
          payload: {
            agentId: "agent-hot-handoff",
            sessionId: "session-hot-handoff",
            plane: "tool",
            action: "bash_exec",
            payload: { command: `echo ${attempt}` },
            provenance: [{ source: "user", trustLabel: "trusted" }],
            flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
          },
        });
        expect(evaluate.statusCode).toBe(200);
      }

      const hotApproval = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-hot-handoff",
            sessionId: "session-hot-handoff",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "whoami" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "critical",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Human review required"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });

      let state;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
        if (state.approvals.pending.length >= 2) break;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }

      expect(state.approvals.pending.length).toBeGreaterThanOrEqual(2);
      expect(state.approvals.pending[0].sessionId).toBe("session-hot-handoff");
      expect(state.approvals.pending[1].sessionId).toBe("session-cool-handoff");

      const respond = await isolated.app.inject({
        method: "POST",
        url: `/approval/${encodeURIComponent(state.approvals.pending[1].requestId)}/respond`,
        payload: { decision: "approved", note: "move to next" },
      });

      expect(respond.statusCode).toBe(200);
      expect(respond.json().queue.pendingCount).toBe(1);
      expect(respond.json().queue.criticalCount).toBe(1);
      expect(respond.json().queue.nextRequestId).toBe(state.approvals.pending[0].requestId);
      expect(respond.json().queue.nextTarget).toContain("session-hot-handoff");
      expect(respond.json().queue.nextTargetDetail).toContain("Human review required");

      await hotApproval;
      await coolApproval;
    } finally {
      await isolated.app.close();
    }
  });

  it("keeps queue handoff aligned with FloodGuard-prioritized pending order after a decision", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3016,
      approval: {
        ...config.approval,
        mode: "always",
        timeoutMs: 400,
        backend: "memory",
      },
      runtimeGuards: {
        enabled: true,
        requestPerMinutePerSession: 3,
        toolActionPerMinutePerSession: 3,
        approvalRequestsPerMinutePerSession: 10,
        approvalResponsesPerMinutePerActor: 60,
        maxPendingApprovalsGlobal: 10,
        maxPendingApprovalsPerSession: 10,
        costBudgetPerHourPerSession: 1200,
        costWeights: {
          evaluateBase: 1,
          approvalRequest: 4,
          approvalRequiresManual: 2,
          toolActionMultiplier: 3,
          highRiskMultiplier: 2,
          criticalRiskMultiplier: 3,
        },
        shield: {
          requestRateMultiplier: 0.5,
          toolActionRateMultiplier: 0.5,
          approvalRequestRateMultiplier: 0.5,
          approvalResponseRateMultiplier: 0.5,
          maxPendingGlobalMultiplier: 0.6,
          maxPendingSessionMultiplier: 0.6,
          costBudgetMultiplier: 0.75,
          defaultDurationMs: 10 * 60_000,
        },
      },
    });

    try {
      const coolApproval = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-cool-handoff-ordered",
            sessionId: "session-cool-handoff-ordered",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "pwd" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Baseline review"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });
      await waitForPendingApproval(isolated.app, 10);
      await new Promise((resolve) => setTimeout(resolve, 25));

      for (let attempt = 0; attempt < 2; attempt += 1) {
        const evaluate = await isolated.app.inject({
          method: "POST",
          url: "/evaluate",
          payload: {
            agentId: "agent-hot-handoff-ordered",
            sessionId: "session-hot-handoff-ordered",
            plane: "tool",
            action: "bash_exec",
            payload: { command: `echo ordered-${attempt}` },
            provenance: [{ source: "user", trustLabel: "trusted" }],
            flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
          },
        });
        expect(evaluate.statusCode).toBe(200);
      }

      const hotApproval = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-hot-handoff-ordered",
            sessionId: "session-hot-handoff-ordered",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "whoami" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Flood pressure review"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });
      await waitForPendingCount(isolated.app, 2, 20);
      await new Promise((resolve) => setTimeout(resolve, 25));

      const mediumApproval = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-medium-handoff-ordered",
            sessionId: "session-medium-handoff-ordered",
            plane: "tool",
            action: "http_request",
            payload: { url: "https://api.openai.com/v1/models" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "critical",
            matchedRules: ["network:require-approval-egress"],
            reasons: ["Critical network review"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });

      let state;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
        if (state.approvals.pending.length >= 3) break;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }

      expect(state.approvals.pending.length).toBeGreaterThanOrEqual(3);
      expect(state.approvals.pending[0].sessionId).toBe("session-medium-handoff-ordered");
      expect(state.approvals.pending[1].sessionId).toBe("session-hot-handoff-ordered");
      expect(state.approvals.pending[2].sessionId).toBe("session-cool-handoff-ordered");

      const respond = await isolated.app.inject({
        method: "POST",
        url: `/approval/${encodeURIComponent(state.approvals.pending[0].requestId)}/respond`,
        payload: { decision: "approved", note: "move to pressure-prioritized next" },
      });

      expect(respond.statusCode).toBe(200);
      expect(respond.json().queue.pendingCount).toBe(2);
      expect(respond.json().queue.criticalCount).toBe(0);
      expect(respond.json().queue.nextRequestId).toBe(state.approvals.pending[1].requestId);
      expect(respond.json().queue.nextTarget).toContain("session-hot-handoff-ordered");
      expect(respond.json().queue.nextTargetDetail).toContain("Flood pressure review");

      await Promise.all([coolApproval, hotApproval, mediumApproval]);
    } finally {
      await isolated.app.close();
    }
  });

  it("keeps pending approval drilldown navigation aligned with FloodGuard-prioritized queue order", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3011,
      approval: {
        ...config.approval,
        mode: "always",
        timeoutMs: 400,
        backend: "memory",
      },
      runtimeGuards: {
        enabled: true,
        requestPerMinutePerSession: 3,
        toolActionPerMinutePerSession: 3,
        approvalRequestsPerMinutePerSession: 10,
        approvalResponsesPerMinutePerActor: 60,
        maxPendingApprovalsGlobal: 10,
        maxPendingApprovalsPerSession: 10,
        costBudgetPerHourPerSession: 1200,
        costWeights: {
          evaluateBase: 1,
          approvalRequest: 4,
          approvalRequiresManual: 2,
          toolActionMultiplier: 3,
          highRiskMultiplier: 2,
          criticalRiskMultiplier: 3,
        },
        shield: {
          requestRateMultiplier: 0.5,
          toolActionRateMultiplier: 0.5,
          approvalRequestRateMultiplier: 0.5,
          approvalResponseRateMultiplier: 0.5,
          maxPendingGlobalMultiplier: 0.6,
          maxPendingSessionMultiplier: 0.6,
          costBudgetMultiplier: 0.75,
          defaultDurationMs: 10 * 60_000,
        },
      },
    });

    try {
      const coolApproval = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-cool-drilldown",
            sessionId: "session-cool-drilldown",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "pwd" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Human review required"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });
      await waitForPendingApproval(isolated.app, 10);
      await new Promise((resolve) => setTimeout(resolve, 25));

      for (let attempt = 0; attempt < 2; attempt += 1) {
        const evaluate = await isolated.app.inject({
          method: "POST",
          url: "/evaluate",
          payload: {
            agentId: "agent-hot-drilldown",
            sessionId: "session-hot-drilldown",
            plane: "tool",
            action: "bash_exec",
            payload: { command: `echo ${attempt}` },
            provenance: [{ source: "user", trustLabel: "trusted" }],
            flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
          },
        });
        expect(evaluate.statusCode).toBe(200);
      }

      const hotApproval = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-hot-drilldown",
            sessionId: "session-hot-drilldown",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "whoami" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Human review required"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });

      let state;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
        if (state.approvals.pending.length >= 2) break;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }

      expect(state.approvals.pending.length).toBeGreaterThanOrEqual(2);
      expect(state.approvals.pending[0].sessionId).toBe("session-hot-drilldown");
      expect(state.approvals.pending[1].sessionId).toBe("session-cool-drilldown");

      const hottest = await isolated.app.inject({
        method: "GET",
        url: `/api/dashboard/drilldown/approval/${encodeURIComponent(state.approvals.pending[0].requestId)}`,
      });
      expect(hottest.statusCode).toBe(200);
      expect(hottest.json().facts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ label: "Queue", value: "1 of 2 pending" }),
        ])
      );
      expect(hottest.json().queueNavigation).toMatchObject({
        previousRequestId: null,
        previousRule: null,
        nextRequestId: state.approvals.pending[1].requestId,
        nextTarget: expect.stringContaining("session-cool-drilldown"),
        nextRule: "tool:require-approval-shell",
      });

      const next = await isolated.app.inject({
        method: "GET",
        url: `/api/dashboard/drilldown/approval/${encodeURIComponent(state.approvals.pending[1].requestId)}`,
      });
      expect(next.statusCode).toBe(200);
      expect(next.json().facts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ label: "Queue", value: "2 of 2 pending" }),
        ])
      );
      expect(next.json().queueNavigation).toMatchObject({
        previousRequestId: state.approvals.pending[0].requestId,
        previousTarget: expect.stringContaining("session-hot-drilldown"),
        previousRule: "tool:require-approval-shell",
        nextRequestId: null,
        nextRule: null,
      });

      await Promise.all([coolApproval, hotApproval]);
    } finally {
      await isolated.app.close();
    }
  });

  it("shows queue position and rule context in pending approval drilldowns", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3014,
      approval: {
        ...config.approval,
        mode: "always",
        timeoutMs: 400,
        backend: "memory",
      },
    });

    try {
      const first = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-review-low",
            sessionId: "session-review-low",
            plane: "tool",
            action: "http_request",
            payload: { url: "https://api.openai.com/v1/models" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["network:require-approval-egress"],
            reasons: ["Operator review required"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });
      await waitForPendingApproval(isolated.app, 10);
      await new Promise((resolve) => setTimeout(resolve, 25));

      const second = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-review-hot",
            sessionId: "session-review-hot",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "rm -rf /tmp/demo" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "critical",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Critical shell execution requires approval"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });

      let state;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
        if (state.approvals.pending.length >= 2) break;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }

      expect(state.approvals.pending.length).toBeGreaterThanOrEqual(2);

      const hottest = await isolated.app.inject({
        method: "GET",
        url: `/api/dashboard/drilldown/approval/${encodeURIComponent(state.approvals.pending[0].requestId)}`,
      });
      expect(hottest.statusCode).toBe(200);
      const hottestDetail = hottest.json();
      expect(hottestDetail.facts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ label: "Queue", value: "1 of 2 pending" }),
          expect.objectContaining({ label: "Rule hit", value: "tool:require-approval-shell" }),
        ])
      );
      expect(hottestDetail.queueNavigation).toMatchObject({
        previousRequestId: null,
        previousTarget: null,
        previousDetail: null,
        previousRule: null,
        nextRequestId: state.approvals.pending[1].requestId,
        nextTarget: expect.stringContaining("session-review-low"),
        nextDetail: expect.stringContaining("Operator review required"),
        nextRule: "network:require-approval-egress",
      });

      const next = await isolated.app.inject({
        method: "GET",
        url: `/api/dashboard/drilldown/approval/${encodeURIComponent(state.approvals.pending[1].requestId)}`,
      });
      expect(next.statusCode).toBe(200);
      const nextDetail = next.json();
      expect(nextDetail.facts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ label: "Queue", value: "2 of 2 pending" }),
          expect.objectContaining({ label: "Rule hit", value: "network:require-approval-egress" }),
        ])
      );
      expect(nextDetail.queueNavigation).toMatchObject({
        previousRequestId: state.approvals.pending[0].requestId,
        previousTarget: expect.stringContaining("session-review-hot"),
        previousDetail: expect.stringContaining("Critical shell execution requires approval"),
        previousRule: "tool:require-approval-shell",
        nextRequestId: null,
        nextTarget: null,
        nextDetail: null,
        nextRule: null,
      });

      await isolated.app.inject({
        method: "POST",
        url: `/approval/${encodeURIComponent(state.approvals.pending[0].requestId)}/respond`,
        payload: { decision: "approved", note: "top done" },
      });
      await isolated.app.inject({
        method: "POST",
        url: `/approval/${encodeURIComponent(state.approvals.pending[1].requestId)}/respond`,
        payload: { decision: "approved", note: "done" },
      });

      await first;
      await second;
    } finally {
      await isolated.app.close();
    }
  });

  it("surfaces queue position and same-session lane labels directly on pending approval rows", async () => {
    const isolated = await buildServer({
      ...config,
      port: 3016,
      approval: {
        ...config.approval,
        mode: "always",
        timeoutMs: 400,
        backend: "memory",
      },
    });

    try {
      const first = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-lane-primary",
            sessionId: "session-lane-hot",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "rm -rf /tmp/a" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "critical",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Critical shell execution requires approval"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });
      await waitForPendingApproval(isolated.app, 10);
      await new Promise((resolve) => setTimeout(resolve, 25));

      const second = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-lane-secondary",
            sessionId: "session-lane-hot",
            plane: "tool",
            action: "bash_exec",
            payload: { command: "rm -rf /tmp/b" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "critical",
            matchedRules: ["tool:require-approval-shell"],
            reasons: ["Critical shell execution requires approval"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });
      await new Promise((resolve) => setTimeout(resolve, 25));

      const third = isolated.app.inject({
        method: "POST",
        url: "/approval/request",
        payload: {
          context: {
            agentId: "agent-lane-other",
            sessionId: "session-lane-other",
            plane: "tool",
            action: "http_request",
            payload: { url: "https://api.openai.com/v1/models" },
          },
          policyResult: {
            decision: "approve",
            riskLevel: "high",
            matchedRules: ["network:require-approval-egress"],
            reasons: ["Operator review required"],
            requiresApproval: true,
            highRiskFlow: true,
          },
        },
      });

      let state;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
        if (state.approvals.pending.length >= 3) break;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }

      expect(state.approvals.pending).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            sessionId: "session-lane-hot",
            queuePositionLabel: "1 of 3 pending",
            sessionLaneLabel: "2 pending approvals in this session",
          }),
          expect.objectContaining({
            sessionId: "session-lane-hot",
            queuePositionLabel: "2 of 3 pending",
            sessionLaneLabel: "2 pending approvals in this session",
          }),
          expect.objectContaining({
            sessionId: "session-lane-other",
            queuePositionLabel: "3 of 3 pending",
            sessionLaneLabel: "1 pending approval in this session",
          }),
        ])
      );

      await Promise.all([first, second, third]);
    } finally {
      await isolated.app.close();
    }
  });


  it("supports incident simulation mode for demo telemetry", async () => {
    const { app } = await serverPromise;
    const baselineState = (await app.inject({ method: "GET", url: "/api/dashboard/state" })).json();

    const start = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/simulation",
      payload: { action: "start" },
    });
    expect(start.statusCode).toBe(200);
    expect(start.json().simulation.enabled).toBe(true);

    const stateResponse = await app.inject({ method: "GET", url: "/api/dashboard/state" });
    const state = stateResponse.json();

    expect(state.simulation.enabled).toBe(true);
    expect(state.approvals.pending.some((item: { simulated?: boolean }) => item.simulated)).toBe(true);
    expect(state.runtimeFlows.some((item: { simulated?: boolean }) => item.simulated)).toBe(true);
    expect(state.eventFeed.some((item: { synthetic?: boolean }) => item.synthetic)).toBe(true);

    const clear = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/simulation",
      payload: { action: "clear" },
    });
    expect(clear.statusCode).toBe(200);
    expect(clear.json().simulation.enabled).toBe(false);

    const clearedState = (await app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
    expect(clearedState.simulation.enabled).toBe(false);
    expect(clearedState.runtimeFlows.some((item: { simulated?: boolean }) => item.simulated)).toBe(false);
    expect(clearedState.activeAgents.some((item: { agentId: string }) => item.agentId === "sim-operator")).toBe(false);
    expect(clearedState.posture.activeAgents).toBe(baselineState.posture.activeAgents);
  });

  it("keeps operator truth consistent when watchdog pressure exists without approval pressure", async () => {
    const isolated = await buildServer({
      ...config,
      watchdog: {
        ...config.watchdog,
        staleAfterMs: 1,
        timeoutMs: 2,
        killSwitchMode: "monitor",
      },
    });

    try {
      const evaluation = await isolated.app.inject({
        method: "POST",
        url: "/evaluate",
        payload: {
          agentId: "agent-watchdog-truth",
          sessionId: "session-watchdog-truth",
          plane: "governance",
          action: "list_status",
          payload: {},
        },
      });
      expect(evaluation.statusCode).toBe(200);
      expect(evaluation.json().decision).toBe("allow");

      await new Promise((resolve) => setTimeout(resolve, 10));

      const state = (await isolated.app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
      const watchdogQueueItem = state.priorityQueue.find((item: { category: string; owner: string }) =>
        item.category === "watchdog" && item.owner === "agent-watchdog-truth"
      );

      expect(state.posture.pendingApprovals).toBe(0);
      expect(state.posture.approvalPressure).toBe(0);
      expect(state.posture.healthPressure).toBeGreaterThanOrEqual(1);
      expect(state.posture.operatorPressure).toBeGreaterThanOrEqual(1);
      expect(state.service.attentionRequired).toBe(true);
      expect(state.service.operatorSummary).toContain("0 approval(s) open");
      expect(state.service.operatorSummary).toContain("health pressure");
      expect(state.health.watchdogStates.some((item: { agentId: string; status: string }) => item.agentId === "agent-watchdog-truth" && item.status === "expired")).toBe(true);
      expect(watchdogQueueItem).toEqual(expect.objectContaining({ status: "critical", primaryAction: "Inspect agent" }));
      expect(state.service.latestVerifiedOutcome).toEqual(
        expect.objectContaining({
          source: "audit",
          decision: "allow",
          action: "list_status",
          agentId: "agent-watchdog-truth",
        })
      );
      expect(state.commandDeck.risks.items.some((item: { title: string }) => item.title.includes("No live runtime risk"))).toBe(false);
    } finally {
      await isolated.app.close();
    }
  });

  it("supports floodguard telemetry, shield mode, and prioritized pending approvals", async () => {
    const { app } = await serverPromise;

    await app.inject({ method: "POST", url: "/api/dashboard/control/floodguard-mode", payload: { mode: "shield", durationMs: 60_000 } });

    const pendingA = app.inject({
      method: "POST",
      url: "/approval/request",
      payload: {
        context: { agentId: "agent-low", sessionId: "session-low", plane: "tool", action: "safe_action", payload: {} },
        policyResult: { decision: "approve", riskLevel: "low", matchedRules: [], reasons: ["low risk"], requiresApproval: true, highRiskFlow: false },
      },
    });

    const pendingB = app.inject({
      method: "POST",
      url: "/approval/request",
      payload: {
        context: { agentId: "agent-high", sessionId: "session-high", plane: "tool", action: "bash_exec", payload: {} },
        policyResult: { decision: "approve", riskLevel: "critical", matchedRules: [], reasons: ["critical risk"], requiresApproval: true, highRiskFlow: true },
      },
    });

    const pending = await waitForPendingApproval(app);

    const state = (await app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
    expect(state.floodGuard.mode).toBe("shield");
    expect(typeof state.floodGuard.shieldUntil).toBe("string");
    expect(Array.isArray(state.floodGuard.recentBlocks)).toBe(true);
    if (state.approvals.pending.length >= 2) {
      const riskRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      expect((riskRank[state.approvals.pending[0].riskLevel] ?? 0)).toBeGreaterThanOrEqual(riskRank[state.approvals.pending[1].riskLevel] ?? 0);
    }
    const approvalQueueItem = state.priorityQueue.find((item: { category: string }) => item.category === "approval");
    expect(approvalQueueItem).toBeDefined();
    expect(approvalQueueItem.status).toBe("critical");
    expect(approvalQueueItem.summary).toContain("waiting");
    expect(approvalQueueItem.drilldownKind).toBe("approval");
    expect(approvalQueueItem.drilldownId).toBe(approvalQueueItem.id);
    expect(approvalQueueItem.primaryAction).toBe("Review");
    expect(state.controlMatrix.find((item: { label: string }) => item.label === "Approval Gate")?.detail).toContain("oldest waiting");
    expect(state.service.recommendedActions.some((item: string) => item.includes("oldest has been waiting"))).toBe(true);
    expect(state.floodGuard.operatorGuidance.status).toBe("active");
    expect(state.floodGuard.operatorGuidance.summary).toContain("Shield mode is active");
    expect(state.floodGuard.operatorGuidance.recommendedAction).toContain("before returning to normal mode");
    expect(state.service.recommendedActions.some((item: string) => item.includes("before returning to normal mode"))).toBe(true);

    for (const item of pending.slice(0, 4)) {
      await app.inject({
        method: "POST",
        url: "/approval/" + item.requestId + "/respond",
        payload: { decision: "approved", note: "flush" },
      });
    }

    await pendingA;
    await pendingB;

    const override = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/floodguard-session/session-high",
      payload: { action: "set", multiplier: 1.5, durationMs: 60_000 },
    });
    expect(override.statusCode).toBe(200);
    expect(override.json().override.sessionId).toBe("session-high");

    const withOverride = (await app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
    expect(Array.isArray(withOverride.floodGuard.sessionOverrides)).toBe(true);
    expect(withOverride.floodGuard.sessionOverrides.some((item: { sessionId: string }) => item.sessionId === "session-high")).toBe(true);

    const cleared = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/floodguard-session/session-high",
      payload: { action: "clear" },
    });
    expect(cleared.statusCode).toBe(200);

    const normal = await app.inject({ method: "POST", url: "/api/dashboard/control/floodguard-mode", payload: { mode: "normal" } });
    expect(normal.statusCode).toBe(200);
    expect(normal.json().mode).toBe("normal");
  });

  it("supports operator approval mode changes, session controls, and drilldowns", async () => {
    const { app } = await serverPromise;

    const evaluation = await app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-session",
        sessionId: "session-42",
        plane: "tool",
        action: "bash_exec",
        payload: { command: "ls -la" },
        provenance: [{ source: "user", trustLabel: "trusted" }],
        flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
      },
    });
    expect(evaluation.statusCode).toBe(200);

    const modeResponse = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/approval-mode",
      payload: { mode: "never" },
    });
    expect(modeResponse.statusCode).toBe(200);
    expect(modeResponse.json().mode).toBe("never");

    const autoApproval = await app.inject({
      method: "POST",
      url: "/approval/request",
      payload: {
        context: {
          agentId: "agent-session",
          sessionId: "session-42",
          plane: "tool",
          action: "rm_exec",
          payload: { command: "rm -rf /tmp/foo" },
        },
        policyResult: {
          decision: "approve",
          riskLevel: "high",
          matchedRules: ["tool:require-approval-shell"],
          reasons: ["Destructive shell execution requires human approval"],
          requiresApproval: true,
          highRiskFlow: true,
        },
      },
    });
    expect(autoApproval.statusCode).toBe(200);
    expect(autoApproval.json().decision).toBe("approved");

    const sessionControl = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/session/session-42",
      payload: { action: "pause", note: "Hold investigation" },
    });
    expect(sessionControl.statusCode).toBe(200);
    expect(sessionControl.json().session.status).toBe("paused");

    const blockedEval = await app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-session",
        sessionId: "session-42",
        plane: "tool",
        action: "bash_exec",
        payload: { command: "pwd" },
      },
    });
    expect(blockedEval.statusCode).toBe(423);

    const stateResponse = await app.inject({ method: "GET", url: "/api/dashboard/state" });
    const state = stateResponse.json();
    expect(state.controls.approvalMode).toBe("never");
    expect(state.sessions.recent.some((item: { sessionId: string; status: string }) => item.sessionId === "session-42" && item.status === "paused")).toBe(true);

    const terminateResponse = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/session/session-42",
      payload: { action: "terminate", confirm: true, note: "Containment" },
    });
    expect(terminateResponse.statusCode).toBe(200);
    expect(terminateResponse.json().session.status).toBe("terminated");

    const terminatedState = (await app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
    expect(terminatedState.posture.criticalSignals).toBeGreaterThan(0);
    expect(terminatedState.service.attentionRequired).toBe(true);
    expect(terminatedState.service.operatorSummary).toContain("critical signal(s)");
    expect(terminatedState.service.operatorSummary).toContain("terminated");
    expect(terminatedState.service.recommendedActions).toContain("Inspect terminated sessions and capture audit evidence before normalizing controls.");
    expect(terminatedState.priorityQueue.some((item: { category: string; status: string }) => item.category === "session" && item.status === "critical")).toBe(true);

    const resumeTerminated = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/session/session-42",
      payload: { action: "resume" },
    });
    expect(resumeTerminated.statusCode).toBe(409);
    expect(resumeTerminated.json().error).toContain("cannot be resumed");

    const pauseTerminated = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/session/session-42",
      payload: { action: "pause", note: "Attempt reopen" },
    });
    expect(pauseTerminated.statusCode).toBe(409);
    expect(pauseTerminated.json().error).toContain("cannot be paused");

    const afterResumeAttempt = (await app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
    expect(afterResumeAttempt.sessions.recent.some((item: { sessionId: string; status: string }) => item.sessionId === "session-42" && item.status === "terminated")).toBe(true);

    const sessionDrilldown = await app.inject({ method: "GET", url: "/api/dashboard/drilldown/session/session-42" });
    expect(sessionDrilldown.statusCode).toBe(200);
    const sessionDetail = sessionDrilldown.json();
    expect(sessionDetail.kind).toBe("session");
    expect(sessionDetail.related.evidence.length).toBeGreaterThan(0);
    expect(sessionDetail.related.tasks.length).toBeGreaterThan(0);
  });

  it("rejects terminate controls that skip explicit confirmation", async () => {
    const { app } = await serverPromise;

    const evaluation = await app.inject({
      method: "POST",
      url: "/evaluate",
      payload: {
        agentId: "agent-confirm",
        sessionId: "session-confirm",
        plane: "tool",
        action: "bash_exec",
        payload: { command: "id" },
        provenance: [{ source: "user", trustLabel: "trusted" }],
        flow: { direction: "internal", labels: ["destructive_action"], highRisk: true },
      },
    });
    expect(evaluation.statusCode).toBe(200);

    const terminateResponse = await app.inject({
      method: "POST",
      url: "/api/dashboard/control/session/session-confirm",
      payload: { action: "terminate", note: "Containment" },
    });
    expect(terminateResponse.statusCode).toBe(400);
    expect(terminateResponse.json().error).toContain("explicit confirmation");

    const state = (await app.inject({ method: "GET", url: "/api/dashboard/state" })).json();
    expect(state.sessions.recent.some((item: { sessionId: string; status: string }) => item.sessionId === "session-confirm" && item.status === "active")).toBe(true);
  });
});
