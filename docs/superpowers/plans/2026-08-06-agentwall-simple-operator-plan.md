# AgentWall Simple Operator Implementation Plan

> **For agentic workers:** Use the repository task workflow. Complete each task in order when it has a dependency. Use tests for every new behavior.

**Goal:** Make AgentWall simple for first-time users, complete the local operator experience, add persistent MCP inventory control, and state an enterprise upgrade path.

**Architecture:** Keep the existing policy, proxy, audit, and verification engines. Add a guided setup module, a typed operator action route, and a persistent MCP baseline store. Rebuild the public copy and console around the existing server contracts.

**Tech Stack:** TypeScript 5, Node.js 22.12+, Fastify 5, Zod 4, YAML, vanilla browser JavaScript, CSS, Jest.

## Global Constraints

- Public prose uses ASD-STE100 style.
- Public files contain no competitor name or competitor link.
- Existing security defaults stay fail-closed where they already apply.
- Explicit environment variables override generated local environment values.
- The UI never accepts or executes an arbitrary shell command.
- Host changes show a plan before an install action.
- Audit records never store secrets or raw sensitive payloads.
- New production behavior starts with a failing behavior test.
- Subagents skip formatters, linters, builds, and project-wide tests.
- The controller runs `npm run lint`, `npm test`, and the advisor after each phase.

---

## Task 1: Add guided local setup

**Files:**
- Create: `src/setup.ts`
- Modify: `src/cli.ts:100-235,271-304,1621-1727`
- Modify: `src/onboarding.ts:54-123`
- Test: `tests/setup-command.test.ts`
- Modify: `tests/cli.test.ts`

**Interfaces:**
- `createLocalOperatorFiles(baseDir: string, options: LocalSetupOptions): LocalSetupResult`
- `loadGeneratedEnvironment(baseDir: string): Record<string, string>`
- `LocalSetupOptions` uses `mode`, `host`, `port`, `allowedHosts`, `lanAccess`, and `force`.
- `LocalSetupResult` returns `configPath`, `policyPath`, `environmentPath`, `auditPath`, `dashboardUrl`, and `created: boolean`.

- [ ] **Step 1: Write the failing test**

Test these observable behaviors:

```ts
it("creates safe local files and a mode-0600 operator environment", () => {
  const result = createLocalOperatorFiles(tempDir, {
    mode: "monitor",
    host: "127.0.0.1",
    port: 3000,
    allowedHosts: [],
    lanAccess: false,
    force: false,
  });
  expect(result.environmentPath).toContain(".agentwall/operator.env");
  expect(statSync(result.environmentPath).mode & 0o777).toBe(0o600);
  expect(readFileSync(result.environmentPath, "utf8")).toContain("AGENTWALL_OPERATOR_TOKEN=");
  expect(readFileSync(result.environmentPath, "utf8")).toContain("AGENTWALL_AUDIT_FILE=");
});

it("does not replace an existing config without force", () => {
  writeFileSync(join(tempDir, "agentwall.config.yaml"), "existing");
  expect(() => createLocalOperatorFiles(tempDir, options)).toThrow(/overwrite/i);
});

it("gives an explicit environment variable priority over the generated file", () => {
  process.env.AGENTWALL_PROXY_PORT = "9999";
  expect(loadGeneratedEnvironment(tempDir).AGENTWALL_PROXY_PORT).toBe("9999");
});
```

- [ ] **Step 2: Run the focused test and confirm the expected missing-symbol failure**

Run: `npm test -- --runInBand tests/setup-command.test.ts`
Expected: FAIL because the setup module and command do not exist.

- [ ] **Step 3: Implement the setup module**

Generate a 32-byte random token with `randomBytes(32).toString("hex")`.
Write the starter files through `writeStarterFiles`.
Write `.agentwall/operator.env` with the token and absolute audit path.
Create the parent directory with mode `0700` where supported.
Write the environment file with mode `0600` where supported.
Append `.agentwall/`, `agentwall-approvals.json`, and the audit file to `.gitignore` only when absent.
Preserve existing user lines in `.gitignore`.
Reject overwrite unless `force` is true.

- [ ] **Step 4: Load generated values without overriding explicit values**

Before startup, read `.agentwall/operator.env` from the current directory.
Parse only `KEY=value` lines for known AgentWall variables.
Do not execute the file as shell code.
Use `process.env[key]` when it exists.
Use the generated value only when the process value is absent.
Pass the merged environment to the child process in `runNodeScript`.

- [ ] **Step 5: Add the `agentwall setup` command**

Accept `--mode`, `--host`, `--port`, `--allow-hosts`, `--lan`, and `--force`.
Use monitor mode and loopback binding by default.
Print two next commands: `agentwall start` and `agentwall doctor`.
Never print the operator token.
Keep `agentwall init` unchanged for compatibility.

- [ ] **Step 6: Run the focused tests and the existing CLI tests**

Run: `npm test -- --runInBand tests/setup-command.test.ts tests/cli.test.ts`
Expected: PASS with zero failures.

---

## Task 2: Add a typed operator action API

**Files:**
- Create: `src/routes/operator.ts`
- Modify: `src/server.ts:1-204`
- Modify: `src/fleet/command.ts:327-599`
- Modify: `src/config.ts` only when the route needs a typed generated path
- Test: `tests/operator-routes.test.ts`

**Interfaces:**
- `OperatorActionSchema` is a Zod discriminated union on `action`.
- `OperatorActionResult` contains `ok`, `action`, `status`, `message`, `next`, and optional `data`.
- `operatorRoutes(app, context)` registers `GET /api/operator/actions` and `POST /api/operator/actions`.
- Supported actions are `doctor`, `verify`, `lockdown`, `reload`, `approval-mode`, `floodguard-mode`, `session`, `fleet-list`, `fleet-issue`, `fleet-rotate`, `fleet-revoke`, `intercept-status`, `intercept-init`, `intercept-trust`, `perimeter-plan`, `perimeter-status`, `perimeter-verify`, `sandbox-probe`, `sandbox-plan`, `decoy-list`, `decoy-generate`, and `setup-status`.

- [ ] **Step 1: Write failing route tests**

Cover these behaviors:

```ts
it("lists only allowlisted operator actions", async () => {
  const response = await app.inject({ method: "GET", url: "/api/operator/actions" });
  expect(response.statusCode).toBe(200);
  expect(response.json().actions).not.toContain("shell");
});

it("rejects an unknown action before it reaches an executor", async () => {
  const response = await app.inject({ method: "POST", url: "/api/operator/actions", payload: { action: "shell" } });
  expect(response.statusCode).toBe(400);
});

it("requires confirmation before a destructive session action", async () => {
  const response = await app.inject({ method: "POST", url: "/api/operator/actions", payload: { action: "session", sessionId: "session-1", operation: "terminate" } });
  expect(response.statusCode).toBe(409);
  expect(response.json().next).toMatch(/confirm/i);
});
```

- [ ] **Step 2: Run the route tests and confirm the expected missing-route failure**

Run: `npm test -- --runInBand tests/operator-routes.test.ts`
Expected: FAIL because the route does not exist.

- [ ] **Step 3: Implement the action schema and route registration**

Use Zod validation for every body.
Reuse the existing authenticated Fastify request context.
Reuse existing dashboard control functions for lockdown, reload, approval mode, FloodGuard, and session operations.
Return status `400` for schema errors, `401` for missing operator auth, `403` for cross-origin mutations, `409` for missing confirmation, and `200` for completed actions.
Never return raw secrets in list, status, or error data.
Return a one-sentence message and a concrete next action.

- [ ] **Step 4: Expose structured fleet operations**

Add typed helpers beside `runFleetCommand`:

```ts
export interface FleetActionResult {
  operation: "list" | "issue" | "rotate" | "revoke";
  agentId?: string;
  credentialId?: string;
  secret?: string;
  previousCredentialId?: string;
  previousAcceptedUntil?: string;
  credentials?: Array<{ agentId: string; credentialId: string; state: string; issuedAt: string; expiresAt?: string; revokedAt?: string; revokedReason?: string }>;
}
```

Use the existing `CredentialStore` methods.
Return a newly issued secret only in the one response that creates it.
Do not write that secret to the audit chain.
Reuse `effectNotes` logic for the plain-language response.

- [ ] **Step 5: Add safe host-operation responses**

Return a plan for perimeter and sandbox operations.
Return current status for interception, decoys, and setup.
Require `confirm: true` for `intercept-init`, `decoy-generate`, and perimeter install if that action is added.
Do not add an arbitrary process runner.

- [ ] **Step 6: Register the routes and run focused tests**

Run: `npm test -- --runInBand tests/operator-routes.test.ts tests/route-auth.test.ts tests/fleet-credentials.test.ts`
Expected: PASS with zero failures.

---

## Task 3: Add persistent MCP inventory learning and lock mode

**Files:**
- Create: `src/mcp/baseline.ts`
- Modify: `src/mcp/types.ts`
- Modify: `src/mcp/gates.ts:114-126,251-317`
- Modify: `src/mcp/wrap.ts:66-87,370-522`
- Modify: `src/cli.ts:1409-1574`
- Test: `tests/mcp-baseline.test.ts`
- Modify: `tests/mcp-gates.test.ts`

**Interfaces:**
- `McpBaselineMode = "off" | "learn" | "lock"`.
- `McpBaselineKey = { agentId: string; serverName: string; commandHash?: string }`.
- `McpBaselineStore` exposes `read(key)`, `write(key, tools)`, and `path`.
- `McpBaselineDecision = { state: "missing" | "matched" | "learned" | "drift"; drift: string[] }`.
- `GateContext` adds `baselineMode`, `baselineStore`, and `baselineKey`.

- [ ] **Step 1: Write failing baseline tests**

Cover these behaviors:

```ts
it("learns the first approved inventory and persists it atomically", () => {
  const store = new McpBaselineStore(filePath);
  const tools = [{ name: "search", description: "Search records" }];
  expect(store.read(key)).toBeUndefined();
  store.write(key, tools);
  expect(store.read(key)).toEqual(tools);
});

it("reports changed tools as drift in lock mode", () => {
  const context = contextFor({ mode: "lock", baseline: [{ name: "search", description: "Search records" }] });
  const result = evaluateFrame(changedInventory, "server_to_client", context);
  expect(result.decision).toBe("approve");
  expect(result.detectionIds).toContain("det.mcp.tool.drift");
});

it("does not update a locked baseline from a denied inventory", () => {
  const store = new McpBaselineStore(filePath);
  const context = contextFor({ mode: "lock", store });
  evaluateFrame(poisonedInventory, "server_to_client", context);
  expect(store.read(key)).toEqual(originalTools);
});
```

- [ ] **Step 2: Run the baseline tests and confirm the expected missing-symbol failure**

Run: `npm test -- --runInBand tests/mcp-baseline.test.ts tests/mcp-gates.test.ts`
Expected: FAIL because the baseline store and mode are not present.

- [ ] **Step 3: Implement the atomic baseline store**

Use JSON with a version field and keyed entries.
Use a temporary file in the same directory and `rename` for replacement.
Create the parent directory when needed.
Treat a missing file as an empty store.
Treat malformed JSON as a hard lock-mode error and a learn-mode warning result.
Never store tool arguments or tool output.

- [ ] **Step 4: Add learn and lock behavior to the inventory gate**

`off` keeps the current session-only behavior.
`learn` reads the store and writes a clean first inventory.
`lock` reads the store and returns approval for drift.
A poisoned inventory always denies and never writes.
A clean matched inventory returns allow.
Add `mcpBaselineMode`, `mcpBaselineState`, and `mcpBaselinePath` to audit metadata.

- [ ] **Step 5: Add CLI flags and help**

Add `--baseline-mode off|learn|lock`.
Add `--baseline-file <path>`.
Default to `off` for backward compatibility.
Reject an invalid mode before launching the MCP server.
Print the selected mode and file path without printing tool contents.

- [ ] **Step 6: Run MCP tests**

Run: `npm test -- --runInBand tests/mcp-baseline.test.ts tests/mcp-gates.test.ts tests/mcp-wrap.test.ts tests/mcp-wrap-durability.test.ts`
Expected: PASS with zero failures.

---

## Task 4: Build the simple operator console

**Files:**
- Modify: `public/index.html`
- Modify: `public/styles.css`
- Modify: `public/app.js`
- Modify: `src/routes/ui.ts` only if a new static asset route is needed
- Test: `tests/dashboard.test.ts`
- Create: `tests/public-console.test.ts`

**Interfaces:**
- Keep `/api/dashboard/state`, `/api/dashboard/events`, existing dashboard control routes, evidence routes, and approval routes.
- Use `POST /api/operator/actions` for the new action catalog.
- Use `data-action`, `data-confirm`, and `aria-live` attributes for operator controls.

- [ ] **Step 1: Write failing console contract tests**

Assert that the page contains:

```ts
expect(html.body).toContain("Agentwall status");
expect(html.body).toContain("Next action");
expect(html.body).toContain("Approvals");
expect(html.body).toContain("Agents");
expect(html.body).toContain("Evidence");
expect(html.body).toContain("Operations");
expect(html.body).toContain('aria-live="polite"');
expect(html.body).toContain('data-action="operator"');
```

Assert that the script contains:

```ts
expect(script.body).toContain("/api/operator/actions");
expect(script.body).toContain("function renderOperatorAction");
expect(script.body).toContain("prefers-reduced-motion");
```

- [ ] **Step 2: Run the console tests and confirm the expected old-copy failure**

Run: `npm test -- --runInBand tests/public-console.test.ts tests/dashboard.test.ts`
Expected: FAIL because the new shell markers do not exist.

- [ ] **Step 3: Replace the shell with five visible areas**

Use a single rail with Status, Approvals, Policy, Agents, Evidence, and Operations.
Remove the default hidden Advanced User mode.
Keep progressive disclosure inside each area with native `details` elements or buttons.
Keep the existing Knowledge Base route and show it as Help.
Move important warnings to the top of the page.
Show the exact mode and the last update time.

- [ ] **Step 4: Add complete UI state handling**

Render a skeleton while the first state loads.
Render a useful empty state when no approvals or events exist.
Render an inline error with retry when a request fails.
Render success and failure messages in the live region.
Show live EventSource status and polling fallback.
Use confirmation for terminate, revoke, lockdown, and other destructive actions.
Keep all controls keyboard accessible.
Add a small-screen breakpoint below 600 pixels.

- [ ] **Step 5: Add operator action controls**

Load the action catalog from `/api/operator/actions`.
Render only the actions returned by the server.
Use a form for action parameters.
Send JSON through `fetch` with the existing auth behavior.
Show one plain-language next step after each response.
For a returned secret, show it once with a copy button and a warning.
Never persist the secret in browser storage.

- [ ] **Step 6: Add public-console tests and run the focused suite**

Run: `npm test -- --runInBand tests/public-console.test.ts tests/dashboard.test.ts tests/route-auth.test.ts`
Expected: PASS with zero failures.

---

## Task 5: Rewrite public wording and organize the documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/README.md`
- Create: `docs/user-guide.md`
- Create: `docs/operator-guide.md`
- Create: `docs/feature-reference.md`
- Create: `docs/glossary.md`
- Modify: `docs/install.md`
- Modify: `docs/onboarding.md`
- Modify: `docs/enforcement.md`
- Modify: `docs/threat-model.md`
- Modify: `docs/sandbox.md`
- Modify: `docs/architecture.md`
- Modify: `docs/reference.md`
- Modify: `SECURITY.md`
- Modify: `CONTRIBUTING.md`
- Modify: `GOVERNANCE.md`
- Modify: `package.json`

**Interfaces:**
- Preserve all existing command names, option names, route paths, and code blocks.
- Use the new setup flow as the primary quick start.
- Link each capability to one canonical document.

- [ ] **Step 1: Rewrite README as a decision page**

Use this order:

1. What AgentWall does.
2. What it does not do.
3. Install and setup.
4. First run.
5. Feature summary.
6. Limits.
7. Documentation links.
8. Security and license.

Use short sentences and active voice.
Put limits beside the related feature.
Do not use em dashes.
Do not mention another product.

- [ ] **Step 2: Add the user guide**

Cover install, setup, start, doctor, monitor mode, guarded mode, strict mode, approvals, and common errors.
Each procedure has a goal, exact command, expected result, and fix for one common failure.
Use no more than six sentences per paragraph.

- [ ] **Step 3: Add the operator guide and feature reference**

Map every CLI command to its UI action.
State host-only actions with a reason.
List the limits for TLS visibility, event streams, body size, attribution, DNS, and fleet scope.
Document the MCP baseline modes.

- [ ] **Step 4: Add the glossary**

Define proxy, policy, audit record, hash chain, approval, baseline, interception, perimeter, sandbox, and fleet.
Use one sentence per term.

- [ ] **Step 5: Rewrite the remaining public security and operation documents**

Rewrite install, onboarding, enforcement, threat model, sandbox, architecture, reference, security, contributing, and governance content.
Keep technical terms in code and API sections.
Use plain alternatives in explanations.
Remove all competitor names and links.

- [ ] **Step 6: Add a public copy check**

Create `scripts/check-public-copy.js`.
The script scans tracked public text files for competitor names, competitor URLs, em dashes, and placeholder words.
It exits 1 when it finds a banned term.
Add `npm run check:public-copy` to `package.json`.
Add `tests/public-copy.test.ts` for the script behavior.

- [ ] **Step 7: Run the copy check and focused documentation tests**

Run: `npm run check:public-copy`
Expected: PASS with no banned terms.
Run: `npm test -- --runInBand tests/public-copy.test.ts`
Expected: PASS with zero failures.

---

## Task 6: Create brand assets and repository presentation

**Files:**
- Modify: `assets/brand/agentwall-logo-primary.svg`
- Modify: `assets/brand/agentwall-logo-mark.svg`
- Modify: `assets/brand/agentwall-logo-monochrome.svg`
- Modify: `public/assets/brand/favicon.svg`
- Create: `public/assets/brand/agentwall-social-card.svg`
- Modify: `.github/ISSUE_TEMPLATE/*` only when copy requires it
- Modify: `.github/pull_request_template.md`

**Interfaces:**
- Keep existing asset file names used by HTML.
- Use a single mark with a protected center and a simple frame.
- Use one accent color and a monochrome fallback.
- Use no external image URL.

- [ ] **Step 1: Write asset contract checks**

Check that each SVG has a viewBox, no external href, no script, and the wordmark reads `Agentwall`.
Check that the social card has a short title and no competitor reference.

- [ ] **Step 2: Replace the mark with a scalable SVG system**

Use a simple frame and protected center as the symbol.
Use a graphite base and mint accent.
Use system fonts in SVG text.
Keep the mark legible at 16 pixels.

- [ ] **Step 3: Add the repository social card and GitHub copy**

Use the title `Protect agent actions with clear rules`.
Use a short subtitle with no marketing jargon.
Keep issue and pull request instructions short and direct.

- [ ] **Step 4: Run the asset contract checks**

Run: `node scripts/check-public-copy.js`
Expected: PASS with no banned content.
Run: `npm test -- --runInBand tests/public-console.test.ts`
Expected: PASS with zero failures.

---

## Task 7: Write the enterprise upgrade plan

**Files:**
- Create: `docs/enterprise-roadmap.md`
- Modify: `docs/README.md`
- Modify: `README.md`
- Create: `docs/enterprise-controls.md`

**Interfaces:**
- The roadmap describes planned work as planned work.
- Each stage has scope, threat addressed, evidence, exit test, and owner role.
- No planned feature appears in shipped feature lists.

- [ ] **Step 1: Write the roadmap**

Include trust foundation, signed policy distribution, fleet evidence, identity and access, container deployment, operations, assurance, and support.
For each stage, define a binary exit test.
State failure behavior when the control plane or evidence service is unavailable.

- [ ] **Step 2: Add the enterprise control table**

Map each control to the current AgentWall component, current limit, required upgrade, and test evidence.
Include release signing, SBOM, SLSA provenance, OIDC, mTLS, RBAC, key rotation, policy rollback, evidence retention, SLOs, backup restore, and independent review.

- [ ] **Step 3: Link the plan from public docs**

Add one sentence in README and docs/README.
State that the document is a roadmap and does not describe shipped behavior.

- [ ] **Step 4: Run public copy and link checks**

Run: `npm run check:public-copy`
Expected: PASS with no banned terms and no broken local links.

---

## Task 8: Final verification and advisor review

**Files:**
- No source changes unless a verification failure requires a scoped fix.

- [ ] **Step 1: Run the TypeScript gate**

Run: `npm run lint`
Expected: exit code 0.

- [ ] **Step 2: Run the complete test suite**

Run: `npm test`
Expected: zero failed suites and zero failed tests.

- [ ] **Step 3: Run the integration smoke path**

Run: `npm run build`
Run: `node dist/cli.js setup --mode monitor --force` in a temporary directory.
Run: `node dist/cli.js doctor` with the generated environment.
Expected: setup creates local files, the token file is mode 0600, and doctor reports the generated config.

- [ ] **Step 4: Run the copy and asset gates**

Run: `npm run check:public-copy`
Expected: exit code 0.
Inspect the generated local console through the browser at `/dashboard`.
Expected: the status, approval, operator action, and error states render without console errors.

- [ ] **Step 5: Run the advisor**

Run: `gbrain advisor`
Record the current findings in the final report.
Do not run advisor fixes without user approval.

- [ ] **Step 6: Review the full change surface**

Run: `git status --short`.
Check that no generated token, audit file, private host, or temporary fixture is tracked.
Check that every plan task has a test result or an explicit documented limit.
