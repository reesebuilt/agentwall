# Agentwall Runtime FloodGuard (Anti-Flood / Anti-DDoS)

## Feature definition in Agentwall terms

**Runtime FloodGuard** is an inline protection layer for Agentwall control-plane APIs (`/evaluate`, `/approval/request`, `/approval/:id/respond`) that defends agent systems from:

1. **Request floods** — high-rate policy checks that starve runtime
2. **Tool abuse floods** — repeated high-risk tool actions (e.g. shell loops)
3. **Approval floods** — mass approval requests intended to overwhelm operators
4. **Queue floods** — unbounded pending-approval backlog growth
5. **Cost floods** — sustained behavior that drives hidden runtime/cognitive spend

FloodGuard is not a replacement for policy. It is a **rate + queue + budget safety envelope** around policy and approvals.

## What is implemented

Live in code:

- `src/runtime/floodguard.ts`
- integrated into:
  - `POST /evaluate`
  - `POST /approval/request`
  - `POST /approval/:requestId/respond`
- new config surface in `AgentwallConfig.runtimeGuards` with defaults:
  - session request rpm caps
  - per-tool-action rpm cap
  - approval request/response rpm caps
  - global + per-session pending queue caps
  - per-session hourly cost budget (weighted)
- 429 responses include reason + `retry-after` where applicable
- test coverage in `tests/floodguard.test.ts`

## Operator surfaces

FloodGuard state is exposed in both the dashboard and the CLI:

- blocked counts by category, the hottest guard categories, the top pressured sessions, and
  the latest live block reason
- shield mode, with tighter limits while engaged, set from the dashboard or `agentwall shield`
- per-session temporary overrides, with the remaining window shown on the active session card
- approval-queue prioritization, so higher-risk approvals are ordered first
- operator guidance in dashboard state and in `agentwall status`: recommended next move,
  pressure percentage, hottest session, and what to clear before returning to normal mode
- control endpoints under `/api/dashboard/control/floodguard-mode` and
  `/api/dashboard/control/floodguard-session/:sessionId` for mode and per-session overrides

### Live-control verification flow

Use this when validating the operator path end to end against a running Agentwall instance:

```bash
npm test -- --runInBand
npm run build
AGENTWALL_CONFIG=examples/monitor-first.config.yaml node dist/index.js
```

In another shell:

```bash
agentwall status --url http://127.0.0.1:3015
agentwall approval-mode always --url http://127.0.0.1:3015
agentwall shield --minutes 5 --url http://127.0.0.1:3015
agentwall session-boost --session live-session --multiplier 1.5 --minutes 15 --url http://127.0.0.1:3015
agentwall session-reset --session live-session --url http://127.0.0.1:3015
agentwall terminate live-session --confirm --note "Containment" --url http://127.0.0.1:3015
agentwall normal --url http://127.0.0.1:3015
```

If you need to verify `pause`, `resume`, or `terminate`, create a live session first with `/evaluate` or a real runtime request. A `404 Session not found` from those commands means the CLI path worked but the target session does not exist yet.
If you terminate a session, Agentwall treats that as hard containment. A later `resume` returns `409` and operators should start a new runtime session instead of reopening the terminated one.
Terminate is also confirmation-gated end to end now: the CLI needs `--confirm`, and dashboard/API terminate requests must include explicit confirmation before hard containment executes.

`agentwall status` now also prints the exact live control target plus CLI next moves that preserve `--url` or `--config` when you used one, so the suggested follow-up commands stay copy-pasteable against the same Agentwall instance.
The mutating live-control commands now echo that resolved target on success too, so shell-side tuning logs keep showing which Agentwall instance was actually changed.
When the operator is driving a remote or proxied instance, the status header keeps the explicit `--url` target in view and only annotates the server-advertised bind address, instead of silently swapping back to `0.0.0.0` or another internal listener address.
When pressure falls back to normal, those next moves now shift from containment suggestions to cleanup suggestions, including `agentwall approval-mode auto` and `agentwall session-reset <session>` for any still-active temporary override.
That normalization stays conservative: if paused or terminated sessions are still waiting on operator review, the CLI keeps those cleanup suggestions quiet instead of nudging the operator to relax posture too early.
