# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- FloodGuard shield mode control surface in the dashboard.
- FloodGuard per-session temporary override API and operator controls.
- Forward-facing Agentwall logo assets wired into README and public HTML surfaces.
- CLI live-control commands for dashboard status, approval mode, FloodGuard tuning, and direct session pause/resume/terminate actions.
- Approval webhook notifications for queued and resolved manual reviews via `approval.webhookUrl`.

### Changed
- CLI terminate now requires `--confirm` so hard containment is deliberate instead of one typo away.
- Live-control docs now point to the monitor-first example on port `3015` to avoid false 401/404 debugging on the wrong local service.
- Session control CLI errors now explain how to recover from `Session not found` by seeding a live runtime session first.
- CLI status now shows terminated session counts directly so containment state is visible without flipping back to the dashboard.
- CLI status now surfaces FloodGuard guidance, pressure, hottest-session context, active session-override expiry, the exact live control target, and ready-to-run CLI next moves so operators can tune runtime controls from the terminal.
- CLI top-queue output now includes the queue item's next operator action plus risk/wait summary, which makes shell-first approval triage a lot clearer.
- FloodGuard shell/dashboard operator surfaces now also show the hottest block categories, the top pressured sessions, and the latest live block reason so triage can happen before operators start flipping controls blindly.
- CLI next moves now calm back down with the runtime: once pressure is normal they recommend cleanup actions like `approval-mode auto` and `session-reset` instead of still suggesting a pause on the hottest session.
- CLI status now keeps shield normalization conservative too: it will not suggest `agentwall normal` while paused or terminated sessions still need operator review.
- CLI status suggestions now preserve `--url` or `--config` when the operator targeted a non-default instance, keeping follow-up commands copy-pasteable.
- CLI status no longer suggests `pause` for the hottest session when that session is already paused or otherwise contained, which cuts one more pointless operator step out of shell triage.
- Live-control success output now echoes the resolved Agentwall target too, so shell transcripts stay anchored to the exact instance that was changed.
- Dashboard and CLI active-agent-now counts now drop paused or terminated sessions out of the live tally while still retaining those agents in history, which fixes the misleading "active now" readout after containment.
- Approval queue ordering now prioritizes higher-risk items under pressure.
- Priority Queue approval cards now support one-click approve/deny triage from the operator dashboard.
- The default console now includes a Detection Timeline that merges queue pressure, FloodGuard blocks, and critical runtime events into one operator-first feed.
- The approvals panel now leads with a triage summary so operators immediately see what to review first or what the last decision was.
- Approval rows now surface waiting age, operator attribution, and decision context directly in the table so triage takes less scanning.
- The approvals panel now separates Pending Decisions from Recent Decisions so operators see action items before audit history.
- Critical and high-risk approvals now carry stronger inline priority badges so operators can spot the hottest review items immediately.
- Approve and deny actions from the main approvals panel now prompt for a short operator note instead of writing a generic canned note.
- Main-panel approval actions now show explicit success feedback after a decision is saved so the operator gets immediate confirmation.
- Approval rows now surface matched rule context directly in the panel so operators can see the leading policy trigger without opening drilldown.
- Pending approvals now have an explicit mixed-risk ordering test and panel-side sort to keep critical items pinned before older lower-priority reviews.
- The approvals panel now shows a queue health summary with pending count, critical count, and oldest waiting item before the pending decision list.
- Brand asset docs now point at the actual public asset path.
- Policy and config YAML now parses under the YAML 1.2 core schema on js-yaml 5. Merge keys (`<<`) are no longer expanded, so a policy file that relies on one is rejected whole and the last good ruleset stays in force instead of a partially assembled rule taking effect. Unquoted dates load as strings rather than `Date` objects, and a mapping with a complex key is rejected instead of having that key flattened into a lossy string.
- The dashboard runtime-context panel now degrades to "none" when the agent harness config file cannot be parsed, rather than failing the whole dashboard state build on a file Agentwall does not own.

## [0.1.0] - 2026-03-23

### Added
- Core policy evaluation API with provenance-aware decisions.
- Egress guardrails: default-deny, SSRF/private-range controls, host/scheme/port constraints.
- DLP inspection for common secrets and PII classes.
- Human approval flow with persistent queue backend.
- Dashboard views for decision stream, policy drilldowns, and approvals.
- Agent-harness monitor-first integration helpers and preflight adapters.
- Documentation: architecture overview and threat model.
- Community baseline files (`SECURITY.md`, `CONTRIBUTING.md`, issue/PR templates, CoC).
- CI workflow for lint/build/test/audit on push + pull requests.
