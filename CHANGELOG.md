# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- An OpenTimestamps proof parser, `src/audit/ots-proof.ts`, implementing the proof grammar of
  `docs/audit-format.md`. It is bounded against hostile input with caps on argument size, total
  size, fork depth, operation count, and working message length, because the file being verified is
  attacker-influenced by definition. RIPEMD-160 and Keccak-256 operations are declined rather than
  evaluated, matching the independent Go verifier.

### Changed
- The bundled verifier's `anchored` layer judges an anchor record by the evidence instead of by what
  the record says about itself. It recomputes each record's digest from the checkpoint the record
  embeds and reports `digest-mismatch` when they differ, requires non-empty proof bytes behind any
  submission that reached a calendar and reports `proof-missing` when they are absent, and parses the
  proof against the submitted digest, reporting `proof-parse-error` when the container does not
  parse. An anchor claiming `confirmed` with no proof file behind it fails the layer. A submission
  recorded with an `error` is exempt: it never reached a calendar, so it has no proof to point at and
  is already counted as failed.
- `agentwall anchor` parses a calendar response before keeping it, and treats one that does not parse
  as a submission failure rather than writing it as a proof. A broken or hostile answer therefore
  leaves a recorded gap instead of a file that a later verify reports as corrupt evidence.

## [0.2.0] - 2026-08-05

The first tagged release. It freezes the on-disk evidence format and makes that format
checkable by a program that shares no code with Agentwall.

Upgrade if you care whether the audit log can be quietly rewritten. Before this release the
hash chain was verifiable only by the same TypeScript that wrote it, which means a bug in the
writer was invisible to the reader. Now the format is specified in `docs/audit-format.md`, a
second implementation in Go verifies it, and the two are held against a shared corpus on every
commit. Existing audit files stay verifiable: records written before this release carry no
canonical-form marker and are still accepted through the legacy path.

Nothing about the shipped posture changed. Monitor-first is still the default, and no default
decision, policy file, or enforcement behavior moved in this release.

### Added
- Canonical form `cu1`, recorded in each record's `integrity.canon`. Object keys are ordered by
  UTF-16 code unit rather than locale collation, so a verifier in another language reproduces
  the hash without shipping ICU tables. Records without the marker are hashed under the old
  locale-dependent order and remain verifiable through a fallback path.
- A rotation manifest, `segments.jsonl`, that binds every sealed segment to its own bytes. Each
  entry carries a hash of itself and the final hash of the segment before it, so deleting a
  rotated segment, reordering two of them, or rewriting one after it was sealed is now
  detectable rather than silently invisible.
- Live-tail re-derivation. A checkpoint commits to a prefix of the live file, so the log growing
  after a checkpoint is normal and does not invalidate it, while rewriting any record inside the
  committed prefix fails verification.
- Rejection of records containing duplicate JSON keys. Implementations disagree about which
  value of a repeated member wins, so a duplicate key is a way to hand two readers the same
  bytes and have them reach different conclusions about what was recorded.
- Off-box anchoring wired to the CLI: `agentwall anchor` seals the current segment, signs an
  Ed25519 checkpoint over the composite state, and submits it to OpenTimestamps calendars.
  `agentwall verify` reports the chained, linked, and anchored layers separately and exits
  non-zero unless all three hold.
- An independent verifier, `agentwall-verify`, written in Go against `docs/audit-format.md`
  rather than against our source. It uses the Go standard library and nothing else, so
  `go list -m all` prints one line, and it performs no network access and writes no files.
  Released as static binaries for linux, macOS, and Windows.
- A 26 case conformance corpus covering valid evidence, forgeries, and boundary conditions, run
  through both verifiers on every commit. The two agree on 22 cases; the 4 remaining are places
  the bundled TypeScript verifier accepts evidence the format rejects, declared explicitly in
  the harness rather than papered over.
- `docs/audit-format.md`, the normative specification. The implementations conform to it, not
  the other way around.
- FloodGuard shield mode control surface in the dashboard.
- FloodGuard per-session temporary override API and operator controls.
- Forward-facing Agentwall logo assets wired into README and public HTML surfaces.
- CLI live-control commands for dashboard status, approval mode, FloodGuard tuning, and direct session pause/resume/terminate actions.
- Approval webhook notifications for queued and resolved manual reviews via `approval.webhookUrl`.

### Changed
- The npm package is published as `@reesebuilt/agentwall`. The unscoped name `agentwall` on npm
  belongs to an unrelated project and always has. The installed command is still `agentwall`.
- The supported Node floor is 22.12.0, declared in `engines`. Node 20 reached end of life in
  April 2026 and a security tool should not advertise a runtime that stops receiving fixes.
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

### Fixed
- OpenTimestamps proof files are named after the checkpoint digest instead of a counter that
  only advances on rotation. Two anchor passes without a rotation between them previously wrote
  the same filename, so each pass destroyed the proof the previous one had obtained. Anchoring
  on a schedule would have erased evidence at every interval.
- `agentwall verify` no longer reports "nothing anchored off-box yet" when the anchor log has
  entries. It reached that message whenever the anchor log and the checkpoint key were not both
  present, and said it in a state where it was false.

### Removed
- The direct `pino` dependency, which nothing imported. Fastify owns the logger instance the
  server actually uses and depends on pino itself, so the declared dependency only pinned a
  second, unused copy of pino 8 in the tree. Runtime dependencies are now three, `fastify`,
  `js-yaml`, and `zod`, and a clean install carries 11 fewer transitive packages.

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
