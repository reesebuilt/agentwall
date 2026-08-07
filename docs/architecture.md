# AgentWall technical architecture

## System shape

AgentWall is a stateless HTTP decision service. It keeps small local approval records.

The operator uses two local interfaces:

- `agentwall ui` starts the bootstrap UI for the first run.
- The AgentWall service provides the running operator UI.

The bootstrap UI binds to loopback by default. A non-loopback `--host` value exposes it beyond the local host.

The running service binds locally by default. An operator must configure remote access explicitly.

## Architecture boundaries

| Boundary | Purpose | Limit |
| --- | --- | --- |
| Bootstrap UI | Creates setup files and controls the local service. | It controls only the service process that it starts. |
| Operator UI | Shows status and sends typed operator actions. | It does not accept arbitrary shell commands. |
| Policy service | Evaluates an `AgentContext` before an action. | The caller must enforce the returned decision. |
| Forward proxy | Inspects permitted egress and records destinations. | It cannot inspect end-to-end TLS content without interception. |
| Perimeter | Redirects and drops traffic for one Linux uid. | It controls packets, not filesystem access. |
| Sandbox | Restricts one process tree with Landlock and seccomp. | It requires Linux. Network rules cover TCP ports only. |
| Audit chain | Records structured security events. | It records observed events only. It does not prevent an action. |

The perimeter and sandbox use different kernel controls. Run both when the host supports both controls.

## First-run control path

Run `agentwall ui` to start the bootstrap UI.

The command uses loopback and port `3001` by default. The `--host`, `--port`, and `--service-port` options change those values.

The bootstrap UI creates a one-time local session. It stores the session token in an HttpOnly, SameSite=Strict cookie.

The bootstrap server checks the cookie and the request origin for each mutation. It never prints the session token.

The bootstrap API exposes these typed actions:

- `POST /api/bootstrap/setup`
- `POST /api/bootstrap/init`
- `POST /api/bootstrap/onboard`
- `POST /api/bootstrap/start`
- `POST /api/bootstrap/dev`
- `POST /api/bootstrap/stop`

`GET /api/bootstrap/status` reports the setup state and the service state. The service state is `stopped`, `starting`, `running`, or `failed`.

The start action runs only `dist/index.js`. The development action runs only `ts-node src/index.ts`.

The bootstrap API does not accept an operator-supplied executable. This limit prevents command substitution through the first-run UI.

## Running operator control path

The running UI gets its action catalog from `GET /api/operator/actions`.

A mutation sends one typed request to `POST /api/operator/actions`. `OperatorActionSchema` validates a Zod discriminated union on `action`.

The service authenticates the operator before it dispatches an action. It rejects a disallowed origin before a mutation.

The dispatcher uses existing control functions for service actions. It uses a fixed command allowlist for local command actions.

The command path rejects shell syntax, command substitution, absolute executable paths, undeclared binaries, and working-directory traversal.

A file, process, credential, certificate, network rule, audit checkpoint, or session mutation requires confirmation.

The action response contains `ok`, `action`, `status`, `message`, and `next`. It can also contain typed `data`.

The service does not return raw secrets in list, status, or error data. A fleet issue action returns its new secret once.

No supported mutation stays host-only. The UI sends each supported mutation through a typed action.

Read-only operations show their status and output. They also show a copyable AgentWall CLI command.

A read-only view does not convert the command into an unrestricted shell action. The operator can copy the command for offline use.

## Policy decision flow

1. The caller sends an `AgentContext` to `/evaluate`.
2. The policy engine evaluates built-in rules and declarative runtime rules.
3. The engine returns a decision bundle.
4. The service emits an audit event.
5. The service updates runtime state.
6. An approval can delay the caller's action.

The decision bundle contains `decision`, `riskLevel`, `matchedRules`, `reasons`, and `detections`.

The caller remains the enforcement point. AgentWall cannot stop a caller that ignores the result.

## Core modules

- `src/policy/*` contains the rule model, match engine, runtime policy loader, and detection catalog.
- `src/planes/network/*` contains SSRF, private-range, and egress inspection.
- `src/planes/identity/*` contains content and DLP classification.
- `src/approval/*` contains the approval queue, persistence, and response handling.
- `src/audit/*` emits structured events.
- `src/dashboard/*` and `src/routes/*` provide operator state and control APIs.
- `src/operator/*` defines the typed action catalog and local command allowlist.

## Canonical data model

### `AgentContext`

- Identity: `agentId` and optional `sessionId`.
- Action: `plane`, `action`, and `payload`.
- Causality: `provenance[]` and `flow`.
- Authority: `actor` and `control.executionMode`.

### `PolicyResult`

- `decision`: `allow`, `deny`, `approve`, or `redact`.
- `riskLevel`: `low`, `medium`, `high`, or `critical`.
- `matchedRules[]` and `reasons[]`.
- `highRiskFlow`.
- `detections[]` with security metadata and optional ATT&CK mappings.

### `AuditEvent`

An `AuditEvent` contains decision metadata, a context snapshot, and detection mapping references.

## Decision precedence

The highest-impact decision wins. The order is `deny`, `approve`, `redact`, and `allow`.

The highest matched risk sets `riskLevel`. A high-risk flow can elevate a low-risk result.

## Detection mapping

`src/policy/detections.ts` maps stable `ruleId` values to detection metadata.

The metadata includes an id, name, description, and severity. It can include an ATT&CK tactic, technique, and technique ID.

This separation keeps policy logic independent from analyst context.

## Caller contract

Call `/evaluate` before each high-risk action.

Enforce every returned decision.

Wait for approval when the decision is `approve`.

Attach provenance and flow context when these values exist.

Consume the audit stream for observation and response.

The event stream reports live process state only. It does not replace the audit chain or evidence records.
