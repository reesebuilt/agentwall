# Feature reference

This page lists each main capability and its limit.
Read the limit before you depend on a capability.

## Guided local setup

`agentwall setup` creates the starter configuration, policy, operator environment, and audit path.
It uses monitor mode and loopback access by default.
It does not replace existing files without `--force`.

The `.agentwall` directory uses mode `0700` where file modes exist.
The `.agentwall/operator.env` file uses mode `0600` where file modes exist.
An explicit environment variable has priority over a generated value.
AgentWall never prints the generated operator token after setup.

**Limit:** File modes do not provide the same control on every platform.
Check local permissions before you store the files on a shared system.

## Bootstrap UI

`agentwall ui` starts the first-run UI before the service starts.
It binds to `127.0.0.1:3001` by default.
It supports setup, initialization, onboarding, production start, development start, stop, and status.

The UI uses a one-time local session token and origin checks for mutations.
It starts only fixed AgentWall entry points.

**Limit:** The bootstrap UI manages only its child service process.
It does not accept an arbitrary executable or shell command.

## Running dashboard

The running dashboard has Status, Approvals, Policy, Agents, and Evidence areas.
Secondary Operations views contain perimeter, sandbox, interception, MCP, and decoy controls.
Each supported mutation uses a typed, allowlisted action.
Each action also shows its offline CLI command.

**Limit:** The dashboard needs the running AgentWall service.
Use the bootstrap UI when the service is stopped.

## Enforcement modes

`monitor` evaluates and records traffic, but allows it.
`guarded` enforces matching deny rules.
`strict` permits only destinations in the allowlist.

Mode and allowlist changes need a service restart.
Policy rule changes can reload without a restart.
Invalid policy YAML keeps the last valid rules active.

**Limit:** Enforcement controls only traffic that reaches AgentWall.
A direct connection can bypass cooperative proxy capture.

## Forward proxy

The forward proxy handles plaintext HTTP and HTTPS `CONNECT` tunnels.
It records destination, decision, byte counts, and available process data.
A denied connection opens no upstream socket.

Plaintext HTTP inspection covers paths, headers, request bodies, response headers, and response bodies.
The proxy scans compressed bodies after bounded decompression.
It forwards the original allowed bytes without a rewrite.

**Limit:** The body scan reads at most 256 KiB from each body.
AgentWall scans the prefix and forwards the uninspected remainder.
The audit record marks this state as partial visibility.

**Limit:** Event stream bodies pass without body inspection.
AgentWall still checks their headers and records stream visibility.

## TLS visibility

Without interception, AgentWall sees the `CONNECT` authority and available TLS SNI.
It does not see the encrypted path, headers, or body.
It records absent SNI without a guess.

Interception is opt-in and off by default.
It decrypts only configured hosts after the runtime trusts the local CA.

**Limit:** Encrypted ClientHello, missing SNI, and non-TLS tunnels can hide the hostname from the TLS check.
Interception gives the CA key holder site impersonation power for trusted runtimes.

## Linux process attribution

On Linux, AgentWall reads `/proc/net/tcp` and `/proc/<pid>/fd`.
It can record the PID and process name for a proxied connection.

**Limit:** This attribution does not work on other operating systems.
A container can also hide the host socket or process descriptor.
Attribution failure records `pid: null` and does not block traffic.

## Policy engine

The policy engine supports network, file, tool, model, identity, and runtime planes.
The most restrictive decision wins.
The order is `deny` > `approve` > `redact` > `allow`.

Each result includes matched rule IDs, reasons, risk, provenance, and available flow context.

**Limit:** A proxy socket can enforce `deny` directly.
It records `approve` and `redact` when that transport cannot hold or rewrite the data.

## Approvals and sessions

The approval queue supports `auto`, `always`, and `never` modes.
Session controls support pause, resume, terminate, temporary limit boosts, and override reset.
Terminate always needs explicit confirmation.

**Limit:** Session controls apply to AgentWall decision paths.
They do not terminate an external process or close an existing direct socket.

## FloodGuard

FloodGuard tracks request rate, burst pressure, concurrency, and cost.
Shield mode applies stricter temporary limits.
Normal mode restores the standard limits.

**Limit:** Counters live in one process.
A restart resets active counter windows.

## Fleet identity and credentials

One AgentWall instance can declare multiple agents.
Each agent can have an allowlist, budget, and credential.
The UI and CLI can issue, rotate, revoke, and list credentials.
A new secret appears only in the creation response.

Identity precedence is credential, UID with process name, UID, then process name.
Each record states the signal that matched.

**Limit:** A credential separates cooperating agents, but not processes that can read the same secret.
A process name is a label that the process can change.

**Limit:** Fleet policy and budgets have per-instance scope.
Instances do not share counters, policy state, or a clustered control plane.
The transparent perimeter path carries no fleet credential or process identity.

## Perimeter

The perimeter uses a dedicated Linux UID and `nftables` rules.
It redirects that UID's outbound TCP to the transparent proxy.
It drops other outbound TCP for that UID.

`agentwall perimeter plan` prints the rules before a change.
Install, rollback, and run require root and confirmation.

**Limit:** The perimeter runs only on Linux and needs root.
It permits one configured DNS resolver or blocks DNS.
Permitted DNS remains an exfiltration path.

## Sandbox

The sandbox uses Landlock and seccomp on Linux.
It can limit readable, writable, executable, connect, and bind resources.
`agentwall sandbox probe` reports the available kernel features.
`agentwall sandbox plan` reports the profile and gaps.

**Limit:** The sandbox has no network namespace.
TCP restrictions need Landlock ABI 4, which first appears in Linux 6.7.
`--allow-degraded` can run without Landlock and reports the missing protection.

## MCP wrapper

`agentwall mcp wrap` checks JSON-RPC traffic over stdio or Streamable HTTP.
It checks tool inventories, tool arguments, policy, secrets, injection, and tool output.
The HTTP listener uses loopback by default.
A non-loopback listener needs a bearer token.

HTTP request bodies have an 8 MiB default ceiling.
Malformed or oversized input does not reach the upstream server.

### Inventory baseline modes

| Mode | Result |
| --- | --- |
| `off` | Uses a complete session-only inventory and stores no baseline. |
| `learn` | Stores the first complete clean inventory with atomic file replacement. |
| `lock` | Requires approval when a tool or any standard descriptor field is new, removed, or changed. |

The baseline key uses the agent ID, server name, and optional command hash.
A denied inventory never changes the stored baseline.
The baseline file is not part of the audit root of trust.
The store keeps output schemas, annotations, icons, and metadata.
An old lock with no provably dead owner fails closed and requires manual removal.

**Limit:** Baseline matching shows inventory drift.
It does not prove that the server implementation is safe.

## Decoy credentials

`agentwall decoy generate` creates a synthetic value and can save it in a mode `0600` file.
A matching value in inspected traffic creates a critical deny record.
The audit record omits the value.

**Limit:** A decoy works only while another process cannot identify it.
AgentWall sees it only on an inspected path and within the body limit.

## Audit evidence

AgentWall writes SHA-256 hash-chained JSONL records.
Rotation manifests link closed segments.
Signed checkpoints can anchor a digest outside the host.
`agentwall verify` reports chained, linked, and anchored layers separately.

**Limit:** The hash chain detects later changes to written records.
It cannot prove that AgentWall recorded every action.
A pending anchor is not confirmed evidence.

## Evidence views

`/evidence` shows one host's sessions and verification state.
`/evidence/fleet` reads several host chains and verifies each chain independently.
Both views show an offline verification command.

**Limit:** A single evidence request reads at most 100,000 records.
It skips one file above 64 MB and states the limit.
The fleet view does not merge host chains.
An unreachable host never appears clean.

## Operator authorization

All non-health service routes require operator authorization unless a route is explicitly public.
The service compares bearer tokens in constant time.
Only `/health` and `/api/health` are public service routes.

**Limit:** The local operator token is a shared bearer credential.
AgentWall does not provide an external identity provider or role-based access.

## Typed operator actions

`GET /api/operator/actions` lists supported actions.
`POST /api/operator/actions` validates a typed action body.
The route rejects unknown actions, shell syntax, path traversal, and undeclared executables.

**Limit:** Host actions need a visible plan and explicit confirmation.
The browser cannot run an arbitrary process.

## Read-only status

The UI shows `doctor`, `status`, `verify`, planning commands, and other read-only output.
Each view includes a copyable CLI command.

**Limit:** UI output is an operator aid, not an independent trust root.
Use the offline verifier against the evidence files for an independent result.
