# AgentWall threat model

## Security boundary

AgentWall controls only traffic and actions that reach an AgentWall enforcement point.
The forward proxy uses cooperative capture by default.
A client that ignores `HTTP_PROXY` or `HTTPS_PROXY` bypasses that proxy.
AgentWall does not observe, allow, or block traffic that bypasses it.

The optional perimeter changes this boundary for one Linux UID.
It uses nftables to redirect TCP ports 80 and 443 and drop other outbound traffic.
It requires Linux, root access, and an explicit install.
It does not contain DNS.
The transparent listener cannot bind its records to a declared fleet identity.
See [The perimeter](perimeter.md).

## Egress modes

| Mode | Enforcement | Fail-open limit |
| --- | --- | --- |
| `monitor` | Records actual policy results and projected `guarded` and `strict` results. | Allows normal requests. Operator lockdown still denies proxied egress. |
| `guarded` | Enforces a `deny` from a matched policy rule. | Allows a destination when no rule matches. |
| `strict` | Requires an exact allowed host and port. It also enforces policy denials. | Traffic without a declared fleet identity uses global lists. Empty global lists deny every destination that inherits them. |
A declared fleet agent can replace each global list.
An omitted or empty scoped list inherits its related global list.

An invalid mode causes a startup failure.
AgentWall does not select another mode.
This boundary fails closed because a silent fallback could misstate enforcement.

## Primary threats

### SSRF and unsafe egress

AgentWall policy can deny these destination classes:

- private and loopback targets
- link-local and cloud metadata endpoints
- hosts outside the strict allowlist
- non-HTTPS schemes by default
- URLs with embedded credentials

These denials apply only in `guarded` or `strict` and only to traffic that AgentWall sees.
`monitor` records the projected denial but allows the request.
`guarded` enforces matched policy denials.
`strict` also enforces exact host and port allowlists.

The forward proxy denies a CONNECT authority before it opens an upstream socket.
An SNI denial occurs after the destination sees a TCP handshake.
AgentWall closes that connection before it forwards payload bytes.

The perimeter fails closed when it cannot recover a destination from SNI or an HTTP `Host` header.
It records the denial and closes the connection.
A perimeter policy callback exception also denies the connection.

### Prompt injection from external content

Web pages, email, tool output, and retrieved memory can contain adversarial instructions.
AgentWall tracks provenance and trust labels for content that reaches its evaluation surfaces.
Policy can escalate sensitive actions that depend on untrusted or derived content.

The forward proxy scans a complete plaintext HTTP response before it sends bytes to the client.
A matched injection pattern causes a `403` in `guarded` and `strict`.

This capability has four limits.
HTTPS responses remain opaque unless the operator enables TLS interception for that host.
Event-stream bodies pass without inspection.
AgentWall scans at most 256 KiB per body.
The scanner uses deterministic patterns, so paraphrase can evade it.

A clean result means no known pattern matched the bytes AgentWall read.
It does not mean that the content is safe.

### Secret and PII exfiltration

Content inspection detects supported secret and PII patterns.
Policy can deny egress that contains a secret.
It can redact PII on supported direct evaluation flows.
A proxied `redact` decision does not rewrite traffic.
It records the result and allows the connection.

AgentWall inspects content on these surfaces:

- `/inspect/*` and `/evaluate` payloads
- wrapped MCP frames
- channel messages
- watched file writes
- plaintext HTTP proxy requests and responses
- intercepted HTTPS requests and responses for selected hosts

Without TLS interception, CONNECT exposes only its authority, port, and available SNI.
Encrypted paths, headers, and bodies remain opaque.
The egress allowlist controls the visible destination, not the hidden content.

The plaintext proxy scan reads at most 256 KiB per body.
AgentWall forwards excess bytes without inspection and records `bodyVisibility: partial`.
Filler bytes can therefore evade the scan.
Event-stream bodies also pass without inspection and record `bodyVisibility: stream`.

Opt-in TLS interception makes content visible only for selected CONNECT hosts.
It requires `openssl` and a local CA that the client trusts.
The local CA key can impersonate any site to a client that trusts it.
Do not enable interception on a shared or multi-tenant host.

The transparent perimeter listener does not support TLS interception.
Hosts in `interception.bypassHosts` remain opaque and record the bypass.
See [TLS interception](tls-interception.md).

### Tool and MCP manifest drift

A changed manifest can expand an agent's authority.
AgentWall fingerprints manifests and detects tool changes.
Lock mode requires approval before it accepts a new, removed, or changed tool.
A denied inventory does not update the accepted baseline.

The baseline file is not part of the audit root of trust.
A protected local baseline remains a trust assumption.

### Agent liveness failure

The watchdog uses heartbeats to detect agent liveness failure.
High-risk autonomy should stop when the controller cannot prove liveness.
Full distributed watchdog orchestration remains out of scope.

## Failure boundaries

AgentWall fails closed at these defined boundaries:

- An invalid `enforcement.mode` stops startup.
- `strict` with an empty global host or port list denies every destination that inherits it.
- An invalid policy reload keeps the last valid immutable snapshot active.
- Operator lockdown denies all traffic that reaches the proxy.
- The perimeter denies an unnamed destination.
- A perimeter policy callback exception denies the connection.
- An MCP gate exception returns a denial.
- MCP `approve` blocks the action. It does not queue an interactive approval.
- Enabled TLS interception refuses startup when required CA, key, mint, or `openssl` checks fail. A trust assertion can override a failed trust probe.

AgentWall fails open at these defined boundaries:

- `monitor` allows normal requests after evaluation.
- `guarded` allows a destination when no policy rule matches.
- A policy rule that throws is skipped while other rules continue.
- If SNI is absent, a previously allowed CONNECT authority remains in effect.
- Bytes after the 256 KiB body cap pass without inspection.
- Event-stream bodies pass without inspection.
- `interception.bypassHosts` connections use an opaque tunnel.
- Policy decisions `approve` and `redact` do not stop a proxy connection.

Traffic that bypasses AgentWall is outside these failure boundaries.
AgentWall makes no decision for traffic that it does not receive.

## Trust assumptions

AgentWall trusts:

- protected local configuration
- explicit allowlists
- approved manifest fingerprints
- human approvals
- the configured local CA for TLS interception
- the client to honor proxy configuration when no perimeter exists

AgentWall does not trust:

- user input
- web content
- email content
- tool output
- tool metadata from unapproved or changed manifests
- any outbound target outside the strict allowlist

## Out of scope

- model-internal prompt defenses
- data already present in model context
- operator mistakes after approval
- full distributed watchdog orchestration
- traffic that bypasses both the proxy and the optional perimeter
- DNS containment by the perimeter
- unknown patterns, paraphrased injection, and uninspected body bytes
