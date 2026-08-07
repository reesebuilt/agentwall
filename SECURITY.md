# Security policy

AgentWall is a security tool.
A vulnerability can defeat the protection that an operator expects.
The project gives security reports the highest priority.

## Report a vulnerability

Report a vulnerability privately.
Do not open a public issue.

- Preferred channel: Open a private security advisory on GitHub. The project monitors this channel.
- Alternative channel: Email `security@agentwall.dev`.

Include this information:

- the affected version or commit
- exact reproduction steps
- a command or test that shows the failure, when possible
- the impact
- a suggested mitigation, when available

A reproduction that works gives the maintainer the best evidence.
A repository test that fails is also useful.

## Response targets

These targets are not a contractual SLA.

- Initial acknowledgment: within 72 hours.
- Triage decision: within 7 days.
- Fix or mitigation schedule: after triage, based on severity.

Send a follow-up if the project misses an acknowledgment target.

## In scope

A report is in scope when it breaks a documented AgentWall property.
Examples include:

- bypass of operator authentication
- access to a protected route without a valid token
- access to any undocumented public route
- a policy result that is less restrictive than its rules require
- a break in `deny` > `approve` > `redact` > `allow` precedence
- audit record forgery, truncation, order changes, or silent rewrites that `agentwall verify` does not report
- an Ed25519 checkpoint forgery
- checkpoint verification against a key that did not sign it
- a second writer that bypasses the audit chain single-writer lock
- SSRF or allowlist bypass on traffic that reaches AgentWall
- bypass of private, loopback, link-local, or cloud metadata protection
- DLP bypass for a supported secret type on an inspected surface
- a forward-proxy crash or hang that stops egress for all proxy clients
- a TLS interception bypass outside configured `interception.bypassHosts`
- unsafe storage or use of the TLS interception CA key

Only `/health` and `/api/health` are public by default.
Other routes require operator authentication.
`AGENTWALL_ALLOW_LOOPBACK_DEV=1` intentionally accepts unauthenticated loopback callers.
Use that environment variable only for local development.

## Documented limits

These are documented limits, not defects. They are listed in [docs/limits.md](docs/limits.md).
Reporting them is not a vulnerability, though arguments about how they should change are
welcome as normal issues.

These limits are not vulnerabilities by themselves.
Report a documentation bug if the public claim is broader than the limit.
Propose a control change in a normal issue.

### Egress modes

`monitor` records policy results and mode projections.
It allows normal requests.
Operator lockdown still denies all traffic that reaches the proxy.

`guarded` enforces a `deny` from a matched policy rule.
It allows a destination when no rule matches.
A policy rule that throws is skipped, so that rule fails open.

`strict` requires an exact allowed host and port.
It also enforces policy denials.
An empty global host or port allowlist denies every destination that inherits it.
A declared fleet agent can replace either global list.
An omitted or empty scoped list inherits its related global list.
Traffic without a declared fleet identity uses both global lists.

An invalid mode stops startup.
AgentWall does not fall back to another mode.

### Capture boundary

The forward proxy uses cooperative capture by default.
A process can ignore `HTTP_PROXY` and `HTTPS_PROXY`.
AgentWall does not observe or block that process's direct connection.
AgentWall does not install nftables rules unless an operator installs the optional perimeter.

The Linux perimeter contains outbound traffic for one configured agent UID.
It requires root access and an explicit install.
It does not contain DNS.

### TLS and content inspection

Without TLS interception, CONNECT traffic exposes only the authority, port, and available SNI.
HTTPS paths, headers, and bodies remain encrypted.

Opt-in TLS interception applies only to selected forward-proxy CONNECT hosts.
It requires `openssl` and a local CA in the client trust store.
It does not apply to the transparent perimeter listener.
A configured `interception.bypassHosts` connection stays opaque and records the bypass.

Plaintext and intercepted body scans stop after 256 KiB per body.
AgentWall forwards the remainder and records a partial result.
Event-stream bodies pass without body inspection.
Deterministic scanners do not detect unknown patterns or all paraphrases.
A clean scan covers only the bytes and patterns that AgentWall checked.

The proxy does not perform a `redact` decision on a live body.
It records `redact` and allows the connection.
Only `deny` stops a proxy connection.

### Evidence limits

Process attribution reads `/proc` and works only on Linux.

An OpenTimestamps anchor stays `pending` until a Bitcoin block confirms it.
A pending anchor is not proof.
The command reports this state.

An anchor proves that records did not change after its creation.
It does not prove that the log is complete.
Silent omission at write time remains an unsolved limit.

A signature proves that a key holder vouched for the record.
It is insufficient when the audited principal can read the signing key.
An off-box anchor reduces this risk.

## Disclosure policy

Do not disclose the vulnerability publicly before the project releases a fix or mitigation.
The changelog credits the reporter unless the reporter declines credit.

## Policy scope

This policy covers this repository.
Report a third-party dependency vulnerability to that project first.
Also notify this project when AgentWall increases the impact.
