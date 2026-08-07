# AgentWall

AgentWall is a local policy and evidence layer for agent actions.
It checks network, tool, content, identity, and runtime decisions.
It records each decision in a hash-chained audit file.

## What AgentWall does

AgentWall provides three enforcement modes.
`monitor` records decisions without blocking.
`guarded` enforces matching deny rules.
`strict` allows only configured destinations.

AgentWall also provides approvals, session controls, per-agent credentials, runtime limits, and independent audit verification.
The local console exposes each supported service mutation through a typed action.

## What AgentWall does not do

AgentWall does not control traffic that bypasses its proxy or Linux perimeter.
The default proxy route depends on standard proxy environment variables.
A process can ignore those variables.

AgentWall does not prove that every action reached the audit writer.
A valid hash chain proves later record integrity, not record completeness.

AgentWall does not provide a clustered control plane.
Fleet identity, policy, and budgets have per-instance scope.

See [documented limits](docs/limits.md) before relying on these controls.

## Install and setup

AgentWall requires Node.js 22.12 or newer.
Linux provides process attribution, the perimeter, and the sandbox.
Other core service features run where the supported Node.js runtime runs.

```bash
npm install -g @repsecure/agentwall
agentwall ui
```

`agentwall ui` starts the bootstrap UI on `http://127.0.0.1:3001` by default.
Use **Setup** to create local configuration, policy, credentials, and an audit path.
Setup uses monitor mode and loopback access by default.
It does not replace existing files without `--force`.

The direct CLI path is:

```bash
agentwall setup
agentwall start
agentwall doctor
```

`agentwall init` remains available for the earlier starter-file workflow.

```bash
agentwall init --mode monitor
agentwall doctor
```

From a source checkout, run `node dist/cli.js` where this page uses `agentwall`.
The unscoped npm package `agentwall` is a different, unrelated project. This one is
`@repsecure/agentwall`.

`init` writes `agentwall.config.yaml` and `policy.yaml` without overwriting work you already
have. `doctor` checks the install and reports **capture**: which declared agent was last seen
and at what binding tier, its standing against budget, and any egress no declared agent claims.
Exit 0 clear, 1 traffic policy said to refuse reached the network, 2 it cannot tell the two
apart, as it says plainly rather than guessing.

From a checkout instead, run `node dist/cli.js` wherever this file says `agentwall`.

```bash
git clone https://github.com/repsecure/agentwall.git
cd agentwall && npm install && npm run build
```

## First run

1. Run `agentwall ui`.
2. Open the printed local URL.
3. Select **Setup** and keep monitor mode.
4. Select **Start service**.
5. Open the authenticated dashboard link.
6. Run `agentwall doctor` after the agent sends traffic.

The dashboard has Status, Approvals, Policy, Agents, and Evidence areas.
The Operations view contains host and process controls.
Each action shows its matching offline CLI command.

For a manual environment, use these variables before `agentwall start`.
```bash
export AGENTWALL_OPERATOR_TOKEN="$(openssl rand -hex 32)"   # without this, every route 401s
export AGENTWALL_AUDIT_FILE="$PWD/audit.jsonl"              # without this, the chain is stdout only
export AGENTWALL_PROXY_PORT=8899                            # without this, the proxy does not start

agentwall start
```

Send test traffic through the proxy from another shell.

```bash
https_proxy=http://127.0.0.1:8899 curl -s -o /dev/null https://example.com/
tail -1 audit.jsonl
```

A proxied request appends a chained record.

```json
{"agentId":"curl","plane":"network","action":"egress:https","decision":"allow",
 "metadata":{"host":"example.com","port":"443","pid":"1101858","comm":"curl"},
 "integrity":{"chainIndex":1,"hash":"0e86f943...","previousHash":"4678da51...",
              "algorithm":"sha256","status":"chained-local","canon":"cu1"}}
```

## Feature summary

### Typed local operation

The bootstrap UI performs setup, initialization, onboarding, start, development start, and stop.
The running dashboard prepares client-owned stdio wrapper commands and performs every other supported service-side mutation through `POST /api/operator/actions`.
The API rejects unknown actions, shell syntax, path traversal, and undeclared executables.

**Limit:** The bootstrap UI manages only its fixed AgentWall child process.
The running dashboard needs the service.

### Network policy and content checks

The forward proxy checks destinations and plaintext HTTP content.
It can scan paths, headers, request bodies, and response bodies.
A denied request opens no upstream socket.

**Limit:** Each body scan stops at 256 KiB.
AgentWall forwards the remaining bytes and records partial visibility.
Event stream bodies pass without body inspection, but their headers remain visible.

### TLS controls

Without interception, AgentWall sees the `CONNECT` authority and available TLS SNI.
Interception can decrypt configured hosts after a runtime trusts the local CA.
Interception is off by default.

**Limit:** HTTPS paths, headers, and bodies remain opaque without interception.
Encrypted ClientHello or missing SNI can also hide the TLS hostname.
The CA key holder can impersonate trusted sites for the configured runtime.

### Process attribution

On Linux, AgentWall maps a proxy socket through `/proc` to its PID and process name.
Each record states the observed identity signal.

**Limit:** Process attribution is Linux-only.
A container can hide the required host namespaces or descriptors.
Attribution failure records `pid: null` and does not block traffic.

### Linux perimeter

`agentwall perimeter` can redirect one UID's outbound TCP through the transparent proxy.
`agentwall perimeter plan` prints the network rules before installation.
Install, run, and rollback need root.

**Limit:** The perimeter needs Linux and `nftables`.
It permits one DNS resolver or blocks DNS.
Permitted DNS remains a possible data path.

### Linux sandbox

`agentwall sandbox` applies Landlock and seccomp controls to one process.
Probe and plan commands show the current kernel support and gaps.

**Limit:** TCP restrictions need Landlock ABI 4 and Linux 6.7 or newer.
The sandbox does not create a network namespace.

### MCP wrapper

`agentwall mcp wrap` checks JSON-RPC frames over stdio or Streamable HTTP.
Use `agentwall mcp status` to list HTTP wrappers managed by the running service.
Use `agentwall mcp stop <wrapper-id>` to stop one managed HTTP wrapper.
The local dashboard provides the same start, list, and stop actions.
Inventory baseline modes are `off`, `learn`, and `lock`.
Lock mode sends inventory drift to approval.

**Limit:** The HTTP wrapper has an 8 MiB default request limit.
A baseline records inventory shape, but it does not prove safe server code.

### Approvals and session controls

The approval modes are `auto`, `always`, and `never`.
Operators can pause, resume, terminate, boost, or reset a session through typed actions.
Terminate needs explicit confirmation.

**Limit:** These controls apply only inside AgentWall decision paths.
They do not terminate an external process or close a direct socket.

### Fleet credentials and budgets

AgentWall can issue, rotate, and revoke per-agent credentials.
It can enforce per-agent destination and budget rules in one instance.
A new secret appears once and never enters the audit chain.

**Limit:** Credentials separate cooperating agents, but not processes that can read the same secret.
Budgets and policy state do not synchronize across instances.
The transparent path carries no fleet identity.

### Audit evidence

AgentWall writes SHA-256 hash-chained JSONL records.
Rotation manifests link closed segments.
Signed checkpoints can anchor the current history outside the host.
Set `audit.anchorIntervalMs` to a positive value to run anchors on the service schedule.
Scheduled anchors require `AGENTWALL_AUDIT_FILE`.
The service logs each result or failure and stops the schedule during shutdown.

A verifier written by the same people in the same language as the writer only proves the code
agrees with itself. Agentwall ships three independent verifiers in Go, Rust, and Python. A
corpus of deliberate forgeries runs all four against each other on every push.

```bash
agentwall verify                                                   # bundled TypeScript verifier
cd verifier && go build -o agentwall-verify . && ./agentwall-verify --audit <path>
```

The verifier reports three separate layers, because they fail independently and one verdict would hide which guarantee you actually have.

```
PASS  chained   records link within each segment, so an edit inside one is detectable
PASS  linked    segments link and match their files, so replacing one is detectable
PASS  anchored  a fingerprint exists off-box, so a local rewrite shows
```

**Limit:** A pending anchor is not confirmed evidence.
An anchor detects later changes, but it cannot prove that the log is complete.

## Limits at a glance

| Limit | Effect |
| --- | --- |
| Cooperative capture by default | A process that ignores proxy settings can bypass AgentWall. |
| TLS content is opaque by default | Enable interception only for reviewed hosts and runtimes. |
| 256 KiB body scan | Content after the prefix is not inspected. |
| Event stream body bypass | AgentWall inspects headers, but not stream body events. |
| Linux-only attribution | Other platforms record the destination without a verified PID. |
| DNS perimeter gap | Permitted DNS can carry data outside the TCP proxy path. |
| Per-instance fleet scope | Instances do not share live budgets, policy state, or credentials automatically. |
| Audit completeness gap | Verification detects changes to written records, not missing events. |

## Documentation

- [User guide](docs/user-guide.md) gives first-run procedures and common fixes.
- [Operator guide](docs/operator-guide.md) maps every CLI action to its UI workflow.
- [Feature reference](docs/feature-reference.md) lists each capability and its limit.
- [Glossary](docs/glossary.md) defines the public terms.
- [Install guide](docs/install.md) gives package, source, and platform details.
- [Onboarding guide](docs/onboarding.md) creates and verifies one agent identity.
- [Enforcement guide](docs/enforcement.md) explains monitor, guarded, and strict modes.
- [Sandbox guide](docs/sandbox.md) explains Linux process controls.
- [Architecture](docs/architecture.md) describes the request and control paths.
- [Threat model](docs/threat-model.md) states protected and unprotected paths.
- [API and configuration reference](docs/reference.md) lists routes and settings.
- [Enterprise roadmap](docs/enterprise-roadmap.md) is a roadmap and does not describe shipped behavior.

The [documentation index](docs/README.md) links the detailed evidence and control documents.

## Security and license

Report a vulnerability through the private process in [SECURITY.md](SECURITY.md).
Do not put a vulnerability report in a public issue.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md) before you propose a change.
AgentWall uses the Apache-2.0 license.
See [LICENSE](LICENSE) and [NOTICE](NOTICE).
