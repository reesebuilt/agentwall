# Onboard an agent runtime

Use this guide to create one runtime identity and prove that AgentWall captures its traffic.

Onboarding writes configuration. It does not prove capture. Onboarding ends only after capture verification exits with status `0`.

## Use the local UI

**Goal:** Complete setup, onboarding, service start, and capture verification from the primary interface.

**Command:**

```bash
agentwall ui
```

**Expected result:** AgentWall prints `http://127.0.0.1:3001` and serves the bootstrap UI on loopback.

1. Open the printed URL.
2. Select **Setup** if no local configuration exists.
3. Select **Onboard** and choose the runtime profile.
4. Copy the generated runtime environment when the UI shows it.
5. Select **Start**.
6. Open the running dashboard.
7. Run the capture verification action for the new agent.

The bootstrap UI uses typed actions for setup, onboarding, start, and stop. It does not accept an arbitrary executable or shell command. A read-only action shows status, output, and a copyable CLI command.

Setup uses monitor mode and loopback addresses by default. Monitor mode records activity and does not block it. AgentWall does not enable LAN access unless you request it.

**Common fix:** Run `agentwall ui --port 3002` if port `3001` is in use.

## Use the direct CLI without the browser

Use this path when a browser is unavailable. Run each command from the directory that contains the AgentWall configuration.

### 1. Create the local operator files

**Goal:** Create a monitor-mode configuration with safe local defaults.

**Command:**

```bash
agentwall setup --mode monitor
```

**Expected result:** AgentWall creates `agentwall.config.yaml`, `policy.yaml`, and `.agentwall/operator.env`. It binds the service to `127.0.0.1:3000` by default.

Where file modes exist, AgentWall creates `.agentwall` with mode `0700`. It writes `.agentwall/operator.env` with mode `0600`.

AgentWall loads known values from `.agentwall/operator.env` before service start. An explicit environment variable takes priority over the same generated value. AgentWall parses the file as data and does not run it as shell code.

**Common fix:** Use `--force` only when you intend to replace existing setup files.

The compatibility initializer remains available.

```
$ agentwall init --mode monitor
Created Agentwall starter files:
- /srv/agents/agentwall.config.yaml
- /srv/agents/policy.yaml
```

**Expected result:** `init` creates the two starter YAML files at the shown location.

**Common fix:** Use `agentwall setup --mode monitor` when you also need the protected local environment file.

### 2. Onboard the runtime

**Goal:** Add a credential-bound runtime identity to the fleet configuration.

**Command and example result:**

```
$ agentwall onboard claude-code
Onboarded "claude-code" from profile claude-code (Claude Code).

  Capture (proxy env): VERIFIED (measured end to end on the verification host)
  Interception (CA store): PARTIAL (mechanism observed, end-to-end path NOT observed)
  Runtime checked: 2.1.220 (Claude Code)

CREDENTIAL, PRINTED ONCE AND NEVER AGAIN

  claude-code:73c22a6c4b85044c1bfcfadf7f08f8d26830e2db1eb14c1b0f92665d21cb4fa2

  AgentWall stored only its digest (sha256:7098590f422b7cfa...).
  Nothing this command wrote contains it. It has NOT been checked for anywhere else, and it is
  now in your shell history, your scrollback, and any file you redirected this output into.
  to mint a replacement; there is no recovery.

CONFIG
  Written:    /srv/agents/agentwall.config.yaml
  Backup:     /srv/agents/agentwall.config.yaml.bak
  Mode:       monitor, and egress is not default-deny. This agent is RECORDED, not
              blocked. Nothing it does today starts failing because you ran this command.
  Allowlist:  api.anthropic.com, platform.claude.com
  Budget:     2000 requests per 3600s

ENVIRONMENT FOR CLAUDE CODE

  # AgentWall itself needs this, or nothing is listening on 3128:
  export AGENTWALL_PROXY_PORT=3128

  # The agent needs these. The credential is the userinfo in the URL.
  export HTTPS_PROXY='http://claude-code:73c22a...@127.0.0.1:3128'
  export HTTP_PROXY='http://claude-code:73c22a...@127.0.0.1:3128'
  ...
  export ALL_PROXY='http://claude-code:73c22a...@127.0.0.1:3128'

  # MEASURED AND IGNORED by this runtime, do not bother: no_proxy

  # NO_PROXY is deliberately NOT set, though this runtime honours it. Every entry in it is an
  # address the agent reaches with AgentWall out of the path, and it would pre-decide
  # verify-capture, whose canary binds loopback. If an agent must reach a local service, add
  # that host to its egress allowlist instead, where the decision is recorded.
```

**Expected result:** AgentWall adds the agent, writes a `.bak` file, and prints one credential. It stores only the credential digest in the configuration.

Copy the credential and environment now. AgentWall cannot recover the credential later. Use `--force` to mint a replacement if you lose it.

`onboard` keeps the current enforcement mode. It reports the posture that the configuration actually uses. It does not change strict mode to monitor mode.

The YAML round trip does not preserve comments. AgentWall writes `agentwall.config.yaml.bak` before it updates the configuration.

**Common fix:** Use `--agent-id` for a second instance. Use `--force` only to replace an existing identity and invalidate its old credential.

### 3. Start AgentWall on the proxy port

**Goal:** Start the service with the proxy port that onboarding printed.

**Command:**

```
$ export AGENTWALL_PROXY_PORT=3128
$ export AGENTWALL_AUDIT_FILE=/var/lib/agentwall/audit.jsonl
$ agentwall start
```

**Expected result:** AgentWall listens on port `3128` for the runtime proxy connection. It writes the audit chain to `/var/lib/agentwall/audit.jsonl`.

An explicit `AGENTWALL_PROXY_PORT` takes priority over the generated value. The runtime proxy URL and the service port must match.

**Common fix:** Set the same proxy port in the AgentWall shell and the runtime proxy URL.

### 4. Export the runtime environment

**Goal:** Give the runtime its credential, proxy, and trust variables.

Paste the printed environment into the shell that starts the runtime. Set it before the runtime process starts.

`NODE_EXTRA_CA_CERTS` is read once at process start. A change inside a running process does not update that process.

**Expected result:** The runtime inherits the proxy URL and presents its credential through `Proxy-Authorization`.

The proxy URL user information carries the credential. AgentWall hashes the decoded agent ID and token, with the colon between them.

**Common fix:** Stop and restart the runtime after you change any startup-only trust variable.

### 5. Prove capture

**Goal:** Prove that the runtime uses AgentWall and cannot reach the canary directly.

**Command:**

```
$ agentwall verify-capture --agent claude-code
```

**Expected result:** Exit status `0` means captured. The result should report the `credential` binding tier.

Exit status `1` means AgentWall found no chain record, the wrong agent, or a bypass. Exit status `2` means the check could not run.

The command starts a single-use canary and asks the runtime to fetch it. It checks the audit record, agent identity, binding tier, and direct canary access.

A `comm` binding is weak because the process declares its own `comm` value. A `credential` binding remains strong across a host boundary.

**Common fix:** Remove a matching `NO_PROXY` entry and rerun the command if the result is inconclusive.

## Do not set `NO_PROXY` by default

A `NO_PROXY` entry bypasses AgentWall for each matching destination. A loopback entry can bypass policy for local databases, tunnels, and local proxies.

The capture canary binds to `127.0.0.1` by default. A loopback exemption preselects a direct route to the canary. `verify-capture` reports `INCONCLUSIVE` with exit status `2` in this case.

Add a required local host to the agent egress allowlist instead. AgentWall then records the decision.

These measurements confirm that host and port matching can differ from a host-only entry.

| Runtime | no `NO_PROXY` | `example.com` | `example.com:9999` |
|---|---|---|---|
| curl 8.5.0 | 1 proxy hit | 0 proxy hits | 1 proxy hit |
| python3 `requests` 2.31.0 | 1 proxy hit | 0 proxy hits | 1 proxy hit |
| Node v24.14.1 with `NODE_USE_ENV_PROXY=1` | 1 proxy hit | 0 proxy hits | 1 proxy hit |

This table makes no claim about an unlisted runtime.

## Check the credential binding

**Goal:** Confirm that the loaded configuration resolves the credential tier.

**Expected result:** A correct credential resolves the declared agent. A wrong credential resolves to `unattributed`.

```
config loaded, fleet agents: [ 'claude-code' ]
resolved.id       : claude-code
resolved.matchedOn: credential
resolved.declared : true
egress allowlist  : [ 'api.anthropic.com', 'platform.claude.com' ]
budget            : { windowSeconds: 3600, maxRequests: 2000 }
wrong secret ->   : unattributed / none / declared: false
```

**Common fix:** Mint a new credential with `agentwall onboard claude-code --force` if the stored digest and runtime credential do not match.

## TLS interception is optional

Capture does not require TLS interception. Body inspection for HTTPS traffic does require it. AgentWall leaves interception off by default unless the current configuration already enables it.

See [tls-interception.md](tls-interception.md) for the CA lifecycle.

Use the trust variable that the runtime supports.

- `NODE_EXTRA_CA_CERTS` is additive for Node and Bun.
- `SSL_CERT_FILE` is additive for Bun.
- `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` replace the trust bundle for Python `requests`.
- A replacement bundle must contain the interception CA and the system roots.
- A bare interception CA can cause `CERTIFICATE_VERIFY_FAILED` for public HTTPS calls.
- `SSL_CERT_FILE` does nothing for Node and Python `requests` in the measured versions.
- The Codex CA trust store remains unverified, so `onboard` prints no trust export for it.

**Common fix:** Use a combined CA bundle when the runtime replaces its public trust store.

## Runtime support and platform limits

These profile grades apply to the measured versions and host.

| Profile | Runtime checked | Capture through proxy environment | CA store support |
|---|---|---|---|
| `claude-code` | Claude Code 2.1.220 | verified on the wire | partial from Node and Bun behavior |
| `codex` | codex-cli 0.146.0 | verified on the wire | unverified native TLS stack |
| `openclaw` | OpenClaw 2026.6.33 | partial from its proxy module | partial from Node behavior |
| `hermes-agent` | application not installed | partial from Python `requests` 2.31.0 | verified for `requests` |
| `pi-agent` | application not installed | partial from Bun 1.3.14 | verified for Bun |
| `generic` | no runtime checked | unverified | unverified |

The measurement host used Ubuntu 24.04 x86-64. It used Node v24.14.1, Bun 1.3.14, Python 3.12.3, `requests` 2.31.0, and curl 8.5.0.

Node v24.14.1 needs `NODE_USE_ENV_PROXY=1` for the measured proxy paths. Bun 1.3.14 uses the same proxy variables without that option.

Claude Code honors uppercase `NO_PROXY` in the measured version. It ignores lowercase `no_proxy` in that measurement.

A runtime or platform update can change proxy and CA behavior. Run capture verification again after an update.

The `hermes-agent` and `pi-agent` profile claims come from their underlying measured stacks. The applications were not installed on the measurement host.

OpenClaw has no on-the-wire capture observation in this measurement. Its proxy module resolved the proxy, but the live run stopped at provider credential checks.

MCP destinations differ by installation. Read the audit chain before you add a required destination to the allowlist.

Onboarding declares the agent identity. It does not prove capture or change the current enforcement mode.
