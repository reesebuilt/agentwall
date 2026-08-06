# Onboarding an agent

`agentwall onboard <profile>` mints an identity for one agent runtime, writes it into your
config, and prints the exact environment that runtime needs.

It does not tell you the agent is protected, and it never will. Configuration is not capture.
The command ends by handing you `agentwall verify-capture --agent <id>`, and onboarding is not
complete until that exits 0.

That refusal is not modesty. Three controls in this repository have shipped green and
non-functional: `perimeter install` never installed a perimeter (spawnSync handed `nft` a socket
and `nft` refused `/dev/stdin`), the bundled gitleaks config reported a clean tree because it
inherited no rules, and content inspection ran on zero proxied bytes because `EgressAttempt`
could not carry a body. All three had tests. All three were green. A success banner from
`onboard` would be the fourth.

---

## Why profiles exist

"Point the runtime at the proxy" hides a per-runtime minefield. Measured on one Ubuntu 24.04
host on 2026-08-06:

| Finding | Consequence |
|---|---|
| Node v24.14.1 ignores `HTTPS_PROXY` for both global `fetch` and `require('https').get` | The request goes out directly, returns 200, and exits 0. Only the proxy's logs reveal it. `NODE_USE_ENV_PROXY=1` fixes it. |
| Bun 1.3.14 honours the same variables with no opt-in | Code that works under Bun silently stops being captured when run under Node. |
| Claude Code honours `NO_PROXY` and ignores `no_proxy` | Reproduced three times. The lowercase spelling does nothing. |
| `REQUESTS_CA_BUNDLE` **replaces** the public trust store | Pointing it at the bare interception CA breaks every public HTTPS call the agent makes. |
| `SSL_CERT_FILE` is ignored by Node, ignored by python `requests`, honoured by Bun, honoured by curl and by the python stdlib | The same variable name, five runtimes, three different behaviours. |

A profile that names the wrong variable produces an operator who believes traffic is governed
while it goes straight out. That is worse than shipping nothing, because it turns an open
question into a false answer. So every profile field carries its own grade and the observation
behind it, and anything unmeasured says so.

---

## What was verified, and what was not

Grades are per field, not per profile, because the two axes come apart. Codex's capture is
measured on the wire while its CA trust store is entirely unknown.

| Profile | Runtime checked | Capture (proxy env) | Interception (CA store) |
|---|---|---|---|
| `claude-code` | Claude Code 2.1.220 | **verified** on the wire | partial, inherited from Node/Bun |
| `codex` | codex-cli 0.146.0 | **verified** on the wire | **unverified**, native TLS stack untested |
| `openclaw` | OpenClaw 2026.6.33 | partial, its own module executed | partial, inherited from Node |
| `hermes-agent` | not installed | partial, `python3` + `requests 2.31.0` measured | **verified** for `requests` |
| `pi-agent` | not installed; bun 1.3.14 measured | partial | **verified** for Bun |
| `generic` | nothing | **unverified** by definition | **unverified** |

"Verified on the wire" means a logging CONNECT proxy observed the connection. For example,
`NO_PROXY` was checked by exempting one host while leaving the proxy set: with
`NO_PROXY=api.anthropic.com`, the proxy saw zero `api.anthropic.com` connections while still
seeing `platform.claude.com:443` and `agent.robinhood.com:443` in the same run. That is a
controlled experiment rather than an absence of evidence.

`hermes-agent` and `pi-agent` were not installed on the verification host. Their proxy lines
describe the underlying stack (`requests`, Bun), which was measured. Applying that to the agent
itself is an assumption, and the profile says so in its own output.

---

## Worked example, end to end

### 1. Create a config, in monitor mode

```
$ agentwall init --mode monitor
Created Agentwall starter files:
- /srv/agents/agentwall.config.yaml
- /srv/agents/policy.yaml
```

Monitor mode records and does not block. A firewall that breaks tooling on day one gets switched
off, so onboarding never starts anywhere else.

### 2. Onboard the runtime

```
$ agentwall onboard claude-code
Onboarded "claude-code" from profile claude-code (Claude Code).

  Capture (proxy env): VERIFIED (measured end to end on the verification host)
  Interception (CA store): PARTIAL (mechanism observed, end-to-end path NOT observed)
  Runtime checked: 2.1.220 (Claude Code)

CREDENTIAL, PRINTED ONCE AND NEVER AGAIN

  claude-code:73c22a6c4b85044c1bfcfadf7f08f8d26830e2db1eb14c1b0f92665d21cb4fa2

  AgentWall stored only its digest (sha256:7098590f422b7cfa...).
  The secret is not written to any file. If you lose it, re-run onboard with --force
  to mint a replacement; there is no recovery.

CONFIG
  Written:    /srv/agents/agentwall.config.yaml
  Backup:     /srv/agents/agentwall.config.yaml.bak
  Mode:       monitor. This agent is RECORDED, not blocked.
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

### Why no `NO_PROXY`

A loopback exemption looks harmless and is not. `NO_PROXY=localhost,127.0.0.1,::1` gives the
agent an un-governed route to everything on loopback: local databases, any SSH tunnel forwarded
there, and any local proxy that itself reaches the internet. It is a hole in the perimeter,
shipped by default, and it is not recorded anywhere in the chain.

It would also pre-decide the capture proof. `verify-capture`'s canary binds `127.0.0.1` by
default, so an agent exempting loopback reaches the canary directly by construction. That
command now reads the `NO_PROXY` its child will inherit and, if the canary host is exempted,
reports INCONCLUSIVE with exit 2 rather than accusing you of a bypass. A check whose own
environment decided the answer must not claim either answer.

Scoping the exemption to a port does not rescue it either: curl matches host only and ignores
the port, Python `requests` and Go honour `host:port`, and Node's global fetch ignores
`NO_PROXY` entirely. Three behaviours, so nothing portable to ship.

None of these agents call AgentWall's dashboard anyway. You reach it from a browser or the CLI,
and neither runs with the agent's proxy environment. Where an agent genuinely must reach a local
service, put that host in the agent's egress allowlist, where the decision is recorded.

### How the credential travels

The credential travels as the userinfo of the proxy URL. That is not a shortcut, it is the only
way to present a credential through an environment variable: every HTTP client turns userinfo
into `Proxy-Authorization: Basic base64(user:pass)`, and
[`parseProxyCredential`](../src/fleet/registry.ts) hashes exactly that decoded string. The secret
is minted as `<agentId>:<token>` for that reason, so it hashes identically whether it arrives as
Basic or as a manual `Bearer`.

### 3. Start AgentWall with the proxy on the port you were told

```
$ export AGENTWALL_PROXY_PORT=3128
$ export AGENTWALL_AUDIT_FILE=/var/lib/agentwall/audit.jsonl
$ agentwall start
```

The proxy port is an environment variable rather than a config key, which is why `onboard` prints
both sides. If they drift, the agent dials a port nothing is listening on.

### 4. Export the environment in the agent's own shell

Paste the block into the shell that launches Claude Code, not into AgentWall's. It has to be the
agent's real environment, and it has to be set **before the process starts**: `NODE_EXTRA_CA_CERTS`
is read once at startup, and setting it from inside a running process does nothing (measured:
same value, same binary, a child process succeeded where the parent failed).

### 5. Prove it, and only then call it done

```
$ agentwall verify-capture --agent claude-code
```

Exit 0 means captured. Exit 1 means not captured: no chain record, the wrong agent, or a bypass.
Exit 2 means the check could not run.

`verify-capture` binds a single-use canary, has the agent fetch it, and asserts three things: the
request appears in the audit chain, it is bound to the expected agent at the expected tier, and
**the canary was not reached directly**. The third assertion is the one that matters. A check that
only looked for a chain record would pass while half the agent's traffic went around the proxy.

Verify the binding tier it reports, not just the pass. An agent bound by `comm` alone is weakly
bound, because `comm` is self-declared by the process. Onboarding through this command gives you
the `credential` tier, which is the strong result and the one that works across a host boundary.

---

## Checking the binding yourself

The config `onboard` writes loads through the normal loader, and the credential it printed binds
at the `credential` tier:

```
config loaded, fleet agents: [ 'claude-code' ]
resolved.id       : claude-code
resolved.matchedOn: credential
resolved.declared : true
egress allowlist  : [ 'api.anthropic.com', 'platform.claude.com' ]
budget            : { windowSeconds: 3600, maxRequests: 2000 }
wrong secret ->   : unattributed / none / declared: false
```

`tests/onboard-command.test.ts` asserts exactly this, including the negative control, by
rebuilding the Basic header from the emitted URL rather than trusting the mint.

---

## TLS interception

Interception is opt-in and off by default. Capture does not need it; reading HTTPS bodies does.
See [tls-interception.md](tls-interception.md) for the CA lifecycle.

The trust variable and its semantics differ per runtime, and getting the semantics backwards
takes the agent off the network:

- **Additive** (`NODE_EXTRA_CA_CERTS` on Node and Bun, `SSL_CERT_FILE` on Bun): point it at the
  CA. Public roots survive.
- **Replacement** (`REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` for python `requests`): point it at
  a bundle containing the interception CA **concatenated with** the system roots. Pointing it at
  the bare CA makes every public HTTPS call fail `CERTIFICATE_VERIFY_FAILED`. `onboard` emits the
  concatenation step for this reason rather than a bare path.
- **Ignored** (`SSL_CERT_FILE` on Node, `SSL_CERT_FILE` for python `requests`): setting it does
  nothing at all. `onboard` prints a warning instead of an export.
- **Unknown** (Codex): `onboard` emits no export line. Determine the variable against the real
  binary first.

---

## Limits

- Profiles were verified on one host: Ubuntu 24.04 x86_64, Node v24.14.1, Bun 1.3.14, python3
  3.12.3 with requests 2.31.0, curl 8.5.0. Another platform may differ, and a runtime upgrade
  can change any of it. Re-run `verify-capture` after upgrading an agent.
- `hermes-agent` and `pi-agent` were not installed on the verification host. Their CA facts are
  measured against `requests` and Bun respectively; their application to those agents is an
  assumption.
- Codex's CA trust store is unverified. Interception is not proven to work with Codex.
- OpenClaw has no on-the-wire capture observation. Its own shipped `proxy-env` module was
  executed and resolves the proxy correctly, and the dist wires undici's `EnvHttpProxyAgent`, but
  no CONNECT was observed because every live model turn stopped at a provider credential check.
- MCP destinations are per-install. The starter allowlists came from one host. Expect to widen
  them, and read the chain rather than guessing which hosts to add.
- `onboard` rewrites the config through a YAML round trip, which does not preserve comments. It
  writes a `.bak` alongside for that reason.
- Onboarding declares an agent; it does not restrict anything by itself. The agent starts in
  monitor mode and is recorded, not blocked. Tightening comes after you have read the records.
