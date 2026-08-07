# Agentwall

A runtime firewall for AI agents.

Agentwall watches what agents actually do on the host, attributes each action to the process
that took it, and writes a record that cannot be quietly rewritten. It runs locally, needs no
account, and has no paid tier.

Prompts are not a security boundary. An agent that has been argued into leaking a key still
holds the key. Agentwall works one layer down, where an action becomes real, and treats the
agent as the untrusted party.

## Before you install

Two limits matter more than any feature below.

**It defaults to observing.** `monitor` evaluates egress, records it, and allows it. You opt in
to blocking with `enforcement.mode`: `guarded` enforces matched deny rules, `strict` is
allowlist-only. Monitor reports what the other two would have done, so you build the allowlist
by reading your own ledger rather than by breaking your tooling to find out.

**Capture is cooperative by default.** The proxy is found through standard proxy environment
variables, and a process that ignores them egresses unseen. `agentwall perimeter` removes that
assumption with a dedicated UID and nftables redirection, at the cost of root, Linux, and a
deliberate install. See [docs/perimeter.md](docs/perimeter.md).

Those two are rows in a table of twenty-three. All of them are in
[docs/limits.md](docs/limits.md). They are not footnotes.

## Install

Linux, Node.js 22.12 or newer.

```bash
npm install -g @repsecure/agentwall

agentwall init --mode monitor
agentwall doctor
```

The unscoped npm package `agentwall` is a different, unrelated project. This one is
`@repsecure/agentwall`.

`init` writes `agentwall.config.yaml` and `policy.yaml` without overwriting work you already
have. `doctor` checks the install and reports **capture**: which declared agent was last seen
and at what binding tier, its standing against budget, and any egress no declared agent claims.
Exit 0 clear, 1 traffic policy said to refuse reached the network, 2 it cannot tell the two
apart — which it says plainly rather than guessing.

From a checkout instead, run `node dist/cli.js` wherever this file says `agentwall`:

```bash
git clone https://github.com/repsecure/agentwall.git
cd agentwall && npm install && npm run build
```

## Run it

```bash
export AGENTWALL_OPERATOR_TOKEN="$(openssl rand -hex 32)"   # without this, every route 401s
export AGENTWALL_AUDIT_FILE="$PWD/audit.jsonl"              # without this, the chain is stdout only
export AGENTWALL_PROXY_PORT=8899                            # without this, the proxy does not start

agentwall start
```

Send traffic through it from a second shell in the same directory:

```bash
https_proxy=http://127.0.0.1:8899 curl -s -o /dev/null https://example.com/
tail -1 audit.jsonl
```

Each request appends a chained record naming the process that made it:

```json
{"agentId":"curl","plane":"network","action":"egress:https","decision":"allow",
 "metadata":{"host":"example.com","port":"443","pid":"1101858","comm":"curl"},
 "integrity":{"chainIndex":1,"hash":"0e86f943...","previousHash":"4678da51...",
              "algorithm":"sha256","status":"chained-local","canon":"cu1"}}
```

The operator console is at `http://127.0.0.1:3000/dashboard`. A browser cannot send a bearer
header, so for local use start with `AGENTWALL_ALLOW_LOOPBACK_DEV=1`, which accepts loopback
callers as a `loopback-dev` principal. Do not set it on a host anyone else can reach.

## Check the record without trusting us

A verifier written by the same people in the same language as the writer only proves the code
agrees with itself. Agentwall ships three independent verifiers — in Go, Rust, and Python — and
a corpus of deliberate forgeries that runs all four against each other on every push.

```bash
agentwall verify                                                   # bundled TypeScript verifier
cd verifier && go build -o agentwall-verify . && ./agentwall-verify --audit <path>
```

`verify` reports three layers separately, because they fail independently and one verdict would
hide which guarantee you actually have:

```
PASS  chained   records link within each segment, so an edit inside one is detectable
PASS  linked    segments link and match their files, so replacing one is detectable
PASS  anchored  a fingerprint exists off-box, so a local rewrite shows
```

`agentwall anchor` seals the segment, signs an Ed25519 checkpoint over the head, and submits the
digest to OpenTimestamps for a Bitcoin block. No account, no API key. An anchor stays `pending`
for roughly one to six hours, and pending is not proof.

`/evidence` reads the same files in a browser, and `/evidence/fleet` does it across hosts, each
chain verified independently on its own bytes rather than merged. Neither is ever the root of
trust: if it is down, every host keeps enforcing and recording. See
[verification](docs/verification.md), [evidence viewer](docs/evidence-viewer.md), and
[fleet evidence](docs/fleet-evidence.md).

## What it does

- **Egress enforcement in three modes**, with a `403` and an `X-Agentwall-Block-Reason` header
  so a broken agent is a diagnosis rather than a mystery.
- **MCP servers wrapped**, stdio and Streamable HTTP: every JSON-RPC frame through ordered gates
  for tool poisoning, inventory drift, secrets and injection in arguments, policy, and injection
  in the output the agent is about to read.
- **A perimeter** that runs the agent under its own UID, redirects that UID's outbound TCP into
  the proxy with nftables, and refuses a connection it cannot name from SNI or `Host:`.
- **Observed identity**: the client socket is mapped back to its owning process through `/proc`,
  so a record carries the real `pid` and `comm` even if the agent lies. Failure degrades to
  `pid: null` and never blocks egress.
- **Predictable policy precedence**: six planes, four outcomes, most restrictive wins
  (`deny` > `approve` > `redact` > `allow`), carrying rule IDs, reasons, risk, and ATT&CK IDs.
- **Hot reload** that rejects an unparseable file whole, so a typo cannot leave half a policy.
- **DLP with inline redaction** across MCP frames, channel messages, watched file writes, and
  plaintext HTTP through the proxy — path, headers, both bodies, to a stated cap. Not https,
  unless [interception](docs/tls-interception.md) is enabled for that host.
- **Lockdown**, an emergency stop with four independent sources (config, API, `SIGUSR1`, a flag
  file) that overrides every mode. The file channel works when the HTTP surface is wedged.
- **Approvals and budgets**: a persistent queue, per-session and per-actor rate limits, cost
  budgets, and session pause, resume, and terminate.
- **An audit log built for real operation**: SHA-256 hash-chained, single-writer `O_EXCL` lock,
  torn-tail recovery, restart-safe resume. A storage failure is a declared gap, never a
  deletion, so a full disk and a tampered file do not look alike.
- **Auth that fails closed**: every route is protected unless explicitly public.

The full path from request to decision to audit is in
[architecture](docs/architecture.md); routes and environment variables are in
[reference](docs/reference.md).

## Limits

Twenty-three documented limits — from monitor-by-default, to `deny` being the only verdict
enforceable on a socket, to single-host scope — are in [docs/limits.md](docs/limits.md). They
are load-bearing, not marketing hedges. Read them before relying on this for anything.

## Built with

TypeScript 5 (strict) on Node.js 22.12+, Fastify 5, Zod, YAML policy via `js-yaml`, Jest.
Runtime dependencies are deliberately three: `fastify`, `js-yaml`, `zod`. The audit and
anchoring paths use Node's own `crypto` and plain HTTP with no third-party clients, because a
dependency inside the component whose whole job is being trustworthy is a supply-chain risk.

## Docs

[docs/README.md](docs/README.md) indexes every page. Start with
[Install](docs/install.md) · [Limits](docs/limits.md) · [Enforcement](docs/enforcement.md) ·
[Perimeter](docs/perimeter.md) · [Threat model](docs/threat-model.md) ·
[Verification](docs/verification.md) · [API and configuration](docs/reference.md) ·
[Changelog](CHANGELOG.md)

## Contributing

Issues and pull requests are welcome, including ones that show a claim in this file is wrong.
See [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports go through
[SECURITY.md](SECURITY.md), not a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
