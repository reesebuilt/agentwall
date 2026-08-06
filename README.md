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

**It observes. It does not block.** Egress through the proxy is recorded and allowed. The
allow decision is hard-coded at [`src/index.ts:29`](src/index.ts). Blocking is a posture you
move to later, once your own ledger shows what your agents legitimately reach.

**Capture is cooperative.** The proxy is found through standard proxy environment variables. A
process that ignores them egresses unseen. Nothing here installs iptables or nftables
redirection. Agentwall raises the cost of unobserved egress; it does not make it impossible.

The rest are in [Limits](#limits). They are not footnotes.

## Install

Linux, Node.js 22.12 or newer.

```bash
npm install -g @repsecure/agentwall

agentwall init --mode monitor
agentwall doctor
```

The unscoped npm package `agentwall` is a different, unrelated project. This one is
`@repsecure/agentwall`.

`init` writes `agentwall.config.yaml` and `policy.yaml` into the current directory. Both are
gitignored, and `init` will not overwrite work you already have. `doctor` checks Node, the
build output, and those two files.

From a checkout instead — run `node dist/cli.js` wherever this file says `agentwall`:

```bash
git clone https://github.com/repsecure/agentwall.git
cd agentwall && npm install && npm run build
```

## Run it

Every variable below is required for the thing it enables.

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
agrees with itself. Agentwall ships two independent verifiers and a corpus of deliberate
forgeries that runs them against each other on every push.

```bash
agentwall verify                                                   # bundled TypeScript verifier
cd verifier && go build -o agentwall-verify . && ./agentwall-verify --audit <path>
```

`verify` reports three layers separately, because they fail independently and one verdict
would hide which guarantee you actually have:

```
PASS  chained   records link within each segment, so an edit inside one is detectable
PASS  linked    segments link and match their files, so replacing one is detectable
PASS  anchored  a fingerprint exists off-box, so a local rewrite shows
```

`agentwall anchor` seals the segment, signs an Ed25519 checkpoint over the head, and submits
the digest to OpenTimestamps for inclusion in a Bitcoin block. No account, no API key. An
anchor stays `pending` for roughly one to six hours, and pending is not proof.

A signature only proves a key holder vouched. Pin the key you expect with `--pubkey-file`; a
foreign key exits 1. The Go verifier has zero third-party dependencies — `cd verifier && go
list -m all` prints one line.

Full detail, including the conformance corpus and what verification does not prove, is in
[docs/verification.md](docs/verification.md).

## What it does

- **Egress capture with observed identity.** A CONNECT-aware forward proxy maps the client
  socket back to its owning process through `/proc/net/tcp` and `/proc/<pid>/fd`, so a record
  carries the real `pid` and `comm` even if the agent lies about who it is. Linux only.
  Attribution failure degrades to `pid: null` and never blocks egress.
- **A policy engine with predictable precedence.** Six planes, four outcomes, most restrictive
  wins: `deny` > `approve` > `redact` > `allow`. Results carry matched rule IDs, plain reasons,
  a risk level, and MITRE ATT&CK technique IDs.
- **Hot-reloadable policy.** A built-in rule pack plus YAML. A file that fails to parse is
  rejected whole and the previous ruleset stays in force, so a typo cannot leave you running
  with half a policy.
- **DLP with inline redaction.** AWS keys, GitHub PATs and OAuth tokens, OpenAI keys, Slack
  tokens, private keys, JWTs, SSNs, credit cards, emails, phone numbers.
- **SSRF and egress inspection.** Scheme, port, and host allowlists blocking private, loopback,
  and link-local ranges plus cloud metadata endpoints. Shell command preflight and manifest
  drift detection alongside.
- **Approvals and budgets.** A persistent approval queue with `auto`/`always`/`never` modes,
  per-session and per-actor rate limits, pending-approval caps, cost budgets, and session
  pause, resume, and terminate enforced at `/evaluate`.
- **An audit log built for real operation.** SHA-256 hash-chained records, a single-writer
  `O_EXCL` lock, torn-tail recovery, and restart-safe resume. A storage failure is reported as
  a declared gap, never as a deletion, so a full disk and a tampered file do not look alike.
- **Auth that fails closed.** A bearer token compared in constant time on an allowlist model:
  every route is protected unless explicitly public, so a route added next year is guarded by
  default. Only `/health` and `/api/health` are public.

Egress observed by the proxy enters the same hash chain. The request-to-decision-to-audit path
is written out in [docs/architecture.md](docs/architecture.md); the routes and every
environment variable are in [docs/reference.md](docs/reference.md).

## Limits

Stated plainly, because a security tool that oversells itself is worse than no tool.

| Limit | What it means |
| --- | --- |
| Monitor-first, no blocking | The proxy records and allows. `decide` is hard-coded to `allow` at [`src/index.ts:29`](src/index.ts). Enforcement is a posture you build toward, not something installing this gives you. |
| Cooperative capture | Proxy environment variables are honoured voluntarily. A process that ignores them egresses unobserved. No iptables or nftables redirection is installed. |
| Anchoring is pending, not instant | An OpenTimestamps anchor stays `pending` until a Bitcoin block confirms, roughly one to six hours. Pending is not proof. |
| Anchoring proves no alteration, not completeness | An anchor shows that what was written was not altered afterwards. It cannot show that everything which should have been written was. |
| A signature is necessary, not sufficient | On a host where the audited principal can read the signing key, an agent with root can sign anything the operator can. Off-box anchoring is what closes that gap. |
| Verifier agreement is bounded by the corpus | The two verifiers return the same verdict on all 26 conformance cases. That is agreement about those cases, not a proof of equivalence, and it says nothing about a forgery neither has been asked to judge. |
| No TLS interception | CONNECT traffic is visible at hostname and port level only. Paths, headers, and bodies stay opaque. MITM would need a CA in every runtime trust store, which breaks the framework-agnostic property the proxy exists for. |
| Attribution is Linux-only | It reads `/proc/net/tcp` and `/proc/<pid>/fd`. There is no macOS or Windows equivalent. The rest of the server is portable; process attribution is not. |
| Channel containment is Telegram only | Slack and Discord appear in the platform schema with no route implementation behind them. |
| The watchdog does not auto-deny | It exposes heartbeat age and a kill-switch flag, and a rule denies on the `watchdog_timeout` label, but nothing wires staleness to that label automatically. Treat it as a signal you act on. |
| Telemetry is off by default | The OTLP/HTTP decision-trace exporter is disabled unless configured. |
| Bearer tokens, not identity | A shared token, not OIDC or mTLS. No identity-provider integration. |
| Single host | Multiple instances can be polled into one summary view. There is no clustered or highly-available control plane. |

## Built with

TypeScript 5 (strict) on Node.js 22.12+, Fastify 5, Zod, YAML policy via `js-yaml`, Jest.
Runtime dependencies are deliberately three: `fastify`, `js-yaml`, `zod`. The audit and
anchoring paths use Node's own `crypto` and plain HTTP with no third-party clients, because a
dependency inside the component whose whole job is being trustworthy is a supply-chain risk
this project declines.

## Docs

[Install](docs/install.md) · [Architecture](docs/architecture.md) ·
[Threat model](docs/threat-model.md) · [Verification](docs/verification.md) ·
[Audit format](docs/audit-format.md) · [API and configuration](docs/reference.md) ·
[FloodGuard](docs/runtime-floodguard.md) · [Tutorials](docs/tutorials/README.md) ·
[Changelog](CHANGELOG.md)

## Contributing

Issues and pull requests are welcome, including ones that show a claim in this file is wrong.
See [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports go through
[SECURITY.md](SECURITY.md), not a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
