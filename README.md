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

**It defaults to observing.** Enforcement exists and is real, but `monitor` is the default:
egress is evaluated and recorded, and allowed. You opt in with `enforcement.mode` — `guarded`
enforces the deny rules that match, `strict` is allowlist-only. Monitor mode reports what the
other two would have done, so you build the allowlist by reading your own ledger rather than
by breaking your tooling to find out. A firewall that starts by breaking your tooling gets
switched off, and a switched-off firewall protects nothing.

**Capture is cooperative by default.** The proxy is found through standard proxy environment
variables, and a process that ignores them egresses unseen. That assumption is removable: a
perimeter runs the agent under its own UID and has nftables redirect that UID's outbound TCP
into the proxy, so cooperation stops being required. It costs root, Linux, and a deliberate
install, it is off unless you set it up, and DNS still leaves the host directly.
See [docs/perimeter.md](docs/perimeter.md).

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
build output, and those two files, and then reports **capture**: which declared agent was last
seen and at what binding tier, each agent's standing against its budget, and any egress since
the last run that no declared agent claims. It exits 0 clear, 1 when traffic reached the
network that policy said to refuse, and 2 when it cannot tell the two apart, which it says
plainly rather than guessing. See [fleet governance](docs/fleet.md#watching-capture-over-time).

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

For reading the record rather than only checking it, `/evidence` is a read-only console over the
same files: a per-session scorecard of what an agent did and what was blocked, the three layers
shown inline, a signed receipt timeline, and the offline command above printed on the page so the
UI is never the root of trust. It has no approve, deny, or edit path and serves no script. See
[docs/evidence-viewer.md](docs/evidence-viewer.md).

Several hosts are `/evidence/fleet`, the same shape one level up: it reads each host's chain from
a path its evidence was delivered to, verifies each independently on its own bytes, and prints all
four verifier implementations against each host's own file. The chains are not merged, a host it
could not read renders as unreachable rather than as clean, and what none of it can see is a table
on the page rather than a footnote. It is a reader and never an authority: if it is down, every
host keeps enforcing and keeps recording. See [docs/fleet-evidence.md](docs/fleet-evidence.md).

## What it does

- **Egress enforcement, in three modes.** `monitor` evaluates and allows while reporting what
  the stricter modes would have done; `guarded` enforces matched deny rules; `strict` is
  allowlist-only. A blocked request gets a `403` and an `X-Agentwall-Block-Reason` header, so a
  broken agent is a diagnosis rather than a mystery.
- **MCP servers wrapped, stdio and Streamable HTTP.** `agentwall mcp wrap` puts every JSON-RPC
  frame through ordered gates: tool-poisoning and drift on the advertised inventory, secrets
  and injection in tool arguments, your policy rules, and injection in the tool output the
  agent is about to read. Same engine, same audit chain, either transport.
- **Lockdown: an emergency stop with four independent sources.** Config, API, `SIGUSR1`, or a
  flag file on disk. Any one engages it, each releases only its own hold, and it overrides
  every mode including monitor. The file channel is the one that still works when the HTTP
  surface is wedged.
- **A perimeter that removes the cooperative-capture assumption.** `agentwall perimeter` runs
  the agent under its own UID and generates nftables rules that redirect that UID's outbound
  TCP into the proxy and drop the rest. The proxy then names the destination from the TLS SNI
  or the HTTP `Host:` header, and refuses a connection it cannot name. Root and Linux, opt-in,
  and `plan` prints the ruleset before anything touches your firewall.
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
  tokens, private keys, JWTs, SSNs, credit cards, emails, phone numbers. It runs on content
  handed to AgentWall directly (the `/inspect/*` and `/evaluate` payloads, MCP frames it
  wraps, channel messages, watched file writes) and on **plaintext HTTP** through the forward
  proxy: path, headers, and both bodies, to a stated cap. It does not run on https through the
  proxy, because that body is never decrypted. See the limits table.
- **Content inspection on the proxy, for the one scheme that needs no CA.** A plaintext HTTP
  request or response through the forward proxy is scanned for credentials, PII, injected
  instructions, and planted decoy tokens before it is forwarded, and a detection blocks with a
  403 and `X-Agentwall-Block-Reason` in `guarded` and `strict`. Response bodies are inspected
  too: a poisoned tool result arriving in an answer is the shape a control that watches only
  egress never sees. See [docs/enforcement.md](docs/enforcement.md).
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
| Monitor by default | Enforcement is real but opt-in. Out of the box the proxy evaluates, records, and allows; `guarded` and `strict` are configured, not automatic. Installing this does not block anything until you say so. See [docs/enforcement.md](docs/enforcement.md). |
| Only `deny` is enforceable on a socket | `approve` and `redact` verdicts are recorded and the request is allowed. A proxy has nowhere to put a held request and no way to rewrite a CONNECT body, so pretending otherwise would be worse than saying it. |
| Cooperative capture, unless you install a perimeter | By default the proxy is found through environment variables a process may simply ignore. `agentwall perimeter` removes that with a dedicated UID and nftables redirection, but it is opt-in, needs root, and is Linux-only. Without it, unobserved egress stays possible. See [docs/perimeter.md](docs/perimeter.md). |
| The perimeter does not contain DNS | The agent resolves names before it connects, so port 53 has to be permitted for anything to work. DNS is itself an exfiltration channel and this model does not close it. |
| The perimeter ruleset is parser-verified, not kernel-verified | `nft` accepts the generated file as valid syntax, and a test checks that wherever `nft` is installed. Whether the kernel accepts the chain types, hooks, and `inet` NAT support at load time is settled by your first `install`. Run `plan`, read it, then install somewhere you can afford a refusal. |
| Anchoring is pending, not instant | An OpenTimestamps anchor stays `pending` until a Bitcoin block confirms, roughly one to six hours. Pending is not proof. |
| Anchoring proves no alteration, not completeness | An anchor shows that what was written was not altered afterwards. It cannot show that everything which should have been written was. |
| A signature is necessary, not sufficient | On a host where the audited principal can read the signing key, an agent with root can sign anything the operator can. Off-box anchoring is what closes that gap. |
| Verifier agreement is bounded by the corpus | The two verifiers return the same verdict on all 26 conformance cases. That is agreement about those cases, not a proof of equivalence, and it says nothing about a forgery neither has been asked to judge. |
| No TLS interception | The ClientHello is read, so a tunnel is visible at hostname, port, and the SNI the client negotiated. Everything after the handshake is opaque: paths, headers, and bodies are never inspected. MITM would need a CA in every runtime trust store, which breaks the framework-agnostic property the proxy exists for. |
| The SNI cross-check is not domain-fronting detection | The proxy compares the CONNECT authority against the negotiated SNI and re-evaluates policy on the latter, which catches a client that names one host and negotiates another. Domain fronting puts its real destination in the HTTP Host header inside the session, and nothing short of interception can read that. Fronted traffic agrees at every layer this can see. |
| Proxy content inspection is plaintext HTTP only | An http request and response through the forward proxy are read and scanned. An https one is not, because it is encrypted, and neither is anything inside a CONNECT tunnel. The transparent listener relays raw TCP and inspects no content on either scheme. |
| The proxy content scan is capped at 256 KiB per body, and the cap is evadable | Past it the prefix is scanned and the remainder is forwarded uninspected, with the record saying so. Refusing large bodies instead would break ordinary agent traffic to buy protection that padding defeats anyway. Treat it as a control against accident and unsophisticated theft, not against an adversary choosing their transport. |
| Event streams are exempt from body inspection | `text/event-stream` and friends are passed through unbuffered on purpose. MCP carries SSE, and buffering an event stream to scan it hangs it. Their headers are still scanned and the record says the body was not. |
| Attribution is Linux-only | It reads `/proc/net/tcp` and `/proc/<pid>/fd`. There is no macOS or Windows equivalent. The rest of the server is portable; process attribution is not. |
| Channel containment is Telegram only | Slack and Discord appear in the platform schema with no route implementation behind them. |
| The watchdog does not auto-deny | It exposes heartbeat age and a stop flag, and a rule denies on the `watchdog_timeout` label, but nothing wires staleness to that label automatically. Treat it as a signal you act on. |
| Telemetry is off by default | The OTLP/HTTP decision-trace exporter is disabled unless configured. |
| Bearer tokens, not identity | A shared token, not OIDC or mTLS. No identity-provider integration. |
| Per-agent identity is only as strong as its signal | A fleet agent is bound by a presented credential, by the socket's uid, or by the process name. A credential separates cooperating agents and does not contain one that can read the secret; `comm` is a label the process sets for itself. Which signal matched is on every record so the claim is never stronger than the evidence. See [docs/fleet.md](docs/fleet.md). |
| Fleet budgets are per-instance and in-memory | Ceilings are enforced by the instance that saw the traffic, and the running windows reset when the process does. The records are durable; the counters are not. Byte budgets refuse the next connection rather than truncating a live one. |
| No fleet identity on the transparent path | A kernel-redirected connection carries no process name, no uid, and no proxy credential, so it resolves to the undeclared agent. `fleet.unmatched: "deny"` therefore refuses everything the perimeter redirects. |
| Single host | Within one instance, identity, allowlists, and budgets are per-agent. Across instances there is nothing: no shared identity, no shared budget, and no clustered or highly-available control plane. Multiple instances can be polled into one read-only summary view. [docs/fleet.md](docs/fleet.md) states what multi-host would actually require. |

## Built with

TypeScript 5 (strict) on Node.js 22.12+, Fastify 5, Zod, YAML policy via `js-yaml`, Jest.
Runtime dependencies are deliberately three: `fastify`, `js-yaml`, `zod`. The audit and
anchoring paths use Node's own `crypto` and plain HTTP with no third-party clients, because a
dependency inside the component whose whole job is being trustworthy is a supply-chain risk
this project declines.

## Docs

[Install](docs/install.md) · [Enforcement](docs/enforcement.md) ·
[Perimeter](docs/perimeter.md) · [Fleet](docs/fleet.md) · [MCP](docs/mcp.md) ·
[Proving capture](docs/verify-capture.md) ·
[Lockdown](docs/lockdown.md) ·
[Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md) ·
[Verification](docs/verification.md) · [Audit format](docs/audit-format.md) ·
[Evidence viewer](docs/evidence-viewer.md) · [Fleet evidence](docs/fleet-evidence.md) ·
[API and configuration](docs/reference.md) · [Probe API](docs/probe-api.md) ·
[Why](docs/why.md) · [Benchmark](docs/benchmark.md) ·
[Compliance](docs/compliance.md) · [Decoy tokens](docs/decoy.md) ·
[Spill watch](docs/spill-watch.md) ·
[FloodGuard](docs/runtime-floodguard.md) · [Tutorials](docs/tutorials/README.md) ·
[Changelog](CHANGELOG.md)

## Contributing

Issues and pull requests are welcome, including ones that show a claim in this file is wrong.
See [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports go through
[SECURITY.md](SECURITY.md), not a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
