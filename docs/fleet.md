# Fleet governance

Several agents on one host, each with its own identity, its own egress allowlist, and its own
budget. Records say **which agent**, not just which process.

Scope, first, because it changes what everything below means: this is per-agent **governance**
within one AgentWall instance. There is no clustered control plane and no shared budget. Two
instances enforce two independent copies of their own limits against their own traffic.
[Multi-host](#what-multi-host-would-take) says what is genuinely missing and what turned out
not to be.

One thing that section used to overstate, corrected here because a stale limit is worse than
no limit: **the credential tier of identity already crosses a host boundary.** A credential is
presented by the client on the proxy connection, not derived from the local kernel, so the same
declared agent resolves identically on any host that has the same declaration. What is missing
for it is issuance, rotation and revocation, which is a much smaller problem than the one that
paragraph described. The `uid` and `comm` tiers really are local facts and really do not travel.

Evidence across hosts is a separate question and is answered separately: see
[fleet evidence](fleet-evidence.md) for the read-only aggregator that verifies each host's chain
on its own bytes.

## Why this exists

AgentWall already resolved a pid and a `comm` for every proxied connection, which answers
*which process*. On a host running an MCP wrapper, a scraper, and four cron jobs, that is not
the question an operator has. The questions are: which of my agents made this call, is this
agent allowed to reach that host, and has this agent spent its allowance. Before this, one
allowlist governed the whole host, so whatever it contained was true for every agent on it.

## Declaring a fleet

```yaml
fleet:
  # What happens to egress no declared agent claims.
  #   global  (default) the process-wide allowlist judges it, exactly as before.
  #   deny              guarded and strict refuse it. Monitor still only records.
  unmatched: global

  agents:
    - id: mcp-wrapper
      label: MCP wrapper
      match:
        uid: 1001
        comm: ["aw-mcp"]
      egress:
        allowedHosts: ["api.anthropic.com"]
        allowedPorts: [443]
      budget:
        windowSeconds: 60
        maxRequests: 120

    - id: scraper
      label: Web scraper
      match:
        credential: "env:AGENTWALL_SCRAPER_TOKEN"
      egress:
        allowedHosts: ["news.example.com", "docs.example.com"]
      budget:
        windowSeconds: 3600
        maxBytes: 52428800
```

Omitting the section entirely is the single-agent deployment. Records then carry the process
`comm` as the `agentId` and the process-wide allowlist judges everything, which is what every
earlier version did.

A malformed section is a **boot failure**, not a fallback. An agent whose `match` has a typo
does not half-work: it silently never binds, all of its traffic falls back to the global
allowlist, and the per-agent policy the operator wrote is simply not in force with nothing on
screen to say so. The refusals are:

| Rejected at start-up | Why |
| --- | --- |
| Two agents that match the same connection at the same strength | Whichever the iteration order picked would be wrong half the time. The message names both ids. |
| A literal secret in `match.credential` | Config files get committed. Only `sha256:<hex>` and `env:<VAR>` are accepted. |
| `env:` naming an unset variable | Otherwise that agent quietly never binds. |
| A `match` with no uid, comm, or credential | An agent that matches nothing, not an agent that matches everything. |
| A `budget` with neither `maxRequests` nor `maxBytes` | A window with no ceiling is not a budget. |
| `unmatched: deny` with no agents declared | That refuses all proxied egress in guarded and strict, which is what the [lockdown](lockdown.md) is for. |

## How an agent is identified, and what each signal is worth

Three signals, checked strongest first. Which one matched is recorded on every egress record
as `agentMatchedOn`, because "this was agent X" means something different depending on the
evidence, and a record that states the claim without the evidence overstates what is known.

| Signal | Where it comes from | What it is worth |
| --- | --- | --- |
| `credential` | A secret the client presents in `Proxy-Authorization` on the proxy connection. | Unforgeable by a process that cannot read the secret; forgeable by any process that can. On a single-uid host most agents can read each other's environment, so this **separates cooperating agents and does not contain a hostile one**. |
| `uid` | Column 7 of `/proc/net/tcp`, the same line the socket inode comes from. | The only signal here an agent cannot simply assert: changing your own uid needs privilege. Also the coarsest, since agents sharing an account are indistinguishable by it alone. |
| `comm` | `/proc/<pid>/comm`, after the fd walk finds the owning process. | A **label the process chose**, not a credential. Measured, not assumed: Node rewrites its own comm to `MainThread` at startup, and `process.title = "aw-scraper"` sets it to anything. Useful for telling apart agents you launched; worth nothing against one that lies. |

Precedence is `credential`, then `uid`+`comm` together, then `uid` alone, then `comm` alone. A
specific declaration always beats a general one, so a `uid: 1001, comm: ["aw-mcp"]` agent and a
`uid: 1001` catch-all can coexist under one account.

The uid is free: it comes off the same `/proc/net/tcp` line as the socket inode, so it costs
one extra array index and survives the case where the `/proc/<pid>/fd` walk finds nothing.

`Proxy-Authorization` is hop-by-hop and is **stripped before the request reaches the
destination**, along with `Proxy-Connection`. A fleet credential relayed upstream would be a
credential handed to every host the agent talks to.

## What is governed per-agent

| Per-agent | How |
| --- | --- |
| Identity in the audit chain | `agentId`, `agentLabel`, `agentMatchedOn`, `agentDeclared`, plus `uid`, `pid`, and `comm` on every egress record. |
| Egress host allowlist | `agents[].egress.allowedHosts`. |
| Egress port allowlist | `agents[].egress.allowedPorts`. |
| Which list judged a connection | `egressAllowlistSource` on the record: `global`, or `agent:<id>`. |
| Request budget | `agents[].budget.maxRequests` over `windowSeconds`. |
| Byte budget | `agents[].budget.maxBytes` over `windowSeconds`. |
| Budget counters in the chain | `budgetRequests`, `budgetMaxRequests`, `budgetBytes`, `budgetMaxBytes`, `budgetWindowSeconds`. |
| Declarative policy rules | A rule with `match.subject.agentId` now binds to the **declared** id rather than to a raw process name. See [reference](reference.md). |

An agent's allowlist **replaces** the global one rather than narrowing it. Narrowing is the
safer-sounding rule and the wrong one: the point of a per-agent allowlist is that a scraper and
an MCP wrapper have *different* destinations, not a subset of a shared set, and under
intersection there is no way to say "this agent, and only this agent, may reach the internal
registry". The cost is that an agent block is complete, not additive: an agent that declares
hosts and forgets its model API loses it. Declaring only one of the two lists leaves the other
at the global value, so narrowing just the ports stays a one-line change.

## What is still global

| Global | Note |
| --- | --- |
| Enforcement mode | One `enforcement.mode` for the instance. There is no per-agent monitor-while-others-are-strict. |
| The lockdown | The emergency stop halts every agent. It is a stop, not a policy dial. |
| The rule set | One `PolicyEngine`. Per-agent behaviour comes from rules **scoped** with `match.subject.agentId`, not from separate rule sets. |
| Built-in rules | `net:block-ssrf-private`, `net:block-metadata-endpoint`, and the rest apply to every agent and cannot be waived per-agent. A per-agent SSRF exemption is a hole with a config key in front of it. |
| FloodGuard | Keys on session and actor across the `/evaluate`, tool, and approval routes. It composes with budgets rather than overlapping: FloodGuard protects the control surfaces from a runaway loop, budgets protect the internet from one agent. Neither sees the other's traffic. |
| Spill watch, decoys, manifest integrity | Host-wide. None of them resolve a fleet identity. |
| The audit chain | One chain per instance, with per-agent attribution inside it. Not one chain per agent. |
| The operator token | One bearer token for the whole instance. It authenticates the operator, not an agent. |

## Budgets: exactly what is enforced

**Requests are exact.** The counter is measured before any upstream socket opens, so the
(N+1)th connection in the window is refused and never reaches the network.

**Bytes are enforced at admission, not mid-stream.** Bytes are attributable only once a
connection closes and the proxy knows how many crossed it. A single connection can therefore
carry more than the entire window's budget; what the ceiling does is refuse the **next**
admission. Cutting a live tunnel at a byte count would mean tearing down a socket the agent is
mid-response on, and a stream truncated at an arbitrary offset is a corruption bug wearing a
policy hat. If you need a hard cap per connection, that is a different control and this is not
it.

**A refused connection costs nothing.** The budget is charged last, only for an attempt every
other gate permitted. Charging denials would mean a client's own retry loop keeps its budget
permanently spent and the limit never recovers.

**Monitor counts but never blocks.** Monitor gates nothing, so every attempt is charged and
the window keeps climbing past the ceiling, and the projection in `reasons` says what guarded
and strict would have done. That is the number you need to size a budget: a counter that
stopped at the limit would answer "am I over" while hiding by how much.

**Counters live in memory and reset with the process.** A restart clears every window. The
records are durable; the running totals are not.

## The transparent path has no fleet identity

Kernel-redirected connections arriving at the [transparent listener](perimeter.md) resolve to
the undeclared agent. There is no `comm`, no `uid`, and no `Proxy-Authorization`, because a
redirected connection is not a proxy request at all. The `/proc` attribution helper is
module-private to the forward proxy and lifting it into a shared module is the prerequisite
for changing this.

The practical consequence: **`unmatched: deny` refuses everything the perimeter redirects.**
Run the perimeter with `unmatched: global`, or route fleet-governed agents through the forward
proxy, until that helper moves.

## Reading it back

`GET /api/fleet` (operator token required) returns the declared fleet with live counters. It
reports whether each agent is credential-matched and never the digest, because a digest of a
shared secret in a JSON response is an offline cracking target handed out by the tool that is
supposed to protect it. The payload states `scope: "single-host"` in the body, not only here.

The console's **Active agents** panel shows the resolved label, the signal it matched on, the
allowlist that judged it, and the budget window, for every record that carried them. Records
that never went through egress resolution show nothing rather than asserting `matched on:
none`, which would train an operator to stop reading the field on the rows where it matters.

A denied request tells the client the specific reason first, so
`X-Agentwall-Block-Reason: api.example.com is not in the scraper egress allowlist` names which
of several allowlists refused it. The full reason list, both allowlists, and the counters are
in the chain.

Across hosts, `GET /evidence/fleet` is a separate, read-only surface that verifies each host's
chain on its own bytes and rolls the records up per agent: which agents ran, on which hosts, in
which window, what each attempted, and what refused it. It is a reader and never an authority,
and it governs nothing. See [fleet evidence](fleet-evidence.md).

## What multi-host would take

This section used to list five requirements. Two of them were overstated and one is now
answered, so it is rewritten rather than left standing: a limit that is no longer true costs
more credibility than the limit it was describing.

**Solved, and it was mostly already solved.** A cross-host principal needs an identity that is
not a local kernel fact, and the credential tier is exactly that. It is presented by the client
in `Proxy-Authorization` on the proxy connection and compared against `sha256:<hex>` or
`env:<VAR>` in the declaration, so the same agent id resolves on every host carrying the same
declaration. No CA and no OIDC issuer is required for that to work today. The `uid` and `comm`
tiers do not travel and never will: two hosts with a uid 1001 have two different accounts.

**Answered by a deliberate design choice, not by building it.** Evidence across hosts is
read-only aggregation over separate chains, not a merged ledger and not a control plane. See
[fleet evidence](fleet-evidence.md), which states what the aggregate proves, why the chains stay
apart, and the failure semantics: if the aggregator is down, every host keeps enforcing and keeps
recording, and only visibility is lost.

**Genuinely still missing, in rough order of difficulty:**

1. **Credential lifecycle.** Issuance, rotation and revocation for the credential tier. Today a
   declaration names a digest or an environment variable and rotating one is a config edit and a
   reload on every host. That is workable for a handful of hosts and not for a hundred, and there
   is no revocation list: the only way to retire a credential is to remove it everywhere.
2. **Signed policy bundles, pulled on an interval.** A fleet-wide allowlist push that is wrong
   takes every agent offline at once. Pull rather than push, so no agent host needs an inbound
   listener, and a host that cannot reach the source keeps enforcing the last good bundle. That
   also needs a rollback faster than the mistake, which is a deployment concern rather than a
   config file.
3. **A shared budget with a consistency story.** A 120-per-minute ceiling across three instances
   is either a distributed counter (a coordination service on the egress hot path, and an outage
   in it becomes an egress outage) or per-instance sub-budgets that sum to the ceiling (no
   coordination, wrong answer whenever load is uneven). Both are defensible; the choice has to be
   stated, because "120 per minute across the fleet" means different things under each. Nothing
   in this repository does either, and budgets remain per-instance and in memory.

What is explicitly **not** on that list any more is a control plane holding identities and
budgets between every agent and the internet. That was described here as a thing multi-host
would need. It is not, and building it would be a mistake: it makes a management outage into an
agent outage. The answer is federation on evidence, which is what
[fleet evidence](fleet-evidence.md) implements.

## Related

- [Egress enforcement](enforcement.md): the three modes and what each one blocks.
- [The perimeter](perimeter.md): closing cooperative capture, and why the transparent path
  carries no identity.
- [FloodGuard](runtime-floodguard.md): the other rate control, and what it keys on instead.
- [Audit evidence format](audit-format.md): what a record is and how it is chained.
- [Fleet evidence](fleet-evidence.md): the read-only aggregator over several hosts' chains,
  what the aggregate proves, and why the chains are not merged.
