# Fleet governance

Several agents on one host, each with its own identity, its own egress allowlist, and its own
budget. Records say **which agent**, not just which process.

Scope, first, because it changes what everything below means: this is per-agent governance
**within one AgentWall instance**. There is no clustered control plane, no cross-host
identity, and no shared budget. Two instances enforce two independent copies of their own
limits against their own traffic. [Multi-host](#what-multi-host-would-take) says what closing
that would actually require; it is not implemented and nothing here pretends otherwise.

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

## Watching capture over time

The section above answers "what happened". `agentwall doctor` answers the harder question:
**is every declared agent still being captured, and is anything getting out that no declared
agent claims?** Configuration proves capture once. This checks it on every run, which is what
catches an agent that starts escaping next Tuesday because somebody edited its launch script.

Real output, from a chain a server wrote (`fleet.unmatched: global`, three declared agents,
one of which has never started):

```
Capture
   chain            /var/lib/agentwall/audit.jsonl
   config           /etc/agentwall/agentwall.config.yaml
   egress records   6 read
   since last run   chain index 2, 6m ago

⚠️  3 undeclared egress records since the last run: 2 reached the network, 1 was refused.
   identity      aw-rogue 3
   destinations  open.example.test 2, closed.example.test 1
   bytes         4.0 KB
   first / last  1m ago / 13s ago

   INCONCLUSIVE: 2 of those were allowed out by the configuration itself.
   fleet.unmatched: global (the global allowlist judges undeclared traffic, by design)
   That is not an escape, and it is not proof of innocence either: an undeclared agent talking
   to an allowlisted host produces exactly this record, and so does an ordinary unlisted
   process. Set `fleet.unmatched: deny` to make the next run able to answer.

   agent               binding      last seen      window          requests      bytes
   claude-code         comm         4s ago         600s budget     2 / 5         8.0 KB / 32.0 KB
   codex               comm         3s ago         1s budget       0 / 5         0 B / -
   hermes              uid          DECLARED, NEVER SEEN

⚠️  declared but never seen: hermes. This says nothing about why on its own.
   It has not started yet, or it is running and its traffic never reaches this proxy: no
   HTTPS_PROXY on the agent, a NO_PROXY entry covering where it goes, or a different chain
   than the one above. An escaped agent and a misrouted one look identical from here, which
   is why this is a prompt to go and check rather than a verdict.

⚠️  weakest binding in use: comm (claude-code, codex)
   A name the process chose for itself. Anything on this host can claim it, including
   whatever you are trying to catch. Bind by uid, or by credential if the agent can be
   made to send Proxy-Authorization.
```

Four things it can tell you that nothing else could:

1. **Undeclared egress since the last run**, as the loudest block rather than a footnote, and
   split three ways: refused (the wall worked), permitted by the configuration itself
   (inconclusive), and reached the network under a posture that said to refuse it (an escape).
   Only the third is a failure. See the verdicts below.
2. **Declared but never seen**, rendered differently from a zero. An agent that was seen four
   minutes ago and did nothing since is idle. An agent that has never appeared at all is
   either not started or not routed through the proxy. Both would be a row of zeros in a
   plain counter table, and only one of them is fine.
3. **Per-agent standing against the declared budget**, in the window the budget names. Agents
   with no budget get an hour-long observation window instead, labelled `observed` rather than
   `budget` so nobody reads a ceiling into it.
4. **The weakest binding tier in use**, across the whole fleet. An agent bound only by `comm`
   is bound by a string the process chose for itself. Note that a declaration naming BOTH a
   credential and a comm is reported at its comm strength: `resolve()` falls through to comm
   when no credential is presented, so the credential is a bonus rather than a requirement.

### Three verdicts, and why there are three

| exit | verdict | what it means |
| --- | --- | --- |
| 0 | clear | Nothing undeclared reached the network since the bookmark, or an install check is the only thing outstanding. |
| 1 | failed | An install check failed, or undeclared egress reached the network while the record says `fleet.unmatched: deny` under an enforcing mode. |
| 2 | inconclusive | The question was asked and cannot be answered from the evidence. |

A two-valued check has to pick a side when the evidence supports neither, and the false-escape
side is the expensive one: accuse an operator of a breach their own configuration prescribes
and the check gets switched off. `fleet.unmatched: global` is the DEFAULT and is what the
perimeter section above tells you to run; under it, undeclared traffic reaching an allowlisted
host is exactly what the configuration asks for. `enforcement.mode: monitor` gates nothing, on
purpose, and is where every adoption starts. Both produce allowed undeclared egress that is
indistinguishable from an escape, so both report INCONCLUSIVE and name the setting to change.

The verdict is read from the record, not from the config file. Each egress record carries the
`fleetUnmatched` posture and the `enforcementMode` in force when the connection was judged, so
tightening the config today does not retroactively convict yesterday's traffic. Records written
before that field existed are judged against the current config, and the report says so.

Under `fleet.unmatched: deny` with an enforcing mode, an allowed undeclared record should not
be producible at all: `src/runtime/enforcement.ts` refuses that combination before opening an
upstream socket. That is why it is the one case that exits 1.

### How "since the last run" works

Doctor keeps a bookmark, `capture-watermark.json`, beside the audit file, holding the highest
chain index it has already accounted for. Each run counts undeclared records past that index
and then advances it. Consequences worth knowing:

- The **first** run has no bookmark, so it reports the whole chain as a baseline and returns
  0. A cron seeds on its first firing and judges from the second.
- An attempt enforcement **refused** is printed and never fails the run. A check that goes red
  when the wall works is a check operators turn off.
- A bookmark **ahead** of the chain (the file was rotated away, replaced, or restarted at
  index zero) is discarded with a note, and everything readable is counted as new. Trusting it
  would report zero new records forever over a chain full of them.
- If the bookmark **cannot be written**, the run is INCONCLUSIVE with its own line. Without it
  every later run re-reads the whole chain as if it were new, so a fresh escape cannot be told
  apart from history.

It reads the chain and the config, and asks the running service nothing. The moment you most
want to know whether an agent is escaping is the moment the serving process is suspect, and a
check that has to interview that process goes quiet exactly then. The same property makes the
numbers slightly different from the ones `GET /api/fleet` reports: the in-process ledger
attributes a connection's bytes to the window that ADMITTED it, while doctor recounts from
records, which are written when a connection CLOSES. For a long-lived model stream those two
windows differ.

With no `fleet:` section declared, the section says so and raises nothing. Every record then
carries the process comm as its identity and there is nothing for traffic to be undeclared
against, so alarming would fail every correct single-agent install permanently.

## What multi-host would take

Not implemented, and this section exists so that nobody mistakes the section above for it.
`src/org/federation.ts` polls peer instances into a read-only summary view; that is reporting,
not governance. Making per-agent governance work across hosts needs at least:

1. **An identity that survives the host boundary.** `uid` and `comm` are local facts about one
   kernel. Two hosts with a uid 1001 have two different accounts. A cross-host principal needs
   a credential, which means issuance, rotation, and revocation, which means a CA or an OIDC
   issuer, and mTLS or signed tokens rather than a shared secret in a config file.
2. **A shared budget with a consistency story.** A 120-per-minute ceiling across three
   instances is either a distributed counter (a coordination service on the egress hot path,
   and an outage in it becomes an egress outage) or per-instance sub-budgets that sum to the
   ceiling (no coordination, wrong answer whenever load is uneven). Both are defensible; the
   choice has to be stated, because "120 per minute across the fleet" means different things
   under each.
3. **Config distribution with a rollback that is faster than the mistake.** A fleet-wide
   allowlist push that is wrong takes every agent offline at once. That needs staged rollout
   and an automatic revert, which is a deployment system, not a config file.
4. **A merged audit chain, or an honest statement that there is not one.** Today each instance
   hash-chains and anchors its own records. N instances produce N chains. Merging them into
   one ordered ledger needs a total order across hosts, which needs either a single writer or
   agreed clocks; the honest alternative is N chains with a cross-reference and a reader that
   is told so.
5. **A control plane that fails safe.** Whatever holds the identities and budgets is now
   between every agent and the internet. If it is down, does egress stop or continue
   ungoverned? Both answers are bad, and picking one is a product decision rather than an
   implementation detail.

None of that is hard to describe and all of it is a different product surface from a proxy on
one box. The current answer stays: one instance, one host, per-agent governance inside it, and
[federation](reference.md) for a read-only view across several.

## Related

- [Egress enforcement](enforcement.md): the three modes and what each one blocks.
- [The perimeter](perimeter.md): closing cooperative capture, and why the transparent path
  carries no identity.
- [FloodGuard](runtime-floodguard.md): the other rate control, and what it keys on instead.
- [Audit evidence format](audit-format.md): what a record is and how it is chained.
