# Fleet governance

Several agents on one host, each with its own identity, its own egress allowlist, and its own
budget. Records say **which agent**, not just which process.

Scope, first, because it changes what everything below means. Allowlists, budgets, and the
audit chain are **per-instance**: two AgentWalls enforce two independent copies of their own
limits against their own traffic, and there is no clustered control plane. Identity is the
exception. A **credential is presented on the proxy connection**, so an issued credential
means the same agent on every host that runs an instance;
[credential lifecycle](#credential-lifecycle-issue-rotate-revoke) is how it is issued,
rotated, and revoked. [Multi-host](#what-multi-host-still-takes) says exactly which parts are
still missing, and it is a shorter list than it used to be.

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

  # The weakest binding this instance will accept from a connection that CLAIMS an agent.
  #   any         (default) whatever binds, binds. Today's behaviour.
  #   uid         refuse a binding that rests on a process name alone.
  #   credential  only a presented secret counts.
  minimumMatchTier: any

  # Where issued credentials live, relative to this file. Optional; this is the default.
  credentialStore: fleet-credentials.json

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
        # The digest comes from the credential store, so this agent can be rotated with an
        # overlap and revoked without editing this file. `agentwall fleet issue` mints it.
        credential: issued
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
| A literal secret in `match.credential` | Config files get committed. Only `sha256:<hex>`, `env:<VAR>`, and `issued` are accepted. |
| `env:` naming an unset variable | Otherwise that agent quietly never binds. |
| A `match` with no uid, comm, or credential | An agent that matches nothing, not an agent that matches everything. |
| A `budget` with neither `maxRequests` nor `maxBytes` | A window with no ceiling is not a budget. |
| `unmatched: deny` with no agents declared | That refuses all proxied egress in guarded and strict, which is what the [lockdown](lockdown.md) is for. |
| One agent with both a config digest and an issued credential | Precedence would be a rule nobody remembers under pressure. Revoking the issued one while a stale config line kept letting the agent in is the worst outcome available. |

## How an agent is identified, and what each signal is worth

Three signals, checked strongest first. Which one matched is recorded on every egress record
as `agentMatchedOn`, because "this was agent X" means something different depending on the
evidence, and a record that states the claim without the evidence overstates what is known.

| Signal | Where it comes from | What it is worth |
| --- | --- | --- |
| `credential` | A secret the client presents in `Proxy-Authorization` on the proxy connection. | Unforgeable by a process that cannot read the secret; forgeable by any process that can. On a single-uid host most agents can read each other's environment, so this **separates cooperating agents and does not contain a hostile one**. The only signal that is **not a local kernel fact**: the same credential binds the same agent on any host running an instance. |
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

## The fleet minimum binding tier

`comm` is a label the process chose. On one laptop, whether that matters is a judgement the
person who wrote the config already made. Across an organisation it is not: "every host
configured its agents carefully" is not a control, and there is nothing to audit.
`fleet.minimumMatchTier` is the fleet-wide floor that makes it one.

| Value | Accepts | Refuses |
| --- | --- | --- |
| `any` (default) | credential, uid+comm, uid, comm | nothing. Exactly today's behaviour. |
| `uid` | credential, uid+comm, uid | comm alone. |
| `credential` | credential | uid+comm, uid, comm. |

There is no `uid+comm` value, deliberately. It is not a trust level above `uid`: it is the
same kernel fact plus a self-declared label, so offering it as a floor would suggest a
strength it does not have.

**The floor judges how a claim was PROVEN, not whether one was made.** A connection no
declared agent claims at all made no claim to judge, and `unmatched` decides its fate.
`minimumMatchTier: credential` with `unmatched: global` closes impersonation of your declared
agents and leaves everything else on the process-wide allowlist. That is coherent and it is
usually not what was meant. Set both.

An agent that cannot bind under the floor is **not a boot failure**. Raising the floor is
exactly how an organisation migrates, and refusing to start would mean the floor cannot be
raised until every host has already been issued a credential. Instead: the agent keeps its
declaration, every one of its connections is refused with the reason in the chain, and the
fact that it is in that state is printed at boot, by `agentwall doctor`, and in `GET
/api/fleet` under `unbindable`.

## Credential lifecycle: issue, rotate, revoke

A digest hand-written into `match.credential` works and has no lifecycle. It cannot be
rotated without an outage and cannot be revoked without editing config on every host that
names it. `agentwall fleet` manages credentials in a store beside the config file instead.

```
agentwall fleet issue  --agent scraper
agentwall fleet rotate --agent scraper --overlap 15m
agentwall fleet revoke --credential cred-1a2b3c4d5e --reason "laptop lost"
agentwall fleet list
```

The store holds a sha256 digest, an issue time, an optional rotation expiry, and a revocation
tombstone. **The secret is printed once and stored nowhere.** Lose it and you rotate; there is
nothing to recover. sha256 with no salt and no KDF is the right primitive here and would be
the wrong one for a password: the secret is 32 bytes from the CSPRNG, so there is no
dictionary to run.

A minted secret is `<agentId>:<token>`, and that shape is load-bearing. It hashes identically
down both paths a client can use:

```
Proxy-Authorization: Bearer scraper:9f0c...        header set directly
HTTPS_PROXY=http://scraper:9f0c...@127.0.0.1:3128  userinfo, sent as Basic base64("user:pass")
```

A bare token would work over the first and bind nothing over the second, which is the form
most deployments actually use. Agent ids that appear in a credential are restricted to
`[A-Za-z0-9._-]` so the userinfo needs no encoding and the Basic decode has one colon in it.

### Rotation, and why the overlap is not optional

Without an overlap window, rotation is an outage. The instant the new digest lands, every
process still presenting the old secret is refused, and on a fleet the gap between "the digest
landed" and "the last host restarted with the new secret" is measured in minutes.

`--overlap` accepts both secrets for a **bounded, stated** period: default 15 minutes, maximum
24 hours, `0` for an immediate cutover when the credential is believed compromised. The
maximum is a real limit, not advice. Two credentials that both work for longer than a day are
two live credentials with one of them forgotten, not a rotation in progress.

The window is visible in three places while it is open: the `rotate` output names the instant
it closes, `agentwall doctor` prints the time remaining as a warning line, and `GET
/api/fleet` reports the credential in state `overlap` with its `expiresAt`. When it closes the
old credential is refused, the refusal carries `agentIdentityRefusal: credential-expired` and
the credential id into the chain, and the record is kept as the history of that rotation.

### Revocation, and exactly when it takes effect

`fleet revoke` ends one credential. Every other credential in the store is untouched: the
agents holding them keep working, which is the difference between revoking a credential and
rotating a fleet.

**When it takes effect: on the first connection more than one second after the file lands. No
restart, no signal, no reload endpoint.** The running proxy re-checks the store's mtime, size,
and inode at most once per second on the egress path and re-reads it when any of them moved.
That is a poll rather than an `fs.watch` on purpose: a watcher is cheaper and can silently
die, and a revocation that never takes effect with nothing on screen to say so is the exact
failure this exists to remove. One `stat` per second under load is the price.

Three consequences worth stating before an incident rather than during one:

- A revoked credential is refused **whatever `fleet.unmatched` says**, and it does **not**
  fall through to `uid` or `comm`. An agent that also matches `comm: ["aw-scraper"]` does not
  keep working by keeping its process name. A revocation that can be survived by renaming a
  process is not a revocation.
- **Monitor mode still blocks nothing**, including this. A revoked credential on a
  monitor-mode instance is recorded, and the projection in `reasons` says guarded and strict
  would have refused it. That is the same rule `fleet.unmatched: deny` follows, and it is
  stated here rather than made an exception, because a control that is consistent is a
  control an operator can reason about. If you need traffic stopped on a monitor-mode host
  right now, that is what the [lockdown](lockdown.md) is for.
- The record is kept rather than deleted, because "this id was revoked at 14:32 because the
  laptop was lost" is the sentence an incident review needs, and because an unknown digest and
  a revoked one have to produce different evidence.

**If the store cannot be read, the proxy keeps enforcing the last copy it parsed.** That
covers both a JSON typo and the file going away underneath a shared mount, and in both cases
`agentwall doctor` reports the failure. Enforcement continues; what is lost is your ability to
change it. The alternative was worse in exactly the deployment this feature is for: under
`minimumMatchTier: credential` with `unmatched: deny`, dropping the records means every agent
on the host loses its identity at once, so a mount blip becomes a fleet-wide egress outage.
Retention cannot grant anything either, because a revocation is a tombstone **written into**
the file and never a deletion of it.

The CLI takes the opposite rule and refuses to write to a store it could not read, because
every write replaces the whole file and a merge would destroy what is actually in it.

### What a refusal claims, and what it does not

A refused connection is denied whichever of these it is. What differs is what the record
ACCUSES anybody of, and getting that wrong makes the control useless in opposite directions:
an alarm on every migration teaches an operator to ignore it, and a shrug at a stolen
credential is worse. So `agentIdentityOrigin` is on every refusal record.

| `agentIdentityOrigin` | When | Rule and detection | Risk |
| --- | --- | --- | --- |
| `operator-configuration` | The agent cannot satisfy `minimumMatchTier` at all, or its credential names an agent this instance no longer declares. Every client is refused identically. | `fleet:deny-unconfigured-agent-identity`, `det.fleet.identity.unconfigured`. **Deliberately unmapped to ATT&CK.** | medium |
| `unproven-claim` | Something bound to a declared agent on a weaker signal while that agent's credential **exists** and was not presented. | `fleet:deny-refused-agent-identity`, `det.fleet.identity.refused`, T1078. | high |
| `indeterminate` | A revoked or expired credential is still being presented. | Same as above. | high |

`indeterminate` is the honest third answer and the record says so in words: a deployment that
missed the rotation and a copy of the secret in someone else's hands **present identical
bytes**, and nothing on the connection separates them. The reasons carry "this evidence does
not distinguish a deployment that missed the change from a copy of the credential in someone
else's hands". Treat it as unresolved until you have confirmed who holds the secret. A
confident verdict either way would be a guess wearing a severity.

The unmapped detection is deliberate and follows `det.net.sni.connect-mismatch`: the nearest
technique for "you raised the floor and have not issued this agent a credential yet" is T1078,
and claiming it would publish an ATT&CK coverage row for an operator's own config change.
`unmappedDetections()` is where a real finding with no accurate framework row belongs.

A hand-written `sha256:` or `env:` digest has none of this. It is refused by `fleet issue`
with a message saying so, rather than quietly gaining a second credential that also binds.

## What is governed per-agent

| Per-agent | How |
| --- | --- |
| Identity in the audit chain | `agentId`, `agentLabel`, `agentMatchedOn`, `agentDeclared`, plus `uid`, `pid`, and `comm` on every egress record. |
| The credential that bound it | `agentCredentialId` on the record, when an issued credential did. Never the digest. |
| A refused identity | `agentIdentityRefusal` (`credential-revoked`, `credential-expired`, `credential-orphaned`, `below-minimum-tier`), `agentIdentityOrigin`, and `agentIdentityRefusalReason`. The origin decides which rule fires; see [what a refusal claims](#what-a-refusal-claims-and-what-it-does-not). |
| The floor that was in force | `fleetMinimumMatchTier` on every egress record when a fleet is declared. "Matched on comm, allowed" means something different under a credential floor than under none. |
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
| The credential store | One store per instance, found beside the config file. Point several hosts at one read-only mount and they share issuance and revocation; that is a deployment choice, not something AgentWall distributes for you. |
| The minimum binding tier | One floor for the instance. There is no per-agent exemption from it, which is the point: an exemption key would let one host opt out of the property the organisation set. |

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

`minimumMatchTier` does nothing on this path, and that is worth being precise about rather
than reassuring about. The floor judges how a claim was proven, and a redirected connection
makes no claim at all, so it is `unmatched` that decides its fate either way. Setting the
floor to `credential` therefore does **not** close the transparent path; it closes
impersonation of your declared agents on the forward proxy.

## Reading it back

`GET /api/fleet` (operator token required) returns the declared fleet with live counters, the
minimum binding tier, the agents that cannot bind under it, and each agent's issued
credentials by id and state. Never the digest, because a digest of a shared secret in a JSON
response is an offline cracking target handed out by the tool that is supposed to protect it.
Credential ids are random and unrelated to the digest, so naming one identifies it for a
`revoke` without describing it.

`agentwall fleet list` is the same information from the file, without needing the instance to
be running. `agentwall doctor` prints the summary plus every open rotation window and every
agent the floor refuses.

The payload keeps `scope: "single-host"`. That is a claim about **governance**, and it is
still true: this instance judges this host's traffic against its own allowlists, budgets, and
chain. It is not a claim about identity, which an issued credential does carry across hosts.
The `detail` field in the same payload says both, so a dashboard cannot render one word and
imply the other.

The console's **Active agents** panel shows the resolved label, the signal it matched on, the
allowlist that judged it, and the budget window, for every record that carried them. Records
that never went through egress resolution show nothing rather than asserting `matched on:
none`, which would train an operator to stop reading the field on the rows where it matters.

A denied request tells the client the specific reason first, so
`X-Agentwall-Block-Reason: api.example.com is not in the scraper egress allowlist` names which
of several allowlists refused it. The full reason list, both allowlists, and the counters are
in the chain.

## What multi-host still takes

This section used to say that identity could not cross a host boundary. **That was wrong, and
it was wrong in a way that made the remaining gap look larger than it is.** The claim rested
on `uid` and `comm` being local kernel facts, which is true, and then treated the credential
tier as though it had the same property, which it never did: a credential is presented on the
proxy connection, not read out of `/proc`, so it means the same thing on every host that runs
an instance. What was actually missing was the lifecycle around it, and that is what the
section above now implements.

What that leaves:

1. ~~An identity that survives the host boundary.~~ **Done.** An issued credential binds the
   same agent anywhere, with rotation and revocation. Two limits stated plainly: it is a
   shared secret rather than mTLS or a signed token, so any process that can read it can
   present it; and AgentWall does not distribute the store. Copying it, or mounting one store
   read-only on several hosts, is your deployment decision. What you get for that is one place
   to revoke.
2. **A shared budget with a consistency story.** Still open. A 120-per-minute ceiling across
   three instances is either a distributed counter (a coordination service on the egress hot
   path, and an outage in it becomes an egress outage) or per-instance sub-budgets that sum to
   the ceiling (no coordination, wrong answer whenever load is uneven). Both are defensible;
   the choice has to be stated, because "120 per minute across the fleet" means different
   things under each.
3. **Config distribution with a rollback faster than the mistake.** Still open for allowlists
   and budgets. A fleet-wide push that is wrong takes every agent offline at once, which needs
   staged rollout and automatic revert. Note that credentials are already the exception: the
   store is pulled from a path, so a host that cannot reach a shared mount keeps enforcing the
   copy it last parsed.
4. **A merged audit chain, or an honest statement that there is not one.** Still open, and the
   honest statement is this one. Each instance hash-chains and anchors its own records, so N
   instances produce N chains. Merging them into one ordered ledger needs a total order across
   hosts, which needs either a single writer or agreed clocks. The alternative worth having is
   N chains, a cross-reference, and a reader that is told so, because each chain stays
   independently verifiable by four separate implementations rather than becoming something an
   aggregator asserts.
5. **A control plane that fails safe.** Deliberately not built, rather than open. Anything
   holding identities and budgets centrally sits between every agent and the internet, and a
   management outage becomes an egress outage. The credential store is the shape that avoids
   it: a file each host reads on its own schedule, with the last good copy kept when the
   source is unreachable. **If the store is gone, agents keep running governed; what is lost
   is your ability to change who they are, not their ability to work.**

The honest summary: identity is a fleet-wide property now, allowlists and budgets are not, and
the audit chain is per-instance by design. [Federation](reference.md) remains a read-only view
across several.

## Related

- [Egress enforcement](enforcement.md): the three modes and what each one blocks.
- [The perimeter](perimeter.md): closing cooperative capture, and why the transparent path
  carries no identity.
- [FloodGuard](runtime-floodguard.md): the other rate control, and what it keys on instead.
- [Audit evidence format](audit-format.md): what a record is and how it is chained.
