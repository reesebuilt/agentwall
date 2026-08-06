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

Across hosts, `GET /evidence/fleet` is a separate, read-only surface that verifies each host's
chain on its own bytes and rolls the records up per agent: which agents ran, on which hosts, in
which window, what each attempted, and what refused it. It is a reader and never an authority,
and it governs nothing. See [fleet evidence](fleet-evidence.md).
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
- [Fleet evidence](fleet-evidence.md): the read-only aggregator over several hosts' chains,
  what the aggregate proves, and why the chains are not merged.
