# Config and policy reload

Re-read `policy.yaml` and `agentwall.config.yaml` without restarting and without dropping a
connection. One operator action, validated before anything is applied, and recorded on the audit
chain.

The short version of the honest part: **policy rules reload completely, config reloads
partially, and a reload tells you exactly which keys it could not apply.** That list is below and
the API returns it per call, so you never have to guess whether a change took effect.

## Four triggers

Every one of them records to the chain, including the two that existed before reload was a
coordinated surface and recorded nothing.

| Trigger | How | Identity on the chain |
| --- | --- | --- |
| `api` | `POST /reload` | The authenticated operator principal |
| `sighup` | `kill -HUP <pid>` | None, see below |
| `watch` | Edit `policy.yaml` in place | None, see below |
| `dashboard` | The console's reload and rule-editing controls | The authenticated operator principal |

`sighup` and `watch` carry no identity and none is invented for them. Anything that can signal
the process or write the policy file is already inside the trust boundary, and a made-up name on
an append-only chain is worse than an honest `none`.

The `watch` trigger is the file watcher that has always been there: it watches the policy file
only, never the config file. Nothing was added to make config reload automatic on a file change,
because an explicit trigger is the right shape for a policy surface, and because a config change
that needs a restart cannot be honoured by a watcher anyway.

### SIGHUP usually finds the policy file already reloaded

Worth knowing before you read the chain. Because the policy watcher is on by default, editing
`policy.yaml` and then sending SIGHUP normally produces **two** records: a `watch` record that
applied the rule change, and a `sighup` record reporting `unchanged` because the watcher got
there first. That is not a bug in either path, and the hashes make it legible: the `watch`
record's before and after hashes differ, the `sighup` record's are identical.

SIGHUP still earns its place. It is the only trigger that re-reads `agentwall.config.yaml`, which
has no watcher, and it is a deterministic trigger for the case where a watch event was missed or
coalesced.

## What reloads, and what does not

Policy rules reload whole. Every rule in `policy.yaml` is re-read, re-validated, and put in force
for the next request.

For `agentwall.config.yaml`, exactly two keys can be applied to a running process:

| Key | Effect |
| --- | --- |
| `logLevel` | Applied immediately |
| `policy.defaultDecision` | Applied immediately, and bumps the policy version |

**Everything else needs a restart.** Not "usually", not "in some cases": the listener owns `host`
and `port`, the forward and transparent proxies read `enforcement.mode` and the egress allowlists
once at start-up so that no file I/O sits in front of a model API call, and the approval gate,
flood guard, watchdog, DLP, telemetry, and audit sinks are each constructed once with their
section as a constructor argument.

That is a deliberate trade and reload does not overturn it. What reload does is tell you. A
response names every key that changed in the file and is not in force:

```json
{
  "ok": true,
  "config": {
    "applied": ["logLevel"],
    "restartRequired": ["egress.allowedHosts", "enforcement.mode"]
  },
  "warnings": [
    "Config keys changed in /etc/agentwall/agentwall.config.yaml that a running process cannot apply: egress.allowedHosts, enforcement.mode. The file and the running process disagree about these until a restart."
  ]
}
```

The running config keeps reporting what is actually in force, not what the file says, so
`/api/dashboard/state` does not start advertising a mode nothing is enforcing.

## A bad file changes nothing

Validation happens in two phases and application happens in neither of them.

1. Parse and validate `agentwall.config.yaml`, including `enforcement.mode`,
   `policy.defaultDecision`, and any changed live-appliable key. This phase has no side effects,
   so a failure returns before the policy file has been touched.
2. Parse, validate, and compile `policy.yaml`. A refused file leaves the previous ruleset in
   force, so a failure returns before any config key is applied.

Only then is anything swapped, and what remains is pointer swaps and scalar assignments that
cannot half-succeed. The consequence is the property worth having: **a bad file of either kind
leaves both subsystems exactly as they were.** There is no partial outcome to reason about, and a
rejected reload answers `400` with the error and the confirmation that the previous policy is
still enforcing.

`policy.defaultDecision` is validated because it used to be trusted. It is typed
`"allow" | "deny"` but arrives from a YAML parse, and an unrecognised value became the decision
returned for every request that matched no rule. Nothing downstream treats an unknown decision as
a block, so a typo there failed OPEN. It is now refused at load time, which means a config file
carrying one will also refuse to boot.

## In-flight requests keep the policy they started with

A request pins the ruleset when it arrives. A reload replaces the engine's pointer to an
immutable snapshot and never mutates the snapshot a request is holding, so a request that started
under one policy finishes under it however many times it evaluates and whatever it awaits in
between. The next request gets the new ruleset.

Before this existed the guarantee was incidental rather than designed: `PolicyEngine.evaluate` is
synchronous and reads the rules array once, so no single evaluation could tear, but nothing
stopped a handler that evaluates twice from straddling a swap. That is a property that survives
only until somebody makes a handler async.

Every snapshot carries a `version` that starts at 1 and increments on every swap, so a reload
record names the exact ruleset that replaced the exact ruleset before it.

## The audit record

Every reload, from every trigger, applied or rejected, emits one `config:reload` record on the
governance plane. A policy change is a security-relevant event, and before this it produced a log
line and nothing else.

The record carries who triggered it, what changed at the rule level, and both files' hashes:

| Field | Meaning |
| --- | --- |
| `reloadSource` | `api`, `sighup`, `watch`, or `dashboard` |
| `reloadOperator` | The authenticated principal, or `none` |
| `reloadOutcome` | `applied`, `unchanged`, or `rejected` |
| `policyHashBefore` / `policyHashAfter` | sha256 of the policy file's raw bytes |
| `configHashBefore` / `configHashAfter` | sha256 of the config file's raw bytes |
| `policyVersion` | The snapshot version now in force |
| `policyRulesAdded` / `policyRulesRemoved` / `policyRulesModified` | Rule ids |
| `configKeysApplied` / `configKeysRestartRequired` | Dotted config keys |

Hashes are of raw bytes, so `sha256sum` reproduces them. A comment-only edit therefore moves the
hash while the rule diff stays empty, which is the truth: the file changed, the rules did not.

`hashBefore` is the hash of the file as it was when its contents were last put in force, not a
fresh read at reload time. That distinction is the whole point: an operator edits the file and
*then* triggers the reload, so re-reading the file to fill both slots would report the new hash
twice and describe a real change as if nothing had moved.

On a **rejected** reload, `policyHashAfter` is the hash of the file that was REFUSED, not of the
rules still in force. The pair reads as "this version was refused, that version is still
running", which is what lets you identify the exact bytes that failed. `reloadOutcome: rejected`
is what tells you nothing was applied; the hash is evidence, not a claim about what is running.

A rejected reload is recorded as `decision: deny` at `riskLevel: high`. Somebody with write
access to the policy file produced something the parser would not take, and that is worth
alerting on.

### When the record cannot be written

A reload is not failed over a missing record: evidence about a policy change must not become a
precondition for an operator fixing policy during an incident. But it is never silent either.
The record is offered to the durable sink, and if the sink refuses it, the loss is counted and
declared in the chain by the same machinery that covers every other dropped record.

The reload response then says so where a caller cannot miss it:

```json
{
  "ok": true,
  "audit": { "recorded": false, "eventId": null, "detail": "no space left on device" },
  "warnings": [
    "This reload is NOT on the audit chain: no space left on device. The change IS in force and there is no chained evidence of it."
  ]
}
```

`audit.recorded: false` on an `ok: true` reload is the one combination worth paging on: the
change is enforcing and there is no tamper-evident record of it.

## Checking before you reload

`GET /reload` reports what is loaded and what a reload can change, without changing anything:

```bash
curl -sS -H "Authorization: Bearer $AGENTWALL_OPERATOR_TOKEN" http://127.0.0.1:3015/reload
```

```json
{
  "policy": { "path": "/etc/agentwall/policy.yaml", "hash": "c1d35f...", "hashOnDisk": "c1d35f...", "policyVersion": 3, "ruleCount": 27 },
  "config": { "path": "/etc/agentwall/agentwall.config.yaml", "hash": "9f2ab1...", "hashOnDisk": "5e82ea...", "liveAppliableKeys": ["logLevel", "policy.defaultDecision"] },
  "lastReload": { "ok": true, "source": "sighup", "at": "2026-08-06T15:20:23.680Z" }
}
```

`hash` is what is in force. `hashOnDisk` is what a reload would read. **When they differ, somebody
has saved an edit that is not in force yet**, as the config file does in the example above. That
is the most useful thing this endpoint tells an operator who is about to reload, and it is why
both are reported rather than one.

## Reloading

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $AGENTWALL_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"rotating the openai rule"}' \
  http://127.0.0.1:3015/reload
```

`reason` is optional, bounded at 512 characters, and lands in the audit record. The body is
strict: a field this route does not implement is a `400` rather than a silent no-op, so asking
for a partial reload tells you it is not a thing instead of returning `200` for something else.

There is no parameter for reloading one file and not the other. The atomicity guarantee is
defined across both files, and letting a caller ask for half of it would hand out the partial
outcome the two-phase order exists to prevent.

## Limits

- Two config keys are live-appliable. Everything else in the file needs a restart, and the
  response names it.
- `policy.configPath` is restart-required. The policy runtime and its watcher are bound to the
  path they were constructed with, so pointing the config at a different policy file needs a
  restart.
- The `watch` trigger reports `policyHashBefore` from the coordinator's own record of what it last
  applied, because the runtime has already swapped by the time the watcher callback runs.
- A large policy file written non-atomically can be read mid-write, which is rejected as a parse
  failure and leaves the previous ruleset in force. The subsequent watch event for the completed
  write reloads it. If your editor truncates in place, prefer an explicit `POST /reload` after
  saving over trusting the watcher.
- Reload does not restart the proxies, re-bind the listener, or re-run nftables programming.
