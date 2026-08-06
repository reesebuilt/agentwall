# The evidence viewer

A read-only console over the audit chain, at `/evidence`.

AgentWall already emitted everything a reviewer needs: hash-chained records, a rotation
manifest, signed checkpoints, and OpenTimestamps proofs. What it did not do was let anyone
read them. Answering "what did this agent do, what was blocked, and can I trust the record"
meant opening JSONL by hand, counting decisions, and running the verifier in another terminal
to learn whether the file had been touched. This page is that work, done for you.

It invents no data. Every number on it is a projection of what `src/audit/` writes and what
[docs/audit-format.md](audit-format.md) specifies. Nothing is recorded to serve the view.

## The one rule

**The page is not the root of trust.** It prints the command that reproduces its own verdict,
because a console over signed evidence that asks you to believe it has given up the only
property that made the evidence worth signing. Run the command. If it disagrees with the page,
believe the command and file a bug.

The layer verdicts on the page are `runVerify()`'s own, reproduced with the PASS or FAIL you
will see in your terminal shown beside them, so you can tell at a glance that the view is not
inventing a verdict of its own.

## Read only, structurally

| Mechanism | What it rules out |
| --- | --- |
| Only `GET` handlers exist; `POST`, `PUT`, `PATCH` and `DELETE` return `405` | Acting on a decision from the review surface |
| The HTML serves no script at all | A client that could be pointed at a control route |
| Nothing the module imports opens a file for writing | Editing the evidence being reviewed |
| Every interpolated value is HTML-escaped, and a session id in a URL is percent-encoded | The audited agent choosing markup that runs in the reviewer's browser |

Evidence you can edit from the console reviewing it is not evidence. To approve, deny, pause a
session, or engage lockdown, use the operational dashboard or the CLI. Those surfaces exist and
this one deliberately is not them.

## Getting in

Nothing here is in the auth allowlist, so `/evidence` and `/api/evidence` sit behind the
operator bearer token like every other non-health route:

```bash
curl -H "authorization: Bearer $AGENTWALL_OPERATOR_TOKEN" http://127.0.0.1:3000/api/evidence
```

A browser cannot send a bearer header by typing a URL. For local review start the service with
`AGENTWALL_ALLOW_LOOPBACK_DEV=1`, which accepts a loopback caller as a `loopback-dev`
principal, then open `http://127.0.0.1:3000/evidence`. That switch is a development
convenience, [compliance.md](compliance.md) scores it as a finding, and it must not be set on a
host anyone else can reach. No second credential scheme was invented for this surface.

`AGENTWALL_AUDIT_FILE` must be set. Unset, decisions are still chained and still written to
stdout, but nothing is appended to a file, there is no chain for a verifier to walk, and the
viewer answers `503` saying exactly that instead of rendering an empty page that looks healthy.

## What the page shows

### Verification, three layers, inline

The same three properties the verifier reports, never collapsed into one tick:

| Layer | Question it answers |
| --- | --- |
| chained | Was a record altered after it was written? |
| linked | Was a whole rotated file removed, reordered, or replaced? |
| anchored | Was the entire local history rewritten? |

Each row carries a state and the CLI verdict beside it. The states are four, not two, because
two states force a lie:

| State | Meaning |
| --- | --- |
| `pass` | Checked and holds |
| `fail` | Checked and does not hold |
| `pending` | Submitted off-box and waiting on a Bitcoin block. Pending is not proof |
| `absent` | No evidence of this property exists for this span, so nothing was checked |

`absent` is the honest answer for a layer nothing has established. A session whose records are
all still in the live file is not covered by the rotation manifest, because the manifest seals
closed segments and the live file is deliberately left out of it while it grows. Rendering that
as a pass would vouch for a property no evidence supports.

### Per-session scorecard

One card per session, and a page per session behind it: which agent, how many records, the span
of chain indexes they occupy, what was allowed, denied, sent to approval or redacted, which
detections fired and how often, which rules matched, and the three layer states scoped to that
session.

The chained row for a session answers two questions rather than one, and the distinction
matters. A chain holds one global sequence, so a session's records are interleaved with other
sessions'. An edit to somebody else's record between two of yours leaves yours reproducing
their hashes perfectly while the ORDER around them is no longer vouched for. The scorecard says
so:

```
chained  FAIL  7 record(s), chain index 0 to 12, in 2 file(s)
  ! audit.jsonl.1 line 5 (record 4, another session): altered, so the ordering around
    this session's records is not vouched for
```

The record table on a session page carries the chain index, timestamp, plane, action, decision
with the writer's own stated reasons beside it, risk level, detections, and the integrity state
of that record. It does not carry the record's `metadata`, `payload`, `provenance` or `flow`
blocks. A reviewer who needs the full record body uses the `jq` command the page prints.

A card that reported only "your records reproduce" would be true and misleading.

### Signed receipt timeline

One row per anchor submission: when it was submitted, which calendar answered, which sealed
segment count the checkpoint committed, the highest record index it demonstrably commits to,
the proof file behind it, and the attestations those bytes actually carry.

"Commits through record N" is re-derived from the files on disk, not read off the record. A
checkpoint commits a manifest head plus a live tail, and the tail is inside a hash, so the
reach is recovered by finding which candidate reproduces the composite the checkpoint signed.
When nothing reproduces it, the reach is reported as unknown rather than as the sealed span,
because naming the sealed span would claim coverage the bytes no longer support.

Records written after the newest anchor read as `absent`, with the gap named:

```
anchored  ABSENT  the furthest usable anchor commits through record 13; this span runs to 14,
                  so the records past that rest on local controls alone
```

### The offline command, on the page

```bash
node dist/cli.js verify --audit <the file the page is reading>
node dist/cli.js verify --audit <path> --json
cd verifier && go build -o agentwall-verify . && ./agentwall-verify --audit <path>
./agentwall-verify --audit <path> --pubkey-file <the key you expect>
```

The pinned form is on the page too, because a checkpoint signature verifies against the public
key the checkpoint itself carries: unpinned it proves internal consistency and nothing else.

Each session page also prints the command that pulls that session's records out of the JSONL:

```bash
cat audit.jsonl.1 audit.jsonl | jq -c 'select(.sessionId == "sess-a")'
```

Selecting by member rather than by text on purpose, so the command does not depend on the order
the writer happened to serialize keys in.

## Pending is never rendered as verified

This is the load-bearing behaviour and it has a case in the conformance corpus.

`agentwall verify` counts an anchor as confirmed from the record's own `status` field, and
nothing compares that claim against the attestations inside the proof. Corpus case
`l1-confirmed-with-pending-proof` pins that limit: an anchor claiming `confirmed` whose proof
carries only a pending attestation passes with exit 0. See
[verification.md](verification.md#the-conformance-corpus).

The viewer derives the state from the proof bytes instead:

| Condition | State |
| --- | --- |
| The submission never reached a calendar (`error` is set) | `failed` |
| No proof on disk, empty proof, or the proof does not parse | `unproven` |
| The proof reaches a Bitcoin attestation | `confirmed` |
| The proof reaches only a calendar attestation | `pending` |

So on corpus case `l1` the CLI prints `PASS` and the page says `pending`, and the row names the
overclaim: `the record's own status says "confirmed"; its proof does not carry that`. This view
is permitted to say LESS than the counter and never more. That is the only direction a console
over signed evidence is allowed to differ in.

The same applies to a submission that failed to reach any calendar. It is recorded with
`status: "pending"` and an `error`, and the record is written either way because silence is
worse. It is counted as failed here, never as waiting on a block.

## Records the verifier cannot recompute

A record whose hash does not reproduce gets one of two labels, because the two are different
findings:

- `altered`: the record names canonical form `cu1` and does not reproduce its hash. That is
  what an edit after write looks like.
- `unmarked-canon`: the record does not reproduce its hash AND names no canonical form. Records
  written before the `cu1` marker land here. A verifier without ICU collation tables cannot
  rebuild that hash, so unverifiable and edited are indistinguishable from outside.

Both fail the chained layer, exactly as both verifiers fail them, because the verdict must not
soften. Only the stated cause differs, so an operator with old history is not told somebody
tampered with it. Corpus case `l2-legacy-canon-unmarked` is this case.

A torn tail is surfaced and does NOT fail the layer: a final line with no terminator that does
not parse is what a hard kill mid-append leaves, and a security tool that reports tampering on
every hard kill gets its alerts ignored.

A line carrying a duplicate member is shown as a fault and is not filed under a session, because
what such a record says depends on which parser reads it.

## Limits

- **The verdict is file-wide.** There is no per-session `verify` command, and the scorecard says
  so on every session page. The scoped layer states are a projection; the CLI column is what the
  printed command checks.
- **Bounded reads.** One request reads at most 100,000 records and skips any single file above
  64 MB. When a cap bites, the page names it and points at the CLI, which reads all of it. A
  route that rehashes an unbounded file is a route an operator can hang.
- **Nothing is cached.** The chain grows while you read it, and a cached verdict is a verdict
  about a file that no longer exists. Showing `chained PASS` from before a break was appended is
  precisely the failure this view exists to prevent.
- **Completeness is not shown, because it cannot be.** An intact chain shows that what was
  written was not altered afterwards, never that everything which should have been written was.
  A decision that was never recorded leaves nothing to detect, here or in any verifier.

## Tests behind the claims on this page

```bash
npx jest tests/evidence-viewer.test.ts
```

Every chain in that suite is written by the production writers through the running server, not
by a hand-assembled fixture. The tamper case alters one byte in a record the chain already
covers, asserts the break is reported and attributed to the right record and session, then
restores the byte and asserts the view goes clean again. The pending case anchors, asserts the
state is `pending` and the CLI verdict is `PASS`, and asserts the page never renders `confirmed`
against it.
