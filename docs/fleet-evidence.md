# Fleet evidence

A read-only view over several hosts' audit chains at once, at `/evidence/fleet`.

It is the [single-host evidence viewer](evidence-viewer.md) one level up. Same construction,
same refusals, same rule that the page is not the root of trust. What is new is that N hosts
produce N chains, and this reads all of them, verifies each on its own bytes, and puts the
verdicts side by side.

## What the aggregate proves

**Each chain listed was re-derived from its own bytes by this process, and holds or does not
hold on its own.** Nothing else. That sentence is the whole product of this page and every
other claim on it is downstream of it.

The aggregator never asks a host for a verdict. It reads the host's evidence files and
recomputes every record hash, every segment seal, and every anchor's reach itself. A
compromised host therefore cannot report itself clean here: it would have to produce bytes
that survive a rehash, which is the thing the format exists to make hard.

Every row is reproducible without trusting this process, in four independent implementations
written from [the format document](audit-format.md) and agreeing on 27 conformance cases. Each
host's page prints all four against that host's own file:

```bash
node dist/cli.js verify --audit /srv/agentwall-evidence/build-01/audit.jsonl
cd verifier && go build -o agentwall-verify . && ./agentwall-verify --audit <path>
cd verifier-rs && cargo build --release && ./target/release/agentwall-verify --audit <path>
python3 verifier-py/agentwall-verify-py --audit <path>
```

That property is worth strictly more across a fleet than on one laptop. On one laptop it means
you can check the console. Across a fleet it means an auditor can reproduce the aggregator's
answer for every host without trusting the aggregator, the language it is written in, or the
machine it runs on. If a command disagrees with the page, believe the command and file a bug.

## What it does not prove

- **Completeness, on any host.** An intact chain shows that what was written was not altered
  afterwards, never that everything which should have been written was. A decision that was
  never recorded leaves nothing to detect, here or in any verifier, on one host or a thousand.
- **Anything about a host that is not in the sources file.** This reads exactly where it is
  told to look. Its silence about an undeclared host is silence.
- **Anything about a host it could not read.** See [failure semantics](#failure-semantics).
- **Any ordering between hosts.** See [why the chains are not merged](#why-the-chains-are-not-merged).
- **That a host was not rewritten wholesale.** A chain with no off-box anchor is checked only
  against itself. The page counts that as a coverage gap, per host, rather than leaving it
  implied.

## Why the chains are not merged

N hosts produce N independently anchored chains. Merging them into one ordered ledger needs a
total order across hosts, which needs either a single writer or agreed clocks. Both are real
distributed systems problems, and taking one on would put a coordination dependency inside the
thing whose entire value is that it can be checked offline from a directory of files.

It also buys nothing an auditor asked for. The questions are *which agents ran, on which hosts,
in which window, what was each permitted, what did it attempt, what was refused*. Those are
answered by N verdicts side by side and a rollup over the records. None of them needs to know
whether host A's 14:03:11 came before host B's 14:03:11.

So the chains stay apart, and this page says so where a reader will see it rather than in a
footnote. The practical consequence is worth stating too: **a break on one host is a finding on
that host.** Nothing in another host's chain links to it, so nothing in another host's verdict
depends on it. Verify that yourself by altering a byte in one host's file and reloading; the
other host's verdict is byte-for-byte what it was.

## Why this is not a control plane

Nothing here sits on an egress path. **If this process is down, every host keeps enforcing its
own policy and keeps writing its own chain. What is lost is visibility, never enforcement.**

That is a decision, not an accident. A central authority holding identities and budgets between
every agent and the internet turns a management outage into an agent outage, and a security
tool that takes the fleet offline when its own console has a bad afternoon is a security tool
people switch off. Federate on evidence instead: each host keeps its own AgentWall, its own
policy, and its own chain, and the reader is separate and read-only.

Read the failure semantics as a promise you can rely on during an incident:

| What is down | What happens |
| --- | --- |
| This aggregator | Every host keeps enforcing and keeps recording. You lose the view, not the control. |
| The transport that delivers evidence here | Hosts keep enforcing and recording locally. Their rows here go `stale`, then `unreachable` if the files go away. |
| One agent host | Its own governance stops with it. Every other host is unaffected: no shared budget, no shared identity, nothing to fail over. |

## How the evidence gets here

The aggregator reads paths. It opens no socket to any host, so an agent host needs no inbound
listener and this process holds no credential on one.

Delivery is whatever transport you already run: `rsync` over ssh, an object-store sync, a
read-only mount. Copy each host's evidence directory whole and the manifest, anchor log,
checkpoint key and proofs resolve beside the audit file exactly as the CLI resolves them.

This is deliberately not an HTTP pull of each host's `/api/evidence`. That would return the
host's own verdict about itself, and an aggregator that reports what it was told is not
verifying anything. Reading the bytes and rehashing them is the difference.

The cost of the choice is stated rather than hidden: **`unreachable` here means the evidence
could not be read at this path.** It does not distinguish a host that is down from a transport
that is down, and it must not be read as either.

## Configuration

```bash
export AGENTWALL_FLEET_EVIDENCE=/etc/agentwall/fleet-evidence.yaml
```

```yaml
staleAfterSeconds: 900
hosts:
  - id: build-01
    label: Build runner, us-east
    auditPath: hosts/build-01/audit.jsonl
  - id: support-01
    auditPath: /srv/agentwall-evidence/support-01/audit.jsonl
```

See [examples/fleet-evidence.yaml](../examples/fleet-evidence.yaml) for the annotated form.

`staleAfterSeconds` is required and has no default. There is no safe silent answer: a host
whose delivery broke three days ago still verifies every record it already sent, and without a
freshness bound that renders green.

Relative paths resolve against the sources file rather than the working directory, so the same
file behaves identically from any shell.

**A malformed sources file is a hard failure, never a partial load.** The page renders no host
at all and names the parse error. An aggregator that quietly dropped the host with the typo
would show a green fleet missing a member, which is the worst possible output from a tool whose
job is saying what it could not see. Two hosts under one id are refused for the same reason.

The sources file is separate from the enforcement config on purpose. An aggregator is usually
not a host that runs agents, and requiring it to have a local chain before it can show somebody
else's would be a coupling with nothing behind it. It is also re-read on every request, so
adding or removing a host takes effect without a restart.

## Failure semantics

Five host states, because fewer force a lie. The two that matter most are `unreachable` and
`empty`: both produce zero findings, and rendering either as a clean host is the difference
between evidence and decoration.

| State | Meaning |
| --- | --- |
| `verified` | Every layer that could be checked holds, on evidence inside the freshness bound. |
| `broken` | A layer fails on this host's own chain. The finding is local to this host. |
| `stale` | The chain verifies and the newest record is older than the bound. This is history, not current state. |
| `empty` | The evidence was read and holds no records. Nothing was recorded, which is not the same as nothing happening. |
| `unreachable` | The evidence could not be read at the path given, so nothing about this host was checked. |

An unreachable host renders with its last-seen time where one can be recovered from the files
beside the missing audit file, and "never delivered anything to this path" where none can. It
shows **no layer verdict at all**, rather than a passing one over an absent file: a verdict
there would be invented, and an invented verdict is either a false clean or a false alarm.

The aggregate verdict has three states and cannot say "clean" while anything is unread:

| Verdict | When |
| --- | --- |
| `verified` | Every declared host was read, is fresh, and holds. |
| `broken` | At least one host fails its own chain verification. |
| `incomplete` | Every chain that could be read verifies, and something could not be read, is stale, or recorded nothing. |

### A host can be `verified` with its anchored layer showing `fail`

`agentwall verify` fails the anchored layer on a chain nobody has anchored off-box, with the
detail `nothing anchored off-box yet`. That is correct for a layer counter and wrong as a host
verdict: an absence of external evidence is not external evidence that disagrees, and painting
every unanchored deployment as tampered with is how a fleet console teaches an operator to
ignore red.

So the failure is reclassified, not hidden. The layer table still shows `fail` beside the CLI's
`FAIL`, verbatim, because this view must never quietly disagree with the verifier. What changes
is where the fact is filed: as a counted coverage gap, `no-off-box-anchor`, with its consequence
spelled out. An anchor that *exists* and does not reproduce is a different matter and still
condemns the host.

## What an auditor gets

Per host, and per agent within it:

- Which agents ran, over what window, and in how many sessions.
- **What the identity claim rests on**, from the record's own `agentMatchedOn`: a credential, a
  uid, a comm, or a combination. This is not decoration. A credential is presented on the proxy
  connection and works identically across a host boundary; a `comm` is a label the process chose
  and is worth nothing against one that lies. See [fleet governance](fleet.md#how-an-agent-is-identified-and-what-each-signal-is-worth).
- Which allowlist judged each connection, `global` or `agent:<id>`.
- What each agent attempted: destinations, with attempts and refusals per destination.
- What refused it, by rule id.
- Allowed, refused, sent to a human, and redacted counts.
- **Whether credential material was seen in flight, and whether it was redacted.** These are
  separate questions with different answers depending on the plane, and the page does not
  merge them. On the `/evaluate` plane AgentWall returns the content and can rewrite it, so a
  `redact` decision means the material was removed. On the proxy a body is never rewritten:
  the class of secret is recorded, the value never is, and in guarded or strict the connection
  is refused, but bytes that already left are gone.

## Coverage gaps are content, not a footnote

Every host page and the fleet page carry a table of what the evidence cannot see. An audit
answer that omits its own gaps is the overclaim pattern, and this project's credibility rests
on not doing that.

Each row separates three things that are routinely conflated:

- **the limit**, a property of the controls, true whatever any chain contains;
- **whether it is measurable at all**, because three of these can never be counted from
  evidence and reporting them as zero would report the evasions as absent;
- **the count in this evidence**, which is `unmeasured` rather than `0` when there was no
  population to count against.

So the column shows one of three things and never collapses them: a number, `unmeasured`, or
`not measurable`.

| Gap | What is not covered | Countable |
| --- | --- | --- |
| `https-body-unread` | A CONNECT tunnel is decided from host and port; the body is ciphertext and is never scanned. [Interception](tls-interception.md) is opt-in per destination. Where it is off, every finding for that connection is absent rather than negative. | yes |
| `inspection-cap` | A plaintext or intercepted body is buffered to 256 KiB, scanned, and the remainder forwarded uninspected. A clean scan over one of these covers a prefix, not a body. | yes |
| `padding-evasion` | Anything placed past 256 KiB is forwarded unread. Pad a body, put the payload after the cap, and the scan finds nothing. | **no**, by construction: a successful evasion produces exactly what an innocent large body produces |
| `dns-channel` | A named resolver is a working bidirectional channel to an external host that never touches the proxy. Demonstrated, not theorised: see [the perimeter](perimeter.md). | **no**: a DNS query produces no record in any chain, so the absence of rows is the absence of a record type |
| `stream-uninspected` | Event streams are relayed without buffering, so no finding may be claimed for one. | yes |
| `interception-bypassed` | A destination on the bypass list is tunnelled without decryption on purpose. Deliberate opacity, a different claim from incidental opacity. | yes |
| `no-redaction-in-flight` | A proxied body is not rewritten. The class of secret is recorded; the bytes still went. | yes |
| `monitor-mode` | An `allow` from a monitor-mode instance is an observation, not a permission granted after a check the agent could have failed. | yes |
| `transparent-no-identity` | A kernel-redirected connection carries no fleet identity, so per-agent allowlists and budgets do not bind to it. | yes |
| `no-off-box-anchor` | A chain nobody anchored is checked only against itself. Whoever holds the host can rewrite its history whole and consistently, and nothing outside would object. | yes, per host |
| `completeness` | Verification cannot show that everything which should have been written was. | **no**, by definition |

Fleet-wide counts say how many hosts they were summed over, because "0 capped bodies" across
three of twelve hosts is a different statement from the same number across all twelve, and only
one of them is reassuring.

## Read only, structurally

Same mechanisms as the single-host viewer, and one more.

| Mechanism | What it rules out |
| --- | --- |
| Only `GET` handlers exist; `POST`, `PUT`, `PATCH` and `DELETE` return `405` | Acting on a decision from the review surface |
| The HTML serves no script at all | A client that could be pointed at a control route |
| Nothing the module imports opens a file for writing | Editing the evidence being reviewed |
| Nothing here opens a socket to any host, and no credential on any host is held | This surface being a foothold into the fleet it reports on |
| Every interpolated value is HTML-escaped, and a host id in a URL is percent-encoded | An audited agent, or an operator-supplied label, choosing markup that runs in the reviewer's browser |

Evidence you can edit from the console reviewing it is not evidence. To act on a decision, use
the operational dashboard or the CLI **on the host that owns it**.

## Getting in

Nothing here is in the auth allowlist, so `/evidence/fleet` and `/api/evidence/fleet` sit behind
the operator bearer token like every other non-health route:

```bash
curl -H "authorization: Bearer $AGENTWALL_OPERATOR_TOKEN" \
  http://127.0.0.1:3000/api/evidence/fleet
```

A browser cannot send a bearer header by typing a URL. For local review start the service with
`AGENTWALL_ALLOW_LOOPBACK_DEV=1`, which accepts a loopback caller as a `loopback-dev` principal.
That switch is a development convenience, [compliance.md](compliance.md) scores it as a finding,
and it must not be set on a host anyone else can reach.

| Route | Returns |
| --- | --- |
| `GET /evidence/fleet` | The fleet page |
| `GET /evidence/fleet/host/:hostId` | One host's page: layers, agents, coverage, and the four reproduce commands |
| `GET /api/evidence/fleet` | The fleet report as JSON, without per-record arrays |
| `GET /api/evidence/fleet/host/:hostId` | One host's report, with session scorecards and without record bodies |

`AGENTWALL_FLEET_EVIDENCE` unset answers `503` naming the variable, at every one of those, rather
than `404`ing and leaving an operator to guess whether the feature exists.

## Limits

- **Nothing is cached, including the sources file.** Chains grow while you read them, and a
  cached verdict is a verdict about files that no longer exist.
- **Bounded reads, per host.** Each host read is capped at 100,000 records and skips any single
  file above 64 MB, the same caps the single-host viewer uses. When a cap bites the page names
  it, prefixed with the host id, and points at the CLI which reads all of it.
- **Reading N hosts costs N rehashes per request.** They are bounded but not free. This surface
  is built for a reviewer opening a page, not for a polling monitor.
- **`unreachable` names no cause.** It reports what this process observed, which is that no
  bytes were there. A dead host, a dead transport, a wrong path, a permission this process does
  not hold, and a host that never configured an audit file all produce it, and the page lists
  them rather than picking one.
- **A copy left beside a chain makes a host `inconclusive`, and an adversary can cause that
  deliberately.** Segment discovery accepts any file named after the audit file that parses as
  one, so `cp audit.jsonl audit.jsonl.bak` inside an evidence directory is walked as a rotated
  segment. Overlapping chain-index ranges are something the writer cannot produce, so the host
  is reported as not judgeable rather than as tampered with. Somebody who can write to the
  evidence directory can therefore force `inconclusive` to mask a real break, exactly as they
  could delete the directory to force `unreachable`. Neither renders as clean, which is the
  property that matters, but neither should be read as an all-clear either.
- **Copy an evidence directory wholesale and the writer's lock file comes with it.** That was a
  real defect, found while building this page and fixed rather than documented: the durable sink
  writes `<audit>.lock` beside the chain and holds it for the life of the writer, and the Python
  and Rust verifiers walked it as a rotated segment, failed to parse the pid inside, and reported
  the `chained` layer FAIL on a completely healthy host. The bundled and Go verifiers already
  excluded it. All four now do, and `tests/fleet-evidence.test.ts` holds the two this machine can
  run to it. Worth knowing because this page is the first surface that hands an auditor the
  Python command, and an older checkout of that verifier will still cry wolf.

## Tests behind the claims on this page

```bash
npx jest tests/fleet-evidence.test.ts
```

Every chain in that suite is written by the production writers through a running server, not by
a hand-assembled fixture, and each simulated host is a separate server instance with its own
audit file. The tamper case alters one byte on one host, asserts the break is reported there,
asserts the other host's verdict is byte-for-byte unchanged, then restores the byte and asserts
the fleet goes clean. The unreachable, empty and stale cases each assert they render distinctly
from a verified host and from each other. The coverage counters are exercised against records a
real forward proxy produced and against the metadata the production decision function emits for
the interception path, because those two paths spell the content keys differently and a reader
that knew only one would report a decrypted, scanned body as carrying nothing.

## Related

- [Evidence viewer](evidence-viewer.md): the single-host surface this extends, and where the
  per-session scorecard and the three verification layers are explained.
- [Audit evidence format](audit-format.md): the normative on-disk spec every verifier reads.
- [Verification](verification.md): the four implementations, the conformance corpus, and what
  each layer establishes.
- [Fleet governance](fleet.md): per-agent identity, allowlists and budgets within one host, and
  what each identity signal is worth.
