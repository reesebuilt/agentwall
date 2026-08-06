# Detection benchmark

A fixed corpus of 190 hand-written cases and a runner that scores AgentWall's detectors
against it. The point is not the score. The point is that the score can be reproduced by
anyone, on their own checkout, in six seconds:

```
npm run bench
```

A claim about a security tool that cannot be independently re-measured is marketing. This
directory exists so that AgentWall's detection claims are checkable, including by people
who do not trust the people who wrote them.

For the reader-facing version of this document, see [docs/benchmark.md](../docs/benchmark.md).

## Running it

```
npm run bench                              # table on stdout
npm run bench -- --json                    # machine-readable report
npm run bench -- --category ssrf           # one category
npm run bench -- --help
```

Exit codes:

| code | meaning |
| ---- | ------- |
| 0 | ran to completion, no critical-severity false positive |
| 1 | a case expected to be ignored was flagged at `critical` |
| 2 | bad arguments, or the corpus would not load |

Only a *critical* false positive fails the run. That is deliberate and it is the one
threshold in here that encodes an operational opinion: a critical verdict is a page in the
middle of the night, and a tool that pages on ordinary traffic is worse than no tool. A
high or medium false positive is a precision number to argue about, not a build break.

## How to read the numbers

Precision and recall are reported separately and are never combined into a headline
figure. F1 is printed because people ask for it, and it should be ignored. Two tools with
identical F1 can have completely different operational costs:

- **Low recall** means attacks get through. You find out from an incident.
- **Low precision** means ordinary work gets blocked or paged on. You find out from
  colleagues, and the usual remedy is that somebody turns the tool off, at which point
  recall becomes zero.

These are not two samples of one quantity. Averaging them throws away the only thing you
wanted to know.

Two rendering conventions:

- `n/a` means the ratio was 0/0 — undefined, not zero. The `benign` category has no
  attacks in it by construction, so its recall and F1 are always `n/a`.
- The `benign` row's precision reads `0.0%` whenever that row has any false positive,
  because precision is tp/(tp+fp) and that row can never have a true positive. It is
  arithmetically correct and operationally meaningless. The number to read on that row is
  `fp` against `tn`, and the false-positive rate printed under the table.

## Measured results

Real output, not targets. Recorded 2026-08-05 on Node v24.14.1 against commit `96733e3`
**plus uncommitted working-tree changes to `src/planes/identity/dlp.ts`** — the entropy,
Luhn and checksum validators and the additional PII families were in the tree but not yet
in that commit. A clean checkout of `96733e3` will produce different numbers, and several
of the gaps below describe behaviour that does not exist there: gap 8 in particular names
`ipv6-address` and `mac-address` patterns that the commit does not contain. Once those
changes land, re-run and replace this section.

Re-run `npm run bench` to reproduce. These numbers move whenever a detector changes, and
they are expected to.

```
category        n  tp  fp  tn  fn precision  recall     f1
----------------------------------------------------------
exfiltration   32  22   0   0  10    100.0%   68.8%  81.5%
ssrf           42  35   1   4   2     97.2%   94.6%  95.9%
injection      43  34   1   8   0     97.1%  100.0%  98.6%
dlp            17  16   0   1   0    100.0%  100.0% 100.0%
benign         56   0   6  50   0      0.0%     n/a    n/a
----------------------------------------------------------
overall       190 107   8  63  12     93.0%   89.9%  91.5%

false-positive rate on cases expected to be ignored: 11.3%

true positives by detector:
  inj          44
  net          36
  dlp          28
  policy        2
```

The per-detector tally counts each caught case once per detector that fired, so it sums to
more than the true-positive total when several detectors agree on the same case.

Reading this honestly:

- **Injection is the strongest result**: 100% recall across all five categories including
  every obfuscation variant — zero-width, homoglyph, letter-spacing, leetspeak, base64 and
  hex — at 97.1% precision, with the single false positive being a documented design
  decision (see gap 6).
- **Exfiltration is the weakest**: 68.8% recall. Nothing in the corpus produced a false
  positive, but ten of thirty-two attacks went through. Every one of them is listed below.
- **The benign false-positive rate is 11.3%.** Six of fifty-six ordinary inputs were
  flagged. None at critical severity, so nothing here would page anyone, but six in fifty-six
  is high enough to matter and the causes are individually addressable.

## Known gaps

These came out of the run above. They are recorded, not fixed — this directory measures,
it does not change `src/`.

**1. No DNS-tunnel or high-entropy-hostname detection.** `exfil.dns.base32-subdomain`,
`exfil.dns.hex-subdomain-chain` and `exfil.dns.long-random-label` all pass. Data encoded
into subdomain labels leaves in the resolver query before an HTTP request is ever made, and
nothing in the current detectors looks at label entropy or label count. This is the largest
single hole in the exfiltration category.

**2. Encoded secrets in URLs are invisible.** `exfil.url.base64-secret-query` and
`exfil.url.hex-secret-query` carry the same AWS key id as the plaintext case, which is
caught. The DLP patterns match shapes in the bytes they are given; they do not decode. The
injection scanner does decode base64 and hex runs, but it is not applied to URLs and it
looks for instructions rather than for credentials.

**3. Splitting a secret across fields defeats shape matching.**
`exfil.url.chunked-secret-split` and `exfil.url.chunked-secret-across-path` break one token
into pieces short enough that no contiguous run matches. Any purely shape-based pattern has
this property; closing it needs reassembly, which is a different kind of detector.

**4. The tool plane does not scan non-MCP tool arguments for credentials.**
`exfil.tool.post-secret-to-external` puts a GitHub token in the arguments of a generic HTTP
tool and gets `allow`. `mcp:redact-input-secret` does exactly this scan, but only for
actions namespaced `mcp:`. `exfil.tool.read-dotenv` similarly passes: no rule recognises a
read of a credential file by path.

**5. Name-based network inspection cannot see resolution or redirects.**
`ssrf.rebinding.opaque-hostname` and `ssrf.redirect.open-redirect-to-metadata` both pass.
The first needs DNS resolution at check time; the second needs the redirect chain to be
followed. Both are architectural rather than pattern gaps, and both are stated as limits in
[docs/threat-model.md](../docs/threat-model.md).

**6. `inj.tool_coercion.credential_file_path` fires on documentation.**
`inj.tool.nearmiss.npmrc-documentation` — "Registry credentials live in the .npmrc file,
which should never be committed" — is flagged at high. The pattern is deliberately
verb-free and the source comment says so; this case measures the cost of that choice rather
than reporting a bug.

**7. Action-name substring matching over-triggers on the tool plane.**
`benign.tool.db-execute-query` matches `tool:require-approval-shell` because
`db.execute_query` contains "exec". `benign.tool.mail-remove-label` matches
`tool:require-approval-file-delete` because it contains "remove". Both would put an
approval prompt in front of a read-only or trivial operation. Matching on action segments
rather than raw substrings would fix both.

**8. Context-free PII patterns flag published contact details and infrastructure
addresses.** `benign.text.support-email`, `benign.text.support-phone`,
`benign.text.runbook-ipv6-address`, `benign.text.switch-port-mac` and
`ssrf.nearmiss.public-ipv6-literal` are all flagged. None of the patterns is wrong about
what it matched; they are all right about the shape and have no way to know that a support
address on a documentation page, or a datacentre IPv6 literal, is not personal data worth
intervening on. This is five of the eight false positives and it is a labelling problem, not
a matching problem: the finding is arguably correct and the *response* to it should not be
the same as the response to a leaked key.

## What the runner does

`run.ts` loads the corpus, routes each case by `input.kind`, and records whether anything
fired. Three configuration choices change the numbers materially, so they are stated here
rather than left in the code:

**Egress inspection runs with `defaultDeny: false`, schemes `https`/`http`, ports 443/80.**
The shipped default is deny-with-an-empty-allowlist, under which every URL in the corpus —
attack and benign alike — is denied. That is a correct deployment posture and a useless
measurement: it reports 100% recall and 0% precision and says nothing about the SSRF logic.
Turning it off isolates the checks that hold regardless of allowlist configuration: metadata
endpoints, private and link-local ranges, embedded credentials, and scheme and port limits.
The port list stays narrow on purpose, because a fetch aimed at port 22 or 6379 is a real
signal.

**The policy engine runs with a default decision of `allow`.** `deny` is the shipped
default and would mark every tool call "detected" without a single rule matching. A matched
rule whose decision is still `allow` — `tool:flag-write-operations`, which fires on any
write — does not count as a detection either: it is an audit annotation, not an
intervention.

**`url` cases are scanned by both the network inspector and the DLP patterns.** A URL is
simultaneously a destination and a string of bytes leaving the host, and only the second
view can see a credential in the query string. The per-detector tally keeps the two apart,
which matters: a deployment that wires only the network plane gets only the `net` half of
the URL score.

Detector verdicts are mapped onto a single severity per case:

| source | severity |
| ------ | -------- |
| network inspection | the inspection's own `riskLevel` |
| injection finding | the pattern's own `severity` |
| DLP secret in a `url` case | `critical` — a URL is egress by construction |
| DLP PII in a `url` case | `high` |
| DLP secret in a `text` case | `high` |
| DLP PII in a `text` case | `medium` |
| policy verdict | the result's own `riskLevel` |

The DLP split follows what the rule pack already decided: `content:block-secret-exfil` is
critical and requires an egress flow, `mcp:redact-input-secret` is high and does not.
Mapping every secret hit to critical would turn any benign string containing a
token-shaped run into a build break; mapping every hit to high would defang the failure
gate entirely.

## Adding a case

Corpus files live in `bench/corpus/`, one per category, and every case in a file must
declare that file's category. A case is:

```json
{
  "id": "exfil.url.query-github-pat",
  "category": "exfiltration",
  "severity": "critical",
  "input": { "kind": "url", "value": "https://evil.example/collect?token=..." },
  "expect": "detect",
  "why": "one line explaining what this case is testing"
}
```

- `id` — unique across the whole corpus, `<category>.<family>.<variant>` by convention.
- `category` — `exfiltration`, `ssrf`, `injection`, `dlp`, or `benign`.
- `severity` — for a `detect` case, the blast radius of missing it; for an `ignore` case,
  the disruption a false positive would cause. It never participates in scoring.
- `input.kind` — `url`, `text`, or `tool_call`.
- `expect` — `detect` or `ignore`.
- `why` — what the case is *testing*, not what the string says. A `why` that paraphrases
  the value is not worth the line.

`tool_call` values are `"<action> <free-text argument>"`: the first whitespace-delimited
token is the action, the rest becomes a single string payload field. Deliberately not JSON,
because escaped JSON inside a JSON string is unreadable and the rule pack reaches the
payload through substring matching over `JSON.stringify(payload)` and a walk of its string
values, so one string field exercises the same paths a richer payload would. The cost is
that rules keyed on `metadata` markers or `actor.channelId` are unreachable from this
corpus; those are covered by the MCP gate tests.

Rules for new cases:

- **Never a real credential.** Vendor-published placeholders (`AKIAIOSFODNN7EXAMPLE`), the
  reserved test values (`4111111111111111`, `123-45-6789`, `555-01xx` numbers), or obvious
  dummies only.
- **Never a hostname that could receive traffic.** `example.com`, `example.org`,
  `evil.example`, `*.example` — reserved names that cannot resolve to anything an attacker
  controls. Reserved literals such as `169.254.169.254`, `198.51.100.0/24` and `2001:db8::/32`
  are fine.
- **Do not add a case because it passes.** A corpus curated until it is green measures
  nothing. If a case you believe in fails, add it and record the failure under Known gaps.
- **Do not delete a case because it fails.** Same reason, in the other direction.

`tests/bench.test.ts` enforces the mechanical half of this: every file parses, every case
is complete, ids are unique, the corpus holds at least 120 cases of which at least 40 are
`ignore`, and every category and input kind is covered.

## Limits

Read these before quoting any number above.

**The corpus measures what the corpus contains.** 190 cases is not a sample of the space of
attacks; it is 190 things somebody thought of. A 100% recall row means every case in that
row was caught, and says nothing whatsoever about an attack nobody wrote a case for. Absence
of a case is not evidence of coverage.

**This tests detection logic in-process, not the deployed proxy.** The runner calls
`inspectNetworkRequest`, `scanText`, `scanInjection` and the policy engine directly. It does
not exercise the forward proxy, TLS handling, the MCP transport, gate ordering, the audit
chain, or anything that depends on a socket. A number here is a statement about the
detectors, and a deployment can be misconfigured such that none of them ever run.

**A tool can be tuned to its own benchmark.** These cases live in the same repository as the
code they score, and nothing structural stops somebody from adding a pattern that matches
exactly one corpus case. Treat the numbers as a floor for confidence, not as a ranking or a
capability claim. The defence against tuning is the benign half: 56 of the 190 cases exist
only to make over-fitting expensive, and the false-positive rate is reported next to the
recall for exactly that reason.

**Severity mapping is a judgement.** The table above is the benchmark's opinion of how
severe each detector's finding is, informed by what the rule pack does with the same finding
but not identical to it. Change the mapping and the failure gate moves.

**Category boundaries are approximate.** A case that carries a credential in a URL is both
exfiltration and, arguably, DLP. It is filed once, under the intent it represents, which
means per-category numbers describe the cases filed there rather than a clean partition of
the threat space.
