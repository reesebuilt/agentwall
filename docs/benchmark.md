# Detection benchmark

AgentWall ships the corpus its detection numbers come from. You can re-measure them on your
own checkout:

```
npm run bench
```

Six seconds, no network, no configuration. The output is a per-category table of precision
and recall over 190 hand-written cases, followed by a list of every attack that was missed
and every ordinary input that was flagged.

This exists because a detection claim you cannot re-measure is a claim you have to take on
trust, and security tools are the last place that is reasonable. If you disagree with a
number below, the cases are in `bench/corpus/` and you can read every one of them.

## Running it

```
npm run bench                        # table on stdout
npm run bench -- --json              # machine-readable report, for CI
npm run bench -- --category ssrf     # one category
npm run bench -- --help
```

`--json` emits a single object: overall and per-category metrics, plus arrays naming every
false positive and every false negative. Its `schema` field is `1` and will change if the
shape does.

Exit codes are `0` for a clean run, `1` when a case that should have been ignored was
flagged at `critical` severity, and `2` for bad arguments or an unloadable corpus. Only a
critical false positive fails the run, because a critical verdict is a page in the middle of
the night and a tool that pages on ordinary traffic gets switched off.

## How to read the numbers

Precision and recall are reported separately. They are never combined into a single score,
and the F1 column exists only because people ask for it.

- **Recall** is the fraction of attacks that were caught. Low recall means attacks get
  through, and you find out from an incident.
- **Precision** is the fraction of alerts that were real. Low precision means ordinary work
  gets blocked, and you find out from colleagues — after which somebody disables the tool,
  and recall becomes zero.

Those failures have completely different costs and different fixes. A single number hides
which one you have, so this benchmark refuses to produce one.

Two conventions in the output:

- `n/a` means the ratio was 0/0 — undefined, not zero. The `benign` category contains no
  attacks by construction, so its recall and F1 are always `n/a`.
- The `benign` row's precision reads `0.0%` whenever there is any false positive, because
  that row can never contain a true positive. Read `fp` against `tn` on that row, and the
  false-positive rate printed below the table.

Under the table you get a per-detector tally of what caught what (`net`, `dlp`, `inj`,
`policy`), which tells you how the score would change in a deployment that only wires some
of the planes.

## What is in the corpus

| category | cases | what it covers |
| -------- | ----: | -------------- |
| `exfiltration` | 32 | secrets in URL query, path, fragment and userinfo; base64 and hex encodings; DNS-tunnel-shaped hostnames; secrets split across fields; prose and tool-call directives |
| `ssrf` | 42 | loopback, RFC1918, shared address space, link-local, IPv6 private ranges, cloud metadata, decimal/octal/hex/short IP forms, internal name suffixes, rebinding and redirect shapes, non-web schemes and ports |
| `injection` | 43 | all five injection categories, each raw and obfuscated with zero-width characters, homoglyphs, letter spacing, leetspeak, base64 and hex |
| `dlp` | 17 | one case per secret and personal-data family, plus a documentation placeholder that must not fire |
| `benign` | 56 | documentation and registry URLs, commit SHAs, UUIDs, semver, base64 image data, code snippets, shell one-liners, security prose, log lines, and ordinary tool calls |

71 of the 190 cases are `expect: "ignore"`. That proportion is the point. A detector that
flags everything scores perfectly against attacks and is useless, and a corpus without a
large benign half cannot tell the two apart.

No case contains a real credential, and no case names a hostname that could receive
traffic: destinations are under reserved names (`example.com`, `evil.example`) or reserved
literals (`169.254.169.254`, `198.51.100.0/24`, `2001:db8::/32`).

## The measured results

The numbers from the most recent recorded run, including the full list of known gaps the run
surfaced, are in [bench/README.md](../bench/README.md). They are kept there rather than here
because they are output, not documentation, and they change whenever a detector changes.

Summary as recorded on 2026-08-05: overall precision 93.0%, overall recall 89.9%, and a
false-positive rate of 11.3% on the cases that should be ignored. Injection recall was
100%, exfiltration recall was 68.8%, and twelve attacks in the corpus were not detected at
all. All twelve are named in the gap list.

That run's exact provenance — the commit, the Node version, and which detector changes were
in the working tree but not yet committed — is stated alongside the table. Check it before
treating the summary as a property of any particular revision, and re-run rather than trust
it if you are on a different one.

## Adding a case

Cases live in `bench/corpus/<category>.json`. Each is:

```json
{
  "id": "ssrf.metadata.aws-imds",
  "category": "ssrf",
  "severity": "critical",
  "input": { "kind": "url", "value": "http://169.254.169.254/latest/meta-data/" },
  "expect": "detect",
  "why": "one line explaining what this case is testing"
}
```

`input.kind` is `url`, `text`, or `tool_call`. A `tool_call` value is
`"<action> <free-text argument>"`. `expect` is `detect` or `ignore`. `severity` is the
author's judgement of what it costs to get the case wrong and never affects scoring.

Two rules matter more than the format:

- **Never a real credential and never a resolvable attacker-controlled hostname.** Use
  vendor placeholders and reserved names.
- **Do not add a case because it passes, and do not delete one because it fails.** A corpus
  curated until it is green measures nothing at all. A case you believe in that fails is the
  most valuable case in the file; record it as a gap.

`tests/bench.test.ts` checks the mechanical requirements — parsing, required fields, unique
ids, minimum corpus size, minimum benign count — so a malformed case fails the suite rather
than quietly skewing a number. The full corpus format, the runner's configuration, and the
severity mapping are documented in [bench/README.md](../bench/README.md).

## Limits

**The corpus measures what the corpus contains.** These are 190 things somebody thought of,
not a sample of the space of attacks. A 100% recall row means every case in that row was
caught and says nothing about an attack nobody wrote a case for. Do not read a full row as
coverage of a category.

**It tests detection logic in-process, not the deployed proxy.** The runner calls the
scanners and the policy engine directly. It does not exercise the forward proxy, TLS
handling, the MCP transport, gate ordering, or the audit chain — all of which have their own
tests, and any of which can be misconfigured such that no detector ever runs on your
traffic. A good score here is necessary and not sufficient.

**A tool can be tuned to its own benchmark.** The corpus lives in the same repository as the
code it scores. Nothing structural prevents a pattern written to match one corpus case.
Treat these numbers as a floor for confidence rather than as a ranking. The benign half is
the main defence: over-fitting to the attack cases shows up immediately as a worse
false-positive rate, which is why the two are always printed together.

**Severity mapping is a judgement call.** Each detector's finding is mapped onto one
severity so the run can have a pass/fail gate. The mapping is documented in
[bench/README.md](../bench/README.md); change it and the gate moves.

**Related reading.** [docs/threat-model.md](threat-model.md) states what AgentWall defends
against and what it explicitly does not. Several benchmark misses are instances of limits
described there rather than bugs, and the gap list says which.
