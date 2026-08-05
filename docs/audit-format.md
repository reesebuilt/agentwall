# Agentwall audit evidence format

This document specifies the bytes Agentwall writes as evidence, and the checks a verifier
performs on them. It is normative: the implementation conforms to this document, not the
reverse. It is written so that someone who has never read the Agentwall source can implement
a verifier in another language and get bit-identical results.

Everything needed is here: file shapes, the canonical form the hashes are computed over, the
exact byte strings that are hashed and signed, the linkage rules, and the proof grammar. Every
hexadecimal value in the worked examples is real and reproducible with a SHA-256 tool and an
Ed25519 library.

## Status of this document

In this document MUST, MUST NOT, and MAY carry their usual force. MUST and MUST NOT statements
are the contract; a program that violates one is not a conforming verifier.

What is part of the contract:

- The byte strings that are hashed or signed, exactly as given, including member order inside
  those strings.
- The canonical form named `cu1`, including its key ordering.
- The linkage rules between records, between segments, and between a checkpoint and an anchor.
- The set of verdicts: whether each layer verifies, and the counts of pending, confirmed, and
  failed anchors.

What is not part of the contract, and MUST NOT be relied on:

- The wording of any diagnostic message. Two conforming verifiers report the same verdict and
  may describe it in different words. An implementation MAY attach stable code names to the
  conditions described here, such as a duplicate key, a torn tail, an index gap, a link break,
  or a hash mismatch; those names are that implementation's interface, not part of this format.
- Member order inside the records on disk. A verifier looks members up by name. Order matters
  only inside the hashed byte strings this document spells out.
- Whitespace inside a record line. The writer emits none, and a verifier reuses whatever the
  line contains rather than reformatting it.
- File names and directory layout, which are operator-configurable. The defaults are below.

## Three independent properties

The evidence is split across files because it supports three different claims that fail
independently, and collapsing them into one verdict would hide which one an operator actually
has:

| Layer | Question it answers | Evidence |
| --- | --- | --- |
| chained | Was a record altered after it was written? | Per-record hash chain inside each file |
| linked | Was a whole rotated file removed, reordered, or replaced? | Rotation manifest |
| anchored | Was the entire local history rewritten? | Signed checkpoint plus an off-box timestamp |

A verifier reports each separately. `chained` passing tells an operator nothing about whether
anything was anchored, and `anchored` passing tells them nothing about whether the log is
complete. See [What this format does not prove](#what-this-format-does-not-prove).

## The files

Paths are operator-configurable. The audit file path is the anchor for every default: the
others resolve beside it or are derived from its name.

| File | Default | Contents |
| --- | --- | --- |
| audit file | operator-supplied, no default | Live JSONL record chain |
| rotated segments | `<audit>.1`, `<audit>.2`, or a date-suffixed variant | Closed JSONL record chains |
| rotation manifest | `segments.jsonl` beside the audit file | One line per sealed segment |
| anchor log | `anchors.jsonl` beside the audit file | One line per anchor submission |
| proof directory | `proofs/` beside the audit file | OpenTimestamps proof files |
| checkpoint key | `checkpoint-key.pem` beside the audit file | Ed25519 private key, PKCS#8 PEM |

The checkpoint key is a signing key, not evidence. A verifier never needs it: every checkpoint
carries its own public key, and an operator who wants to bind checkpoints to a key they expect
supplies that key's base64 SPKI as a pin. The rest of this document treats the key file as
absent.

## The audit record file

A record file is JSONL: UTF-8, no byte order mark, one JSON object per line, each line
terminated by a single LF (`0x0A`). The final record is LF terminated like the others.

A line that is empty or contains only whitespace is not a record and is ignored. This matters
because the trailing LF of the last record produces one such chunk in most line splitters.

Every record is an audit event with an `integrity` member:

| Member | Type | Meaning |
| --- | --- | --- |
| `chainIndex` | integer | Position in the chain |
| `hash` | 64 lowercase hex characters | SHA-256 over the hash material defined below |
| `previousHash` | 64 lowercase hex characters, or `null` | The preceding record's `hash` |
| `algorithm` | `"sha256"` | Hash algorithm |
| `status` | `"chained-local"` | What the writer attests |
| `canon` | `"cu1"`, or absent | Which canonical form `hash` was computed over |

`status` is deliberately not `"verified"`. It records that the writer linked the record at
write time. It is not a verification result, and a verifier MUST NOT treat it as one.

`canon` names the canonical form, so a verifier can recompute the hash without guessing. Its
absence is meaningful and is covered in
[Records without a canon marker](#records-without-a-canon-marker).

All other members are the audited event itself. Their names and types are the product's
concern, not the format's: canonicalization is defined over arbitrary JSON, so a record with
members this document never mentions verifies exactly the same way.

## Canonicalization cu1

`cu1` is the canonical form the record hash is computed over. It is defined over the JSON
source tokens of the record's own line, not over parsed values.

### Why token reuse

Every lexeme in a record line was emitted by the same serializer that produced the writer's
canonical form. Reusing those lexemes reproduces the writer's bytes exactly, without
reimplementing another language's number formatting or string escaping.

The alternative, parsing values and reserializing them, requires a verifier to reproduce
ECMAScript number formatting (`1e21`, `-0`, 17 significant digits chosen by shortest
round trip) and ECMAScript string escaping. That is a reimplementation of a specific runtime
inside the component whose entire job is to be independent of it.

A conforming verifier MUST NOT reserialize parsed values. It parses only enough to know the
structure and the decoded key strings, and it emits the original lexemes.

### canon(v)

Let `v` be a JSON value taken from a record line. `canon(v)` is a byte string:

- `null`, `true`, `false`, numbers, and strings: the exact source lexeme, byte for byte. For a
  string this includes the surrounding double quotes and every escape sequence as written. A
  verifier MUST NOT unescape, re-escape, normalize Unicode, or reformat a number.
- Arrays: `[` followed by `canon` of each item joined by `,` followed by `]`. Item order is
  preserved exactly as it appears in the source.
- Objects: members sorted ascending by the decoded key, then `{` followed by, for each member,
  the key's source lexeme, then `:`, then `canon` of its value, joined by `,`, followed by `}`.

Note the asymmetry in the object rule, because it is the single most likely place for an
independent implementation to differ: sorting compares DECODED keys, while emission uses the
ORIGINAL key lexeme. Two keys written `"\u00c4"` and as the raw two UTF-8 bytes of U+00C4 sort
identically and emit differently, because each emits the bytes its own line contained.

Two members of one object with the same decoded key make the record malformed. A verifier
reports it and MUST NOT silently keep one of them. The Agentwall writer cannot produce such a
record; a file containing one has been edited.

A verifier MUST detect the duplicate in the raw line, before handing it to a parser. This is
not a matter of strictness. Parsers disagree about duplicates and none of them say so: some
keep the last occurrence, some keep the first, some refuse the document. Once a parser has
returned, the second member is gone and no later check can see it was ever there. A record
whose meaning depends on which language read it cannot be evidence whatever hash it carries,
which is why the disagreement itself is the failure.

A malformed record therefore counts toward NOTHING. It MUST NOT link into the chain, MUST NOT
count toward a segment's `count` or contribute its `finalHash`, and MUST NOT count toward a
checkpoint's committed live tail. Records either side of it are judged against each other. An
implementation MAY name this failure; the bundled one reports it as `dup-key`.

### Key ordering

Keys are compared as sequences of UTF-16 code units. Compare the first code unit of each key
numerically; on equality move to the next; a key that is a proper prefix of another sorts
first.

This is a total order on any pair of distinct keys, it needs no locale data, no collation
tables, and no library. It is not the same as code point order, and the difference is
observable, so it is stated here rather than left to be discovered.

Worked example. Given this object on a record line:

```json
{"\uff21":5,"apple":2,"\ud835\udc00":4,"Zebra":1,"\u00c4":3}
```

`canon` of that object is exactly:

```json
{"Zebra":1,"apple":2,"\u00c4":3,"\ud835\udc00":4,"\uff21":5}
```

Hand-check it against the first code unit of each decoded key:

| Key as written | Decoded character | First UTF-16 code unit | Code point |
| --- | --- | --- | --- |
| `"Zebra"` | Z | `0x005A` | U+005A |
| `"apple"` | a | `0x0061` | U+0061 |
| `"\u00c4"` | Latin capital A with diaeresis | `0x00C4` | U+00C4 |
| `"\ud835\udc00"` | Mathematical bold capital A | `0xD835` | U+1D400 |
| `"\uff21"` | Fullwidth Latin capital A | `0xFF21` | U+FF21 |

The last two rows are the ones that catch a wrong implementation. U+1D400 has a much higher
code point than U+FF21, and sorts BEFORE it here, because outside the Basic Multilingual Plane
a character is two code units and the first of them, the high surrogate, is in `0xD800` to
`0xDBFF`. An implementation that sorts by code point, or by UTF-8 bytes, orders these two keys
the other way and produces a different hash for the same record.

Implementation note for languages whose strings are not UTF-16: encoding each key to UTF-16
big-endian and comparing the resulting byte strings lexicographically gives exactly this
order, because every code unit becomes two bytes most significant first.

### canonicalPayload and hashMaterial

For a record `R`, let `E` be `R` with its `integrity` member removed and every other member
left byte for byte as the line contains it. Then:

    canonicalPayload(R) = canon(E)

The hash material is the concatenation of these literal bytes, with no whitespace anywhere:

    {"chainIndex":I,"previousHash":P,"algorithm":"sha256","payload":J}

where:

- `I` is `integrity.chainIndex` as a base-10 integer with no sign for positive values, no
  leading zeros, no fraction, and no exponent. A conforming writer emits `chainIndex` in
  exactly that form, so reusing the source lexeme gives the same bytes.
- `P` is the four bytes `null`, or `integrity.previousHash`'s source lexeme including its
  surrounding double quotes.
- `J` is `canonicalPayload(R)` encoded as a JSON string: an opening double quote, then the
  payload with two substitutions and no others, every `\` becoming `\\` and every `"`
  becoming `\"`, then a closing double quote. The quotes are part of `J`, which is why the
  skeleton above shows none around it.

Only those two characters need escaping. `canonicalPayload` is itself JSON text, and JSON text
cannot contain an unescaped control character or an unpaired surrogate, so no other escape can
arise. A verifier MAY assert that `canonicalPayload` contains no byte below `0x20` and treat a
violation as a malformed record.

Then:

    integrity.hash = lowercase hex SHA-256 of hashMaterial encoded as UTF-8

`integrity.hash` MUST be lowercase hex, so a verifier compares it byte for byte against its
own lowercase recomputation. Nothing else about the record affects the hash: member order on
disk, and any whitespace a later tool may have introduced between tokens, are both absorbed
by canonicalization.

### Worked example: one record

This is a complete record line, exactly as a writer emits it, with the trailing LF omitted:

```json
{"id":"01JQ8Z0MZ9V6QK9J0H7X4T2R5B","timestamp":"2026-01-01T00:00:00.000Z","agentId":"curl","plane":"network","action":"egress:https","decision":"allow","riskLevel":"low","matchedRules":[],"reasons":["monitor-first: observed, not gated"],"requiresApproval":false,"highRiskFlow":false,"metadata":{"host":"example.com","port":"443","durationMs":"378"},"integrity":{"chainIndex":0,"hash":"d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303","previousHash":null,"algorithm":"sha256","status":"chained-local","canon":"cu1"}}
```

Step 1, drop `integrity` and canonicalize. Twelve members sort to this order, and `metadata`
sorts internally as well:

```json
{"action":"egress:https","agentId":"curl","decision":"allow","highRiskFlow":false,"id":"01JQ8Z0MZ9V6QK9J0H7X4T2R5B","matchedRules":[],"metadata":{"durationMs":"378","host":"example.com","port":"443"},"plane":"network","reasons":["monitor-first: observed, not gated"],"requiresApproval":false,"riskLevel":"low","timestamp":"2026-01-01T00:00:00.000Z"}
```

Step 2, build the hash material. `chainIndex` is 0 and `previousHash` is `null`, so `P` is the
bare word. The payload appears embedded, with each `"` escaped:

```json
{"chainIndex":0,"previousHash":null,"algorithm":"sha256","payload":"{\"action\":\"egress:https\",\"agentId\":\"curl\",\"decision\":\"allow\",\"highRiskFlow\":false,\"id\":\"01JQ8Z0MZ9V6QK9J0H7X4T2R5B\",\"matchedRules\":[],\"metadata\":{\"durationMs\":\"378\",\"host\":\"example.com\",\"port\":\"443\"},\"plane\":\"network\",\"reasons\":[\"monitor-first: observed, not gated\"],\"requiresApproval\":false,\"riskLevel\":\"low\",\"timestamp\":\"2026-01-01T00:00:00.000Z\"}"}
```

That material is 471 bytes. Step 3, hash it:

    SHA-256 = d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303

which is the `hash` the record carries. A reader can confirm this by writing the material of
step 2 to a file with no trailing newline and running `sha256sum` on it.

### Records without a canon marker

A record whose `integrity` has no `canon` member was hashed under an earlier canonical form
that ordered object keys by locale collation. That order depends on collation tables outside
the file, so it is not reproducible from this document, and this format does not define it.

A verifier that finds no `canon` member derives the hash under `cu1` and compares. When the
comparison fails it reports that the record either was altered or predates `cu1`, without
claiming to know which, because from the file alone it cannot tell. The two derivations agree
for records whose object keys are all lowercase ASCII, which is why many such records verify
under `cu1` regardless.

Records carrying `canon: "cu1"` have exactly one valid derivation: the one in this document.

## Chain rules

A verifier walks each record file independently, in file order, from the first line.

For the first record of a file:

- `chainIndex` MAY be any non-negative integer. A file need not start at 0, because a chain
  that continues across a rotation starts its next file at the index it had reached.
- `previousHash` MAY be `null` only when `chainIndex` is 0. A first record with a non-zero
  `chainIndex` and a `null` `previousHash` is a break.

For every subsequent record in the same file:

- `chainIndex` MUST equal the previous record's `chainIndex` plus 1. A gap is a failure, not a
  tolerated condition. Detecting removal is the reason the index exists.
- `previousHash` MUST equal the previous record's `integrity.hash`.

For every record in every file:

- `integrity.hash` MUST equal the value recomputed per
  [canonicalPayload and hashMaterial](#canonicalpayload-and-hashmaterial).
- A record with no `integrity` member is a failure.

Two record shapes are reported distinctly because they mean different things:

- A line that is not valid JSON, anywhere except the final line, is a failure. Nothing in
  normal operation produces one.
- A truncated final line is reported as a torn tail, separately from other parse failures. A
  process killed mid-append produces exactly one, legitimately, and a verifier that called
  that tampering would cry wolf on every hard kill. Records before it are unaffected: they are
  complete, and their hashes still chain.

Records that share a `chainIndex` inside one file are a distinct diagnosis from a single
altered record. Many records but few distinct indexes is the signature of two processes each
keeping their own chain state and appending to one file, not of an edit.

### Worked example: two records chained

The record from the worked example above is followed on the next line by:

```json
{"id":"01JQ8Z0N2C4M8P1S6D3F9G7H2K","timestamp":"2026-01-01T00:00:01.000Z","agentId":"curl","plane":"network","action":"egress:https","decision":"allow","riskLevel":"low","matchedRules":[],"reasons":["monitor-first: observed, not gated"],"requiresApproval":false,"highRiskFlow":false,"metadata":{"host":"example.com","port":"443","durationMs":"412"},"integrity":{"chainIndex":1,"hash":"8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428","previousHash":"d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303","algorithm":"sha256","status":"chained-local","canon":"cu1"}}
```

Its `chainIndex` is 1, one more than its predecessor. Its `previousHash` is its predecessor's
`hash`. Its own hash material is:

```json
{"chainIndex":1,"previousHash":"d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303","algorithm":"sha256","payload":"{\"action\":\"egress:https\",\"agentId\":\"curl\",\"decision\":\"allow\",\"highRiskFlow\":false,\"id\":\"01JQ8Z0N2C4M8P1S6D3F9G7H2K\",\"matchedRules\":[],\"metadata\":{\"durationMs\":\"412\",\"host\":\"example.com\",\"port\":\"443\"},\"plane\":\"network\",\"reasons\":[\"monitor-first: observed, not gated\"],\"requiresApproval\":false,\"riskLevel\":\"low\",\"timestamp\":\"2026-01-01T00:00:01.000Z\"}"}
```

    SHA-256 = 8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428

Because `previousHash` is inside the material, changing any byte of the first record changes
its hash, which invalidates the second record's `previousHash`, whose own hash then changes as
well. One edit is detectable at the edited record and at every record after it.

## Rotation manifest

The manifest is JSONL, one line per sealed segment, in seal order. Each line has these members:

| Member | Type | Meaning |
| --- | --- | --- |
| `path` | string | The segment file, as it was at seal time |
| `count` | integer | Records in the segment |
| `firstIndex` | integer | `chainIndex` of the segment's first record |
| `lastIndex` | integer | `chainIndex` of the segment's last record |
| `finalHash` | hex | `integrity.hash` of the segment's last record |
| `previousSegmentHash` | hex or `null` | The previous entry's `finalHash` |
| `sealedAt` | string | Seal timestamp, from the sealer's clock |
| `entryHash` | hex | SHA-256 over this entry's other members |

`entryHash` is the lowercase hex SHA-256 of these literal bytes, using each value's source
lexeme, in exactly this member order, with no whitespace:

    {"path":p,"count":c,"firstIndex":f,"lastIndex":l,"finalHash":h,"previousSegmentHash":s,"sealedAt":t}

The order here is fixed by this document and is unrelated to the order the members happen to
appear in on the line. A manifest line is a plain JSON object, so a verifier reads the values
by name and assembles the bytes above.

Linkage rules:

- The first entry's `previousSegmentHash` MUST be `null`.
- Entry `i`'s `previousSegmentHash` MUST equal entry `i-1`'s `finalHash`.
- Every entry's `entryHash` MUST match the recomputation.

Removing a middle entry breaks the chain of `previousSegmentHash` values at the following
entry. Editing an entry to hide that breaks its own `entryHash`. Both are reported.

Those three rules check the manifest against itself and say nothing about the files it names.
A verifier that stops there can be handed a segment rewritten from end to end, with its own
per-record chain rebuilt so it verifies, and will report the `linked` layer as passing. The
anchor would then cover a manifest that covers only itself, which is the whole of what the
manifest is for. So the manifest is also checked against the bytes:

- A verifier MUST resolve every entry's `path` and read the segment it names.
- When that segment is present, its last record's `integrity.hash` MUST equal `finalHash`,
  its record count MUST equal `count`, and its first and last records' `chainIndex` MUST
  equal `firstIndex` and `lastIndex`. Any difference is a failure of the `linked` layer.
- A present file holding no readable record MUST be reported the same way. Truncating a
  sealed segment to nothing leaves the file in place, so presence alone is not the test.
- A segment the manifest names but that is absent from disk is a DIFFERENT finding, reported
  as missing rather than as a content difference. Absent evidence and contradicting evidence
  lead an operator to different places, so a verifier MUST keep them distinguishable.
- Both findings belong to the `linked` layer. Absence is the degenerate case of the check
  above, since bytes that are not there cannot be compared, and putting it anywhere else
  would let `linked` report a pass while a segment the manifest vouches for is gone. Which
  layer owns a condition is part of the contract, because the verdicts are; two verifiers
  that agree a segment is missing and disagree about which layer says so do not agree.

An implementation MAY name the absence. The bundled one reports it as `segment-missing`.

`finalHash` folds in every record before it, so requiring the file to still produce it is what
turns the entry into a statement about the segment's contents rather than about the manifest
line. `count` and the two indexes are checked alongside it so a truncation or an extension is
named directly instead of surfacing only as a hash difference.

An implementation MAY name the content failure. The bundled one reports it as
`segment-content-mismatch`.

A relative `path` resolves against the directory containing the manifest file, which keeps a
manifest portable when a whole evidence directory is copied. An absolute `path` is used as
recorded. A verifier MUST NOT resolve a relative `path` against its own working directory: the
same evidence would then verify from one directory and fail from another, which makes the
verdict a property of the operator's shell rather than of the evidence. `path` is advisory in
one specific sense: files get moved, and a segment that is named in the manifest but absent
from disk is reported as missing rather than assumed intact.

The live audit file is never a manifest entry. It grows between seals, so sealing it would
record a hash that is stale the moment it is written. Its current state is committed by the
checkpoint instead. Rotated files present on disk but absent from the manifest sit outside the
anchor and are reported.

### Worked example: one manifest entry

A segment holding the two records above, sealed as `audit.1.jsonl`, hashes these bytes:

```json
{"path":"audit.1.jsonl","count":2,"firstIndex":0,"lastIndex":1,"finalHash":"8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428","previousSegmentHash":null,"sealedAt":"2026-01-01T00:00:02.000Z"}
```

    SHA-256 = 6172869bd41e220a1ee64372e9aea4a68d8b11e9bb675a6f11611a2890d5f861

and the manifest line is that object with `"entryHash":"6172869b..."` appended.

## Checkpoint

A checkpoint is a signed statement about the state of the whole evidence set at one moment. It
appears embedded in each anchor log line.

| Member | Type | Meaning |
| --- | --- | --- |
| `chainIndex` | integer | Sealed segment count at signing time |
| `hash` | hex | Composite hash defined below |
| `signedAt` | string | Signing timestamp, from the signer's clock |
| `signature` | base64 | Raw 64-byte Ed25519 signature |
| `publicKey` | base64 | DER SPKI public key |
| `algorithm` | `"ed25519"` | Signature algorithm |

`chainIndex` here is a segment count, not a record index. It reuses the member name and does
not reuse the meaning, so a verifier MUST NOT compare it against any record's `chainIndex`.

The composite hash is the lowercase hex SHA-256 of these literal bytes, in this member order,
with no whitespace:

    {"manifestHead":H,"segments":n,"liveTail":{"finalHash":h,"count":c}}

where `H` is the newest manifest entry's `finalHash` as a quoted string, or `null` when the
manifest is empty; `n` is the number of sealed segments; and the whole `liveTail` value is
`null` when the live file holds no complete record. Committing both the sealed history and the
live tail means one checkpoint covers everything on disk rather than only the rotated part.

The signed bytes are these, in this member order, encoded as UTF-8:

    {"chainIndex":N,"hash":H,"signedAt":T,"algorithm":"ed25519"}

`signature` is the base64 of the raw Ed25519 signature over exactly those bytes. Ed25519 needs
no separate pre-hash, so a verifier passes the byte string itself to its verify function.

A checkpoint binds state as of signing. The live file growing afterwards is expected and does
not invalidate it. A later checkpoint commits to the larger state.

A verifier checks each checkpoint's signature against the `publicKey` the checkpoint itself
carries. That is a self-consistency check and nothing more: whoever forged a record could sign
it with a key they generated. When an operator supplies a pinned public key, a verifier
additionally requires each checkpoint's `publicKey` to equal the pin, compared as the base64
DER SPKI string, and reports a mismatch as a failure. Pinning is what turns a self-consistent
signature into evidence about who signed.

### Re-deriving what a checkpoint committed

A valid signature says the composite was signed by the key. It says nothing about whether the
composite still describes anything on disk. A verifier that checks only the signature reports
the `anchored` layer as passing over evidence the anchored value no longer matches, so:

- A verifier MUST rebuild the composite from the evidence files and require the checkpoint's
  `hash` to equal one of the rebuilt values. A checkpoint whose composite cannot be rebuilt is
  a failure of the `anchored` layer.
- `manifestHead` is rebuilt from the checkpoint's own `chainIndex`: it is entry `chainIndex-1`'s
  `finalHash`, or `null` when `chainIndex` is zero. The manifest is append-only, so that entry
  is still where it was. A manifest now holding FEWER than `chainIndex` entries cannot supply
  it, and MUST be reported: dropping the newest entries breaks no `previousSegmentHash` link,
  because what remains still chains, and the checkpoint is the only thing that notices.
- `liveTail` is not readable from the checkpoint, because only the composite is stored. It is
  rebuilt by candidate: for each eligible segment file, each prefix of `c` records offers the
  pair (that record's `integrity.hash`, `c`). The `null` tail and each eligible manifest
  entry's own (`finalHash`, `count`) are candidates too, the latter covering a rotated segment
  whose file is gone, which is already reported as missing.

An implementation MAY name this failure. The bundled one reports it as `live-tail-mismatch`.

Which files are eligible, and why this does not cry wolf on a healthy deployment:

- The committed `finalHash` is the hash of the live file's record number `count`, and every
  record hash folds in the records before it, so a checkpoint commits a PREFIX and not a
  length. Records appended afterwards leave that prefix identical, so it still reproduces. A
  verifier MUST NOT compare the committed pair against the live file's CURRENT end: a running
  deployment appends between anchor passes, and every checkpoint but the newest would fail.
- Rotation moves the committed prefix out of the live file and into a closed segment, so a
  checkpoint older than the last rotation reproduces from a rotated file. Eligible files are
  the live file, closed segments still awaiting a seal, and manifest entries from index
  `chainIndex` onward, which is exactly the set that closed after this checkpoint was signed.
- A segment already sealed when the checkpoint was signed is NOT eligible. It was not the live
  file at that moment, so allowing it to satisfy a committed tail would widen the check for
  nothing.

What is left is the failure: a prefix that was rewritten, truncated, or reordered produces a
different hash at that count and reproduces from nothing eligible.

### Worked example: a checkpoint

State: one sealed segment whose `finalHash` is the manifest entry above, and a live file with
one record whose hash is
`bd5cb6e6d98cc93e166c79b0945889642a3c2e7fdad1892bab83044b76c51348`.

Composite hash input:

```json
{"manifestHead":"8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428","segments":1,"liveTail":{"finalHash":"bd5cb6e6d98cc93e166c79b0945889642a3c2e7fdad1892bab83044b76c51348","count":1}}
```

    SHA-256 = fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0

Signed bytes:

```json
{"chainIndex":1,"hash":"fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0","signedAt":"2026-01-01T00:00:03.000Z","algorithm":"ed25519"}
```

The resulting checkpoint, signed by a key generated for this document:

```json
{"chainIndex":1,"hash":"fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0","signedAt":"2026-01-01T00:00:03.000Z","signature":"0Kt6u/CfbfxIdPm6Kgp6WpAzi8301ca8Zw7RpqOxoIq1BC4n6sOiY0eVOZTMfcOfo+eoTHH+CodhmYhYmh/ADg==","publicKey":"MCowBQYDK2VwAyEAvU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE=","algorithm":"ed25519"}
```

The `publicKey` decodes to 44 bytes of DER SPKI, of which the last 32 are the raw Ed25519
public key. Any Ed25519 implementation verifies the base64 signature above against the signed
bytes above and that key. Flipping one byte of the signed bytes, or one bit of the signature,
makes it fail; that is the check.

## Anchor log

The anchor log is JSONL, one line per anchor submission. Each line is an anchor record with the
signed checkpoint embedded under `checkpoint`.

| Member | Type | Meaning |
| --- | --- | --- |
| `backend` | `"opentimestamps"` | Anchor backend |
| `digest` | hex | What was submitted, defined below |
| `chainIndex` | integer | Copy of the checkpoint's `chainIndex` |
| `reference` | string | Backend handle: the calendar that answered, or empty |
| `proofPath` | string, optional | Where the proof was written |
| `submittedAt` | string | Submission timestamp, from the submitter's clock |
| `status` | `"pending"` or `"confirmed"` | Backend state |
| `error` | string, optional | Set when the submission failed |
| `checkpoint` | object | The checkpoint above |

`digest` is the lowercase hex SHA-256 of these literal bytes, in this member order, with no
whitespace:

    {"chainIndex":N,"hash":H,"signedAt":T,"signature":S,"publicKey":K}

Note that this differs from the signed bytes in two ways: it includes `signature` and
`publicKey`, and it has no `algorithm` member. A verifier recomputes it from the embedded
checkpoint and requires it to equal the record's `digest`. A mismatch means the record does not
describe the checkpoint it carries, so the proof, whatever it attests to, does not attest to
this checkpoint.

`error` set means the submission never reached a calendar. Such a record counts as failed
whatever its `status` says. The writer records the attempt either way, because silence about a
failed anchor is worse than a recorded failure, and it writes `status: "pending"` because that
is the only status the submission path produces. A verifier that trusted `status` here would
report a failed anchor as merely waiting for a Bitcoin block, which is precisely the overclaim
this layer exists to prevent. Error wins over status.

A verifier counts each record as exactly one of confirmed, pending, or failed, applying that
precedence, and reports the three counts.

`proofPath` is the lookup key for the proof file. A verifier MUST NOT derive the file name from
the digest instead: naming a proof after its digest is a writer convention, not a rule of the
format, and the recorded path is the only thing that points at a file named any other way.
Making the recorded path authoritative also means a verifier opens the file before it has to
recompute anything about it.

`proofPath` carries whatever the producer wrote, which is a path relative to the producer's
working directory unless it is absolute. The directory holding proofs and the directory holding
the anchor log are configured independently, and they coincide only under the default paths, so
this format does not define a directory that a relative `proofPath` is relative to. What a
verifier can rely on is the recorded base name inside the proof directory it was given, and
that is where it looks when the recorded path itself does not resolve. Reading the base name
rather than the whole path is also what lets an evidence directory be checked after being
copied to another host. A record whose proof cannot be found is reported as missing its proof.

### Worked example: an anchor record

For the checkpoint above:

```json
{"chainIndex":1,"hash":"fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0","signedAt":"2026-01-01T00:00:03.000Z","signature":"0Kt6u/CfbfxIdPm6Kgp6WpAzi8301ca8Zw7RpqOxoIq1BC4n6sOiY0eVOZTMfcOfo+eoTHH+CodhmYhYmh/ADg==","publicKey":"MCowBQYDK2VwAyEAvU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE="}
```

    SHA-256 = d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94

and the log line is:

```json
{"backend":"opentimestamps","digest":"d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94","chainIndex":1,"submittedAt":"2026-01-01T00:00:04.000Z","reference":"https://alice.btc.calendar.opentimestamps.org/digest","status":"pending","proofPath":"proofs/d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94.ots","checkpoint":{"chainIndex":1,"hash":"fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0","signedAt":"2026-01-01T00:00:03.000Z","signature":"0Kt6u/CfbfxIdPm6Kgp6WpAzi8301ca8Zw7RpqOxoIq1BC4n6sOiY0eVOZTMfcOfo+eoTHH+CodhmYhYmh/ADg==","publicKey":"MCowBQYDK2VwAyEAvU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE=","algorithm":"ed25519"}}
```

The 32 raw bytes of `digest` are what the calendar was asked to timestamp, and they are the
starting message for the proof below.

## OpenTimestamps proof files

The calendar's response body is the proof: the operations that lead from the submitted digest
up to an attestation. Discarding it would reduce an anchor to a claim that an HTTP request
once happened, so it is written to a file and the anchor record points at it.

### Containers

A proof file is one of two shapes, and a verifier distinguishes them by looking for the magic
bytes at offset 0:

1. A full `.ots` file. It begins with these 31 magic bytes:

       00 4F 70 65 6E 54 69 6D 65 73 74 61 6D 70 73 00 00 50 72 6F 6F 66 00 BF 89 E2 E8 84 E8 92 94

   then a version varint, then a hash-op tag, then the digest, then the operations stream.

2. A raw calendar response: the operations stream alone, starting immediately after the
   32-byte digest that was submitted. Nothing precedes it, so a file that does not begin with
   the magic bytes is read as this form.

Both forms carry the same operations stream, and the starting message in both cases is the 32
raw bytes of the anchor record's `digest`.

### Grammar

| Element | Encoding |
| --- | --- |
| varint | Unsigned little-endian base 128. Each byte contributes 7 bits, least significant group first. The high bit set means another byte follows. |
| varbytes | A varint length, then exactly that many bytes. |
| `F0` | append: varbytes, appended to the current message |
| `F1` | prepend: varbytes, prepended to the current message |
| `F2` | reverse: reverse the current message |
| `F3` | hexlify: replace the message with its lowercase hex representation |
| `02` | sha1 of the current message |
| `03` | ripemd160 of the current message |
| `08` | sha256 of the current message |
| `67` | keccak256 of the current message |
| `FF` | fork: the current message continues down another branch as well; both branches continue independently |
| `00` | attestation: 8 tag bytes, then a varbytes payload |

Two attestation tags matter:

| Attestation | Tag bytes | Payload |
| --- | --- | --- |
| pending | `83 DF E3 0D 2E F9 0C 8E` | A varbytes UTF-8 calendar URI |
| Bitcoin | `05 88 96 0D 73 D7 19 01` | Contains a varint block height |

An attestation tag a verifier does not recognize is skipped using its varbytes length, which is
why the length prefix exists. Unknown attestations are neither proof nor failure.

### Verification

Start with the 32 raw bytes of the anchor record's `digest` as the current message. Apply each
operation in order. At a fork, continue both branches from the message as it stands. Collect
every attestation reached, each with the message value that reached it.

A pending attestation is reported as pending, with its calendar URI, and MUST NOT be reported
as proof. It records that a calendar accepted a submission and nothing more. OpenTimestamps
batches submissions into a Merkle tree whose root goes into a Bitcoin transaction, so a pending
attestation is a submission awaiting a block, which typically takes one to six hours.

A Bitcoin attestation is reported with its block height and the 32-byte value that reached it.
That value is the claimed Merkle root of the named block. Confirming it requires comparing it
against the block's actual Merkle root, obtained from a Bitcoin source. A verifier that reads
only local files does not fetch one and MUST NOT report the attestation as confirming
anything by itself. What it does establish, offline, is that the proof's operations really do
lead from this digest to that value, so the only remaining question is one lookup an operator
can perform with any Bitcoin node or block explorer.

A verifier operates on attacker-influenced input by definition, so it bounds what a proof can
make it do: a cap on the size of each operation argument, a cap on total work, and a cap on
fork depth. A proof exceeding a cap is reported as a parse error rather than being followed. A
verifier that can be wedged by its own input is an attack surface.

### Worked example: a pending proof

Take the anchor record above, whose digest is
`d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94`, and this operations stream
as the whole proof file, 67 bytes:

    f0 08 1122334455667788 08 00 83dfe30d2ef90c8e 2e 2d
    68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267

Read it as:

| Bytes | Meaning |
| --- | --- |
| `f0` | append |
| `08` | varbytes length 8 |
| `1122334455667788` | the 8 bytes appended |
| `08` | sha256 |
| `00` | attestation |
| `83dfe30d2ef90c8e` | pending tag |
| `2e` | varbytes length 46, the attestation payload |
| `2d` | varint 45, the URI length inside the payload |
| `687474...6f7267` | `https://alice.btc.calendar.opentimestamps.org` |

The message evolves as follows. After the append, 40 bytes:

    d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc941122334455667788

After the sha256, 32 bytes:

    a422fc26d26edb0ea1b4a0b2b421d0d0e7e8d60c814db3d654a5fa2130c0ae00

A reader can reproduce that by piping the 40 bytes above through `xxd -r -p | sha256sum`. The
result is the value the pending attestation covers. The correct report for this proof is one
pending attestation naming that calendar, and no confirmation of anything.

As a full `.ots` file the same proof is the 31 magic bytes, then version varint `01`, then
hash-op tag `08`, then the 32 digest bytes, then the same 67 operation bytes, 132 bytes in all:

    004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294
    0108
    d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94
    f0081122334455667788080083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267

### Worked example: a Bitcoin attestation

The same operations with a Bitcoin attestation for block height 850000 instead, 24 bytes:

    f0 08 1122334455667788 08 00 0588960d73d71901 03 d0f033

The payload is 3 bytes, holding the varint `d0 f0 33`. Decoded least significant group first:
`0x50 + (0x70 << 7) + (0x33 << 14)`, that is `80 + 14336 + 835584`, which is 850000. The
attested value is the same
`a422fc26d26edb0ea1b4a0b2b421d0d0e7e8d60c814db3d654a5fa2130c0ae00`, and the honest report is:
this proof leads from the digest to that value, which is claimed to be the Merkle root of
block 850000; compare it with a Bitcoin source to finish the check.

## What this format does not prove

Each of these is a real limit, not a caveat about implementation quality. A verifier that
reports otherwise is wrong.

- **Completeness of capture.** Every hash and every signature is computed over records that
  exist. Nothing here can show that an action which was never written down did not happen. An
  anchor proves records were not altered afterwards; it does not prove the log is complete.
- **Authorship, without a pinned key.** A checkpoint signature verified against the key the
  checkpoint itself carries proves only internal consistency. Anyone who can write the file
  can generate a key, sign their version, and produce a set of records that verifies
  perfectly. Only comparing `publicKey` against a key an operator recorded independently makes
  a signature evidence about who signed.
- **Bitcoin inclusion, without a block source.** An offline verifier can prove that a proof's
  operations lead from a digest to a value. It cannot know that the value is a real block's
  Merkle root. That comparison needs data this format does not contain.
- **Time.** `sealedAt`, `signedAt`, and `submittedAt` come from the clock of the process that
  wrote them, which is the same process an attacker on that host controls. They are advisory.
  A confirmed Bitcoin attestation is the only element that bounds when a digest existed, and
  it bounds it from one side: not later than that block.
- **Ordering of adopted segments.** Segments sealed as they rotate carry a genuine link,
  because each seal records the hash the previous seal produced. Segments adopted after the
  fact, from files that already existed, are ordered by file modification time, which anyone
  who can rewrite the files can also set. Adoption starts a chain from wherever a deployment
  already is; it does not attest to that deployment's past.
- **Anything about the host.** The chain covers what was written, not whether the writer saw
  everything, ran unmodified, or was the only writer. A single-writer lock is what defends
  against a second appender; two writers appending concurrently interleave two chains into one
  file, and the resulting index reuse is detectable but not repairable.
- **Legacy records, in an independent implementation.** Records with no `canon` marker whose
  keys are not all lowercase ASCII were hashed under an order this format does not define.
  Reporting them as unverifiable here is correct, not a defect.
- **Which file a committed live tail came from.** Rebuilding a checkpoint's live tail asks
  whether the committed prefix still exists among the files it could have been written to, not
  whether it is in the one file it originally occupied. Nothing in the evidence records that.
  An adversary who copies the live file aside, lets the copy be sealed as a rotated segment,
  and then rewrites the live file satisfies the check, at the price of leaving the original
  records on disk under another name.

## Conformance checklist

A verifier written from this document is conforming when all of the following hold:

- It reuses source lexemes and never reserializes a parsed value.
- It sorts object keys by UTF-16 code units, and emits the original key lexeme.
- It detects duplicate keys within one object on the raw line, before parsing, and counts
  such a record toward no chain link, no segment count, and no committed live tail.
- It builds each hashed byte string with the member order given here, with no whitespace.
- It reports `chained`, `linked`, and `anchored` separately, and reports counts of pending,
  confirmed, and failed anchors.
- It distinguishes a torn final line from other parse failures.
- It resolves a relative manifest `path` against the manifest's directory, never against its
  own working directory.
- It checks every manifest entry against the segment it names, reports both a missing segment
  and a contradicting one on the `linked` layer, and keeps the two distinguishable.
- It rebuilds each checkpoint's composite from the evidence and requires the checkpoint's
  `hash` to match, treating a live file that has only grown or rotated as healthy.
- It treats an anchor record with `error` as failed, whatever its `status`.
- It reports a pending attestation as pending, never as proof.
- It reports a Bitcoin attestation as a value plus a height to be compared elsewhere, never as
  a completed check.
- It reaches its verdict from the evidence files alone. Every check in this document is
  computable offline, and none of them modifies a file.

## Where the implementation lives

The bundled implementation of this format is in
[`src/audit/chain.ts`](../src/audit/chain.ts) for canonicalization and record hashing,
[`src/audit/file-sink.ts`](../src/audit/file-sink.ts) for the writer and the per-file chain
walk, [`src/audit/rotation.ts`](../src/audit/rotation.ts) for the manifest,
[`src/audit/signing.ts`](../src/audit/signing.ts) for checkpoints,
[`src/audit/anchor.ts`](../src/audit/anchor.ts) for anchor records and proof persistence, and
[`src/audit/anchor-service.ts`](../src/audit/anchor-service.ts) for the three-layer verify.

Where that code and this document disagree, this document is correct and the code has a bug.
