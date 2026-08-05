# agentwall-verify

An independent verifier for AgentWall audit evidence, written in Go with nothing beyond the
standard library.

## What it verifies

The tool reports three layers separately and never collapses them into one verdict, because each
proves a different thing:

- `chained`: every record's hash recomputes from its own bytes and links to the record before it,
  so an edit inside a segment is detectable.
- `linked`: the rotation manifest ties each sealed segment to the previous one, and each entry is
  bound to the actual bytes of the segment file it names, so removing or rewriting a whole segment
  is detectable.
- `anchored`: an off-box OpenTimestamps submission exists, its checkpoint signature verifies, its
  digest matches the checkpoint it anchored, and the checkpoint's committed live tail still
  reproduces from the files on disk, so rewriting everything locally is detectable.

A pending anchor is reported as pending, never as proof. A Bitcoin attestation is reported with
its block height and the derived value, alongside the statement that confirming inclusion needs a
Bitcoin block source this offline tool does not fetch.

## What independence means here

This verifier shares no code with the bundled TypeScript verifier. That matters because the bundled
one recomputes each record's hash by calling `chainAuditEvent`, the same function in
`src/audit/chain.ts` that wrote the hash: it is a useful tamper check, and a verifier that calls the
writer's own code proves only that the code agrees with itself. This program is a different language
with a different JSON parser and a different cryptography stack, and it implements
`docs/audit-format.md` rather than importing anything from `src/`. The format document is the only
thing the two programs have in common, so when both accept a file, the agreement is evidence about
the FORMAT.

Zero third party dependencies is a property you check rather than a claim you accept:

    cd verifier && go list -m all
    github.com/reesebuilt/agentwall/verifier

One line, and it is this module. SHA-256, Ed25519, SPKI parsing, and JSON all come from the Go
standard library, maintained by the Go security team, so a reader auditing this verifier reads this
directory and stops.

## What independence does not mean

A bug in the format specification is shared by both implementations by construction: two readers of
the same wrong spec agree with each other and are both wrong. Independence guards against
implementation bugs and shared runtime assumptions, not against a specification mistake. The
specification is `docs/audit-format.md`, and it is short enough to read.

## How to run

The Go module lives in `verifier/`, so the go commands run from that directory rather than from the
repository root. Built and tested with Go 1.22:

    cd verifier
    go build -o agentwall-verify .
    ./agentwall-verify --audit testdata/corpus/g4-anchored-pending/audit.jsonl

    chained  PASS  24 records across 4 segment(s)
    linked   PASS  3 segment(s) linked, head 8759f6167246d827...
    anchored PASS  0 confirmed, 1 pending a Bitcoin block; pending at https://alice.btc.calendar.opentimestamps.org/timestamp
    signatures are self-consistent; supply --pubkey to bind them to a key you expect
    overall  PASS

`go run . --audit <path>` runs it without producing a binary, and prints one line of its own,
`exit status 1`, when the verifier exits nonzero.

    agentwall-verify --audit <path> [--manifest <path>] [--anchors <path>] [--proofs <dir>]
                     [--pubkey <base64-spki> | --pubkey-file <path>] [--json] [--version]

The manifest, anchor log, and proofs directory default to `segments.jsonl`, `anchors.jsonl`, and
`proofs/` beside the audit file. The tool reads no environment variables, performs no network IO,
and never writes a file.

## Pinning a key

Without a pin, checkpoint signatures are verified against the key embedded in each checkpoint, which
proves only that the record is self-consistent, and the tool says so in that case.
`testdata/corpus/b8-checkpoint-foreign-key` is the good case with its checkpoint re-signed by
another key, and the forgery is internally consistent: the signature verifies against the public key
the checkpoint carries. Unpinned, it passes.

    ./agentwall-verify --audit testdata/corpus/b8-checkpoint-foreign-key/audit.jsonl; echo "exit $?"

    chained  PASS  24 records across 4 segment(s)
    linked   PASS  3 segment(s) linked, head 8759f6167246d827...
    anchored PASS  0 confirmed, 1 pending a Bitcoin block; pending at https://alice.btc.calendar.opentimestamps.org/timestamp
    signatures are self-consistent; supply --pubkey to bind them to a key you expect
    overall  PASS
    exit 0

Pass `--pubkey` (base64 SPKI) or `--pubkey-file` (a base64 SPKI or PEM file) to bind the checkpoints
to a key you expect, and the same bytes fail:

    ./agentwall-verify --audit testdata/corpus/b8-checkpoint-foreign-key/audit.jsonl \
                       --pubkey-file testdata/corpus/b8-checkpoint-foreign-key/pubkey.txt; echo "exit $?"

    chained  PASS  24 records across 4 segment(s)
    linked   PASS  3 segment(s) linked, head 8759f6167246d827...
    anchored FAIL  0 confirmed, 1 pending a Bitcoin block; pending at https://alice.btc.calendar.opentimestamps.org/timestamp
        - checkpoint-key-mismatch: anchor 1: checkpoint public key does not match the pinned key
    overall  FAIL
    exit 1

The pin discriminates rather than refusing everything. The same pin over the honest case passes,
because every checkpoint in the corpus except this case's is signed by the key `pubkey.txt` names:

    ./agentwall-verify --audit testdata/corpus/g4-anchored-pending/audit.jsonl \
                       --pubkey-file testdata/corpus/b8-checkpoint-foreign-key/pubkey.txt; echo "exit $?"

    chained  PASS  24 records across 4 segment(s)
    linked   PASS  3 segment(s) linked, head 8759f6167246d827...
    anchored PASS  0 confirmed, 1 pending a Bitcoin block; pending at https://alice.btc.calendar.opentimestamps.org/timestamp
    overall  PASS
    exit 0

A pin read out of the directory that holds the evidence is worth less than one recorded elsewhere
when the key was created, because whoever can rewrite the log can rewrite a key file sitting beside
it. A self-signed checkpoint proves nothing until the key is pinned to something the writer does not
control.

## Conformance corpus

`testdata/corpus/` holds one directory per case, each with an `expected.json` naming the exit code
and the three layer verdicts the format requires. Good cases are written by the production writers
in `src/audit`, so the corpus cannot drift into a private idea of the format. Forgeries are byte
edits on top of a case that passed, and they are internally consistent on purpose, so catching one
takes a property the forger cannot recompute: a relinked and rehashed tail is exposed by the chain
index sequence, a rewritten sealed segment by the manifest entry bound to that segment's bytes, a
sealed segment deleted from disk by the manifest entry that still names it, a live file rewritten
after signing by the live tail the checkpoint committed to, and a re-signed checkpoint only by a
pinned key.

`scripts/conformance.js` runs both verifiers over every case, compares each against `expected.json`
and against the other, and copies each case to a temp directory first so a verifier cannot alter what
it checks. From the repository root:

    npm run build
    cd verifier && go build -o agentwall-verify . && cd ..
    node scripts/conformance.js

    26 cases, typescript and go: 26 agreed, 0 declared divergence(s), 0 failure(s)

`go test ./...` in this directory runs the unit tests plus a corpus walk that asserts every case's
`expected.json` against this verifier alone.

## Where the two verifiers stand

Both verifiers return the same verdict on every case in the corpus, and the harness declares no
divergences. That is agreement about the 26 cases the corpus contains, not a proof that the two
implementations are equivalent: a forgery nobody has written a case for has been put to neither of
them. The harness fails the run if they ever stop agreeing on a case it does contain.

On the `anchored` layer the bundled verifier recomputes each anchor record's digest from the
embedded checkpoint, requires non-empty proof bytes behind any submission that reached a calendar,
and parses the proof against the submitted digest under the same caps as this one, so
`digest-mismatch`, `proof-missing`, and `proof-parse-error` are reported by both. On the `chained`
layer both report a partial final line as `torn-tail` rather than as a broken chain, because a hard
kill mid-append leaves exactly one and calling it tampering would cry wolf.

## Exit codes

- `0`: all three layers verified.
- `1`: a verification failure or incomplete evidence, including a chain that is internally
  consistent but has no off-box anchor.
- `2`: a usage or IO error, such as a missing `--audit` argument or an unreadable file.

## Problem codes

Problem codes are stable and machine readable and appear in the JSON output only. The problem
prose beside a code is not part of any contract. The codes are: `bad-json`, `dup-key`,
`torn-tail`, `missing-integrity`, `index-gap`, `link-break`, `hash-mismatch`,
`hash-mismatch-or-legacy-canon`, `manifest-entry-hash`, `manifest-link-break`, `segment-missing`,
`segment-content-mismatch`, `segment-unsealed`, `checkpoint-bad-signature`,
`checkpoint-key-mismatch`, `digest-mismatch`, `proof-missing`, `proof-parse-error`,
`live-tail-mismatch`, and `anchor-failed`.

## Limits

- Verification shows that records were not altered after they were written. It cannot show that the
  log is complete: a decision that was never recorded leaves nothing here to detect, and no
  property of the format can recover it.
- It does not fetch a Bitcoin block, so a Bitcoin attestation is reported with its derived value
  for a caller to compare against a block merkle root, not confirmed here.
- A pending attestation is a submission to a calendar, not proof of inclusion, and is reported as
  pending.
- It implements the `cu1` canonical form only. A record hashed under the earlier locale collated
  key order carries no `cu1` marker and is reported as `hash-mismatch-or-legacy-canon`, because an
  independent verifier cannot reproduce ICU collation and cannot tell a legacy record from an
  altered one.
- It evaluates SHA-1 and SHA-256 operations in OpenTimestamps proofs. A proof branch that requires
  RIPEMD-160 or Keccak-256 is reported as `proof-parse-error`, because implementing an unreviewed
  hash primitive inside a tool whose value is being trustworthy is a worse trade than declining.
- The OpenTimestamps parser enforces a per argument size cap, a total size cap, a depth cap, an
  operation cap, and a working message cap, because the proof file is attacker influenced by
  definition and a verifier that its own input can exhaust is itself an attack surface.
- The live tail search reads the record hashes of the local evidence into memory. It is linear in
  the size of the local files the operator points the tool at, not in an attacker controlled single
  blob, so it is intentionally uncapped: a cap would report tampering on a large honest deployment.
