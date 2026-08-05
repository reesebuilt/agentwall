# Verifying AgentWall's evidence

An audit file is worth only as much as your ability to check it without asking us.
Everything here runs locally, needs no account, and uses the same commands used to
develop the tool.

### The bundled verifier

```bash
npm ci && npm run build
node dist/cli.js verify --audit verifier/testdata/corpus/g4-anchored-pending/audit.jsonl
```

```
PASS  chained   24 records across 4 segment(s)
            records link within each segment, so an edit inside one is detectable
PASS  linked    3 segment(s) linked, head 8759f6167246d827
            segments link and match their files, so removing or replacing one is detectable
PASS  anchored  0 confirmed, 1 pending a Bitcoin block
            a fingerprint exists off-box and still matches what is here, so a local rewrite shows

1 anchor(s) pending a Bitcoin block. Pending is not proof;
re-run verify once a block confirms.
```

`verify` reports three layers separately, because they fail independently and one combined verdict
would hide which guarantee you actually have. Exit status is 0 only when all three pass, and
`--json` gives the machine-readable form. Run the same command against corpus case
`b1-decision-flipped`, where one decision is flipped from deny to allow and the record's own hash is
left untouched: the `chained` layer then fails with
`line 2: hash mismatch, record altered after write`, names the file by absolute path, and the
command exits 1.

The `anchored` layer judges an anchor record by its evidence rather than by what the record says
about itself. It recomputes each record's digest from the checkpoint the record embeds
(`digest-mismatch`), requires non-empty proof bytes behind any submission that reached a calendar
(`proof-missing`), and parses that proof against the submitted digest (`proof-parse-error`). A
submission recorded with an error is exempt: it never reached a calendar, so it has no proof to
point at and is already counted as failed.

`anchored` fails until an anchor exists. `agentwall anchor` seals the live segment, signs an
Ed25519 checkpoint over the head, and submits its digest to OpenTimestamps, which needs network
access and no account:

```bash
cp -r verifier/testdata/corpus/g3-rotated-segments /tmp/aw-anchor-demo
node dist/cli.js anchor --audit /tmp/aw-anchor-demo/audit.jsonl
```

```
Anchored
  checkpoint index  3
  checkpoint hash   d8e5eac822f4d723eadc8c9a89c96597e282c22006c1d1d70437bd6a411556c3
  covers            24 records (3 sealed segment(s) + 6 live)
  calendar          https://alice.btc.calendar.opentimestamps.org/digest
  proof             /tmp/aw-anchor-demo/proofs/0475b7690ead3a875eadc85592210df784d775d405f042c9bee10d1dfab6a8bb.ots
  status            pending

OpenTimestamps anchors into a Bitcoin block, so this stays pending for roughly
one to six hours. It is not proof until a block confirms it.
```

The copy exists because anchoring writes a signing key, an anchor log, and a proof file beside the
audit file, and the corpus in git stays exactly as it was generated. The proof filename in your run
differs from the one above: the signing key is created on first use, so your checkpoint is signed
by a key that exists only on your machine.

### The independent verifier, from a bare checkout

Go 1.22 or newer, and nothing else. The Go module lives in `verifier/`, so these commands run from
that directory rather than from the repository root:

```bash
cd verifier
go build -o agentwall-verify .
./agentwall-verify --audit testdata/corpus/g4-anchored-pending/audit.jsonl
```

```
chained  PASS  24 records across 4 segment(s)
linked   PASS  3 segment(s) linked, head 8759f6167246d827...
anchored PASS  0 confirmed, 1 pending a Bitcoin block; pending at https://alice.btc.calendar.opentimestamps.org/timestamp
signatures are self-consistent; supply --pubkey to bind them to a key you expect
overall  PASS
```

`go run . --audit <path>` runs it without producing a binary, and prints one line of its own,
`exit status 1`, when the verifier exits nonzero.

Zero dependencies is a property you check rather than a claim you accept:

```bash
go list -m all
```

```
github.com/repsecure/agentwall/verifier
```

One line, and it is this module. SHA-256, Ed25519, SPKI parsing, and JSON all come from the Go
standard library, which is why the verifier is written in Go: a program whose whole job is being
trustworthy should not ask you to trust a supply chain first.

### Pin the key, or a checkpoint signature is decoration

This is the honest core of the anchored layer. Corpus case `b8-checkpoint-foreign-key` is the good
case with its checkpoint re-signed by a different key, and it is internally consistent: the
signature verifies against the public key the checkpoint carries. Unpinned, it passes.

```bash
./agentwall-verify --audit testdata/corpus/b8-checkpoint-foreign-key/audit.jsonl; echo "exit $?"
```

```
chained  PASS  24 records across 4 segment(s)
linked   PASS  3 segment(s) linked, head 8759f6167246d827...
anchored PASS  0 confirmed, 1 pending a Bitcoin block; pending at https://alice.btc.calendar.opentimestamps.org/timestamp
signatures are self-consistent; supply --pubkey to bind them to a key you expect
overall  PASS
exit 0
```

The line above the verdict is the verifier naming what it did not check. A self-signed checkpoint
proves nothing until you pin the key, because anyone who can rewrite the log can sign the rewrite
with a key they generated. Pin the key you expect and the same bytes fail:

```bash
./agentwall-verify --audit testdata/corpus/b8-checkpoint-foreign-key/audit.jsonl \
                   --pubkey-file testdata/corpus/b8-checkpoint-foreign-key/pubkey.txt; echo "exit $?"
```

```
chained  PASS  24 records across 4 segment(s)
linked   PASS  3 segment(s) linked, head 8759f6167246d827...
anchored FAIL  0 confirmed, 1 pending a Bitcoin block; pending at https://alice.btc.calendar.opentimestamps.org/timestamp
    - checkpoint-key-mismatch: anchor 1: checkpoint public key does not match the pinned key
overall  FAIL
exit 1
```

The pin discriminates rather than refusing everything. The same pin against the honest case passes,
because every checkpoint in the corpus except `b8`'s is signed by the key `pubkey.txt` names:

```bash
./agentwall-verify --audit testdata/corpus/g4-anchored-pending/audit.jsonl \
                   --pubkey-file testdata/corpus/b8-checkpoint-foreign-key/pubkey.txt; echo "exit $?"
```

```
chained  PASS  24 records across 4 segment(s)
linked   PASS  3 segment(s) linked, head 8759f6167246d827...
anchored PASS  0 confirmed, 1 pending a Bitcoin block; pending at https://alice.btc.calendar.opentimestamps.org/timestamp
overall  PASS
exit 0
```

`--pubkey <base64-spki>` takes the key inline, `--pubkey-file <path>` reads base64 or PEM. The pin
is worth what its source is worth: a key you recorded elsewhere when it was created is worth more
than one read out of the directory that holds the evidence. The bundled verifier has no pin flag.
It compares each checkpoint against the public half of the signing key file beside the audit log
([`src/audit/anchor-service.ts:421-433`](../src/audit/anchor-service.ts)), which is the writer's own
key rather than one you chose.

### The conformance corpus

`verifier/testdata/corpus/` holds one directory per case, each with an `expected.json` naming the
exit code and the three layer verdicts the format requires. Good cases are written by the
production writers in `src/audit`, so the corpus cannot drift into a private idea of the format.
Forgeries are byte edits applied on top of a case that passed, and they are internally consistent
on purpose, so catching one takes a property the forger cannot recompute:

- `b2-record-removed-tail-relinked` removes a record, then relinks and rehashes the entire tail.
  Every `previousHash` in the file is correct. The chain index sequence is what exposes it.
- `b15-sealed-segment-rewritten` rewrites a sealed segment end to end and relinks it internally.
  The manifest entry bound to that segment's bytes is what exposes it.
- `b16-live-tail-rewritten-after-checkpoint` rewrites the last live record after the checkpoint was
  signed. The live tail that checkpoint committed to is what exposes it, and re-committing to the
  rewrite needs the signing key.
- `b8-checkpoint-foreign-key` re-signs the checkpoint consistently under another key. Only a pin
  supplied from outside the evidence exposes it.
- `b17-sealed-segment-missing` deletes a sealed segment file and leaves the manifest naming it. Both
  verifiers report `segment-missing` on the `linked` layer, which is the layer that made the claim.
- `b4-index-reuse-concurrent-writers` appends a second writer's records under indexes already used.
  Both verifiers fail the `chained` layer with an index gap and a broken link, and the message names
  a gap, restart, or reused index, because that shape is what two processes appending to one chain
  look like rather than one altered record. The single-writer lock exists to prevent it.

Two limit cases pin what the format does not bind, so neither limit can be quietly forgotten.
`l1-confirmed-with-pending-proof` passes: an anchor claiming `confirmed` whose proof carries only a
pending attestation is accepted, because nothing compares the status claim against the attestations
in the proof. `l2-legacy-canon-unmarked` fails with `hash-mismatch-or-legacy-canon`, because records
hashed under the pre-marker key order cannot be recomputed by a verifier that does not carry ICU
collation tables, and reporting them as unverifiable is a different statement from reporting them as
tampered.

Run both verifiers over every case:

```bash
npm run build
cd verifier && go build -o agentwall-verify . && cd ..
node scripts/conformance.js
```

The run prints one line per case. Its tail:

```
ok         b9-anchor-digest-altered  exit=1 chained=true linked=true anchored=false
ok         b10-proof-truncated  exit=1 chained=true linked=true anchored=false
ok         b11-torn-tail  exit=1 chained=true linked=true anchored=false
ok         b12-duplicate-key-shadowed  exit=1 chained=false linked=true anchored=false
ok         b13-confirmed-without-proof  exit=1 chained=true linked=true anchored=false
ok         b14-submission-never-reached-calendar  exit=1 chained=true linked=true anchored=false
ok         b15-sealed-segment-rewritten  exit=1 chained=true linked=false anchored=true
ok         b16-live-tail-rewritten-after-checkpoint  exit=1 chained=true linked=true anchored=false
ok         b17-sealed-segment-missing  exit=1 chained=true linked=false anchored=true
ok         l1-confirmed-with-pending-proof  exit=0 chained=true linked=true anchored=true
ok         l2-legacy-canon-unmarked  exit=1 chained=false linked=true anchored=false

26 cases, typescript and go: 26 agreed, 0 declared divergence(s), 0 failure(s)
```

Each case is copied to a temp directory before it runs, so a verifier cannot alter what it checks.
Regeneration is deterministic, which is what makes an unexpected diff mean something:

```bash
npm run gen:corpus && git status --porcelain verifier/testdata
```

That prints nothing, because the regenerated tree is byte identical to the committed one.

Both verifiers return the same verdict on every case, which is why the summary declares no
divergences. That is agreement across the 26 cases the corpus contains, not a proof that the two
implementations are equivalent: a forgery nobody has written a case for has been put to neither of
them. The harness fails the run if they ever stop agreeing on a case it does contain
([`scripts/conformance.js:40-50`](../scripts/conformance.js)).

### What verification does not prove

- **Completeness.** An anchor shows that what was written was not altered afterwards. It cannot
  show that everything which should have been written was. A decision that was never recorded
  leaves nothing to detect, and no verifier finds it.
- **A correct specification.** Two readers of the same wrong document agree with each other and are
  both wrong, so independence catches implementation bugs and shared runtime assumptions, not a
  format mistake. The document is [docs/audit-format.md](audit-format.md), which is why it is
  written at the byte level and kept short enough to read in one sitting.
- **Inclusion in a Bitcoin block, while an anchor is pending.** Pending means a calendar accepted a
  submission. Both verifiers report pending as pending, and the Go verifier reports a Bitcoin
  attestation as a block height plus the derived value for you to compare against that block's
  merkle root, which it does not fetch.

To run the tests behind the claims in this file:

```bash
npx jest tests/audit-chain.test.ts tests/audit-signing.test.ts tests/audit-anchor.test.ts \
         tests/operator-auth.test.ts tests/route-auth.test.ts tests/ssrf.test.ts tests/policy.test.ts
npm run lint     # tsc --noEmit
npm test         # full suite
cd verifier && go test ./...
```
