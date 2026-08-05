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

This verifier shares no code with the bundled TypeScript verifier. It is a different language with
a different JSON parser and a different cryptography stack, and it has zero third party
dependencies:

    cd verifier && go list -m all
    github.com/reesebuilt/agentwall/verifier

Because the two implementations share no runtime, agreement between them is evidence about the
format rather than about a shared library. That agreement is checked against a corpus of
deliberate forgeries, where each side must independently reject the same tampering.

## What independence does not mean

A bug in the format specification is shared by both implementations by construction: two readers of
the same wrong spec agree with each other and are both wrong. Independence guards against
implementation bugs and shared runtime assumptions, not against a specification mistake. The
specification is `docs/audit-format.md`, and it is short enough to read.

## How to run

From a checkout with the Go toolchain installed:

    go run ./verifier --audit path/to/audit.jsonl
    go build -o agentwall-verify ./verifier && ./agentwall-verify --audit path/to/audit.jsonl

A release also ships a static binary that runs with no toolchain.

    agentwall-verify --audit <path> [--manifest <path>] [--anchors <path>] [--proofs <dir>]
                     [--pubkey <base64-spki> | --pubkey-file <path>] [--json] [--version]

The manifest, anchor log, and proofs directory default to `segments.jsonl`, `anchors.jsonl`, and
`proofs/` beside the audit file. The tool reads no environment variables, performs no network IO,
and never writes a file.

## Pinning a key

Without a pin, checkpoint signatures are verified against the key embedded in each checkpoint,
which only proves the record is self-consistent: a forger can sign with their own key. The tool
says so in that case. Pass `--pubkey` (base64 SPKI) or `--pubkey-file` (a base64 SPKI or PEM file)
to bind the checkpoints to a key you expect; a checkpoint carrying any other key then fails with
`checkpoint-key-mismatch`.

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
