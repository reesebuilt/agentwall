# agentwall-verify (Rust)

A third independent verifier for AgentWall audit evidence, written in Rust with no dependencies
at all and no `unsafe`.

## Why a third one

The bundled TypeScript verifier and the Go verifier already agree on the 26 corpus cases. Two
implementations agreeing is evidence about the format only if they were written independently,
and the more implementations that agree, the harder it is for a shared misreading to hide in the
gap between the document and the code.

This one was written from `docs/audit-format.md` alone. `verifier/*.go` and `src/audit/*.ts` were
deliberately not read while it was built, except for the CLI flag surface and the JSON output
shape in `verifier/main.go` and `verifier/report.go`, which exist so one harness can drive every
implementation with the same arguments. Porting the Go verifier would have produced a translation,
and a harness comparing a program with its own translation measures nothing.

Two consequences worth naming:

- The problem codes here are not the Go verifier's codes. The format says diagnostic names are
  "that implementation's interface, not part of this format", so matching them would have been a
  cosmetic hint of a shared lineage that does not exist. What the harness compares is the verdict
  and the three anchor counters, which are contract.
- The gaps this reading found in the normative document are recorded below, because a place where
  two honest implementers could differ is a latent divergence whether or not anyone has hit it.

## Zero dependencies is a property you check, not a claim you accept

```
cd verifier-rs && cargo tree
agentwall-verify-rs v0.2.0
```

One line, and it is this crate. SHA-256, SHA-512, SHA-1, RIPEMD-160, Keccak-256, Ed25519
verification, base64, and the JSON reader are all in `src/`. Nothing is shared with the Go or
TypeScript verifiers, so a bug in one cannot be a bug in all three by inheritance.

Writing your own cryptography is normally a mistake, so each primitive is held against published
vectors rather than trusted:

- SHA-256 and SHA-512 against the FIPS 180-4 examples, and SHA-256 additionally against the
  worked example in `docs/audit-format.md`.
- SHA-1 and RIPEMD-160 against their published test suites, cross-checked against OpenSSL.
- Ed25519 against the RFC 8032 section 7.1 vectors, and against the real signature the format
  document carries in "Worked example: a checkpoint".
- Keccak-256 against the published Ethereum values. No published Keccak-256 vector longer than
  one rate block was available, so the same sponge is also run with SHA3 padding and checked
  against SHA3-256 values from Python's `hashlib`, which covers the permutation, the rate and the
  absorb loop with an implementation nobody here wrote. The Keccak vectors then pin the one byte
  SHA3 cannot, the padding constant.

`cargo test` runs all of that plus the 26 corpus cases in process.

## Usage

```
cargo build --release
./target/release/agentwall-verify --audit /path/to/audit.jsonl
```

Flags match the Go verifier: `--audit`, `--manifest`, `--anchors`, `--proofs`, `--pubkey`,
`--pubkey-file`, `--json`, `--version`. Exit 0 when every layer passes, 1 when any layer fails,
2 for a usage or IO error, which is not a verdict about evidence.

`--pubkey` matters more than it looks. Without a pin, a checkpoint signature is checked against
the key the checkpoint itself carries, which proves internal consistency and nothing about who
signed. The tool says so on every unpinned run rather than leaving an operator to infer it.

## Conformance

`scripts/conformance.js` drives this binary alongside the TypeScript, Go and Python verifiers over
the corpus and fails the run when any two disagree without a declared divergence, and again when a
declared divergence stops happening. Set `CONFORMANCE_VERIFIER_RS` to point at a binary elsewhere,
or `CONFORMANCE_SKIP_RS=1` to leave Rust out on a machine with no Rust toolchain.

Note that a toolchain is a real prerequisite: this crate pins Rust 1.90.0 in `rust-toolchain.toml`
and there is no vendored binary, so a machine without rustup needs one before the Rust
implementation can take part.

## Where this reading of the format had to make a choice

`docs/audit-format.md` is normative, and these are places it does not settle the answer. Each is
resolved here as described, with the reasoning; all four currently agree with the other
implementations, so none is a live divergence. They are written down because agreement that is
not compelled by the document is agreement that can silently end.

1. **An absent anchor log.** The document never states what `anchored` reports when there is no
   anchor at all. Resolved as a failure: the layer's evidence is "Signed checkpoint plus an
   off-box timestamp", and with neither on disk the layer's question has no answer. Note this is
   deliberately not symmetric with an empty rotation manifest, which is treated as a vacuous
   pass, because "was a whole rotated file removed" really is answerable as no when there are no
   rotated files, while "was the entire local history rewritten" is not answerable from local
   files alone. Six corpus cases pin the first reading and four pin the second, so the fixtures
   forbid the symmetric answer even though the prose does not.

2. **A rotated file on disk that no manifest entry vouches for.** The document says such a file
   "sits outside the anchor and is reported", where it says "is a failure" elsewhere when it
   means fatal. Resolved as a non-fatal report, because the checkpoint section names "closed
   segments still awaiting a seal" as an eligible source for a committed live tail, which makes
   that state a normal moment between a rotation and its seal. Failing the layer for it would cry
   wolf on a healthy deployment, which is the same reasoning the format uses to keep a torn tail
   non-fatal. No corpus case exercises this.

3. **Stored against recomputed hash in the live-tail rebuild.** The document says each prefix
   "offers the pair (that record's `integrity.hash`, `c`)", which names the stored member.
   Resolved as the stored value. Using the recomputed one would make `anchored` fail for a reason
   `chained` already owns, and the document is explicit that which layer owns a condition is part
   of the contract. The honest cost is that an attacker who rewrites a record's content and leaves
   its `integrity.hash` alone satisfies this layer; `chained` reports that loudly at the record
   they touched, which is corpus case b1.

4. **What the pending, confirmed and failed counters count.** The document defines them in the
   anchor-log section, gives exactly one override ("`error` set ... counts as failed whatever its
   `status` says"), and the conformance checklist enumerates that one override alone. Resolved as
   `status` with `error` as the sole override. The alternative, deriving the counters from the
   attestation the proof reaches, makes `confirmed` unreachable on every possible input, because
   the document also forbids reporting a Bitcoin attestation as a completed check offline. Every
   attestation actually reached is reported beside the counts, so a reader who sees
   `confirmed: 1` sees, next to it, exactly what the proof does and does not establish.

Two smaller ones, both unexercised by the corpus: a record whose `integrity.canon` is present but
is not `cu1` is treated as having no defined derivation and fails, and an anchor whose `status` is
absent or is neither `pending` nor `confirmed` is counted failed and reported, since the format
enumerates two values and requires each record to land in exactly one of three counters. A record
whose `integrity.status` is not `chained-local` is NOT treated as a failure, because the format
says that member "is not a verification result, and a verifier MUST NOT treat it as one".
