# agentwall-verify-py

A fourth independent verifier for the AgentWall audit evidence format, in Python.

It was written from [`docs/audit-format.md`](../docs/audit-format.md) and nothing else. It
shares no code with the bundled TypeScript verifier, the Go verifier in [`verifier/`](../verifier),
or the Rust verifier in [`verifier-rs/`](../verifier-rs). That is the entire point: four
implementations agreeing about a forgery is evidence about the FORMAT, while a port of one
implementation into another language is evidence about the port.

## Why there are no dependencies, and why that is load-bearing

The standard library has no Ed25519. The obvious fix is `pip install cryptography`, and it is
the wrong one here.

`cryptography` calls OpenSSL. Node calls OpenSSL. So a Python verifier built that way and the
bundled TypeScript verifier would not be two independent checks of a signature; they would be
two bindings to one check. They would share every OpenSSL bug, agree on a forged signature
with total confidence, and the conformance harness would print a green row saying so. The
agreement is worth exactly as much as the independence underneath it.

So [`ed25519.py`](agentwall_verify/ed25519.py) implements RFC 8032 verification directly, in
about a hundred lines, borrowing only SHA-512 from `hashlib`. Verification is public work on
public bytes, so the absence of constant-time arithmetic is not a weakness: there is no secret
to leak, and correctness is the whole requirement.

The same reasoning covers two hash operations the OpenTimestamps grammar names.
[`hashes.py`](agentwall_verify/hashes.py) implements keccak256, which `hashlib` does not have
at all because `sha3_256` is the padded FIPS variant and gives a different digest, and
RIPEMD-160, which `hashlib` only has when the local OpenSSL build still enables its legacy
provider. Leaving either to the environment would make a verdict about evidence depend on how
somebody compiled Python.

**If you are about to simplify this by adding a dependency, that is the property you would be
deleting.**

## Running it

No install step. From a checkout:

    python3 verifier-py/agentwall-verify-py --audit /path/to/audit.jsonl

Or as an installed package:

    pip install ./verifier-py
    agentwall-verify-py --audit /path/to/audit.jsonl

Flags, matching the Go verifier so one harness drives both:

    --audit <path>              the audit JSONL file (required)
    --manifest <path>           rotation manifest (default segments.jsonl beside audit)
    --anchors <path>            anchor log (default anchors.jsonl beside audit)
    --proofs <dir>              OTS proof directory (default proofs/ beside audit)
    --pubkey <base64-spki>      pin checkpoints to a key
    --pubkey-file <path>        pin checkpoints to a key read from a file
    --json                      machine-readable report
    --version

Exit codes: 0 all layers verified, 1 verification failure or incomplete evidence, 2 usage or
IO error.

It reads no environment, performs no network IO, and never writes a file.

## What it reports

Three layers, separately, because they answer different questions and fail independently:

| Layer | Question |
| --- | --- |
| `chained` | Was a record altered after it was written? |
| `linked` | Was a whole rotated file removed, reordered, or replaced? |
| `anchored` | Was the entire local history rewritten? |

Plus the three anchor counts, and the attestations each proof actually reaches. That last part
is not decoration. The counters report the backend state each anchor record claims about
itself, so a reader who saw only `confirmed: 1` could reasonably think a Bitcoin block had been
checked. The attestation list says what the proof reaches: a calendar for a pending
attestation, or a value and a block height still to be compared against a Bitcoin source.

## What it does not prove

Everything in
[What this format does not prove](../docs/audit-format.md#what-this-format-does-not-prove)
applies here unchanged. In particular this verifier cannot tell you the log is complete, and it
cannot confirm a Bitcoin attestation, because that needs a block source and this reads local
files only.

## Tests

    cd verifier-py && python3 -m pytest

The suite is anchored to the document rather than to this implementation. The cu1 vectors, the
manifest entry hash, the checkpoint composite, the signed bytes, the submitted digest, and all
three OpenTimestamps proofs are the worked examples from `docs/audit-format.md`, copied
verbatim including their hashes. The Ed25519 vectors are from RFC 8032 section 7.1, and the
keccak256 and RIPEMD-160 vectors are the published ones. A test that only agreed with this code
would be worth nothing here.

`tests/test_cli.py` also runs all 27 corpus cases end to end against their `expected.json`.

Exercised on CPython 3.11 and 3.12. The 3.9 floor in `pyproject.toml` is what the syntax
requires, not a version this has been run against.

## Conformance

    node scripts/conformance.js

drives all four implementations over the corpus and compares each one against the format's
`expected.json`, never against a majority. A disagreement fails the run unless it is declared
in that file's `DIVERGENCES` table with a written reason, and a declaration that stops
reproducing fails the run as stale.

The Rust verifier needs a Cargo toolchain to build, which is not installed system wide on every
machine. `CONFORMANCE_SKIP_RS=1` leaves it out; `CONFORMANCE_SKIP_GO=1` and
`CONFORMANCE_SKIP_PY=1` do the same for the others. A binary that is missing and not explicitly
skipped is a hard failure, so nobody gets a green run by not building.
