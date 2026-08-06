"""Stable names for the conditions this verifier reports.

The format is explicit that diagnostic names are an implementation's own
interface and not part of the contract: two conforming verifiers agree on the
verdict and may describe it in different words. These names exist so an
operator can grep a report and so this verifier's own tests can assert on
something, not so another implementation can be graded against them.
"""

from __future__ import annotations


class Problem:
    """One finding, with whether it sinks the layer that owns it."""

    __slots__ = ("code", "text", "fatal")

    def __init__(self, code: str, text: str, fatal: bool = True) -> None:
        self.code = code
        self.text = text
        self.fatal = fatal

    def __str__(self) -> str:
        return self.code + ": " + self.text


# chained
PARSE_ERROR = "parse-error"
TORN_TAIL = "torn-tail"
DUP_KEY = "dup-key"
MISSING_INTEGRITY = "missing-integrity"
MALFORMED_INTEGRITY = "malformed-integrity"
UNSUPPORTED_ALGORITHM = "unsupported-algorithm"
UNKNOWN_CANON = "unknown-canon"
HASH_MISMATCH = "hash-mismatch"
HASH_MISMATCH_OR_LEGACY = "hash-mismatch-or-legacy-canon"
INDEX_GAP = "index-gap"
INDEX_REUSE = "index-reuse"
LINK_BREAK = "link-break"
CHAIN_GAP_DECLARED = "chain-gap-declared"

# linked
MANIFEST_PARSE_ERROR = "manifest-parse-error"
MANIFEST_ENTRY_MALFORMED = "manifest-entry-malformed"
MANIFEST_ENTRY_HASH = "manifest-entry-hash"
MANIFEST_LINK_BREAK = "manifest-link-break"
SEGMENT_MISSING = "segment-missing"
SEGMENT_CONTENT_MISMATCH = "segment-content-mismatch"
SEGMENT_UNSEALED = "segment-unsealed"

# anchored
ANCHOR_LOG_MISSING = "anchor-log-missing"
NO_ANCHORS = "no-anchors"
ANCHOR_PARSE_ERROR = "anchor-parse-error"
ANCHOR_MALFORMED = "anchor-malformed"
ANCHOR_FAILED = "anchor-failed"
DIGEST_MISMATCH = "digest-mismatch"
CHECKPOINT_MALFORMED = "checkpoint-malformed"
CHECKPOINT_BAD_SIGNATURE = "checkpoint-bad-signature"
CHECKPOINT_KEY_MISMATCH = "checkpoint-key-mismatch"
MANIFEST_TOO_SHORT = "manifest-too-short"
LIVE_TAIL_MISMATCH = "live-tail-mismatch"
PROOF_MISSING = "proof-missing"
PROOF_PARSE_ERROR = "proof-parse-error"
PROOF_NO_ATTESTATION = "proof-no-attestation"
