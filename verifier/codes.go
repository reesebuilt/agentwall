package main

// Stable problem codes. These are the machine-readable half of the report contract: a caller
// may match on a code, so the strings never change meaning once shipped. The human text beside
// a code may change freely because it carries no contract.
const (
	codeBadJSON              = "bad-json"
	codeDupKey               = "dup-key"
	codeTornTail             = "torn-tail"
	codeMissingIntegrity     = "missing-integrity"
	codeIndexGap             = "index-gap"
	codeLinkBreak            = "link-break"
	codeHashMismatch         = "hash-mismatch"
	codeHashMismatchOrLegacy = "hash-mismatch-or-legacy-canon"
	codeManifestEntryHash    = "manifest-entry-hash"
	codeManifestLinkBreak    = "manifest-link-break"
	codeSegmentMissing       = "segment-missing"
	codeCheckpointBadSig     = "checkpoint-bad-signature"
	codeCheckpointKeyMism    = "checkpoint-key-mismatch"
	codeDigestMismatch       = "digest-mismatch"
	codeProofMissing         = "proof-missing"
	codeProofParseError      = "proof-parse-error"
	codeAnchorFailed         = "anchor-failed"
	// codeSegmentUnsealed reports rotated segment files present on disk but never sealed into
	// the manifest. The honesty semantics require this to be a real failure (evidence that
	// sits outside the anchor), yet the section 4 code list has no entry for it, so this code
	// fills that gap. It is flagged in the step report as a spec omission.
	codeSegmentUnsealed = "segment-unsealed"
	// codeSegmentContentMismatch reports a sealed segment whose bytes no longer match the
	// manifest entry that names it: its actual last-record hash, record count, or index range
	// differs from what the anchored manifest committed. Without this check the off-box anchor
	// binds the manifest and the manifest binds only itself, so a whole segment can be rewritten
	// (relinked internally so its own chain still verifies) and go undetected. The format spec as
	// written omits this binding; this verifier performs it because an anchor that proves nothing
	// about segment contents is not the guarantee the layers claim.
	codeSegmentContentMismatch = "segment-content-mismatch"
	// codeLiveTailMismatch reports a checkpoint whose committed live tail (final hash and record
	// count) cannot be reproduced from the live file. The checkpoint commits to the live tail
	// inside its composite hash; if the committed prefix of the live file was rewritten after
	// signing, the thing anchored no longer describes the evidence. Growth of the live file after
	// signing is expected and is not a mismatch: the committed prefix is searched for within the
	// current file.
	codeLiveTailMismatch = "live-tail-mismatch"
)
