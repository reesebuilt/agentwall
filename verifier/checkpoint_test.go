package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckpointSignatureVerifies(t *testing.T) {
	k := genKey(t)
	cp := signCheckpoint(t, k, 0, strings.Repeat("ab", 32), "2026-01-01T00:00:00.000Z")
	cf, ok := extractCheckpoint(mustParse(t, cp))
	if !ok {
		t.Fatal("extractCheckpoint failed")
	}
	if !verifyCheckpointSignature(cf) {
		t.Fatal("valid checkpoint signature did not verify")
	}
}

func TestCheckpointSignatureRejectsTamper(t *testing.T) {
	// Flipping a signed field must invalidate the signature: the checkpoint binds chainIndex,
	// hash, and signedAt, so changing any of them breaks it.
	k := genKey(t)
	cp := signCheckpoint(t, k, 0, strings.Repeat("ab", 32), "2026-01-01T00:00:00.000Z")
	tampered := strings.Replace(cp, `"signedAt":"2026-01-01T00:00:00.000Z"`, `"signedAt":"2026-01-02T00:00:00.000Z"`, 1)
	cf, ok := extractCheckpoint(mustParse(t, tampered))
	if !ok {
		t.Fatal("extractCheckpoint failed")
	}
	if verifyCheckpointSignature(cf) {
		t.Fatal("tampered checkpoint signature verified")
	}
}

func TestAnchorDigestRecomputes(t *testing.T) {
	k := genKey(t)
	cp := signCheckpoint(t, k, 0, strings.Repeat("ab", 32), "2026-01-01T00:00:00.000Z")
	d1 := anchorDigestOf(t, cp)
	d2 := anchorDigestOf(t, cp)
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("anchor digest not stable 64-hex: %q %q", d1, d2)
	}
}

// runAnchors verifies the anchors of an evidenceTree, which has no manifest, so heads and
// entryTails are empty and the live tail is re-derived from the live file alone.
func runAnchors(t *testing.T, dir string, pin *pinnedKey) anchorLayerResult {
	t.Helper()
	return verifyAnchors(
		filepath.Join(dir, "anchors.jsonl"),
		filepath.Join(dir, "proofs"),
		dir,
		filepath.Join(dir, "audit.jsonl"),
		nil, nil, pin,
	)
}

func TestVerifyAnchorsPassesValidPendingAnchor(t *testing.T) {
	dir, _ := evidenceTree(t)
	res := runAnchors(t, dir, nil)
	if res.qualifying < 1 {
		t.Fatalf("expected a qualifying anchor, got %d; problems %v", res.qualifying, res.problems)
	}
	if res.pending != 1 {
		t.Fatalf("pending = %d, want 1", res.pending)
	}
	if res.checkpointsChecked != 1 {
		t.Fatalf("checkpointsChecked = %d, want 1", res.checkpointsChecked)
	}
	for _, p := range res.problems {
		if p.fatal {
			t.Fatalf("unexpected fatal problem: %v", res.problems)
		}
	}
}

func TestVerifyAnchorsDigestMismatch(t *testing.T) {
	// Altering the record's digest so it no longer matches the embedded checkpoint is caught,
	// which the bundled TS verifier does not check at all.
	dir, _ := evidenceTree(t)
	anchorsPath := filepath.Join(dir, "anchors.jsonl")
	data := readFileString(t, anchorsPath)
	idx := strings.Index(data, `"digest":"`) + len(`"digest":"`)
	corrupted := data[:idx] + flipHex(data[idx]) + data[idx+1:]
	writeFile(t, anchorsPath, corrupted)
	res := runAnchors(t, dir, nil)
	if !hasCode(res.problems, codeDigestMismatch) {
		t.Fatalf("expected digest-mismatch, got %v", res.problems)
	}
}

func TestVerifyAnchorsBadSignature(t *testing.T) {
	dir, _ := evidenceTree(t)
	anchorsPath := filepath.Join(dir, "anchors.jsonl")
	data := readFileString(t, anchorsPath)
	// Flip a character inside the signature base64. The digest covers the signature too, so this
	// also disturbs the digest; assert specifically that the signature check fails.
	idx := strings.Index(data, `"signature":"`) + len(`"signature":"`)
	flipped := data[:idx] + flipB64(data[idx]) + data[idx+1:]
	writeFile(t, anchorsPath, flipped)
	res := runAnchors(t, dir, nil)
	if !hasCode(res.problems, codeCheckpointBadSig) {
		t.Fatalf("expected checkpoint-bad-signature, got %v", res.problems)
	}
}

func TestVerifyAnchorsPinMatchAndMismatch(t *testing.T) {
	dir, k := evidenceTree(t)

	// Correct pin: qualifies.
	res := runAnchors(t, dir, &pinnedKey{der: k.spkiDER})
	if res.qualifying < 1 || hasCode(res.problems, codeCheckpointKeyMism) {
		t.Fatalf("correct pin should verify: qualifying=%d problems=%v", res.qualifying, res.problems)
	}

	// Wrong pin: the embedded key differs from the pin, so the checkpoint fails key-mismatch even
	// though its own signature is valid. This is the check that makes pinning matter.
	other := genKey(t)
	res = runAnchors(t, dir, &pinnedKey{der: other.spkiDER})
	if !hasCode(res.problems, codeCheckpointKeyMism) {
		t.Fatalf("wrong pin should report checkpoint-key-mismatch, got %v", res.problems)
	}
}

func TestVerifyAnchorsMissingProof(t *testing.T) {
	dir, _ := evidenceTree(t)
	// Delete the proof file so the anchor points at nothing.
	removeGlob(t, filepath.Join(dir, "proofs", "*.ots"))
	res := runAnchors(t, dir, nil)
	if !hasCode(res.problems, codeProofMissing) {
		t.Fatalf("expected proof-missing, got %v", res.problems)
	}
}

func TestVerifyAnchorsNoLog(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "audit.jsonl"), makeRecord(t, `{"n":0}`, 0, "")+"\n")
	res := runAnchors(t, dir, nil)
	if res.qualifying != 0 || res.detail != "nothing anchored off-box yet" {
		t.Fatalf("empty anchor state wrong: qualifying=%d detail=%q", res.qualifying, res.detail)
	}
}

func TestVerifyAnchorsLiveTailMismatch(t *testing.T) {
	// Rewrite the live file after the checkpoint committed to it. The committed tail can no
	// longer be reproduced from any segment prefix, so the anchor is flagged. This is the second
	// hole the independent verifier closes over the format as written.
	dir, _ := evidenceTree(t)
	// Replace the live file with a different but internally valid chain.
	audit := filepath.Join(dir, "audit.jsonl")
	var lines []string
	prev := ""
	for i := range 3 {
		payload := fmt.Sprintf(`{"action":"allow","seq":%d}`, i)
		lines = append(lines, makeRecord(t, payload, int64(i), prev))
		prev = recordHash(t, payload, int64(i), prev)
	}
	writeFile(t, audit, strings.Join(lines, "\n")+"\n")
	res := runAnchors(t, dir, nil)
	if !hasCode(res.problems, codeLiveTailMismatch) {
		t.Fatalf("expected live-tail-mismatch, got %v", res.problems)
	}
}

func TestLoadPinAcceptsBase64AndPEM(t *testing.T) {
	k := genKey(t)
	p1, err := loadPin(k.spkiB64, "")
	if err != nil || p1 == nil {
		t.Fatalf("base64 pin failed: %v", err)
	}
	if string(p1.der) != string(k.spkiDER) {
		t.Fatal("base64 pin decoded to wrong DER")
	}
	// A PEM public key file resolves to the same DER.
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "pub.pem")
	writeFile(t, pemPath, pemPublicKey(k.spkiDER))
	p2, err := loadPin("", pemPath)
	if err != nil || p2 == nil {
		t.Fatalf("pem pin failed: %v", err)
	}
	if string(p2.der) != string(k.spkiDER) {
		t.Fatal("pem pin decoded to wrong DER")
	}
}
