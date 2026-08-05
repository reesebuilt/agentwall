package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// makeRecord builds a valid cu1 audit record line for the given payload, chain index, and
// previous hash. It computes the hash through the production canon and hashMaterial, which the
// canon tests have already pinned to spec-derived literals, so a fixture built here is a genuine
// cu1 record and not a restatement of the walker's own logic.
func makeRecord(t *testing.T, payload string, idx int64, prev string) string {
	t.Helper()
	c := canon(nil, mustParse(t, payload))
	var prevLex []byte
	var prevField string
	if prev == "" {
		prevLex = []byte("null")
		prevField = "null"
	} else {
		prevLex = []byte(`"` + prev + `"`)
		prevField = `"` + prev + `"`
	}
	h := sha256Hex(hashMaterial(strconv.FormatInt(idx, 10), prevLex, c))
	integ := fmt.Sprintf(`"integrity":{"chainIndex":%d,"hash":"%s","previousHash":%s,"algorithm":"sha256","status":"chained-local","canon":"cu1"}`, idx, h, prevField)
	trimmed := strings.TrimSpace(payload)
	if trimmed == "{}" {
		return "{" + integ + "}"
	}
	return trimmed[:len(trimmed)-1] + "," + integ + "}"
}

// recordHash returns the cu1 hash a record with this payload, index, and previous hash carries.
func recordHash(t *testing.T, payload string, idx int64, prev string) string {
	t.Helper()
	c := canon(nil, mustParse(t, payload))
	var prevLex []byte
	if prev == "" {
		prevLex = []byte("null")
	} else {
		prevLex = []byte(`"` + prev + `"`)
	}
	return sha256Hex(hashMaterial(strconv.FormatInt(idx, 10), prevLex, c))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeChain writes a small valid chain of n records to path and returns the last record's hash.
func writeChain(t *testing.T, path string, n int) string {
	t.Helper()
	var lines []string
	prev := ""
	var last string
	for i := range n {
		payload := fmt.Sprintf(`{"action":"deny","seq":%d,"meta":{"b":1,"a":2}}`, i)
		lines = append(lines, makeRecord(t, payload, int64(i), prev))
		last = recordHash(t, payload, int64(i), prev)
		prev = last
	}
	writeFile(t, path, strings.Join(lines, "\n")+"\n")
	return last
}

// testKey is an Ed25519 key pair with the base64 SPKI a checkpoint carries.
type testKey struct {
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	spkiB64  string
	spkiDER  []byte
	pemPKCS8 string
}

func genKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return testKey{
		priv:    priv,
		pub:     pub,
		spkiB64: base64.StdEncoding.EncodeToString(der),
		spkiDER: der,
	}
}

// signCheckpoint builds a checkpoint object JSON signed by k. chainIndex is the sealed segment
// count and hash is the composite the writer would have produced; this verifier does not
// recompute the composite, so any 64-hex value stands in for a test.
func signCheckpoint(t *testing.T, k testKey, chainIndex int64, hash, signedAt string) string {
	t.Helper()
	payload := fmt.Sprintf(`{"chainIndex":%d,"hash":"%s","signedAt":"%s","algorithm":"ed25519"}`, chainIndex, hash, signedAt)
	sig := ed25519.Sign(k.priv, []byte(payload))
	return fmt.Sprintf(
		`{"chainIndex":%d,"hash":"%s","signedAt":"%s","signature":"%s","publicKey":"%s","algorithm":"ed25519"}`,
		chainIndex, hash, signedAt, base64.StdEncoding.EncodeToString(sig), k.spkiB64,
	)
}

// anchorDigestOf recomputes the anchor digest over a checkpoint JSON exactly as the verifier
// does, so a test anchor record can carry the correct digest.
func anchorDigestOf(t *testing.T, checkpointJSON string) string {
	t.Helper()
	cp := mustParse(t, checkpointJSON)
	cf, ok := extractCheckpoint(cp)
	if !ok {
		t.Fatalf("extractCheckpoint failed for %q", checkpointJSON)
	}
	return sha256Hex(anchorDigestMaterial(cf))
}

// pendingProof builds a synthetic .ots-style raw ops stream: append 8 bytes, sha256, then a
// pending attestation carrying a calendar URI. It starts from the given digest.
func pendingProof(digestHex, uri string) []byte {
	var b []byte
	// F0 append, varbytes of 8 zero bytes
	b = append(b, 0xF0)
	b = appendVarbytes(b, make([]byte, 8))
	// 08 sha256
	b = append(b, 0x08)
	// 00 attestation, pending tag, varbytes payload = varbytes URI
	b = append(b, 0x00)
	b = append(b, tagPending...)
	inner := appendVarbytes(nil, []byte(uri))
	b = appendVarbytes(b, inner)
	return b
}

// bitcoinProof builds a synthetic raw ops stream: append 8 bytes, sha256, then a Bitcoin
// attestation carrying a block height.
func bitcoinProof(height uint64) []byte {
	var b []byte
	b = append(b, 0xF0)
	b = appendVarbytes(b, make([]byte, 8))
	b = append(b, 0x08)
	b = append(b, 0x00)
	b = append(b, tagBitcoin...)
	inner := appendVarint(nil, height)
	b = appendVarbytes(b, inner)
	return b
}

func appendVarint(dst []byte, n uint64) []byte {
	for {
		b := byte(n & 0x7F)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		dst = append(dst, b)
		if n == 0 {
			return dst
		}
	}
}

func appendVarbytes(dst, payload []byte) []byte {
	dst = appendVarint(dst, uint64(len(payload)))
	return append(dst, payload...)
}

// evidenceTree assembles a full valid evidence tree in a temp dir and returns its audit path,
// the pinned key, and the checkpoint hash it anchored.
func evidenceTree(t *testing.T) (dir string, k testKey) {
	t.Helper()
	dir = t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	lastHash := writeChain(t, audit, 3)

	k = genKey(t)
	// The checkpoint commits to the live tail: 0 sealed segments, and the live file's 3 records
	// with lastHash as its final hash. compositeLiteral builds those bytes per the spec so the
	// live-tail re-derivation can reproduce them.
	cpHash := compositeLiteral(t, "null", 0, lastHash, 3, true)
	checkpoint := signCheckpoint(t, k, 0, cpHash, "2026-01-01T00:00:00.000Z")
	digest := anchorDigestOf(t, checkpoint)

	proofDir := filepath.Join(dir, "proofs")
	if err := os.MkdirAll(proofDir, 0o700); err != nil {
		t.Fatalf("mkdir proofs: %v", err)
	}
	proofName := digest + ".ots"
	writeFileBytes(t, filepath.Join(proofDir, proofName), pendingProof(digest, "https://calendar.example.com/"+digest))

	anchor := fmt.Sprintf(
		`{"backend":"opentimestamps","digest":"%s","chainIndex":0,"reference":"https://calendar.example.com","proofPath":"%s","submittedAt":"2026-01-01T00:00:01.000Z","status":"pending","checkpoint":%s}`,
		digest, proofName, checkpoint,
	)
	writeFile(t, filepath.Join(dir, "anchors.jsonl"), anchor+"\n")
	return dir, k
}

func writeFileBytes(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// hasCode reports whether any problem in the layer carries the given code.
func layerHasCode(l layer, code string) bool {
	for _, p := range l.problems {
		if p.code == code {
			return true
		}
	}
	return false
}

func findLayer(r *report, name string) layer {
	for _, l := range r.layers {
		if l.name == name {
			return l
		}
	}
	panic("layer not found: " + name)
}

// hexDigest is a tiny convenience for tests that need a digest byte slice.
func hexDigest(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// compositeLiteral builds the checkpoint composite bytes by hand per the format and returns the
// SHA-256 hex, independent of the production compositeHash so a match between them is meaningful.
func compositeLiteral(t *testing.T, headField string, segments int, finalHash string, count int, hasTail bool) string {
	t.Helper()
	var s string
	if hasTail {
		s = fmt.Sprintf(`{"manifestHead":%s,"segments":%d,"liveTail":{"finalHash":"%s","count":%d}}`, headField, segments, finalHash, count)
	} else {
		s = fmt.Sprintf(`{"manifestHead":%s,"segments":%d,"liveTail":null}`, headField, segments)
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// pemPublicKey PEM-encodes SPKI DER as a PUBLIC KEY block for the pin-file test.
func pemPublicKey(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// readFileString reads a file as a string for tests that mutate evidence in place.
func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// flipHex returns a different hex digit, keeping the string valid hex.
func flipHex(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}

// flipB64 returns a different base64 character.
func flipB64(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

// removeGlob deletes files matching a glob, for tests that remove a proof.
func removeGlob(t *testing.T, pattern string) {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	for _, m := range matches {
		if err := os.Remove(m); err != nil {
			t.Fatalf("remove %s: %v", m, err)
		}
	}
}
