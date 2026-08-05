package main

import (
	"strings"
	"testing"
)

func TestOTSPendingAttestation(t *testing.T) {
	digest := strings.Repeat("00", 32)
	proof := pendingProof(digest, "https://calendar.example.com/x")
	atts, err := parseOTS(proof, hexDigest(digest))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(atts) != 1 || atts[0].kind != "pending" || atts[0].uri != "https://calendar.example.com/x" {
		t.Fatalf("unexpected attestations: %+v", atts)
	}
}

func TestOTSBitcoinAttestation(t *testing.T) {
	digest := strings.Repeat("11", 32)
	proof := bitcoinProof(850000)
	atts, err := parseOTS(proof, hexDigest(digest))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(atts) != 1 || atts[0].kind != "bitcoin" || atts[0].height != 850000 {
		t.Fatalf("unexpected attestations: %+v", atts)
	}
	if len(atts[0].value) == 0 {
		t.Fatal("bitcoin attestation should carry a derived value")
	}
}

func TestOTSFork(t *testing.T) {
	// A fork splits the message into two branches, each ending in its own attestation. Both must
	// be collected and neither may corrupt the other's message.
	digest := strings.Repeat("22", 32)
	var b []byte
	b = append(b, 0xFF) // fork: first edge follows, then the final edge
	// first edge: sha256 then pending attestation
	b = append(b, 0x08)
	b = append(b, 0x00)
	b = append(b, tagPending...)
	b = appendVarbytes(b, appendVarbytes(nil, []byte("uri-a")))
	// final edge: sha256 then pending attestation
	b = append(b, 0x08)
	b = append(b, 0x00)
	b = append(b, tagBitcoin...)
	b = appendVarbytes(b, appendVarint(nil, 42))

	atts, err := parseOTS(b, hexDigest(digest))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(atts) != 2 {
		t.Fatalf("expected 2 attestations from fork, got %+v", atts)
	}
}

func TestOTSTruncatedProofErrors(t *testing.T) {
	// A proof truncated mid-varbytes must be a clean parse error, not a panic or a silent pass.
	digest := strings.Repeat("33", 32)
	proof := pendingProof(digest, "https://calendar.example.com/x")
	truncated := proof[:len(proof)-3]
	if _, err := parseOTS(truncated, hexDigest(digest)); err == nil {
		t.Fatal("expected parse error on truncated proof")
	}
}

func TestOTSFullFileForm(t *testing.T) {
	// A full .ots file carries the magic header, a version varint, a file hash-op, and the file
	// digest before the ops stream. The parser must skip that header and still find attestations.
	digest := strings.Repeat("44", 32)
	var b []byte
	b = append(b, otsMagic...)
	b = appendVarint(b, 1)             // version
	b = append(b, 0x08)                // file hash-op sha256
	b = append(b, make([]byte, 32)...) // embedded file digest
	b = append(b, pendingProof(digest, "u")...)
	atts, err := parseOTS(b, hexDigest(digest))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(atts) != 1 || atts[0].kind != "pending" {
		t.Fatalf("unexpected attestations: %+v", atts)
	}
}

func TestOTSRejectsOversizedVarbytes(t *testing.T) {
	// A varbytes claiming a length beyond the per-arg cap must be rejected before allocation, so a
	// hostile proof cannot name a huge buffer.
	digest := strings.Repeat("55", 32)
	var b []byte
	b = append(b, 0xF0)                   // append
	b = appendVarint(b, otsMaxVarBytes+1) // length beyond the cap, no payload follows
	if _, err := parseOTS(b, hexDigest(digest)); err == nil {
		t.Fatal("expected error on oversized varbytes length")
	}
}

func TestOTSRejectsDeepFork(t *testing.T) {
	// A pathological run of forks must hit the depth cap rather than overflow the stack.
	digest := strings.Repeat("66", 32)
	var b []byte
	for range otsMaxDepth + 5 {
		b = append(b, 0xFF, 0x08) // fork then sha256, descending each time
	}
	b = append(b, 0x00)
	b = append(b, tagPending...)
	b = appendVarbytes(b, appendVarbytes(nil, []byte("u")))
	if _, err := parseOTS(b, hexDigest(digest)); err == nil {
		t.Fatal("expected depth-cap error on deeply forked proof")
	}
}

func TestOTSUnsupportedHashOpIsError(t *testing.T) {
	// A branch that needs ripemd160 or keccak256 is reported as unverifiable rather than
	// evaluated with a hand-rolled primitive.
	digest := strings.Repeat("77", 32)
	for _, op := range []byte{0x03, 0x67} {
		b := []byte{op}
		if _, err := parseOTS(b, hexDigest(digest)); err == nil {
			t.Fatalf("expected error for unsupported op 0x%02x", op)
		}
	}
}
