package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func fatalCodes(problems []problem) []string {
	var out []string
	for _, p := range problems {
		if p.fatal {
			out = append(out, p.code)
		}
	}
	return out
}

func hasCode(problems []problem, code string) bool {
	for _, p := range problems {
		if p.code == code {
			return true
		}
	}
	return false
}

func TestChainAcceptsValidChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeChain(t, path, 5)
	res := verifyChainFile(path)
	if res.records != 5 {
		t.Fatalf("records = %d, want 5", res.records)
	}
	if codes := fatalCodes(res.problems); len(codes) != 0 {
		t.Fatalf("expected no fatal problems, got %v", codes)
	}
}

func TestChainDetectsPayloadTamper(t *testing.T) {
	// Flipping a payload byte after write must be caught by the hash even though the record still
	// parses and still links: an edit inside a record is exactly what the chain exists to catch.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rec := makeRecord(t, `{"action":"deny"}`, 0, "")
	tampered := strings.Replace(rec, `"deny"`, `"allow"`, 1)
	writeFile(t, path, tampered+"\n")
	res := verifyChainFile(path)
	if !hasCode(res.problems, codeHashMismatch) {
		t.Fatalf("expected hash-mismatch, got %v", res.problems)
	}
}

func TestChainLegacyRecordReportedDistinctly(t *testing.T) {
	// A record with no canon marker whose cu1 hash does not match is reported as
	// hash-mismatch-or-legacy-canon, because an independent verifier cannot tell a legacy
	// locale-hashed record from an altered one.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	line := `{"action":"deny","integrity":{"chainIndex":0,"hash":"` + strings.Repeat("00", 32) + `","previousHash":null,"algorithm":"sha256","status":"chained-local"}}`
	writeFile(t, path, line+"\n")
	res := verifyChainFile(path)
	if !hasCode(res.problems, codeHashMismatchOrLegacy) {
		t.Fatalf("expected hash-mismatch-or-legacy-canon, got %v", res.problems)
	}
	if hasCode(res.problems, codeHashMismatch) {
		t.Fatal("a canon-less record must not report plain hash-mismatch")
	}
}

func TestChainDetectsIndexGap(t *testing.T) {
	// A deleted middle record leaves a gap in the index sequence and a broken link.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	r0 := makeRecord(t, `{"n":0}`, 0, "")
	h0 := recordHash(t, `{"n":0}`, 0, "")
	h1 := recordHash(t, `{"n":1}`, 1, h0)
	r2 := makeRecord(t, `{"n":2}`, 2, h1) // record 1 omitted
	writeFile(t, path, r0+"\n"+r2+"\n")
	res := verifyChainFile(path)
	if !hasCode(res.problems, codeIndexGap) {
		t.Fatalf("expected index-gap, got %v", res.problems)
	}
}

func TestChainDetectsLinkBreak(t *testing.T) {
	// Relinking a record's previousHash breaks the link and, because previousHash is hashed,
	// also breaks the hash.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	r0 := makeRecord(t, `{"n":0}`, 0, "")
	r1 := makeRecord(t, `{"n":1}`, 1, strings.Repeat("cd", 32)) // wrong previousHash
	writeFile(t, path, r0+"\n"+r1+"\n")
	res := verifyChainFile(path)
	if !hasCode(res.problems, codeLinkBreak) {
		t.Fatalf("expected link-break, got %v", res.problems)
	}
}

func TestChainTornTailIsNonFatal(t *testing.T) {
	// A final line with no terminating newline that does not parse is the signature of a hard
	// kill, not tampering. It is reported as torn-tail and does not fail the chain.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	r0 := makeRecord(t, `{"n":0}`, 0, "")
	writeFile(t, path, r0+"\n"+`{"n":1,"integrity":{"chainIndex":1,`) // torn, no newline
	res := verifyChainFile(path)
	if !hasCode(res.problems, codeTornTail) {
		t.Fatalf("expected torn-tail, got %v", res.problems)
	}
	if codes := fatalCodes(res.problems); len(codes) != 0 {
		t.Fatalf("torn-tail must be non-fatal, got fatal %v", codes)
	}
}

func TestChainInteriorBadJSONIsFatal(t *testing.T) {
	// A broken line that is NOT the final one, or that ends with a newline, is corruption, not a
	// torn tail, and must be fatal.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	r0 := makeRecord(t, `{"n":0}`, 0, "")
	r2 := makeRecord(t, `{"n":2}`, 2, recordHash(t, `{"n":1}`, 1, recordHash(t, `{"n":0}`, 0, "")))
	writeFile(t, path, r0+"\n"+`{"n":1,broken}`+"\n"+r2+"\n")
	res := verifyChainFile(path)
	if !hasCode(res.problems, codeBadJSON) {
		t.Fatalf("expected bad-json, got %v", res.problems)
	}
}

func TestChainDuplicateKeyIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	line := `{"n":1,"n":2,"integrity":{"chainIndex":0,"hash":"` + strings.Repeat("00", 32) + `","previousHash":null,"algorithm":"sha256"}}`
	writeFile(t, path, line+"\n")
	res := verifyChainFile(path)
	if !hasCode(res.problems, codeDupKey) {
		t.Fatalf("expected dup-key, got %v", res.problems)
	}
}

func TestChainNullPreviousHashOnlyAtIndexZero(t *testing.T) {
	// previousHash may be null only at index 0; a null link at a nonzero first index is a break.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	line := makeRecord(t, `{"n":5}`, 5, "")
	writeFile(t, path, line+"\n")
	res := verifyChainFile(path)
	if !hasCode(res.problems, codeLinkBreak) {
		t.Fatalf("expected link-break for null previousHash at index 5, got %v", res.problems)
	}
}

func TestChainRotationResumesMidSequence(t *testing.T) {
	// A segment's first record may carry any index with a non-null previousHash: rotation
	// resumes the sequence rather than restarting it.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	prev := strings.Repeat("ef", 32)
	r := makeRecord(t, `{"n":10}`, 10, prev)
	writeFile(t, path, r+"\n")
	res := verifyChainFile(path)
	if codes := fatalCodes(res.problems); len(codes) != 0 {
		t.Fatalf("mid-sequence resume should verify, got %v", codes)
	}
}

func TestChainMissingIntegrityIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeFile(t, path, `{"n":1}`+"\n")
	res := verifyChainFile(path)
	if !hasCode(res.problems, codeMissingIntegrity) {
		t.Fatalf("expected missing-integrity, got %v", res.problems)
	}
}

func TestChainProblemsAreCapped(t *testing.T) {
	// A file full of broken lines must not produce an unbounded problem list; the report is
	// summarized so a hostile file cannot inflate the verifier's own output.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	var sb strings.Builder
	for i := range 1000 {
		sb.WriteString(fmt.Sprintf("{bad line %d}\n", i))
	}
	writeFile(t, path, sb.String())
	res := verifyChainFile(path)
	if len(res.problems) > problemCap+1 {
		t.Fatalf("problems not capped: got %d", len(res.problems))
	}
}
