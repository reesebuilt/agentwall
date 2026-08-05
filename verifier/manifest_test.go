package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// makeSegment builds a manifest entry line with a correct entryHash for the given fields. It is
// used both for entries that match their file and for entries deliberately made to mismatch.
func makeSegment(t *testing.T, path string, count, first, last int, finalHash, prevSeg, sealedAt string) string {
	t.Helper()
	prevField := "null"
	if prevSeg != "" {
		prevField = `"` + prevSeg + `"`
	}
	base := fmt.Sprintf(`{"path":"%s","count":%d,"firstIndex":%d,"lastIndex":%d,"finalHash":"%s","previousSegmentHash":%s,"sealedAt":"%s"}`,
		path, count, first, last, finalHash, prevField, sealedAt)
	withDummy := base[:len(base)-1] + `,"entryHash":""}`
	e, ok := extractManifestEntry(mustParse(t, withDummy))
	if !ok {
		t.Fatalf("could not extract manifest entry from %q", withDummy)
	}
	h := sha256Hex(manifestEntryMaterial(e))
	return base[:len(base)-1] + `,"entryHash":"` + h + `"}`
}

// writeSegmentFile writes a valid chain of n records to path and returns the final record hash.
func writeSegmentFile(t *testing.T, path string, n int) string {
	t.Helper()
	var lines []string
	prev := ""
	var last string
	for i := range n {
		payload := fmt.Sprintf(`{"seg":%d}`, i)
		lines = append(lines, makeRecord(t, payload, int64(i), prev))
		last = recordHash(t, payload, int64(i), prev)
		prev = last
	}
	writeFile(t, path, strings.Join(lines, "\n")+"\n")
	return last
}

// segmentAndEntry writes a segment file of n records and returns a manifest entry that matches
// its actual shape, so a clean case has no content mismatch.
func segmentAndEntry(t *testing.T, dir, name string, n int, prevSeg, sealedAt string) (entry, finalHash string) {
	t.Helper()
	finalHash = writeSegmentFile(t, filepath.Join(dir, name), n)
	entry = makeSegment(t, name, n, 0, n-1, finalHash, prevSeg, sealedAt)
	return entry, finalHash
}

func TestManifestLinksTwoSegments(t *testing.T) {
	dir := t.TempDir()
	s0, h0 := segmentAndEntry(t, dir, "audit.jsonl.1", 4, "", "2026-01-01T00:00:00.000Z")
	s1, _ := segmentAndEntry(t, dir, "audit.jsonl.2", 3, h0, "2026-01-01T00:00:01.000Z")
	mPath := filepath.Join(dir, "segments.jsonl")
	writeFile(t, mPath, s0+"\n"+s1+"\n")

	res := verifyManifest(mPath, filepath.Join(dir, "audit.jsonl"))
	if res.segments != 2 {
		t.Fatalf("segments = %d, want 2", res.segments)
	}
	for _, p := range res.problems {
		if p.fatal {
			t.Fatalf("unexpected fatal problem: %v", res.problems)
		}
	}
}

func TestManifestDetectsEntryHashTamper(t *testing.T) {
	// Tamper sealedAt, which is inside the entryHash but not a content field, so only the entry
	// hash check fires and it is cleanly isolated from the content binding.
	dir := t.TempDir()
	s0, _ := segmentAndEntry(t, dir, "audit.jsonl.1", 4, "", "2026-01-01T00:00:00.000Z")
	tampered := strings.Replace(s0, `"sealedAt":"2026-01-01T00:00:00.000Z"`, `"sealedAt":"2027-01-01T00:00:00.000Z"`, 1)
	mPath := filepath.Join(dir, "segments.jsonl")
	writeFile(t, mPath, tampered+"\n")

	res := verifyManifest(mPath, filepath.Join(dir, "audit.jsonl"))
	if !hasCode(res.problems, codeManifestEntryHash) {
		t.Fatalf("expected manifest-entry-hash, got %v", res.problems)
	}
}

func TestManifestDetectsLinkBreak(t *testing.T) {
	// The second entry links to the wrong previous finalHash. Its entryHash is computed over that
	// wrong value, so the entry hash still checks out and only the linkage fails.
	dir := t.TempDir()
	s0, _ := segmentAndEntry(t, dir, "audit.jsonl.1", 4, "", "2026-01-01T00:00:00.000Z")
	s1, _ := segmentAndEntry(t, dir, "audit.jsonl.2", 3, strings.Repeat("cc", 32), "2026-01-01T00:00:01.000Z")
	mPath := filepath.Join(dir, "segments.jsonl")
	writeFile(t, mPath, s0+"\n"+s1+"\n")

	res := verifyManifest(mPath, filepath.Join(dir, "audit.jsonl"))
	if !hasCode(res.problems, codeManifestLinkBreak) {
		t.Fatalf("expected manifest-link-break, got %v", res.problems)
	}
}

func TestManifestDetectsMissingSegment(t *testing.T) {
	dir := t.TempDir()
	// The manifest names audit.jsonl.1 but the file is never created on disk.
	s0 := makeSegment(t, "audit.jsonl.1", 4, 0, 3, strings.Repeat("a1", 32), "", "2026-01-01T00:00:00.000Z")
	mPath := filepath.Join(dir, "segments.jsonl")
	writeFile(t, mPath, s0+"\n")

	res := verifyManifest(mPath, filepath.Join(dir, "audit.jsonl"))
	if !hasCode(res.problems, codeSegmentMissing) {
		t.Fatalf("expected segment-missing, got %v", res.problems)
	}
}

func TestManifestSegmentContentMismatch(t *testing.T) {
	// The attack the independent verifier caught: rewrite an entire sealed segment, relinking it
	// so its own per-file chain still verifies, without touching the anchored manifest entry. The
	// entry hash and linkage still pass; only binding the entry to the file's actual bytes catches
	// it.
	dir := t.TempDir()
	s0, _ := segmentAndEntry(t, dir, "audit.jsonl.1", 4, "", "2026-01-01T00:00:00.000Z")
	mPath := filepath.Join(dir, "segments.jsonl")
	writeFile(t, mPath, s0+"\n")

	// Rewrite the segment file with different, internally valid content.
	writeSegmentFile(t, filepath.Join(dir, "audit.jsonl.1"), 5)

	res := verifyManifest(mPath, filepath.Join(dir, "audit.jsonl"))
	if !hasCode(res.problems, codeSegmentContentMismatch) {
		t.Fatalf("expected segment-content-mismatch, got %v", res.problems)
	}
	if hasCode(res.problems, codeManifestEntryHash) || hasCode(res.problems, codeManifestLinkBreak) {
		t.Fatalf("only the content binding should catch this, got %v", res.problems)
	}
}

func TestManifestVacuousPass(t *testing.T) {
	// No manifest and no rotated files means nothing to link: a vacuous pass, not a failure, so a
	// deployment that has never rotated is not told its tool is broken.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "audit.jsonl"), makeRecord(t, `{"n":0}`, 0, "")+"\n")
	res := verifyManifest(filepath.Join(dir, "segments.jsonl"), filepath.Join(dir, "audit.jsonl"))
	if res.segments != 0 {
		t.Fatalf("segments = %d, want 0", res.segments)
	}
	for _, p := range res.problems {
		if p.fatal {
			t.Fatalf("vacuous pass should have no fatal problems, got %v", res.problems)
		}
	}
	if !strings.Contains(res.detail, "nothing to link") {
		t.Fatalf("detail = %q, want it to mention nothing to link", res.detail)
	}
}

func TestManifestUnsealedRotatedFileFails(t *testing.T) {
	// A rotated segment sitting on disk but never sealed into the manifest is a real failure: it
	// is evidence outside the anchor.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "audit.jsonl"), makeRecord(t, `{"n":0}`, 0, "")+"\n")
	writeSegmentFile(t, filepath.Join(dir, "audit.jsonl.1"), 2)
	res := verifyManifest(filepath.Join(dir, "segments.jsonl"), filepath.Join(dir, "audit.jsonl"))
	if !hasCode(res.problems, codeSegmentUnsealed) {
		t.Fatalf("expected segment-unsealed, got %v", res.problems)
	}
}

func TestManifestFirstEntryPrevMustBeNull(t *testing.T) {
	dir := t.TempDir()
	// First entry carries a non-null previousSegmentHash, which is a linkage break at the head.
	s0, _ := segmentAndEntry(t, dir, "audit.jsonl.1", 4, strings.Repeat("dd", 32), "2026-01-01T00:00:00.000Z")
	mPath := filepath.Join(dir, "segments.jsonl")
	writeFile(t, mPath, s0+"\n")
	res := verifyManifest(mPath, filepath.Join(dir, "audit.jsonl"))
	if !hasCode(res.problems, codeManifestLinkBreak) {
		t.Fatalf("expected manifest-link-break at head, got %v", res.problems)
	}
}
