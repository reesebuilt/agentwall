package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunNoArgsExitsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("no --audit should exit 2, got %d", code)
	}
	if !strings.Contains(errb.String(), "--audit is required") {
		t.Fatalf("stderr should explain the missing flag, got %q", errb.String())
	}
}

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("--version should exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), verifierVersion) {
		t.Fatalf("version output missing version: %q", out.String())
	}
}

// The release stamps the tag into the binary via -ldflags, but `go run ./verifier` from a plain
// checkout reports the compiled-in default instead. That default is a second copy of the
// project's version number, and a second copy drifts: bump package.json, forget report.go, and
// the verifier tells a stranger it is a version that was never released. This test is the only
// thing that notices.
func TestVersionMatchesPackageJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "package.json"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("no package.json beside the verifier; running outside the repo")
	}
	if err != nil {
		t.Fatalf("reading package.json: %v", err)
	}
	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatalf("parsing package.json: %v", err)
	}
	if pkg.Version == "" {
		t.Fatal("package.json has no version field")
	}
	if pkg.Version != verifierVersion {
		t.Fatalf("verifierVersion %q does not match package.json version %q; update verifier/report.go", verifierVersion, pkg.Version)
	}
}

func TestRunMissingAuditFileIsIOError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--audit", filepath.Join(t.TempDir(), "nope.jsonl")}, &out, &errb); code != 2 {
		t.Fatalf("missing audit file should exit 2, got %d", code)
	}
}

func TestRunPassingTreeExitsZero(t *testing.T) {
	dir, _ := evidenceTree(t)
	var out, errb bytes.Buffer
	code := run([]string{"--audit", filepath.Join(dir, "audit.jsonl"), "--json"}, &out, &errb)
	if code != 0 {
		t.Fatalf("valid tree should exit 0, got %d; stderr=%s stdout=%s", code, errb.String(), out.String())
	}
	var jr jsonReport
	if err := json.Unmarshal(out.Bytes(), &jr); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if !jr.OK {
		t.Fatalf("ok should be true: %+v", jr)
	}
	if jr.Pending != 1 {
		t.Fatalf("pending = %d, want 1", jr.Pending)
	}
	if len(jr.Layers) != 3 {
		t.Fatalf("want 3 layers, got %d", len(jr.Layers))
	}
	want := map[string]bool{"chained": true, "linked": true, "anchored": true}
	for _, l := range jr.Layers {
		if !want[l.Name] {
			t.Fatalf("unexpected layer name %q", l.Name)
		}
		if !l.OK {
			t.Fatalf("layer %q should be ok: %+v", l.Name, l)
		}
	}
	if jr.Verifier.Name != verifierName || jr.Verifier.Language != "go" || jr.Verifier.Canon != "cu1" {
		t.Fatalf("verifier block wrong: %+v", jr.Verifier)
	}
}

func TestRunFailingTreeExitsOne(t *testing.T) {
	// Corrupt one payload byte in the audit file. The chained layer must fail and the run exits 1.
	dir, _ := evidenceTree(t)
	auditPath := filepath.Join(dir, "audit.jsonl")
	data := readFileString(t, auditPath)
	corrupted := strings.Replace(data, `"action":"deny"`, `"action":"allow"`, 1)
	if corrupted == data {
		t.Fatal("test setup did not corrupt anything")
	}
	writeFile(t, auditPath, corrupted)

	var out, errb bytes.Buffer
	code := run([]string{"--audit", auditPath, "--json"}, &out, &errb)
	if code != 1 {
		t.Fatalf("corrupted tree should exit 1, got %d", code)
	}
	var jr jsonReport
	if err := json.Unmarshal(out.Bytes(), &jr); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if jr.OK {
		t.Fatal("ok should be false on a corrupted tree")
	}
	for _, l := range jr.Layers {
		if l.Name == "chained" && l.OK {
			t.Fatal("chained layer should be false after a payload edit")
		}
	}
}

func TestRunUnpinnedPrintsSelfConsistencyNote(t *testing.T) {
	dir, _ := evidenceTree(t)
	var out, errb bytes.Buffer
	run([]string{"--audit", filepath.Join(dir, "audit.jsonl")}, &out, &errb)
	want := "signatures are self-consistent; supply --pubkey to bind them to a key you expect"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("human output missing the exact unpinned note:\n%s", out.String())
	}
}

func TestRunUnanchoredChainExitsOne(t *testing.T) {
	// A chain with no anchor log verifies internally but has nothing off-box, which the product
	// treats as incomplete evidence: chained PASS, overall exit 1.
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	writeChain(t, auditPath, 3)
	var out, errb bytes.Buffer
	code := run([]string{"--audit", auditPath, "--json"}, &out, &errb)
	if code != 1 {
		t.Fatalf("unanchored chain should exit 1, got %d", code)
	}
	var jr jsonReport
	if err := json.Unmarshal(out.Bytes(), &jr); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	for _, l := range jr.Layers {
		if l.Name == "chained" && !l.OK {
			t.Fatalf("chained should pass on a valid unanchored chain: %+v", l)
		}
		if l.Name == "anchored" && l.OK {
			t.Fatal("anchored should be false with no anchor log")
		}
	}
}

func TestRunConflictingPinFlags(t *testing.T) {
	dir, _ := evidenceTree(t)
	var out, errb bytes.Buffer
	code := run([]string{"--audit", filepath.Join(dir, "audit.jsonl"), "--pubkey", "x", "--pubkey-file", "y"}, &out, &errb)
	if code != 2 {
		t.Fatalf("conflicting pin flags should exit 2, got %d", code)
	}
}
