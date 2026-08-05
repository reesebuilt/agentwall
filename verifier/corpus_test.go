package main

// Conformance corpus walker.
//
// The corpus at testdata/corpus is produced by a separate step. This test walks it when present
// and skips cleanly when it is not, so this verifier can be built and merged before or after the
// corpus lands. Each case is copied to a temp directory before running, because verification is
// read-only but the corpus in git is immutable and running a verifier that could ever touch a
// file must not touch the checked-in tree.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// expectedCase is the per-case oracle, matching the C4 schema.
type expectedCase struct {
	Exit   int `json:"exit"`
	Layers struct {
		Chained  bool `json:"chained"`
		Linked   bool `json:"linked"`
		Anchored bool `json:"anchored"`
	} `json:"layers"`
	GoCodesInclude []string `json:"go_codes_include"`
}

func TestConformanceCorpus(t *testing.T) {
	root := "testdata/corpus"
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Skipf("no corpus at %s: %v", root, err)
	}
	ran := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		caseDir := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(caseDir, "expected.json")); err != nil {
			continue
		}
		ran++
		t.Run(e.Name(), func(t *testing.T) {
			runCorpusCase(t, caseDir)
		})
	}
	if ran == 0 {
		t.Skip("corpus directory present but contains no cases")
	}
}

func runCorpusCase(t *testing.T, caseDir string) {
	tmp := t.TempDir()
	copyTree(t, caseDir, tmp)

	expBytes, err := os.ReadFile(filepath.Join(tmp, "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	var exp expectedCase
	if err := json.Unmarshal(expBytes, &exp); err != nil {
		t.Fatalf("parse expected.json: %v", err)
	}

	args := []string{"--audit", filepath.Join(tmp, "audit.jsonl"), "--json"}
	if pk := filepath.Join(tmp, "pubkey.txt"); fileExists(pk) {
		args = append(args, "--pubkey-file", pk)
	}

	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	if code != exp.Exit {
		t.Fatalf("exit = %d, want %d\nstderr=%s\nstdout=%s", code, exp.Exit, errb.String(), out.String())
	}

	var jr jsonReport
	if err := json.Unmarshal(out.Bytes(), &jr); err != nil {
		t.Fatalf("output not JSON: %v\n%s", err, out.String())
	}
	got := map[string]bool{}
	for _, l := range jr.Layers {
		got[l.Name] = l.OK
	}
	if got["chained"] != exp.Layers.Chained || got["linked"] != exp.Layers.Linked || got["anchored"] != exp.Layers.Anchored {
		t.Fatalf("layers = %v, want chained=%v linked=%v anchored=%v", got, exp.Layers.Chained, exp.Layers.Linked, exp.Layers.Anchored)
	}

	if len(exp.GoCodesInclude) > 0 {
		all := allProblemStrings(jr)
		for _, code := range exp.GoCodesInclude {
			if !strings.Contains(all, code) {
				t.Fatalf("expected go code %q in problems, got:\n%s", code, all)
			}
		}
	}
}

func allProblemStrings(jr jsonReport) string {
	var sb strings.Builder
	for _, l := range jr.Layers {
		for _, p := range l.Problems {
			sb.WriteString(p)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// copyTree copies a corpus case directory into dst, preserving the relative layout so relative
// paths inside the case resolve the same way they do in the checked-in tree.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy corpus case: %v", err)
	}
}
