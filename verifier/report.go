package main

// Report assembly and rendering.
//
// The three layers are reported separately and never collapsed into one verdict. That is the
// honesty the format demands: a chain that verifies internally but has no off-box anchor proves
// less than one that does, and folding both into a single green tick would overstate the weaker
// case. JSON field names mirror the bundled TypeScript verifier so a caller can compare the two
// outputs field for field.

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	verifierName     = "agentwall-verify"
	verifierVersion  = "0.2.0"
	verifierLanguage = "go"
	verifierCanon    = "cu1"
)

// problem is one finding. code is stable and machine-readable and appears in JSON output; text
// is human guidance and is explicitly not part of any cross-implementation contract. fatal
// distinguishes a finding that fails its layer from one that is merely reported, such as a torn
// final line after a hard kill.
type problem struct {
	code  string
	text  string
	fatal bool
}

func (p problem) String() string { return p.code + ": " + p.text }

type layer struct {
	name     string
	ok       bool
	detail   string
	problems []problem
}

// hasFatal reports whether any recorded problem should fail the layer.
func (l *layer) hasFatal() bool {
	for i := range l.problems {
		if l.problems[i].fatal {
			return true
		}
	}
	return false
}

type report struct {
	ok        bool
	layers    []layer
	pending   int
	confirmed int
	failed    int
	// note carries the exact unpinned self-consistency sentence for human output. It is not a
	// finding and does not appear in JSON, which mirrors the TypeScript report shape exactly.
	note string
}

type jsonVerifier struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Language string `json:"language"`
	Canon    string `json:"canon"`
}

type jsonLayer struct {
	Name     string   `json:"name"`
	OK       bool     `json:"ok"`
	Detail   string   `json:"detail"`
	Problems []string `json:"problems"`
}

type jsonReport struct {
	OK        bool         `json:"ok"`
	Layers    []jsonLayer  `json:"layers"`
	Pending   int          `json:"pending"`
	Confirmed int          `json:"confirmed"`
	Failed    int          `json:"failed"`
	Verifier  jsonVerifier `json:"verifier"`
}

// writeJSON emits the machine-readable report. Problems are rendered as "code: text" so a
// harness can match a stable code with a substring test while a human still reads the guidance.
func (r *report) writeJSON(w io.Writer) error {
	jr := jsonReport{
		OK:        r.ok,
		Pending:   r.pending,
		Confirmed: r.confirmed,
		Failed:    r.failed,
		Verifier: jsonVerifier{
			Name:     verifierName,
			Version:  verifierVersion,
			Language: verifierLanguage,
			Canon:    verifierCanon,
		},
	}
	jr.Layers = make([]jsonLayer, 0, len(r.layers))
	for i := range r.layers {
		l := &r.layers[i]
		problems := make([]string, 0, len(l.problems))
		for j := range l.problems {
			problems = append(problems, l.problems[j].String())
		}
		jr.Layers = append(jr.Layers, jsonLayer{
			Name:     l.name,
			OK:       l.ok,
			Detail:   l.detail,
			Problems: problems,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&jr)
}

// writeHuman emits aligned PASS/FAIL lines followed by each layer's findings.
func (r *report) writeHuman(w io.Writer) {
	for i := range r.layers {
		l := &r.layers[i]
		status := "FAIL"
		if l.ok {
			status = "PASS"
		}
		fmt.Fprintf(w, "%-8s %s  %s\n", l.name, status, l.detail)
		for j := range l.problems {
			fmt.Fprintf(w, "    - %s\n", l.problems[j].String())
		}
	}
	if r.note != "" {
		fmt.Fprintln(w, r.note)
	}
	overall := "FAIL"
	if r.ok {
		overall = "PASS"
	}
	fmt.Fprintf(w, "overall  %s\n", overall)
}

// capProblems bounds a problem list so a hostile file with millions of broken lines cannot make
// the report itself unbounded. A verifier whose output an attacker can inflate without limit is
// a denial-of-service vector, so the tail is summarized rather than emitted in full.
func capProblems(problems []problem, limit int) []problem {
	if len(problems) <= limit {
		return problems
	}
	extra := len(problems) - limit
	capped := make([]problem, 0, limit+1)
	capped = append(capped, problems[:limit]...)
	capped = append(capped, problem{
		code:  problems[limit].code,
		text:  fmt.Sprintf("... and %d more findings suppressed", extra),
		fatal: true,
	})
	return capped
}

// firstN truncates s to at most n bytes for detail strings that must stay on one line.
func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "..."
}

// joinSemicolon joins parts with a semicolon and space, skipping empties, for one-line detail
// strings that already use commas internally.
func joinSemicolon(parts []string) string {
	kept := parts[:0:0]
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "; ")
}
