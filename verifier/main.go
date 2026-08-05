package main

// agentwall-verify: an independent verifier for AgentWall audit evidence.
//
// It shares no code with the bundled TypeScript verifier and depends on nothing outside the Go
// standard library, so agreement between the two is evidence about the FORMAT rather than about a
// shared runtime. It reads the per-record hash chain, the rotation manifest linkage, the Ed25519
// checkpoint signatures, and the OpenTimestamps proof structure, and reports the three layers
// separately. It reads no environment, performs no network IO, and never writes a file.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const usageText = `agentwall-verify verifies AgentWall audit evidence.

usage:
  agentwall-verify --audit <path> [--manifest <path>] [--anchors <path>] [--proofs <dir>]
                   [--pubkey <base64-spki> | --pubkey-file <path>] [--json] [--version]

Defaults resolve beside the audit file: segments.jsonl, anchors.jsonl, and proofs/.
Exit codes: 0 all layers verified, 1 verification failure or incomplete evidence, 2 usage or IO error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point. It returns the process exit code so tests can assert exit
// codes without spawning a subprocess.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agentwall-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }

	auditPath := fs.String("audit", "", "path to the audit JSONL file (required)")
	manifestPath := fs.String("manifest", "", "path to the rotation manifest (default segments.jsonl beside audit)")
	anchorsPath := fs.String("anchors", "", "path to the anchor log (default anchors.jsonl beside audit)")
	proofsDir := fs.String("proofs", "", "directory of OTS proof files (default proofs/ beside audit)")
	pubkey := fs.String("pubkey", "", "base64 SPKI public key to pin checkpoints to")
	pubkeyFile := fs.String("pubkey-file", "", "file containing a public key to pin checkpoints to")
	jsonOut := fs.Bool("json", false, "emit JSON instead of human-readable output")
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		// flag already printed the error and usage to stderr. A usage error is exit 2.
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "%s %s\n", verifierName, verifierVersion)
		return 0
	}

	if *auditPath == "" {
		fmt.Fprintln(stderr, "error: --audit is required")
		fs.Usage()
		return 2
	}
	if *pubkey != "" && *pubkeyFile != "" {
		fmt.Fprintln(stderr, "error: pass at most one of --pubkey or --pubkey-file")
		return 2
	}
	if !fileExists(*auditPath) {
		fmt.Fprintf(stderr, "error: audit file %q not found\n", *auditPath)
		return 2
	}

	pin, err := loadPin(*pubkey, *pubkeyFile)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	dir := filepath.Dir(*auditPath)
	resolved := func(v, def string) string {
		if v != "" {
			return v
		}
		return filepath.Join(dir, def)
	}
	mPath := resolved(*manifestPath, "segments.jsonl")
	aPath := resolved(*anchorsPath, "anchors.jsonl")
	pDir := resolved(*proofsDir, "proofs")

	rep := verify(*auditPath, mPath, aPath, pDir, filepath.Dir(aPath), pin)

	if *jsonOut {
		if err := rep.writeJSON(stdout); err != nil {
			fmt.Fprintf(stderr, "error writing JSON: %v\n", err)
			return 2
		}
	} else {
		rep.writeHuman(stdout)
	}

	if rep.ok {
		return 0
	}
	return 1
}

// verify assembles the three layers. The manifest is read first because it names the sealed
// segments the chain layer must walk alongside the live file.
func verify(auditPath, manifestPath, anchorsPath, proofsDir, anchorsDir string, pin *pinnedKey) *report {
	m := verifyManifest(manifestPath, auditPath)

	// Layer 1, chained: the live audit file plus every sealed segment that exists on disk. A
	// segment sealed in the manifest but missing from disk is reported by the linked layer, not
	// here, so the chain layer walks only files it can read.
	var chainProblems []problem
	totalRecords := 0
	segCount := 0
	for _, p := range append(append([]string{}, m.paths...), auditPath) {
		segCount++
		cr := verifyChainFile(p)
		totalRecords += cr.records
		chainProblems = append(chainProblems, cr.problems...)
	}
	chainProblems = capProblems(chainProblems, problemCap)
	chained := layer{
		name:     "chained",
		detail:   fmt.Sprintf("%d records across %d segment(s)", totalRecords, segCount),
		problems: chainProblems,
	}
	chained.ok = !chained.hasFatal()

	// Layer 2, linked: segment-to-segment manifest linkage. An empty manifest with nothing to
	// seal is a vacuous pass; rotated files sitting unsealed are a real failure.
	linked := layer{
		name:     "linked",
		detail:   m.detail,
		problems: m.problems,
	}
	linked.ok = !linked.hasFatal()

	// Layer 3, anchored: checkpoint signatures and off-box anchor state. Exit 0 requires at least
	// one non-failed anchor with a structurally valid proof and a valid signature, because
	// internal consistency alone is not the product's claim.
	a := verifyAnchors(anchorsPath, proofsDir, anchorsDir, auditPath, m.heads, m.entryTails, pin)
	anchored := layer{
		name:     "anchored",
		detail:   a.detail,
		problems: a.problems,
	}
	anchored.ok = !anchored.hasFatal() && a.qualifying > 0

	rep := &report{
		layers:    []layer{chained, linked, anchored},
		pending:   a.pending,
		confirmed: a.confirmed,
		failed:    a.failed,
	}
	rep.ok = chained.ok && linked.ok && anchored.ok
	if pin == nil && a.checkpointsChecked > 0 {
		// Without a pin the signature check only proves each checkpoint is signed by whatever key
		// it carries, which a forger controls. Say so rather than let a pass imply authorship.
		rep.note = "signatures are self-consistent; supply --pubkey to bind them to a key you expect"
	}
	return rep
}
