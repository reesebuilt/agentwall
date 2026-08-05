package main

// Rotation manifest linkage, format sections 3.4.
//
// The manifest turns the sequence of rotated segments into a hash chain one level up from the
// per-record chain: each entry carries the previous segment's final hash, so deleting or
// reordering a whole segment breaks the manifest even though every surviving segment still
// verifies on its own. An empty manifest with nothing to seal is a vacuous pass, but rotated
// files sitting on disk unsealed are a real failure: evidence that exists outside the anchor.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

type manifestResult struct {
	segments int
	head     string
	detail   string
	problems []problem
	// paths lists the resolved on-disk path of every sealed segment, so the chain layer can
	// walk them alongside the live file.
	paths []string
	// heads lists each sealed segment's finalHash in manifest order, so the anchored layer can
	// reconstruct the manifest head a checkpoint committed to.
	heads []string
	// entryTails lists each entry's (finalHash, count) so the anchored layer can offer a rotated
	// segment as a live-tail candidate even when its file is no longer on disk.
	entryTails []tailPair
}

// verifyManifest reads segments.jsonl beside the audit file, checks each entryHash and the
// segment-to-segment linkage, resolves relative paths against the manifest directory, and flags
// rotated files that were never sealed.
func verifyManifest(manifestPath, auditPath string) manifestResult {
	var res manifestResult
	dir := filepath.Dir(manifestPath)

	entries, manifestExists, perr := readManifestEntries(manifestPath)
	if perr != nil {
		res.problems = append(res.problems, *perr)
		return res
	}

	sealedBase := map[string]struct{}{}
	var prevFinal string
	for i, e := range entries {
		sealedBase[filepath.Base(e.path)] = struct{}{}

		// Recompute entryHash from the entry's own lexemes in the fixed member order. Reusing
		// lexemes means a rewritten count or path changes the bytes that were hashed and is
		// caught, without this verifier having to reproduce the writer's number formatting.
		material := manifestEntryMaterial(e)
		if sha256Hex(material) != e.entryHash {
			res.problems = append(res.problems, problem{code: codeManifestEntryHash, text: fmt.Sprintf("manifest entry %d (%s): entryHash does not match its contents", i, e.path), fatal: true})
		}

		if i == 0 {
			if !e.prevSegIsNull {
				res.problems = append(res.problems, problem{code: codeManifestLinkBreak, text: fmt.Sprintf("manifest entry 0 (%s): previousSegmentHash is not null", e.path), fatal: true})
			}
		} else if e.prevSegIsNull || e.previousSegmentHash != prevFinal {
			res.problems = append(res.problems, problem{code: codeManifestLinkBreak, text: fmt.Sprintf("manifest entry %d (%s): previousSegmentHash does not link to the prior segment's finalHash", i, e.path), fatal: true})
		}
		prevFinal = e.finalHash
		res.heads = append(res.heads, e.finalHash)
		res.entryTails = append(res.entryTails, tailPair{finalHash: e.finalHash, count: e.count})

		resolved := e.path
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(dir, resolved)
		}
		if !fileExists(resolved) {
			res.problems = append(res.problems, problem{code: codeSegmentMissing, text: fmt.Sprintf("manifest entry %d: %s is sealed in the manifest but missing from disk", i, e.path), fatal: true})
			continue
		}
		res.paths = append(res.paths, resolved)

		// Bind the segment's BYTES to the entry that names it. The manifest entry and its
		// entryHash only prove the entry is internally consistent; nothing above ties the entry
		// to the file's actual contents. Without this an attacker can rewrite an entire sealed
		// segment, relink it so its own chain verifies, and the anchored manifest still passes
		// because the anchor binds the manifest and the manifest binds only itself. Comparing the
		// segment's real summary against the committed values closes that hole.
		s := summarizeSegment(resolved)
		if !s.ok || s.count != e.count || s.firstIndex != e.firstIndex || s.lastIndex != e.lastIndex || s.finalHash != e.finalHash {
			res.problems = append(res.problems, problem{code: codeSegmentContentMismatch, text: fmt.Sprintf("manifest entry %d (%s): segment on disk does not match the committed count, index range, or final hash", i, e.path), fatal: true})
		}
	}

	res.segments = len(entries)
	if len(entries) > 0 {
		res.head = entries[len(entries)-1].finalHash
	}

	// Rotated files that exist beside the live file but are absent from the manifest sit outside
	// the anchor. Compared by base name so a manifest that stored relative paths still matches
	// files discovered by absolute path.
	unsealed := discoverRotatedFiles(auditPath)
	unsealedCount := 0
	for _, p := range unsealed {
		if _, ok := sealedBase[filepath.Base(p)]; !ok {
			unsealedCount++
		}
	}
	if unsealedCount > 0 {
		res.problems = append(res.problems, problem{code: codeSegmentUnsealed, text: fmt.Sprintf("%d rotated segment(s) on disk are not sealed into the manifest, so they sit outside the anchor", unsealedCount), fatal: true})
	}

	// Detail text for the human report.
	switch {
	case res.segments == 0 && unsealedCount == 0 && !manifestExists:
		res.detailSet("no manifest; no rotations yet, nothing to link")
	case res.segments == 0 && unsealedCount == 0:
		res.detailSet("no rotations yet, nothing to link")
	case res.segments == 0:
		res.detailSet(fmt.Sprintf("%d rotated segment(s) found, none sealed yet", unsealedCount))
	default:
		d := fmt.Sprintf("%d segment(s) linked, head %s", res.segments, firstN(res.head, 16))
		if unsealedCount > 0 {
			d += fmt.Sprintf(", %d unsealed", unsealedCount)
		}
		res.detailSet(d)
	}
	return res
}

// detailSet stashes the human detail string so the caller assembles the layer without
// recomputing it.
func (r *manifestResult) detailSet(s string) { r.detail = s }

type manifestEntry struct {
	path                string
	pathLexeme          []byte
	count               int64
	countLexeme         []byte
	firstIndex          int64
	firstIndexLexeme    []byte
	lastIndex           int64
	lastIndexLexeme     []byte
	finalHash           string
	finalHashLexeme     []byte
	previousSegmentHash string
	prevSegLexeme       []byte
	prevSegIsNull       bool
	sealedAtLexeme      []byte
	entryHash           string
}

// manifestEntryMaterial assembles the exact bytes hashed for a manifest entry, in the fixed
// member order path, count, firstIndex, lastIndex, finalHash, previousSegmentHash, sealedAt.
func manifestEntryMaterial(e manifestEntry) []byte {
	var b []byte
	b = append(b, `{"path":`...)
	b = append(b, e.pathLexeme...)
	b = append(b, `,"count":`...)
	b = append(b, e.countLexeme...)
	b = append(b, `,"firstIndex":`...)
	b = append(b, e.firstIndexLexeme...)
	b = append(b, `,"lastIndex":`...)
	b = append(b, e.lastIndexLexeme...)
	b = append(b, `,"finalHash":`...)
	b = append(b, e.finalHashLexeme...)
	b = append(b, `,"previousSegmentHash":`...)
	b = append(b, e.prevSegLexeme...)
	b = append(b, `,"sealedAt":`...)
	b = append(b, e.sealedAtLexeme...)
	b = append(b, '}')
	return b
}

// readManifestEntries parses every line of the manifest. A parse failure or a missing required
// member is a fatal bad-json finding; a manifest a verifier cannot read is not a manifest it can
// attest linkage over.
func readManifestEntries(manifestPath string) ([]manifestEntry, bool, *problem) {
	f, err := os.Open(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, &problem{code: codeBadJSON, text: fmt.Sprintf("cannot open manifest: %v", err), fatal: true}
	}
	defer f.Close()

	var entries []manifestEntry
	reader := bufio.NewReader(f)
	lineNo := 0
	for {
		raw, rerr := reader.ReadBytes('\n')
		line := trimEOL(raw)
		if len(bytes.TrimSpace(line)) == 0 {
			if rerr != nil {
				break
			}
			continue
		}
		lineNo++
		v, err := parseLine(line)
		if err != nil {
			return nil, true, &problem{code: codeBadJSON, text: fmt.Sprintf("manifest line %d is not valid JSON: %v", lineNo, err), fatal: true}
		}
		e, ok := extractManifestEntry(v)
		if !ok {
			return nil, true, &problem{code: codeBadJSON, text: fmt.Sprintf("manifest line %d is missing required members", lineNo), fatal: true}
		}
		entries = append(entries, e)
		if rerr != nil {
			break
		}
	}
	return entries, true, nil
}

func extractManifestEntry(v *jsonValue) (manifestEntry, bool) {
	var e manifestEntry
	if v == nil || v.kind != kindObject {
		return e, false
	}
	get := func(k string, want valueKind) (*jsonValue, bool) {
		m, ok := v.field(k)
		if !ok || m.kind != want {
			return nil, false
		}
		return m, true
	}
	p, ok := get("path", kindString)
	if !ok {
		return e, false
	}
	e.path, e.pathLexeme = p.str, p.raw
	c, ok := get("count", kindNumber)
	if !ok {
		return e, false
	}
	e.countLexeme = c.raw
	if e.count, ok = parseIntLexeme(c.raw); !ok {
		return e, false
	}
	fi, ok := get("firstIndex", kindNumber)
	if !ok {
		return e, false
	}
	e.firstIndexLexeme = fi.raw
	if e.firstIndex, ok = parseIntLexeme(fi.raw); !ok {
		return e, false
	}
	li, ok := get("lastIndex", kindNumber)
	if !ok {
		return e, false
	}
	e.lastIndexLexeme = li.raw
	if e.lastIndex, ok = parseIntLexeme(li.raw); !ok {
		return e, false
	}
	fh, ok := get("finalHash", kindString)
	if !ok {
		return e, false
	}
	e.finalHash, e.finalHashLexeme = fh.str, fh.raw
	ps, ok := v.field("previousSegmentHash")
	if !ok {
		return e, false
	}
	switch ps.kind {
	case kindNull:
		e.prevSegIsNull = true
		e.prevSegLexeme = []byte("null")
	case kindString:
		e.previousSegmentHash, e.prevSegLexeme = ps.str, ps.raw
	default:
		return e, false
	}
	sa, ok := get("sealedAt", kindString)
	if !ok {
		return e, false
	}
	e.sealedAtLexeme = sa.raw
	eh, ok := get("entryHash", kindString)
	if !ok {
		return e, false
	}
	e.entryHash = eh.str
	return e, true
}

// discoverRotatedFiles returns closed segment files beside the live audit file. Closed means
// rotated out, named liveBase followed by a dot and a suffix, and not a lock file. A candidate
// counts only if its first record parses and carries an integrity block, matching how the
// writer decides a file is a sealable segment.
func discoverRotatedFiles(auditPath string) []string {
	dir := filepath.Dir(auditPath)
	base := filepath.Base(auditPath)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	prefix := base + "."
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
			continue
		}
		if len(name) >= 5 && name[len(name)-5:] == ".lock" {
			continue
		}
		full := filepath.Join(dir, name)
		if looksLikeSegment(full) {
			out = append(out, full)
		}
	}
	return out
}

// looksLikeSegment reports whether a file's first non-empty line is a record with an integrity
// block. Only the first record is inspected so a large or hostile file cannot turn this scan
// into a stall.
func looksLikeSegment(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	for {
		raw, rerr := reader.ReadBytes('\n')
		line := trimEOL(raw)
		if len(bytes.TrimSpace(line)) == 0 {
			if rerr != nil {
				return false
			}
			continue
		}
		v, err := parseLine(line)
		if err != nil {
			return false
		}
		_, ok := v.field("integrity")
		return ok
	}
}

// segSummary is a sealed segment's shape: how many records it holds, its index range, and its
// last record's stored hash. It is what a manifest entry commits to, so recomputing it from the
// file lets the linked layer bind the entry to the bytes.
type segSummary struct {
	count      int64
	firstIndex int64
	lastIndex  int64
	finalHash  string
	ok         bool
}

// summarizeSegment reads a segment and derives its summary. Unparseable or integrity-less lines
// are skipped, matching how a segment is sealed: a hard kill can leave one partial trailing line
// that is not a sealed record.
func summarizeSegment(path string) segSummary {
	var s segSummary
	f, err := os.Open(path)
	if err != nil {
		return s
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	for {
		raw, rerr := reader.ReadBytes('\n')
		line := trimEOL(raw)
		if len(bytes.TrimSpace(line)) == 0 {
			if rerr != nil {
				break
			}
			continue
		}
		v, perr := parseLine(line)
		if perr != nil {
			if rerr != nil {
				break
			}
			continue
		}
		integ, ok := extractIntegrity(v)
		if !ok {
			if rerr != nil {
				break
			}
			continue
		}
		if !s.ok {
			s.firstIndex = integ.chainIndex
			s.ok = true
		}
		s.lastIndex = integ.chainIndex
		s.finalHash = integ.hash
		s.count++
		if rerr != nil {
			break
		}
	}
	return s
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
