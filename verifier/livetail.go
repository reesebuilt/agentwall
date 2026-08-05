package main

// Live-tail re-derivation for checkpoints, format section 3.5 plus the content-binding
// correction.
//
// A checkpoint commits, inside its composite hash, to the live file's final record hash and
// count and to the manifest head at signing time. Nothing else re-derives those values, so a
// live tail rewritten after signing would pass unnoticed: the off-box anchor would bind a
// checkpoint whose committed state no longer describes the file on disk. This reconstructs the
// composite from the current evidence and confirms it.
//
// A checkpoint binds state AS OF signing, and the live file legitimately grows and rotates
// afterward, so the committed records are a prefix of some segment file that exists now: the live
// file if it has not rotated, a closed segment if it has. Candidates are searched over every
// segment file on disk plus every manifest entry, so honest growth and rotation still reproduce
// while a rewritten prefix does not.
//
// This search is intentionally uncapped. It is linear in the local evidence the operator points
// the tool at, not in an attacker-controlled single blob, so a cap that turned "too big" into a
// mismatch would report tampering on a large honest deployment. The hostile-input caps live in
// the OTS parser, where the bytes of one small proof are attacker controlled.

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
)

// tailPair is one committed live-tail candidate: a final record hash and a record count.
type tailPair struct {
	finalHash string
	count     int64
}

// liveTailVerifier reconstructs and checks each checkpoint's committed live tail.
type liveTailVerifier struct {
	heads      []string   // sealed segment finalHashes in manifest order
	sources    [][]string // stored record hashes, per segment file on disk (live plus rotated)
	entryTails []tailPair // (finalHash, count) of each manifest entry, for rotated segments whose file may be absent
}

// newLiveTailVerifier gathers the candidate sources once so they can be reused across every
// checkpoint in the anchor log.
func newLiveTailVerifier(auditPath string, heads []string, entryTails []tailPair) *liveTailVerifier {
	var sources [][]string
	sources = append(sources, collectRecordHashes(auditPath))
	for _, rf := range discoverRotatedFiles(auditPath) {
		sources = append(sources, collectRecordHashes(rf))
	}
	return &liveTailVerifier{heads: heads, sources: sources, entryTails: entryTails}
}

// check reports whether the checkpoint's composite hash can be reproduced from the current
// manifest head and some committed live-tail candidate. Candidates are the null tail, every
// prefix of every segment file on disk, and every manifest entry's shape.
func (lt *liveTailVerifier) check(cf checkpointFields) bool {
	n := cf.chainIndex

	// The manifest head at signing is the newest of the first n sealed segments. The manifest is
	// append-only, so the first n entries are the ones that existed at signing.
	var headField string
	switch {
	case n == 0:
		headField = "null"
	case n > 0 && int64(len(lt.heads)) >= n:
		headField = `"` + lt.heads[n-1] + `"`
	default:
		// The checkpoint claims more sealed segments than the manifest now holds; the committed
		// state cannot be reconstructed, which is itself a mismatch.
		return false
	}

	want := cf.hashStr

	// The live tail may have been null at signing (segments anchored, no complete live record).
	if compositeHash(headField, n, "", 0, false) == want {
		return true
	}
	// The committed count is some prefix length of a segment file that existed at signing. After
	// rotation that file is a closed segment, so every segment file on disk is a candidate source.
	for _, hs := range lt.sources {
		for c := 1; c <= len(hs); c++ {
			if compositeHash(headField, n, hs[c-1], int64(c), true) == want {
				return true
			}
		}
	}
	// A rotated segment whose file is now absent is still recorded by its manifest entry, so the
	// entry's shape is a candidate too.
	for _, tp := range lt.entryTails {
		if compositeHash(headField, n, tp.finalHash, tp.count, true) == want {
			return true
		}
	}
	return false
}

// compositeHash reconstructs the checkpoint composite and returns its lowercase hex SHA-256. The
// member order is fixed by the writer: manifestHead, segments, liveTail, and inside liveTail
// finalHash then count. Integers are base-10 and hashes are quoted, matching the writer's
// serialization; there are no source lexemes to reuse because the composite is never stored as
// text, only as the hash a checkpoint carries.
func compositeHash(headField string, segments int64, tailFinalHash string, count int64, hasTail bool) string {
	var b []byte
	b = append(b, `{"manifestHead":`...)
	b = append(b, headField...)
	b = append(b, `,"segments":`...)
	b = append(b, strconv.FormatInt(segments, 10)...)
	b = append(b, `,"liveTail":`...)
	if hasTail {
		b = append(b, `{"finalHash":"`...)
		b = append(b, tailFinalHash...)
		b = append(b, `","count":`...)
		b = append(b, strconv.FormatInt(count, 10)...)
		b = append(b, '}')
	} else {
		b = append(b, `null`...)
	}
	b = append(b, '}')
	return sha256Hex(b)
}

// collectRecordHashes reads a segment file and returns its records' stored hashes in order.
// Unparseable or integrity-less lines are skipped, matching how the writer counts records.
func collectRecordHashes(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var hashes []string
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
		if v, perr := parseLine(line); perr == nil {
			if integ, ok := extractIntegrity(v); ok {
				hashes = append(hashes, integ.hash)
			}
		}
		if rerr != nil {
			break
		}
	}
	return hashes
}
