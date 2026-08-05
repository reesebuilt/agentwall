package main

// Per-file hash chain verification, format section 3.3.
//
// A file is walked one line at a time. Each record's integrity.hash is recomputed from the
// record's own bytes under cu1 and compared; the chain index must advance by one and each
// previousHash must equal the prior record's stored hash. A final line that was torn by a hard
// kill is reported distinctly from a corrupt interior line, because a hard kill leaves exactly
// one partial trailing line and treating that normal event as tampering would cry wolf.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// problemCap bounds per-file findings. A file damaged by concurrent writers can produce one
// problem per record; without a cap a hostile file could make the report itself a memory sink.
const problemCap = 200

// chainGapAction is the action a writer puts on the record that declares it could not store
// records it produced. The value is part of the evidence format, not of this program, so it
// matches the writer's constant exactly; the two are held together by the format spec.
const chainGapAction = "audit:chain-gap"

type chainResult struct {
	records  int
	problems []problem
}

// verifyChainFile walks one JSONL segment or the live audit file.
func verifyChainFile(path string) chainResult {
	f, err := os.Open(path)
	if err != nil {
		return chainResult{problems: []problem{{code: codeBadJSON, text: fmt.Sprintf("%s: cannot open: %v", path, err), fatal: true}}}
	}
	defer f.Close()

	base := filepathBase(path)
	var problems []problem
	reader := bufio.NewReader(f)

	var have bool // a prior good record exists in this file
	var prevIndex int64
	var prevHash string
	records := 0
	lineNo := 0

	for {
		raw, rerr := reader.ReadBytes('\n')
		endWithoutNewline := rerr == io.EOF && len(raw) > 0 && !bytes.HasSuffix(raw, []byte{'\n'})
		line := trimEOL(raw)
		if len(bytes.TrimSpace(line)) == 0 {
			if rerr != nil {
				break
			}
			continue
		}
		lineNo++
		records++

		v, perr := parseLine(line)
		if perr != nil {
			if perr == errDupKey {
				problems = append(problems, problem{code: codeDupKey, text: fmt.Sprintf("%s line %d: object contains a duplicate key", base, lineNo), fatal: true})
			} else if endWithoutNewline {
				// The final line has no terminating newline and does not parse: the signature of
				// a process killed mid-append, not of an edit. Reported, but not fatal to the
				// chain, so a live crash does not read as corruption.
				problems = append(problems, problem{code: codeTornTail, text: fmt.Sprintf("%s line %d: final line is torn (no newline, does not parse); expected after a hard kill", base, lineNo), fatal: false})
			} else {
				problems = append(problems, problem{code: codeBadJSON, text: fmt.Sprintf("%s line %d: not valid JSON: %v", base, lineNo, perr), fatal: true})
			}
			if rerr != nil {
				break
			}
			continue
		}

		integ, ok := extractIntegrity(v)
		if !ok {
			problems = append(problems, problem{code: codeMissingIntegrity, text: fmt.Sprintf("%s line %d: missing or malformed integrity block", base, lineNo), fatal: true})
			if rerr != nil {
				break
			}
			continue
		}

		if !have {
			// First good record of the file. A null previousHash is only legitimate at index 0;
			// rotation resumes mid-sequence with a non-null previousHash, so a null link at a
			// nonzero index is a break.
			if integ.prevIsNull && integ.chainIndex != 0 {
				problems = append(problems, problem{code: codeLinkBreak, text: fmt.Sprintf("%s line %d: previousHash is null but chainIndex is %d (null is only valid at index 0)", base, lineNo, integ.chainIndex), fatal: true})
			}
		} else {
			if integ.chainIndex != prevIndex+1 {
				problems = append(problems, problem{code: codeIndexGap, text: fmt.Sprintf("%s line %d: chainIndex %d, expected %d (gap, restart, or reused index)", base, lineNo, integ.chainIndex, prevIndex+1), fatal: true})
			}
			if integ.prevIsNull || integ.previousHash != prevHash {
				problems = append(problems, problem{code: codeLinkBreak, text: fmt.Sprintf("%s line %d: previousHash does not link to the preceding record", base, lineNo), fatal: true})
			}
		}

		// Recompute the hash from the record's own lexemes under cu1.
		material := hashMaterial(strconv.FormatInt(integ.chainIndex, 10), integ.previousHashLexeme, canonicalPayload(v))
		got := sha256Hex(material)
		if got != integ.hash {
			if integ.canon == "cu1" {
				problems = append(problems, problem{code: codeHashMismatch, text: fmt.Sprintf("%s line %d: recomputed cu1 hash does not match integrity.hash; record altered after write", base, lineNo), fatal: true})
			} else {
				// Without a cu1 marker the record may be legacy (hashed under locale-collated key
				// order this verifier does not reproduce) or altered. It is reported in those
				// words because an independent verifier cannot tell the two apart.
				problems = append(problems, problem{code: codeHashMismatchOrLegacy, text: fmt.Sprintf("%s line %d: cu1 hash does not match; record is either altered or hashed under the legacy locale canon this verifier does not implement", base, lineNo), fatal: true})
			}
		}

		if action, ok := v.field("action"); ok && action.kind == kindString && action.str == chainGapAction {
			dropped := "an unstated number of"
			if meta, ok := v.field("metadata"); ok && meta.kind == kindObject {
				if n, ok := meta.field("droppedRecords"); ok && n.kind == kindString {
					dropped = n.str
				}
			}
			problems = append(problems, problem{code: codeChainGapDeclared, text: fmt.Sprintf("%s line %d: the writer recorded that %s record(s) could not be written here", base, lineNo, dropped), fatal: false})
		}

		have = true
		prevIndex = integ.chainIndex
		prevHash = integ.hash

		if rerr != nil {
			break
		}
	}

	problems = capProblems(problems, problemCap)
	return chainResult{records: records, problems: problems}
}

// integrityFields holds the four hash-bearing members of an integrity block plus the canon
// marker, keeping both the decoded values and the source lexemes the hash material needs.
type integrityFields struct {
	chainIndex         int64
	hash               string
	previousHash       string
	previousHashLexeme []byte
	prevIsNull         bool
	canon              string
}

// extractIntegrity reads and type-checks the integrity block. Any missing or wrong-typed member
// makes the record unverifiable, which is reported as missing-integrity rather than guessed at.
func extractIntegrity(record *jsonValue) (integrityFields, bool) {
	var out integrityFields
	if record == nil || record.kind != kindObject {
		return out, false
	}
	integ, ok := record.field("integrity")
	if !ok || integ.kind != kindObject {
		return out, false
	}

	ci, ok := integ.field("chainIndex")
	if !ok || ci.kind != kindNumber {
		return out, false
	}
	idx, err := parseChainIndex(ci.raw)
	if err != nil {
		return out, false
	}
	out.chainIndex = idx

	h, ok := integ.field("hash")
	if !ok || h.kind != kindString || !isHex64Lower(h.str) {
		return out, false
	}
	out.hash = h.str

	ph, ok := integ.field("previousHash")
	if !ok {
		return out, false
	}
	switch ph.kind {
	case kindNull:
		out.prevIsNull = true
		out.previousHashLexeme = []byte("null")
	case kindString:
		out.previousHash = ph.str
		out.previousHashLexeme = ph.raw
	default:
		return out, false
	}

	al, ok := integ.field("algorithm")
	if !ok || al.kind != kindString {
		return out, false
	}

	if c, ok := integ.field("canon"); ok && c.kind == kindString {
		out.canon = c.str
	}
	return out, true
}

// parseChainIndex reads a chain index from its source lexeme. An integer lexeme is taken as is;
// a value written with a fractional or exponent form is accepted only when it denotes an
// integer, so 5 and 5.0 mean the same index while 5.5 is rejected.
func parseChainIndex(raw []byte) (int64, error) {
	s := string(raw)
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	if f != float64(int64(f)) {
		return 0, fmt.Errorf("chainIndex %s is not an integer", s)
	}
	return int64(f), nil
}

// parseIntLexeme parses an integer-valued number lexeme, accepting the same integral forms as a
// chain index so a manifest count written as 10 or 10.0 reads the same.
func parseIntLexeme(raw []byte) (int64, bool) {
	n, err := parseChainIndex(raw)
	return n, err == nil
}

func isHex64Lower(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// trimEOL removes a single trailing CRLF or LF so a Windows-authored file verifies the same as
// a Unix one; the writer emits LF, but a copied file might carry CRLF.
func trimEOL(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte{'\n'})
	b = bytes.TrimSuffix(b, []byte{'\r'})
	return b
}

// filepathBase returns the last path element without importing path/filepath at call sites that
// only need a short label for messages.
func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
