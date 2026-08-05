package main

// Canonicalization cu1 and the record hash material.
//
// canon walks a parsed value and re-emits it using the source lexemes captured by the
// tokenizer, sorting object members by their decoded key compared as a sequence of UTF-16 code
// units. Reusing lexemes is the design that lets this verifier reproduce the writer's canonical
// bytes without reimplementing ECMAScript number or string formatting; the format spec requires
// it and forbids reserializing parsed values.

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// canon writes the cu1 canonical form of v to dst and returns the extended slice.
func canon(dst []byte, v *jsonValue) []byte {
	switch v.kind {
	case kindNull, kindBool, kindNumber, kindString:
		// Scalars emit their exact source lexeme. Numbers keep whatever the writer produced,
		// so a rewrite that preserves numeric value but changes the bytes still changes the
		// hash and is caught.
		return append(dst, v.raw...)
	case kindArray:
		dst = append(dst, '[')
		for i, item := range v.arr {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = canon(dst, item)
		}
		return append(dst, ']')
	case kindObject:
		ordered := sortedMembers(v.obj)
		dst = append(dst, '{')
		for i := range ordered {
			if i > 0 {
				dst = append(dst, ',')
			}
			// The quoted key lexeme is emitted verbatim; only the ORDER of members is
			// canonical, never the key bytes themselves.
			dst = append(dst, ordered[i].keyRaw...)
			dst = append(dst, ':')
			dst = canon(dst, ordered[i].val)
		}
		return append(dst, '}')
	default:
		return dst
	}
}

// sortedMembers returns the members ordered ascending by decoded key, compared as UTF-16 code
// units. This is the one place a naive byte or locale comparison would be wrong: it is
// invisible for ASCII keys and diverges for mixed-case or non-ASCII keys, which is exactly the
// portability trap the format was changed to avoid.
func sortedMembers(members []member) []member {
	ordered := make([]member, len(members))
	copy(ordered, members)
	sort.SliceStable(ordered, func(i, j int) bool {
		return compareUTF16(ordered[i].keyUnits, ordered[j].keyUnits) < 0
	})
	return ordered
}

// compareUTF16 orders two UTF-16 code unit sequences lexicographically, which is the ordering
// JavaScript's < operator gives on strings. Comparing decoded runes or raw UTF-8 bytes would
// order supplementary-plane and some Latin-1 characters differently, so the code units are
// compared directly.
func compareUTF16(a, b []uint16) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := range n {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// canonicalPayload returns canon(E) where E is the record with its integrity member removed.
// The integrity member is dropped by decoded key so a smuggled second "integrity" key cannot
// leave a copy behind; duplicate keys are already rejected by the tokenizer, but the removal is
// written to be safe if that ever changes.
func canonicalPayload(record *jsonValue) []byte {
	stripped := &jsonValue{kind: kindObject}
	for i := range record.obj {
		if record.obj[i].key == "integrity" {
			continue
		}
		stripped.obj = append(stripped.obj, record.obj[i])
	}
	return canon(nil, stripped)
}

// hashMaterial assembles the exact bytes the writer hashed for a record, per format section
// 3.2: chainIndex as a base-10 integer, previousHash as the literal null or its quoted source
// lexeme, algorithm fixed to sha256, and the canonical payload embedded as a JSON string with
// only backslash and double quote escaped.
func hashMaterial(chainIndexBase10 string, previousHashLexeme []byte, payload []byte) []byte {
	buf := make([]byte, 0, len(payload)+len(previousHashLexeme)+64)
	buf = append(buf, `{"chainIndex":`...)
	buf = append(buf, chainIndexBase10...)
	buf = append(buf, `,"previousHash":`...)
	buf = append(buf, previousHashLexeme...)
	buf = append(buf, `,"algorithm":"sha256","payload":`...)
	buf = appendJSONStringOfJSON(buf, payload)
	buf = append(buf, '}')
	return buf
}

// appendJSONStringOfJSON wraps already-canonical JSON text as a JSON string value, escaping
// only backslash and double quote. The payload is itself JSON produced by canon, so it can
// never contain a raw control byte; escaping the two structural characters is therefore
// sufficient and matches how the writer embedded it.
func appendJSONStringOfJSON(dst, payload []byte) []byte {
	dst = append(dst, '"')
	for _, c := range payload {
		if c == '\\' || c == '"' {
			dst = append(dst, '\\')
		}
		dst = append(dst, c)
	}
	return append(dst, '"')
}

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
