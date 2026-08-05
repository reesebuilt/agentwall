package main

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzRecordLine drives the tokenizer and canonicalizer on arbitrary bytes. The record files
// this tool reads are attacker-influenced, so parsing must never panic and canon must be
// deterministic: a verifier that can be crashed by its own input is an attack surface, and a
// nondeterministic canon would make the same file verify differently on different runs.
func FuzzRecordLine(f *testing.F) {
	seeds := []string{
		`{"a":1}`,
		`{"b":1,"a":2}`,
		`{"meta":{"z":1,"a":[1,2,3]},"n":-1.5e3}`,
		`{"u":"\uD83D\uDE00","Z":"x","a":"y"}`,
		`{"dup":1,"dup":2}`,
		`not json`,
		``,
		`[1,2,3]`,
		`"\u0000"`,
		`{"nested":{"deep":{"deeper":[{}]}}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := parseLine(data)
		if err != nil {
			return // malformed input is a valid outcome, not a crash
		}
		a := canon(nil, v)
		b := canon(nil, v)
		if !bytes.Equal(a, b) {
			t.Fatalf("canon is not deterministic for %q", data)
		}
		if v.kind == kindObject {
			// The payload and hash pipeline must also not panic on any parseable object.
			payload := canonicalPayload(v)
			_ = sha256Hex(hashMaterial("0", []byte("null"), payload))
		}
	})
}

// FuzzOTSProof drives the proof parser on arbitrary bytes. The proof file is attacker-controlled
// by definition, so the parser must never panic and must respect its caps rather than being
// driven into unbounded memory or recursion.
func FuzzOTSProof(f *testing.F) {
	f.Add(pendingProof(strings.Repeat("00", 32), "https://calendar.example.com/x"))
	f.Add(bitcoinProof(850000))
	f.Add([]byte{})
	f.Add([]byte{0xF0, 0x01, 0x41})
	f.Add([]byte{0xFF, 0x08, 0x00})
	f.Add(append(append([]byte{}, otsMagic...), 0x01, 0x08))

	digest := hexDigest(strings.Repeat("ab", 32))
	f.Fuzz(func(t *testing.T, data []byte) {
		// The only contract is: no panic, and it returns. Correctness of well-formed proofs is
		// covered by the unit tests; here we only defend against hostile bytes.
		_, _ = parseOTS(data, digest)
	})
}
