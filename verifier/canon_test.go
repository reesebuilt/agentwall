package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func mustParse(t *testing.T, s string) *jsonValue {
	t.Helper()
	v, err := parseLine([]byte(s))
	if err != nil {
		t.Fatalf("parseLine(%q) failed: %v", s, err)
	}
	return v
}

func TestCanonSortsTopLevelKeys(t *testing.T) {
	// Reordering members must not change the canonical form: the canonical order is by key, not
	// by the order the writer happened to emit.
	got := string(canon(nil, mustParse(t, `{"meta":{"b":1,"a":2},"action":"deny"}`)))
	want := `{"action":"deny","meta":{"a":2,"b":1}}`
	if got != want {
		t.Fatalf("canon = %q, want %q", got, want)
	}
}

func TestCanonKeyOrderIndependence(t *testing.T) {
	// {b,a} and {a,b} canonicalize identically, so they hash identically.
	a := string(canon(nil, mustParse(t, `{"b":1,"a":2}`)))
	b := string(canon(nil, mustParse(t, `{"a":2,"b":1}`)))
	if a != b {
		t.Fatalf("key order changed canonical form: %q vs %q", a, b)
	}
	if a != `{"a":2,"b":1}` {
		t.Fatalf("canon = %q, want %q", a, `{"a":2,"b":1}`)
	}
}

func TestCanonMixedCaseIsCodeUnitOrder(t *testing.T) {
	// Under UTF-16 code unit order 'Z' (0x5A) precedes 'a' (0x61), which a locale-aware sort
	// would get wrong. This is the single most important comparator behavior and is invisible
	// for same-case ASCII, so it is asserted directly.
	got := string(canon(nil, mustParse(t, `{"apple":1,"Zebra":2}`)))
	want := `{"Zebra":2,"apple":1}`
	if got != want {
		t.Fatalf("canon = %q, want %q", got, want)
	}
}

func TestCanonNonASCIIOrder(t *testing.T) {
	// 'z' (U+007A) precedes 'e-acute' (U+00E9) by code unit, which byte order on the UTF-8
	// encoding would also get right, but a locale collation might not.
	got := string(canon(nil, mustParse(t, "{\"\u00e9\":1,\"z\":2}")))
	want := "{\"z\":2,\"\u00e9\":1}"
	if got != want {
		t.Fatalf("canon = %q, want %q", got, want)
	}
}

func TestCanonSupplementaryPlaneOrder(t *testing.T) {
	// A supplementary-plane character encodes to a surrogate pair whose first unit (0xD83D for
	// U+1F600) is below U+FFFF, so it must sort before a key of U+FFFF. Comparing decoded runes
	// instead of code units would order these the other way.
	got := string(canon(nil, mustParse(t, "{\"\\uffff\":1,\"\U0001F600\":2}")))
	want := "{\"\U0001F600\":2,\"\\uffff\":1}"
	if got != want {
		t.Fatalf("canon = %q, want %q", got, want)
	}
}

func TestCanonPreservesArrayOrderAndLexemes(t *testing.T) {
	// Arrays keep order and every scalar keeps its exact source lexeme, including number forms.
	got := string(canon(nil, mustParse(t, `{"xs":[3,1,2],"n":1.50,"e":1e3,"s":"a\"b"}`)))
	want := `{"e":1e3,"n":1.50,"s":"a\"b","xs":[3,1,2]}`
	if got != want {
		t.Fatalf("canon = %q, want %q", got, want)
	}
}

func TestHashMaterialSkeleton(t *testing.T) {
	// The hash material skeleton is fixed by the format. This asserts the exact bytes, so a
	// change to the skeleton is caught rather than silently rehashing every record.
	canonBytes := []byte(`{"action":"deny","meta":{"a":2,"b":1}}`)
	got := string(hashMaterial("0", []byte("null"), canonBytes))
	want := `{"chainIndex":0,"previousHash":null,"algorithm":"sha256","payload":"{\"action\":\"deny\",\"meta\":{\"a\":2,\"b\":1}}"}`
	if got != want {
		t.Fatalf("hashMaterial = %q, want %q", got, want)
	}
}

func TestHashMaterialWithPreviousHashLexeme(t *testing.T) {
	// A non-null previousHash is embedded as its quoted source lexeme, not reformatted.
	got := string(hashMaterial("7", []byte(`"abc123"`), []byte(`{"k":1}`)))
	want := `{"chainIndex":7,"previousHash":"abc123","algorithm":"sha256","payload":"{\"k\":1}"}`
	if got != want {
		t.Fatalf("hashMaterial = %q, want %q", got, want)
	}
}

func TestHashMatchesIndependentSHA(t *testing.T) {
	// The final hash is SHA-256 of the material bytes. The expected value here is computed over a
	// hand-written material literal, independent of the canon code path, so the whole pipeline is
	// pinned to the spec rather than to itself.
	material := `{"chainIndex":0,"previousHash":null,"algorithm":"sha256","payload":"{\"action\":\"deny\",\"meta\":{\"a\":2,\"b\":1}}"}`
	sum := sha256.Sum256([]byte(material))
	want := hex.EncodeToString(sum[:])

	got := sha256Hex(hashMaterial("0", []byte("null"), []byte(`{"action":"deny","meta":{"a":2,"b":1}}`)))
	if got != want {
		t.Fatalf("sha256Hex(hashMaterial) = %s, want %s", got, want)
	}
}

func TestParseRejectsDuplicateKeys(t *testing.T) {
	_, err := parseLine([]byte(`{"a":1,"a":2}`))
	if err != errDupKey {
		t.Fatalf("expected errDupKey, got %v", err)
	}
}

func TestParseRejectsTrailingBytes(t *testing.T) {
	for _, s := range []string{`{} x`, `1 2`, `{"a":1}{"b":2}`, `true false`} {
		if _, err := parseLine([]byte(s)); err == nil {
			t.Fatalf("expected trailing-byte error for %q", s)
		}
	}
}

func TestParseRejectsControlByteInString(t *testing.T) {
	if _, err := parseLine([]byte("\"a\x01b\"")); err == nil {
		t.Fatal("expected error on literal control byte in string")
	}
}

func TestParseRejectsBadNumbers(t *testing.T) {
	for _, s := range []string{`01`, `1.`, `.5`, `1e`, `-`, `+1`, `1.2.3`} {
		if _, err := parseLine([]byte(s)); err == nil {
			t.Fatalf("expected error for malformed number %q", s)
		}
	}
}
