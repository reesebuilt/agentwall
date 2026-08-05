package main

// Strict RFC 8259 JSON tokenizer that preserves the raw source lexeme of every value.
//
// The whole verifier rests on one idea from the format spec: canonicalization reuses the
// record's own JSON lexemes instead of parsing values and serializing them again. So this
// tokenizer records, for each scalar, the exact bytes it occupied in the source line, and
// for each object member the exact quoted key lexeme alongside the decoded key. Nothing
// downstream reserializes a parsed value, which is why a Go verifier can reproduce a writer's
// ECMAScript number and string formatting without reimplementing it.
//
// It is deliberately strict: duplicate object keys are rejected (dup-key), trailing bytes
// after a value are rejected, raw control characters inside strings are rejected, and nesting
// is depth-capped. The files this tool reads are attacker-influenced by definition, so a
// tokenizer that could be driven into unbounded recursion by hostile input would itself be an
// attack surface.

import (
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// maxParseDepth bounds recursion so a deeply nested object or array cannot overflow the Go
// stack. A stack overflow aborts the whole process, which for a verifier means an attacker can
// suppress a verdict by nesting brackets; a bounded error keeps the verdict a verdict.
const maxParseDepth = 500

type valueKind int

const (
	kindNull valueKind = iota
	kindBool
	kindNumber
	kindString
	kindArray
	kindObject
)

// jsonValue is a parsed JSON value that remembers its source lexeme.
type jsonValue struct {
	kind valueKind
	// raw is the exact source lexeme for null, true, false, numbers, and strings. For strings
	// it includes the surrounding double quotes. Canonicalization emits these bytes verbatim.
	raw []byte
	// str is the decoded string value, set only for kindString. Used for object member lookup
	// and equality, never for hashing (hashing reuses raw).
	str string
	arr []*jsonValue
	obj []member
}

// member is one object entry, keeping both the quoted key lexeme and the decoded key.
type member struct {
	keyRaw   []byte   // quoted key lexeme, emitted verbatim by canon
	key      string   // decoded key, used for lookup and dup detection
	keyUnits []uint16 // decoded key as UTF-16 code units, used for the canonical sort order
	val      *jsonValue
}

// errDupKey marks a record malformed because one object carried the same key twice. Reported
// as problem code dup-key: a duplicate key lets a writer smuggle a value the reader ignores,
// so a document whose meaning depends on which duplicate wins is not a document we can attest.
var errDupKey = errors.New("dup-key")

type tokenizer struct {
	data []byte
	pos  int
}

// parseLine parses exactly one JSON value from the whole slice and rejects trailing bytes.
// The audit format is one JSON object per line, so anything after the value is corruption or a
// smuggled second document; either way the line is not a single well-formed record.
func parseLine(data []byte) (*jsonValue, error) {
	t := &tokenizer{data: data}
	t.skipWS()
	v, err := t.parseValue(0)
	if err != nil {
		return nil, err
	}
	t.skipWS()
	if t.pos != len(t.data) {
		return nil, fmt.Errorf("trailing bytes after JSON value at offset %d", t.pos)
	}
	return v, nil
}

func (t *tokenizer) parseValue(depth int) (*jsonValue, error) {
	if depth > maxParseDepth {
		return nil, fmt.Errorf("nesting exceeds depth cap %d", maxParseDepth)
	}
	if t.pos >= len(t.data) {
		return nil, errors.New("unexpected end of input")
	}
	c := t.data[t.pos]
	switch {
	case c == '{':
		return t.parseObject(depth)
	case c == '[':
		return t.parseArray(depth)
	case c == '"':
		start := t.pos
		s, _, err := t.parseString()
		if err != nil {
			return nil, err
		}
		return &jsonValue{kind: kindString, raw: t.data[start:t.pos], str: s}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return t.parseNumber()
	case c == 't':
		return t.parseLiteral("true", kindBool)
	case c == 'f':
		return t.parseLiteral("false", kindBool)
	case c == 'n':
		return t.parseLiteral("null", kindNull)
	default:
		return nil, fmt.Errorf("unexpected byte %q at offset %d", c, t.pos)
	}
}

func (t *tokenizer) parseObject(depth int) (*jsonValue, error) {
	t.pos++ // consume '{'
	v := &jsonValue{kind: kindObject}
	t.skipWS()
	if t.pos < len(t.data) && t.data[t.pos] == '}' {
		t.pos++
		return v, nil
	}
	// seen keeps decoded keys already used in THIS object so a duplicate is caught in one pass
	// rather than by an O(n^2) scan a hostile object with many keys could turn into a stall.
	seen := make(map[string]struct{})
	for {
		t.skipWS()
		if t.pos >= len(t.data) || t.data[t.pos] != '"' {
			return nil, errors.New("expected string key in object")
		}
		keyStart := t.pos
		key, units, err := t.parseString()
		if err != nil {
			return nil, err
		}
		keyRaw := t.data[keyStart:t.pos]
		if _, dup := seen[key]; dup {
			return nil, errDupKey
		}
		seen[key] = struct{}{}
		t.skipWS()
		if t.pos >= len(t.data) || t.data[t.pos] != ':' {
			return nil, errors.New("expected ':' after object key")
		}
		t.pos++ // consume ':'
		t.skipWS()
		val, err := t.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		v.obj = append(v.obj, member{keyRaw: keyRaw, key: key, keyUnits: units, val: val})
		t.skipWS()
		if t.pos >= len(t.data) {
			return nil, errors.New("unterminated object")
		}
		switch t.data[t.pos] {
		case ',':
			t.pos++
		case '}':
			t.pos++
			return v, nil
		default:
			return nil, fmt.Errorf("expected ',' or '}' in object at offset %d", t.pos)
		}
	}
}

func (t *tokenizer) parseArray(depth int) (*jsonValue, error) {
	t.pos++ // consume '['
	v := &jsonValue{kind: kindArray}
	t.skipWS()
	if t.pos < len(t.data) && t.data[t.pos] == ']' {
		t.pos++
		return v, nil
	}
	for {
		t.skipWS()
		item, err := t.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		v.arr = append(v.arr, item)
		t.skipWS()
		if t.pos >= len(t.data) {
			return nil, errors.New("unterminated array")
		}
		switch t.data[t.pos] {
		case ',':
			t.pos++
		case ']':
			t.pos++
			return v, nil
		default:
			return nil, fmt.Errorf("expected ',' or ']' in array at offset %d", t.pos)
		}
	}
}

// parseString consumes a JSON string starting at the opening quote and returns the decoded
// value plus its UTF-16 code units. The code units are what the canonical key order sorts on,
// so they are produced here from the same escape decoding rather than reconstructed later.
func (t *tokenizer) parseString() (string, []uint16, error) {
	if t.data[t.pos] != '"' {
		return "", nil, errors.New("expected '\"'")
	}
	t.pos++ // consume opening quote
	var units []uint16
	for t.pos < len(t.data) {
		c := t.data[t.pos]
		switch {
		case c == '"':
			t.pos++
			return string(utf16.Decode(units)), units, nil
		case c == '\\':
			t.pos++
			if t.pos >= len(t.data) {
				return "", nil, errors.New("unterminated escape in string")
			}
			e := t.data[t.pos]
			switch e {
			case '"':
				units = append(units, '"')
				t.pos++
			case '\\':
				units = append(units, '\\')
				t.pos++
			case '/':
				units = append(units, '/')
				t.pos++
			case 'b':
				units = append(units, '\b')
				t.pos++
			case 'f':
				units = append(units, '\f')
				t.pos++
			case 'n':
				units = append(units, '\n')
				t.pos++
			case 'r':
				units = append(units, '\r')
				t.pos++
			case 't':
				units = append(units, '\t')
				t.pos++
			case 'u':
				u, err := t.parseHex4()
				if err != nil {
					return "", nil, err
				}
				units = append(units, u)
			default:
				return "", nil, fmt.Errorf("invalid escape \\%c", e)
			}
		case c < 0x20:
			// RFC 8259 forbids literal control characters in strings; they must be escaped. A
			// raw control byte means the line was truncated or hand-mangled, not written by the
			// conforming serializer.
			return "", nil, fmt.Errorf("literal control byte 0x%02x in string", c)
		default:
			// Copy the raw UTF-8 bytes of this rune into the decoded units. utf16 encoding of a
			// rune below the surrogate range is the rune itself; higher runes become a pair.
			r, size := utf8.DecodeRune(t.data[t.pos:])
			if r == 0xFFFD && size == 1 {
				return "", nil, errors.New("invalid UTF-8 in string")
			}
			units = utf16.AppendRune(units, r)
			t.pos += size
		}
	}
	return "", nil, errors.New("unterminated string")
}

// parseHex4 reads exactly four hex digits after \u and returns the code unit. Surrogate pairs
// are left as separate units on purpose: the UTF-16 code unit sequence is precisely what the
// key comparator orders on, so pairing them into a rune here would discard the ordering signal.
func (t *tokenizer) parseHex4() (uint16, error) {
	if t.pos+5 > len(t.data) {
		return 0, errors.New("truncated \\u escape")
	}
	var u uint16
	for i := 1; i <= 4; i++ {
		d := t.data[t.pos+i]
		var nib uint16
		switch {
		case d >= '0' && d <= '9':
			nib = uint16(d - '0')
		case d >= 'a' && d <= 'f':
			nib = uint16(d-'a') + 10
		case d >= 'A' && d <= 'F':
			nib = uint16(d-'A') + 10
		default:
			return 0, fmt.Errorf("invalid hex digit %q in \\u escape", d)
		}
		u = u<<4 | nib
	}
	t.pos += 5 // consume 'u' and four hex digits
	return u, nil
}

// parseNumber scans a JSON number and keeps its exact lexeme. The value is never interpreted
// here; canonicalization reuses the lexeme, so an attacker who rewrites 1000 as 1e3 changes the
// bytes that get hashed and is caught, rather than being normalized away.
func (t *tokenizer) parseNumber() (*jsonValue, error) {
	start := t.pos
	if t.pos < len(t.data) && t.data[t.pos] == '-' {
		t.pos++
	}
	// integer part: single 0 or a nonzero digit followed by digits
	if t.pos >= len(t.data) {
		return nil, errors.New("truncated number")
	}
	if t.data[t.pos] == '0' {
		t.pos++
	} else if t.data[t.pos] >= '1' && t.data[t.pos] <= '9' {
		for t.pos < len(t.data) && isDigit(t.data[t.pos]) {
			t.pos++
		}
	} else {
		return nil, fmt.Errorf("invalid number at offset %d", start)
	}
	// fraction
	if t.pos < len(t.data) && t.data[t.pos] == '.' {
		t.pos++
		if t.pos >= len(t.data) || !isDigit(t.data[t.pos]) {
			return nil, errors.New("number missing fraction digits")
		}
		for t.pos < len(t.data) && isDigit(t.data[t.pos]) {
			t.pos++
		}
	}
	// exponent
	if t.pos < len(t.data) && (t.data[t.pos] == 'e' || t.data[t.pos] == 'E') {
		t.pos++
		if t.pos < len(t.data) && (t.data[t.pos] == '+' || t.data[t.pos] == '-') {
			t.pos++
		}
		if t.pos >= len(t.data) || !isDigit(t.data[t.pos]) {
			return nil, errors.New("number missing exponent digits")
		}
		for t.pos < len(t.data) && isDigit(t.data[t.pos]) {
			t.pos++
		}
	}
	return &jsonValue{kind: kindNumber, raw: t.data[start:t.pos]}, nil
}

func (t *tokenizer) parseLiteral(lit string, k valueKind) (*jsonValue, error) {
	if t.pos+len(lit) > len(t.data) || string(t.data[t.pos:t.pos+len(lit)]) != lit {
		return nil, fmt.Errorf("invalid literal at offset %d", t.pos)
	}
	start := t.pos
	t.pos += len(lit)
	return &jsonValue{kind: k, raw: t.data[start:t.pos]}, nil
}

func (t *tokenizer) skipWS() {
	for t.pos < len(t.data) {
		switch t.data[t.pos] {
		case ' ', '\t', '\n', '\r':
			t.pos++
		default:
			return
		}
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// field returns the member value for a decoded key. Object keys are unique after tokenizing, so
// a linear scan is exact and small objects make it cheap.
func (v *jsonValue) field(key string) (*jsonValue, bool) {
	if v == nil || v.kind != kindObject {
		return nil, false
	}
	for i := range v.obj {
		if v.obj[i].key == key {
			return v.obj[i].val, true
		}
	}
	return nil, false
}
