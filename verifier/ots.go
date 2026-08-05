package main

// OpenTimestamps proof parsing, format section 3.7.
//
// A proof file is either a full .ots file (magic header, version, file hash-op, digest, then an
// ops stream) or a raw calendar response (an ops stream that applies directly to the submitted
// digest). Starting from the anchor record's digest, the ops are applied and attestations are
// collected. A pending attestation is reported as pending with its calendar URI and never as
// proof; a Bitcoin attestation is reported with its block height and the derived value, with the
// report stating that confirming inclusion requires a Bitcoin source this offline tool does not
// fetch.
//
// The file being parsed is attacker-influenced by definition, so every length here is bounded. A
// verifier that its own input can drive into unbounded memory or recursion is itself an attack
// surface: an adversary would only need to hand it a hostile proof to suppress a verdict. The
// caps below make a hostile proof fail fast instead of wedging the process.

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

const (
	otsMaxFileSize  = 1 << 20 // total proof bytes; a proof is a short merkle path, never this large
	otsMaxVarBytes  = 4096    // one append, prepend, or attestation payload
	otsMaxDepth     = 256     // fork and op nesting
	otsMaxOps       = 4096    // total ops across all branches
	otsMaxAtt       = 256     // total attestations collected
	otsMaxMsgLen    = 1 << 16 // working message length; bounds append and hexlify growth
	otsMaxVarintLen = 9       // varint bytes, holding up to a 63-bit value
)

// otsMagic is the 31-byte header of a full .ots file.
var otsMagic = []byte{
	0x00, 0x4F, 0x70, 0x65, 0x6E, 0x54, 0x69, 0x6D, 0x65, 0x73, 0x74, 0x61, 0x6D, 0x70, 0x73,
	0x00, 0x00, 0x50, 0x72, 0x6F, 0x6F, 0x66, 0x00, 0xBF, 0x89, 0xE2, 0xE8, 0x84, 0xE8, 0x92, 0x94,
}

var (
	tagPending = []byte{0x83, 0xDF, 0xE3, 0x0D, 0x2E, 0xF9, 0x0C, 0x8E}
	tagBitcoin = []byte{0x05, 0x88, 0x96, 0x0D, 0x73, 0xD7, 0x19, 0x01}
)

type attestation struct {
	kind   string // "pending" or "bitcoin"
	uri    string // pending calendar URI
	height uint64 // bitcoin block height
	value  []byte // bitcoin derived value at the leaf message
}

type otsReader struct {
	data []byte
	pos  int
	ops  int
	atts int
}

func (r *otsReader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("unexpected end of proof")
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *otsReader) readBytes(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.data) {
		return nil, errors.New("proof truncated")
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

// varint reads an unsigned little-endian base-128 integer, high bit as continuation. Its byte
// count is capped so a hostile file cannot supply an endless run of continuation bytes.
func (r *otsReader) varint() (uint64, error) {
	var result uint64
	var shift uint
	for i := 0; ; i++ {
		if i >= otsMaxVarintLen {
			return 0, errors.New("varint exceeds length cap")
		}
		b, err := r.readByte()
		if err != nil {
			return 0, err
		}
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result, nil
}

// varbytes reads a length then that many bytes, with the length capped so a single field cannot
// name a buffer larger than any legitimate proof element.
func (r *otsReader) varbytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if n > otsMaxVarBytes {
		return nil, fmt.Errorf("varbytes length %d exceeds cap %d", n, otsMaxVarBytes)
	}
	return r.readBytes(int(n))
}

// parseOTSFile reads a proof file and returns its attestations. digest is the anchor record's
// submitted digest, the message the ops stream applies to.
func parseOTSFile(path string, digest []byte) ([]attestation, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > otsMaxFileSize {
		return nil, fmt.Errorf("proof file is %d bytes, exceeding the %d byte cap", info.Size(), otsMaxFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseOTS(data, digest)
}

// parseOTS parses proof bytes given the starting message.
func parseOTS(data, digest []byte) ([]attestation, error) {
	r := &otsReader{data: data}
	if len(data) >= len(otsMagic) && equalBytes(data[:len(otsMagic)], otsMagic) {
		// Full .ots file: skip the header, version varint, file hash-op tag, and its digest to
		// reach the ops stream. The ops still apply to the anchor record's digest.
		r.pos = len(otsMagic)
		if _, err := r.varint(); err != nil { // version
			return nil, err
		}
		tag, err := r.readByte() // file hash-op
		if err != nil {
			return nil, err
		}
		dlen, err := hashOpDigestLen(tag)
		if err != nil {
			return nil, err
		}
		if _, err := r.readBytes(dlen); err != nil { // embedded file digest
			return nil, err
		}
	}

	msg := make([]byte, len(digest))
	copy(msg, digest)

	var atts []attestation
	if err := r.parseTimestamp(msg, 0, &atts); err != nil {
		return nil, err
	}
	if r.pos != len(r.data) {
		return nil, fmt.Errorf("%d trailing bytes after timestamp", len(r.data)-r.pos)
	}
	return atts, nil
}

// parseTimestamp parses one timestamp node: a run of fork edges (each prefixed 0xFF) followed by
// one final edge. Fork branches operate on independent copies of the message so one branch
// cannot corrupt another.
func (r *otsReader) parseTimestamp(msg []byte, depth int, atts *[]attestation) error {
	if depth > otsMaxDepth {
		return errors.New("proof nesting exceeds depth cap")
	}
	for {
		tag, err := r.readByte()
		if err != nil {
			return err
		}
		if tag == 0xFF {
			edgeTag, err := r.readByte()
			if err != nil {
				return err
			}
			branch := make([]byte, len(msg))
			copy(branch, msg)
			if err := r.parseEdge(edgeTag, branch, depth, atts); err != nil {
				return err
			}
			continue
		}
		return r.parseEdge(tag, msg, depth, atts)
	}
}

// parseEdge handles one edge: an attestation leaf (tag 0x00) or an operation whose result feeds
// a child timestamp.
func (r *otsReader) parseEdge(tag byte, msg []byte, depth int, atts *[]attestation) error {
	if tag == 0x00 {
		return r.parseAttestation(msg, atts)
	}
	next, err := r.applyOp(tag, msg)
	if err != nil {
		return err
	}
	return r.parseTimestamp(next, depth+1, atts)
}

// applyOp applies one operation to the message. Growth operations are bounded so a chain of
// appends or hexlifies cannot balloon memory.
func (r *otsReader) applyOp(tag byte, msg []byte) ([]byte, error) {
	r.ops++
	if r.ops > otsMaxOps {
		return nil, errors.New("proof exceeds operation cap")
	}
	switch tag {
	case 0xF0: // append
		arg, err := r.varbytes()
		if err != nil {
			return nil, err
		}
		out := make([]byte, 0, len(msg)+len(arg))
		out = append(out, msg...)
		out = append(out, arg...)
		return capMsg(out)
	case 0xF1: // prepend
		arg, err := r.varbytes()
		if err != nil {
			return nil, err
		}
		out := make([]byte, 0, len(arg)+len(msg))
		out = append(out, arg...)
		out = append(out, msg...)
		return capMsg(out)
	case 0xF2: // reverse
		out := make([]byte, len(msg))
		for i := range msg {
			out[len(msg)-1-i] = msg[i]
		}
		return out, nil
	case 0xF3: // hexlify
		out := []byte(hex.EncodeToString(msg))
		return capMsg(out)
	case 0x02: // sha1
		sum := sha1.Sum(msg)
		return sum[:], nil
	case 0x08: // sha256
		sum := sha256.Sum256(msg)
		return sum[:], nil
	case 0x03: // ripemd160
		// Not evaluated: the Go standard library has no ripemd160, and implementing an
		// unreviewed hash primitive inside a tool whose value is being trustworthy is a worse
		// trade than declining. A proof that needs it is reported unverifiable here.
		return nil, errors.New("ripemd160 op is not supported by this verifier")
	case 0x67: // keccak256
		// Not evaluated for the same reason as ripemd160: no standard-library primitive, and
		// hand-rolling one in a verifier invites the review finding this tool exists to avoid.
		return nil, errors.New("keccak256 op is not supported by this verifier")
	default:
		return nil, fmt.Errorf("unknown op tag 0x%02x", tag)
	}
}

func capMsg(b []byte) ([]byte, error) {
	if len(b) > otsMaxMsgLen {
		return nil, fmt.Errorf("proof message grew past %d bytes", otsMaxMsgLen)
	}
	return b, nil
}

// parseAttestation reads an attestation: eight tag bytes then a varbytes payload. Pending and
// Bitcoin attestations are decoded; any other attestation type is skipped so an unknown future
// type is ignored rather than treated as corruption.
func (r *otsReader) parseAttestation(msg []byte, atts *[]attestation) error {
	r.atts++
	if r.atts > otsMaxAtt {
		return errors.New("proof exceeds attestation cap")
	}
	tag, err := r.readBytes(8)
	if err != nil {
		return err
	}
	payload, err := r.varbytes()
	if err != nil {
		return err
	}
	switch {
	case equalBytes(tag, tagPending):
		sub := &otsReader{data: payload}
		uri, err := sub.varbytes()
		if err != nil {
			return err
		}
		*atts = append(*atts, attestation{kind: "pending", uri: string(uri)})
	case equalBytes(tag, tagBitcoin):
		sub := &otsReader{data: payload}
		height, err := sub.varint()
		if err != nil {
			return err
		}
		val := make([]byte, len(msg))
		copy(val, msg)
		*atts = append(*atts, attestation{kind: "bitcoin", height: height, value: val})
	default:
		// Unknown attestation type: payload already consumed, nothing collected.
	}
	return nil
}

func hashOpDigestLen(tag byte) (int, error) {
	switch tag {
	case 0x02: // sha1
		return 20, nil
	case 0x03: // ripemd160
		return 20, nil
	case 0x08: // sha256
		return 32, nil
	default:
		return 0, fmt.Errorf("unknown file hash-op tag 0x%02x", tag)
	}
}

// summarizeAttestations renders a compact, honest one-line summary. A pending attestation is
// named as pending, and a Bitcoin attestation states that inclusion still needs a block source.
func summarizeAttestations(atts []attestation) string {
	var parts []string
	for _, a := range atts {
		switch a.kind {
		case "pending":
			parts = append(parts, fmt.Sprintf("pending at %s", a.uri))
		case "bitcoin":
			parts = append(parts, fmt.Sprintf("bitcoin height %d (derived %s; compare with the block merkle root from a Bitcoin source to confirm inclusion, which this offline verifier does not fetch)", a.height, firstN(hex.EncodeToString(a.value), 16)))
		}
	}
	return joinSemicolon(parts)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
