package main

// Checkpoint signatures and anchor state, format sections 3.5 and 3.6.
//
// Each anchor record embeds the checkpoint it anchored. This layer recomputes the anchor digest
// from the checkpoint's own lexemes and checks it against the digest the record claims to have
// submitted, verifies the checkpoint's Ed25519 signature against the key embedded in it, and,
// when a key is pinned, additionally requires that embedded key to be the one expected. Without
// a pin the signature check only proves the record is self-consistent, which any forger can
// satisfy by signing with their own key; the report says so in those words.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// pinnedKey is the operator-supplied public key an anchor's embedded key must match. It is
// stored as decoded SPKI DER so the comparison does not depend on base64 formatting.
type pinnedKey struct {
	der []byte
}

type anchorLayerResult struct {
	pending            int
	confirmed          int
	failed             int
	qualifying         int
	checkpointsChecked int
	detail             string
	problems           []problem
}

// verifyAnchors reads anchors.jsonl and evaluates every anchor record. auditPath, heads, and
// entryTails let each checkpoint's committed live tail be re-derived from the evidence on disk.
func verifyAnchors(anchorsPath, proofsDir, anchorsDir, auditPath string, heads []string, entryTails []tailPair, pin *pinnedKey) anchorLayerResult {
	var res anchorLayerResult

	f, err := os.Open(anchorsPath)
	if err != nil {
		// No anchor log means nothing has been anchored off-box yet. That is honest state, not
		// an error: internal consistency is real but it is not the product's whole claim, so the
		// layer stays not-ok and the overall run exits nonzero.
		res.detail = "nothing anchored off-box yet"
		return res
	}
	defer f.Close()

	// The live tail is searched for across every segment file on disk and every manifest entry,
	// so growth and rotation after signing still reproduce while a rewritten prefix does not.
	ltv := newLiveTailVerifier(auditPath, heads, entryTails)

	var summaries []string
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

		v, perr := parseLine(line)
		if perr != nil {
			res.problems = append(res.problems, problem{code: codeBadJSON, text: fmt.Sprintf("anchor log line %d is not valid JSON: %v", lineNo, perr), fatal: true})
			if rerr != nil {
				break
			}
			continue
		}

		summary := res.evaluateAnchor(v, lineNo, proofsDir, anchorsDir, pin, ltv)
		if summary != "" {
			summaries = append(summaries, summary)
		}
		if rerr != nil {
			break
		}
	}

	attempted := res.confirmed + res.pending + res.failed
	if attempted == 0 && len(res.problems) == 0 {
		res.detail = "nothing anchored off-box yet"
		return res
	}
	detail := fmt.Sprintf("%d confirmed, %d pending a Bitcoin block", res.confirmed, res.pending)
	if res.failed > 0 {
		detail += fmt.Sprintf(", %d FAILED to reach a calendar", res.failed)
	}
	if len(summaries) > 0 {
		detail += "; " + joinSemicolon(summaries)
	}
	res.detail = detail
	return res
}

// evaluateAnchor checks one anchor record and returns a short human summary of any proof it
// carried. It updates the running counters and problem list on res.
func (res *anchorLayerResult) evaluateAnchor(v *jsonValue, lineNo int, proofsDir, anchorsDir string, pin *pinnedKey, ltv *liveTailVerifier) string {
	// Error wins over status: a submission that never reached a calendar is written with an
	// error and counts as failed regardless of the status field, because reporting a failed
	// anchor as merely pending would overstate what happened.
	hasError := false
	if e, ok := v.field("error"); ok && e.kind == kindString && e.str != "" {
		hasError = true
	}
	status := ""
	if s, ok := v.field("status"); ok && s.kind == kindString {
		status = s.str
	}
	switch {
	case hasError:
		res.failed++
		res.problems = append(res.problems, problem{code: codeAnchorFailed, text: fmt.Sprintf("anchor %d: submission recorded an error and never reached a calendar", lineNo), fatal: false})
	case status == "confirmed":
		res.confirmed++
	case status == "pending":
		res.pending++
	}

	cp, ok := v.field("checkpoint")
	if !ok || cp.kind != kindObject {
		res.problems = append(res.problems, problem{code: codeDigestMismatch, text: fmt.Sprintf("anchor %d: no embedded checkpoint to verify against", lineNo), fatal: true})
		return ""
	}
	cf, ok := extractCheckpoint(cp)
	if !ok {
		res.problems = append(res.problems, problem{code: codeCheckpointBadSig, text: fmt.Sprintf("anchor %d: checkpoint is malformed", lineNo), fatal: true})
		return ""
	}

	// Recompute the anchor digest from the checkpoint's own lexemes and compare with the digest
	// the record says it submitted. A mismatch means the record points at a checkpoint it did
	// not actually anchor.
	digestOK := false
	recDigest := ""
	if d, ok := v.field("digest"); ok && d.kind == kindString {
		recDigest = d.str
	}
	computed := sha256Hex(anchorDigestMaterial(cf))
	if recDigest == computed {
		digestOK = true
	} else {
		res.problems = append(res.problems, problem{code: codeDigestMismatch, text: fmt.Sprintf("anchor %d: digest does not match the embedded checkpoint", lineNo), fatal: true})
	}

	// Verify the signature against the key embedded in the checkpoint.
	res.checkpointsChecked++
	sigOK := verifyCheckpointSignature(cf)
	if !sigOK {
		res.problems = append(res.problems, problem{code: codeCheckpointBadSig, text: fmt.Sprintf("anchor %d: checkpoint signature does not verify", lineNo), fatal: true})
	}

	// A pin binds the embedded key to one the caller expects. Without it a forger can sign with
	// their own key and pass the signature check, so an unpinned pass is only self-consistency.
	keyOK := true
	if pin != nil {
		der, err := base64.StdEncoding.DecodeString(cf.publicKeyStr)
		if err != nil || !bytes.Equal(der, pin.der) {
			keyOK = false
			res.problems = append(res.problems, problem{code: codeCheckpointKeyMism, text: fmt.Sprintf("anchor %d: checkpoint public key does not match the pinned key", lineNo), fatal: true})
		}
	}

	// A proof file, if present, must exist, parse, and yield at least one attestation for the
	// anchor to count as off-box evidence.
	proofOK := false
	var summary string
	if pp, ok := v.field("proofPath"); ok && pp.kind == kindString && pp.str != "" {
		resolved, found := resolveProofPath(pp.str, proofsDir, anchorsDir)
		if !found {
			res.problems = append(res.problems, problem{code: codeProofMissing, text: fmt.Sprintf("anchor %d: proof file %q not found", lineNo, pp.str), fatal: true})
		} else {
			digestBytes, derr := hex.DecodeString(recDigest)
			if derr != nil {
				digestBytes = nil
			}
			atts, err := parseOTSFile(resolved, digestBytes)
			if err != nil {
				res.problems = append(res.problems, problem{code: codeProofParseError, text: fmt.Sprintf("anchor %d: proof %s did not parse: %v", lineNo, filepathBase(resolved), err), fatal: true})
			} else if len(atts) == 0 {
				res.problems = append(res.problems, problem{code: codeProofParseError, text: fmt.Sprintf("anchor %d: proof %s parsed but carries no attestation", lineNo, filepathBase(resolved)), fatal: true})
			} else {
				proofOK = true
				summary = summarizeAttestations(atts)
			}
		}
	}

	// Re-derive the checkpoint's committed live tail from the live file. The checkpoint commits
	// to the live tail inside its composite hash, and nothing else re-derives it, so a live tail
	// rewritten after signing would otherwise pass. Growth of the live file after signing is
	// expected and is not a mismatch, so the committed prefix is searched for within the file.
	liveTailOK := ltv.check(cf)
	if !liveTailOK {
		res.problems = append(res.problems, problem{code: codeLiveTailMismatch, text: fmt.Sprintf("anchor %d: the checkpoint's committed live tail cannot be reproduced from the live file", lineNo), fatal: true})
	}

	if !hasError && sigOK && keyOK && digestOK && proofOK && liveTailOK {
		res.qualifying++
	}
	return summary
}

// checkpointFields holds the checkpoint members this layer hashes, verifies, and pins, keeping
// both the source lexemes and the decoded values each use needs.
type checkpointFields struct {
	chainIndex       int64
	chainIndexLexeme []byte
	hashStr          string
	hashLexeme       []byte
	signedAtLexeme   []byte
	signatureLexeme  []byte
	signatureStr     string
	publicKeyLexeme  []byte
	publicKeyStr     string
}

func extractCheckpoint(cp *jsonValue) (checkpointFields, bool) {
	var cf checkpointFields
	ci, ok := cp.field("chainIndex")
	if !ok || ci.kind != kindNumber {
		return cf, false
	}
	cf.chainIndexLexeme = ci.raw
	idx, ok := parseIntLexeme(ci.raw)
	if !ok {
		return cf, false
	}
	cf.chainIndex = idx
	h, ok := cp.field("hash")
	if !ok || h.kind != kindString {
		return cf, false
	}
	cf.hashLexeme, cf.hashStr = h.raw, h.str
	sa, ok := cp.field("signedAt")
	if !ok || sa.kind != kindString {
		return cf, false
	}
	cf.signedAtLexeme = sa.raw
	sig, ok := cp.field("signature")
	if !ok || sig.kind != kindString {
		return cf, false
	}
	cf.signatureLexeme, cf.signatureStr = sig.raw, sig.str
	pk, ok := cp.field("publicKey")
	if !ok || pk.kind != kindString {
		return cf, false
	}
	cf.publicKeyLexeme, cf.publicKeyStr = pk.raw, pk.str
	return cf, true
}

// checkpointPayload assembles the signed bytes, format section 3.5: chainIndex, hash, signedAt
// from source lexemes, algorithm fixed to ed25519, in that order.
func checkpointPayload(cf checkpointFields) []byte {
	var b []byte
	b = append(b, `{"chainIndex":`...)
	b = append(b, cf.chainIndexLexeme...)
	b = append(b, `,"hash":`...)
	b = append(b, cf.hashLexeme...)
	b = append(b, `,"signedAt":`...)
	b = append(b, cf.signedAtLexeme...)
	b = append(b, `,"algorithm":"ed25519"}`...)
	return b
}

// anchorDigestMaterial assembles the bytes SHA-256'd to form the anchor digest, format section
// 3.6: chainIndex, hash, signedAt, signature, publicKey from source lexemes, no algorithm
// member, in that order.
func anchorDigestMaterial(cf checkpointFields) []byte {
	var b []byte
	b = append(b, `{"chainIndex":`...)
	b = append(b, cf.chainIndexLexeme...)
	b = append(b, `,"hash":`...)
	b = append(b, cf.hashLexeme...)
	b = append(b, `,"signedAt":`...)
	b = append(b, cf.signedAtLexeme...)
	b = append(b, `,"signature":`...)
	b = append(b, cf.signatureLexeme...)
	b = append(b, `,"publicKey":`...)
	b = append(b, cf.publicKeyLexeme...)
	b = append(b, '}')
	return b
}

// verifyCheckpointSignature checks the Ed25519 signature over the checkpoint payload using the
// key embedded in the checkpoint. A malformed key or signature is a verification failure, not a
// crash: hostile input must not be able to abort the run.
func verifyCheckpointSignature(cf checkpointFields) bool {
	der, err := base64.StdEncoding.DecodeString(cf.publicKeyStr)
	if err != nil {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(cf.signatureStr)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(edPub, checkpointPayload(cf), sig)
}

// resolveProofPath finds a proof file named by an anchor record. proofPath may be absolute,
// relative to the proofs directory, or relative to the anchor log directory; the record was
// written by a different process whose working directory this verifier cannot assume, so a small
// fixed set of candidates is tried and the first that exists wins. No file is ever written.
func resolveProofPath(proofPath, proofsDir, anchorsDir string) (string, bool) {
	candidates := []string{}
	if filepath.IsAbs(proofPath) {
		candidates = append(candidates, proofPath)
	}
	candidates = append(candidates,
		filepath.Join(proofsDir, proofPath),
		filepath.Join(proofsDir, filepath.Base(proofPath)),
		filepath.Join(anchorsDir, proofPath),
	)
	for _, c := range candidates {
		if fileExists(c) {
			return c, true
		}
	}
	return "", false
}

// loadPin reads a pinned public key from either an inline base64 SPKI string or a file. A PEM
// file is accepted so an operator can pass a key in the form a tool handed them; the result is
// always reduced to SPKI DER so the comparison is on key bytes, not on encoding.
func loadPin(inline, file string) (*pinnedKey, error) {
	var raw []byte
	switch {
	case inline != "":
		raw = []byte(inline)
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("cannot read pubkey file: %w", err)
		}
		raw = b
	default:
		return nil, nil
	}
	der, err := publicKeyDER(raw)
	if err != nil {
		return nil, err
	}
	return &pinnedKey{der: der}, nil
}

// publicKeyDER reduces a pinned key, given as a PEM block or a base64 SPKI string, to SPKI DER.
// A PRIVATE KEY PEM is accepted and reduced to its public half, so an operator can pin using the
// same key file the signer holds without first exporting a public key. The comparison downstream
// is on these DER bytes, never on the outer encoding.
func publicKeyDER(raw []byte) ([]byte, error) {
	if bytes.Contains(raw, []byte("-----BEGIN")) {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("pubkey is not a valid PEM block")
		}
		switch {
		case strings.Contains(block.Type, "PUBLIC KEY"):
			if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				return nil, fmt.Errorf("pubkey PEM is not a valid SPKI key: %w", err)
			}
			return block.Bytes, nil
		case strings.Contains(block.Type, "PRIVATE KEY"):
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("private key PEM did not parse: %w", err)
			}
			edKey, ok := key.(ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is not Ed25519")
			}
			der, err := x509.MarshalPKIXPublicKey(edKey.Public())
			if err != nil {
				return nil, err
			}
			return der, nil
		default:
			return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
		}
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("pubkey is neither PEM nor base64 SPKI: %w", err)
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		return nil, fmt.Errorf("pubkey base64 is not a valid SPKI key: %w", err)
	}
	return der, nil
}
