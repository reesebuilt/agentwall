import { createHash } from "crypto";
import { ContentClassification, FlowLabel, ProvenanceSource, TrustLabel } from "../../types";

/**
 * Credential and PII detection over arbitrary text.
 *
 * This runs on the MCP hot path — once per frame, in both directions — and on every
 * content-plane evaluation, so its cost is paid on traffic that is overwhelmingly clean.
 * Three properties follow from that, and every entry in the table below has to respect them:
 *
 *   1. Linear time. No pattern may contain a nested unbounded quantifier. Everything is
 *      anchored on a literal prefix, a word boundary, or a bounded run. A pathological input
 *      must not be able to turn a scan into a stall, because a stalled scan is a stalled gate.
 *   2. Precision over recall on the ambiguous families. A scanner that cries wolf gets turned
 *      off, and a scanner that is off catches nothing. Where a shape is genuinely ambiguous
 *      (a 40-character base64 run, a 16-digit number, a list of English words) the regex only
 *      nominates a candidate and a `validate` function decides. Checksums are the discriminator
 *      wherever the format carries one: Luhn, IBAN mod-97, Base58Check, bech32, EIP-55.
 *   3. Cheap rejection first. Most patterns declare `markers` — lowercase literals that MUST
 *      appear in any string the pattern can match. One `toLowerCase` per scan buys a substring
 *      test per pattern instead of a regex traversal per pattern. A marker that is not a
 *      guaranteed substring of every possible match is a silent miss, so markers are derived
 *      from the literal parts of the pattern and never from what a match "usually" looks like.
 *
 * What this is not: it is not a secret-scanning service and it does not attempt to verify that
 * a credential is live. It sees the bytes in front of it. A credential split across two frames,
 * base64-wrapped, or spelled out in words goes through untouched, and no pattern table fixes
 * that. The value here is that the common shapes — the ones that actually leak, pasted whole
 * into a tool argument or echoed back in a tool result — are caught before they cross a
 * boundary, with a low enough false-positive rate that operators leave redaction on.
 */

interface DlpMatch {
  type: string;
  pattern: RegExp;
  riskLabel: "secret" | "pii";
  redactReplacement: string;
  /**
   * Lowercase literals, at least one of which is present in EVERY string this pattern can
   * match. Purely an optimisation: absence of all markers means the regex cannot match, so it
   * is skipped. A pattern whose matches have no guaranteed literal (a bare number, an address,
   * a base58 blob) declares none and always runs.
   */
  markers?: readonly string[];
  /**
   * Structural check on the matched text. The regex nominates, this decides. Returning false
   * makes the scanner resume one character past the start of the rejected match, so an
   * overlapping candidate is still reachable.
   */
  validate?: (match: string) => boolean;
}

/* -------------------------------------------------------------------------------------------
 * Validators
 * ---------------------------------------------------------------------------------------- */

/** Shannon entropy in bits per character over the string's own symbol distribution. */
function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** How many of {lowercase, uppercase, digit, symbol} the string draws from. */
function characterClassCount(value: string): number {
  let classes = 0;
  if (/[a-z]/.test(value)) classes += 1;
  if (/[A-Z]/.test(value)) classes += 1;
  if (/[0-9]/.test(value)) classes += 1;
  if (/[^A-Za-z0-9]/.test(value)) classes += 1;
  return classes;
}

/**
 * Gate for the AWS secret-key shape, which is just "40 characters of base64 alphabet" and
 * therefore also describes a SHA-1 hex digest, a git object id, a chunk of a base64 payload,
 * and a padded identifier. Those are the false positives that make people disable DLP.
 *
 * Two filters, both cheap. Three of four character classes: real 30-byte base64 secrets
 * essentially always mix case and digits (the chance a random one does not is under one in a
 * thousand), while hex digests only ever draw from two classes and are the single most common
 * 40-character token in a source tree. An entropy floor on top rejects padded and repeated
 * runs that happen to span classes.
 *
 * The honest limit: a 40-character slice of a genuinely random mixed-case base64 blob is
 * indistinguishable from an AWS secret by inspection, and this still reports it. The
 * surrounding lookarounds keep that to isolated tokens rather than every window of a long
 * payload, which is what makes the residual rate tolerable.
 */
function isHighEntropySecret(value: string): boolean {
  return characterClassCount(value) >= 3 && shannonEntropy(value) >= 3.5;
}

const PLACEHOLDER_MARKERS = [
  "your",
  "example",
  "placeholder",
  "changeme",
  "change-me",
  "change_me",
  "redacted",
  "dummy",
  "sample",
  "insert",
  "todo",
  "xxxx",
  "notarealkey",
  "somekey",
  "myapikey",
];

/**
 * Gate for the labelled `api_key = ...` shape. The label is strong evidence, the value is not:
 * documentation, templates, and .env.example files are full of `api_key=your_key_here`, and
 * every one of those that reaches an operator as a blocked egress costs trust.
 *
 * Rejecting a documented placeholder loses nothing — it was never a credential. The entropy
 * floor is deliberately low (2.5 bits/char) because real keys chosen by humans are sometimes
 * weak, and a weak real key is exactly the one you most want to stop leaving the building.
 */
function isLikelySecretValue(match: string): boolean {
  const separator = match.search(/[:=]/);
  if (separator < 0) return false;
  const value = match
    .slice(separator + 1)
    .trim()
    .replace(/^["']|["']$/g, "");
  if (value.length < 20) return false;
  const lowered = value.toLowerCase();
  for (const marker of PLACEHOLDER_MARKERS) {
    if (lowered.includes(marker)) return false;
  }
  return shannonEntropy(value) >= 2.5;
}

/** Luhn mod-10, over a string already known to be digits-only. */
function passesLuhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = digits.charCodeAt(i) - 48;
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * IBAN mod-97-10 (ISO 7064). Rotate the first four characters to the back, map letters to
 * 10..35, and require the resulting decimal to be congruent to 1 mod 97.
 *
 * Limit: this validates the check digits, not the country's national format. A string that is
 * the right length and happens to satisfy mod-97 still passes, which is roughly one in
 * ninety-seven of the uppercase alphanumeric tokens that reach here. Carrying the per-country
 * length table would close most of that gap and is not worth the data blob for the residual.
 */
function isValidIban(candidate: string): boolean {
  const value = candidate.replace(/\s+/g, "").toUpperCase();
  if (value.length < 15 || value.length > 34) return false;
  const rotated = value.slice(4) + value.slice(0, 4);
  let remainder = 0;
  for (const ch of rotated) {
    const code = ch.charCodeAt(0);
    if (code >= 48 && code <= 57) {
      remainder = (remainder * 10 + (code - 48)) % 97;
    } else if (code >= 65 && code <= 90) {
      const mapped = code - 55;
      remainder = (remainder * 10 + Math.floor(mapped / 10)) % 97;
      remainder = (remainder * 10 + (mapped % 10)) % 97;
    } else {
      return false;
    }
  }
  return remainder === 1;
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Bitcoin-flavoured base58 decode. Returns null on any character outside the alphabet. */
function base58Decode(value: string): Uint8Array | null {
  let accumulator = 0n;
  for (const ch of value) {
    const digit = BASE58_ALPHABET.indexOf(ch);
    if (digit < 0) return null;
    accumulator = accumulator * 58n + BigInt(digit);
  }
  const body: number[] = [];
  while (accumulator > 0n) {
    body.unshift(Number(accumulator & 0xffn));
    accumulator >>= 8n;
  }
  let leadingZeroes = 0;
  while (leadingZeroes < value.length && value[leadingZeroes] === "1") leadingZeroes += 1;
  const out = new Uint8Array(leadingZeroes + body.length);
  out.set(body, leadingZeroes);
  return out;
}

/** Base58Check: 21 payload bytes plus the first four bytes of the double SHA-256 over them. */
function isBase58Check(value: string): boolean {
  const decoded = base58Decode(value);
  if (!decoded || decoded.length !== 25) return false;
  const expected = createHash("sha256").update(createHash("sha256").update(decoded.subarray(0, 21)).digest()).digest();
  for (let i = 0; i < 4; i += 1) {
    if (decoded[21 + i] !== expected[i]) return false;
  }
  return true;
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values: readonly number[]): number {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i += 1) {
      if ((top >>> i) & 1) checksum ^= BECH32_GENERATOR[i];
    }
  }
  return checksum >>> 0;
}

/** Accepts both bech32 (SegWit v0) and bech32m (v1+/taproot) constants. */
function isBech32(address: string): boolean {
  const separator = address.lastIndexOf("1");
  if (separator < 1 || separator + 7 > address.length) return false;
  const hrp = address.slice(0, separator);
  const data: number[] = [];
  for (const ch of address.slice(separator + 1)) {
    const digit = BECH32_CHARSET.indexOf(ch);
    if (digit < 0) return false;
    data.push(digit);
  }
  const expanded: number[] = [];
  for (const ch of hrp) expanded.push(ch.charCodeAt(0) >>> 5);
  expanded.push(0);
  for (const ch of hrp) expanded.push(ch.charCodeAt(0) & 31);
  const checksum = bech32Polymod(expanded.concat(data));
  return checksum === 1 || checksum === 0x2bc830a3;
}

function isBitcoinAddress(candidate: string): boolean {
  if (candidate.startsWith("bc1")) return isBech32(candidate);
  return isBase58Check(candidate);
}

/** A Solana address is a 32-byte ed25519 public key rendered in base58. */
function isSolanaAddress(candidate: string): boolean {
  const decoded = base58Decode(candidate);
  return decoded !== null && decoded.length === 32;
}

/**
 * Monero standard addresses: 95 characters, base58 alphabet, network byte 18 rendering as a
 * leading "4". Monero encodes in 8-byte blocks rather than as one big integer, so the usual
 * base58 decode does not apply and there is no cheap checksum to run here. Prefix, alphabet
 * and exact length are the whole check, which is weaker than the Bitcoin path and is why the
 * pattern demands the full 95 characters rather than a range.
 */
function isMoneroAddress(candidate: string): boolean {
  if (candidate.length !== 95) return false;
  for (const ch of candidate) {
    if (BASE58_ALPHABET.indexOf(ch) < 0) return false;
  }
  return true;
}

/* -- Keccak-256, needed for EIP-55 and nothing else ---------------------------------------- */

/**
 * Ethereum's address checksum is defined over Keccak-256, the original submission, not the
 * NIST SHA-3 that shipped with a different padding byte. `crypto.createHash("sha3-256")` is
 * the latter and produces the wrong digest here, so the permutation is inline. Adding a
 * dependency for one checksum is not a trade this project makes.
 *
 * The BigInt lane representation is the slow way to do this. It is also fine: the only input
 * this ever hashes is a 40-character address, one block, once per candidate.
 */
const KECCAK_MASK = (1n << 64n) - 1n;

const KECCAK_ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const KECCAK_ROTATIONS = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function keccakRotate(lane: bigint, offset: number): bigint {
  if (offset === 0) return lane;
  return ((lane << BigInt(offset)) | (lane >> BigInt(64 - offset))) & KECCAK_MASK;
}

function keccakPermute(state: bigint[]): void {
  const c = new Array<bigint>(5);
  const d = new Array<bigint>(5);
  const b = new Array<bigint>(25);
  for (let round = 0; round < 24; round += 1) {
    for (let x = 0; x < 5; x += 1) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x += 1) {
      d[x] = c[(x + 4) % 5] ^ keccakRotate(c[(x + 1) % 5], 1);
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) state[x + 5 * y] ^= d[x];
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = keccakRotate(state[x + 5 * y], KECCAK_ROTATIONS[x][y]);
      }
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & KECCAK_MASK & b[((x + 2) % 5) + 5 * y]);
      }
    }
    state[0] ^= KECCAK_ROUND_CONSTANTS[round];
  }
}

/** Keccak-256 over ASCII input, returned as lowercase hex. */
function keccak256Hex(input: string): string {
  const rate = 136;
  const message = Buffer.from(input, "ascii");
  const padded = new Uint8Array(message.length + (rate - (message.length % rate)));
  padded.set(message);
  padded[message.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;

  const state = new Array<bigint>(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let lane = 0; lane < rate / 8; lane += 1) {
      let value = 0n;
      for (let byte = 7; byte >= 0; byte -= 1) {
        value = (value << 8n) | BigInt(padded[offset + lane * 8 + byte]);
      }
      state[lane] ^= value;
    }
    keccakPermute(state);
  }

  let hex = "";
  for (let lane = 0; lane < 4; lane += 1) {
    let value = state[lane];
    for (let byte = 0; byte < 8; byte += 1) {
      hex += Number(value & 0xffn).toString(16).padStart(2, "0");
      value >>= 8n;
    }
  }
  return hex;
}

/**
 * EIP-55: the case of each hex letter encodes a bit of Keccak-256 over the lowercase address,
 * so a mixed-case address that fails the check is a typo or a fabrication rather than an
 * address, and reporting it would be a false positive on a 42-character hex string.
 *
 * All-lowercase and all-uppercase addresses carry no checksum — they are valid and were the
 * norm before EIP-55 — so they are accepted on shape alone. That is the recall/precision seam:
 * a lowercase 40-hex string prefixed with 0x is indistinguishable from a hash rendered the
 * same way, and this reports it as an address.
 */
function isEthereumAddress(candidate: string): boolean {
  const body = candidate.slice(2);
  const lowered = body.toLowerCase();
  if (body === lowered || body === body.toUpperCase()) return true;
  const digest = keccak256Hex(lowered);
  for (let i = 0; i < 40; i += 1) {
    const ch = lowered[i];
    if (ch < "a" || ch > "f") continue;
    const shouldBeUpper = parseInt(digest[i], 16) >= 8;
    if (shouldBeUpper !== (body[i] === ch.toUpperCase())) return false;
  }
  return true;
}

/**
 * English function words that cannot appear in the BIP-39 English wordlist, either because the
 * list requires the first four letters to identify a word uniquely (which excludes short
 * prefixes such as "the", "can", "out", "all") or because the list contains no grammatical
 * particles at all. Used to separate a mnemonic from a sentence, see `isBip39Shaped`.
 */
const ENGLISH_FUNCTION_WORDS: Record<string, true> = {
  the: true, and: true, but: true, for: true, nor: true, not: true, was: true, were: true,
  are: true, you: true, your: true, his: true, her: true, its: true, our: true, their: true,
  them: true, they: true, she: true, who: true, whom: true, whose: true, which: true,
  what: true, when: true, where: true, why: true, how: true, has: true, had: true,
  have: true, this: true, that: true, these: true, those: true, with: true, from: true,
  than: true, then: true, there: true, here: true, into: true, onto: true, because: true,
  while: true, during: true, would: true, could: true, should: true, shall: true,
  does: true, did: true, been: true, being: true, very: true, just: true, only: true,
  also: true, such: true, each: true, another: true, please: true, thanks: true, okay: true,
  yes: true, too: true, out: true, all: true, can: true, may: true, must: true, might: true,
  however: true, therefore: true, though: true, although: true, whether: true,
};

/**
 * BIP-39 mnemonic, decided without the wordlist.
 *
 * Vendoring 2048 words to serve one pattern is a large data blob on a module that loads on
 * every request path, so this leans on the phrase's structure instead: a legal mnemonic is
 * exactly 12, 15, 18, 21 or 24 lowercase alphabetic words of three to eight letters, drawn
 * with replacement from a 2048-word list (so near-total distinctness), and the enclosing
 * pattern already requires it to occupy a whole line or follow a seed-ish label.
 *
 * Be clear about what that costs. It is a heuristic in both directions. A real phrase written
 * with unusual spacing, wrapped across lines, numbered, or comma-separated is missed entirely.
 * And a line of twelve unusual English words with no function words among them — a word list,
 * a tag cloud, a column of a table — is reported as a seed phrase. The function-word test is
 * what separates prose from mnemonics in practice, and it is a two-strike rule rather than a
 * one-strike rule precisely because a handful of these words might genuinely be on the list.
 */
function isBip39Shaped(match: string): boolean {
  const tokens = match.split(/\s+/).filter((token) => token.length > 0);
  let first = tokens.length - 1;
  while (first >= 0 && /^[a-z]{3,8}$/.test(tokens[first])) first -= 1;
  const words = tokens.slice(first + 1);

  const count = words.length;
  if (count !== 12 && count !== 15 && count !== 18 && count !== 21 && count !== 24) return false;

  if (new Set(words).size / count < 0.9) return false;

  let functionWords = 0;
  for (const word of words) {
    if (ENGLISH_FUNCTION_WORDS[word]) {
      functionWords += 1;
      if (functionWords >= 2) return false;
    }
  }
  return true;
}

/**
 * IPv6 sanity check on top of the shape match. Two colon-separated hex groups are far more
 * likely to be a scope-resolution operator or a truncated hash than an address, so require at
 * least three groups and at least eight hex digits in total. That deliberately gives up on
 * short link-local forms like `fe80::1`, which are not the addresses that identify a person.
 */
function isPlausibleIpv6(candidate: string): boolean {
  const compressed = candidate.includes("::");
  const groups = candidate.split(":").filter((group) => group.length > 0);
  if (groups.length < 3) return false;
  if (!compressed && groups.length !== 8) return false;
  let digits = 0;
  for (const group of groups) digits += group.length;
  return digits >= 8;
}

/* -------------------------------------------------------------------------------------------
 * Pattern table
 *
 * `type` strings are load-bearing: they land in audit records, dashboard state and MCP gate
 * reasons, so an existing one is never renamed. Order matters only for redaction — when two
 * matches overlap, the leftmost span wins and ties go to the earlier entry — so the original
 * core stays first and new families are appended.
 * ---------------------------------------------------------------------------------------- */

const DLP_PATTERNS: readonly DlpMatch[] = [
  // --- original core -----------------------------------------------------------------------
  { type: "aws-access-key", pattern: /\bAKIA[0-9A-Z]{16}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:AWS-KEY]", markers: ["akia"] },
  { type: "aws-secret-key", pattern: /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/, riskLabel: "secret", redactReplacement: "[REDACTED:AWS-SECRET]", validate: isHighEntropySecret },
  { type: "github-pat", pattern: /\bghp_[A-Za-z0-9]{36,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GH-PAT]", markers: ["ghp_"] },
  { type: "github-oauth", pattern: /\bgho_[A-Za-z0-9]{36,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GH-OAUTH]", markers: ["gho_"] },
  // Unchanged on purpose. The character class excludes "-", so "sk-ant-..." cannot satisfy the
  // 32-character run and never reaches this entry; Anthropic keys are claimed by their own
  // pattern below. Widening this to allow hyphens would cover sk-proj- keys but would also
  // start matching ordinary kebab-case identifiers that happen to begin "sk-", so the project
  // key form gets its own precise entry instead.
  { type: "openai-key", pattern: /\bsk-[A-Za-z0-9]{32,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:OPENAI-KEY]", markers: ["sk-"] },
  { type: "slack-bot-token", pattern: /\bxoxb-[A-Za-z0-9-]{50,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:SLACK-TOKEN]", markers: ["xoxb-"] },
  { type: "slack-user-token", pattern: /\bxoxp-[A-Za-z0-9-]{50,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:SLACK-TOKEN]", markers: ["xoxp-"] },
  { type: "private-key", pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, riskLabel: "secret", redactReplacement: "[REDACTED:PRIVATE-KEY]", markers: ["private key"] },
  { type: "jwt", pattern: /\bey[A-Za-z0-9_-]{20,4096}\.[A-Za-z0-9_-]{20,8192}\.[A-Za-z0-9_-]{20,4096}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:JWT]", markers: ["ey"] },
  { type: "generic-api-key", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?/i, riskLabel: "secret", redactReplacement: "[REDACTED:API-KEY]", markers: ["api"], validate: isLikelySecretValue },
  { type: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:SSN]" },
  { type: "credit-card", pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/, riskLabel: "pii", redactReplacement: "[REDACTED:CC]", validate: passesLuhn },
  // Tightened, and the type string is deliberately untouched because callers key off it. The
  // original local part was an unbounded run over a class that contains "." and "-", so a long
  // hyphenated or dotted token made the engine consume to the end of the input and backtrack a
  // character at a time, at every start position — quadratic on adversarial frame content, on
  // the path that gates every MCP message. Both runs are now capped at the RFC 5321 maxima
  // (64-octet local part, 253-octet domain), which bounds the work per start position without
  // changing which strings are addresses. The cost is that an over-long, already invalid local
  // part now matches only its last 64 characters, or not at all when those have no word
  // boundary in front of them.
  { type: "email", pattern: /\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:EMAIL]" },
  { type: "phone-us", pattern: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:PHONE]" },

  // --- cloud providers ---------------------------------------------------------------------
  { type: "aws-session-token", pattern: /\bASIA[0-9A-Z]{16}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:AWS-SESSION]", markers: ["asia"] },
  { type: "gcp-service-account-key", pattern: /"type"\s*:\s*"service_account"/, riskLabel: "secret", redactReplacement: "[REDACTED:GCP-SA-KEY]", markers: ["service_account"] },
  { type: "gcp-api-key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GCP-API-KEY]", markers: ["aiza"] },
  { type: "azure-storage-key", pattern: /\bAccountKey=[A-Za-z0-9+/]{86}==/, riskLabel: "secret", redactReplacement: "[REDACTED:AZURE-STORAGE-KEY]", markers: ["accountkey="] },
  { type: "azure-sas-token", pattern: /\bsv=\d{4}-\d{2}-\d{2}[^\s"'<>]{0,256}&sig=[A-Za-z0-9%+/=]{20,}/, riskLabel: "secret", redactReplacement: "[REDACTED:AZURE-SAS]", markers: ["&sig="] },
  // Covers Azure AD application secrets, which are only recognisable by their label, and every
  // other OAuth client secret with them. Naming it for one provider would have been a lie.
  { type: "oauth-client-secret", pattern: /\bclient[_-]?secret\s*[:=]\s*["']?([A-Za-z0-9._~-]{30,})/i, riskLabel: "secret", redactReplacement: "[REDACTED:CLIENT-SECRET]", markers: ["client_secret", "client-secret", "clientsecret"] },
  { type: "digitalocean-token", pattern: /\bdo[oprs]_v1_[a-f0-9]{64}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:DIGITALOCEAN-TOKEN]", markers: ["_v1_"] },
  { type: "cloudflare-api-token", pattern: /\b(?:cloudflare|cf)[_-]?(?:api[_-]?)?token\s*[:=]\s*["']?([A-Za-z0-9_-]{40})\b/i, riskLabel: "secret", redactReplacement: "[REDACTED:CLOUDFLARE-TOKEN]", markers: ["token"] },
  { type: "cloudflare-origin-ca-key", pattern: /\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:CLOUDFLARE-CA-KEY]", markers: ["v1.0-"] },
  { type: "heroku-api-key", pattern: /\bheroku[_-]?(?:api[_-]?)?key\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b/i, riskLabel: "secret", redactReplacement: "[REDACTED:HEROKU-KEY]", markers: ["heroku"] },

  // --- version control and CI ----------------------------------------------------------------
  { type: "github-app-token", pattern: /\bgh[su]_[A-Za-z0-9]{36,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GH-APP-TOKEN]", markers: ["ghs_", "ghu_"] },
  { type: "github-refresh-token", pattern: /\bghr_[A-Za-z0-9]{36,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GH-REFRESH-TOKEN]", markers: ["ghr_"] },
  { type: "github-fine-grained-pat", pattern: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GH-FINE-GRAINED-PAT]", markers: ["github_pat_"] },
  { type: "gitlab-pat", pattern: /\bglpat-[A-Za-z0-9_-]{20,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GITLAB-PAT]", markers: ["glpat-"] },
  { type: "gitlab-runner-token", pattern: /\bglrt-[A-Za-z0-9_-]{20,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GITLAB-RUNNER-TOKEN]", markers: ["glrt-"] },
  { type: "bitbucket-token", pattern: /\bATBB[A-Za-z0-9]{32,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:BITBUCKET-TOKEN]", markers: ["atbb"] },
  { type: "circleci-token", pattern: /\bCCIPAT_[A-Za-z0-9_]{20,}\b|\bcircle[_-]?ci[_-]?token\s*[:=]\s*["']?[0-9a-f]{40}\b/i, riskLabel: "secret", redactReplacement: "[REDACTED:CIRCLECI-TOKEN]", markers: ["ccipat_", "circle"] },
  { type: "travis-ci-token", pattern: /\btravis[_-]?(?:ci[_-]?)?(?:api[_-]?)?token\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})/i, riskLabel: "secret", redactReplacement: "[REDACTED:TRAVIS-TOKEN]", markers: ["travis"] },
  { type: "jenkins-api-token", pattern: /\bjenkins[_-]?(?:api[_-]?)?token\s*[:=]\s*["']?([A-Za-z0-9]{30,})/i, riskLabel: "secret", redactReplacement: "[REDACTED:JENKINS-TOKEN]", markers: ["jenkins"] },
  { type: "npm-token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:NPM-TOKEN]", markers: ["npm_"] },
  { type: "pypi-token", pattern: /\bpypi-[A-Za-z0-9_-]{50,1024}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:PYPI-TOKEN]", markers: ["pypi-"] },
  { type: "dockerhub-token", pattern: /\bdckr_pat_[A-Za-z0-9_-]{20,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:DOCKERHUB-TOKEN]", markers: ["dckr_pat_"] },

  // --- model providers -----------------------------------------------------------------------
  { type: "anthropic-key", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:ANTHROPIC-KEY]", markers: ["sk-ant-"] },
  { type: "openai-project-key", pattern: /\bsk-proj-[A-Za-z0-9_-]{20,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:OPENAI-PROJECT-KEY]", markers: ["sk-proj-"] },
  { type: "cohere-key", pattern: /\bcohere[_-]?(?:api[_-]?)?key\s*[:=]\s*["']?([A-Za-z0-9]{40})\b/i, riskLabel: "secret", redactReplacement: "[REDACTED:COHERE-KEY]", markers: ["cohere"] },
  { type: "huggingface-token", pattern: /\bhf_[A-Za-z0-9]{34,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:HUGGINGFACE-TOKEN]", markers: ["hf_"] },
  { type: "replicate-token", pattern: /\br8_[A-Za-z0-9]{37,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:REPLICATE-TOKEN]", markers: ["r8_"] },
  { type: "together-key", pattern: /\btogether(?:[_-]?ai)?[_-]?(?:api[_-]?)?key\s*[:=]\s*["']?([0-9a-f]{64})\b/i, riskLabel: "secret", redactReplacement: "[REDACTED:TOGETHER-KEY]", markers: ["together"] },
  { type: "groq-key", pattern: /\bgsk_[A-Za-z0-9]{40,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GROQ-KEY]", markers: ["gsk_"] },
  { type: "mistral-key", pattern: /\bmistral[_-]?(?:api[_-]?)?key\s*[:=]\s*["']?([A-Za-z0-9]{32})\b/i, riskLabel: "secret", redactReplacement: "[REDACTED:MISTRAL-KEY]", markers: ["mistral"] },

  // --- communications and SaaS ---------------------------------------------------------------
  { type: "twilio-account-sid", pattern: /\bAC[0-9a-f]{32}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:TWILIO-SID]", markers: ["ac"] },
  { type: "twilio-auth-token", pattern: /\btwilio[_-]?(?:auth[_-]?)?token\s*[:=]\s*["']?([0-9a-f]{32})\b/i, riskLabel: "secret", redactReplacement: "[REDACTED:TWILIO-TOKEN]", markers: ["twilio"] },
  { type: "sendgrid-key", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:SENDGRID-KEY]", markers: ["sg."] },
  { type: "mailgun-key", pattern: /\bkey-[0-9a-f]{32}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:MAILGUN-KEY]", markers: ["key-"] },
  { type: "stripe-live-secret", pattern: /\bsk_live_[A-Za-z0-9]{16,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:STRIPE-LIVE-KEY]", markers: ["sk_live_"] },
  { type: "stripe-test-secret", pattern: /\bsk_test_[A-Za-z0-9]{16,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:STRIPE-TEST-KEY]", markers: ["sk_test_"] },
  { type: "stripe-restricted-key", pattern: /\brk_(?:live|test)_[A-Za-z0-9]{16,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:STRIPE-RESTRICTED-KEY]", markers: ["rk_live_", "rk_test_"] },
  { type: "square-token", pattern: /\b(?:sq0atp-|sq0csp-|sq0idp-)[A-Za-z0-9_-]{22,256}\b|\bEAAA[A-Za-z0-9_-]{56,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:SQUARE-TOKEN]", markers: ["sq0atp-", "sq0csp-", "sq0idp-", "eaaa"] },
  { type: "shopify-token", pattern: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:SHOPIFY-TOKEN]", markers: ["shp"] },
  { type: "datadog-key", pattern: /\bdatadog[_-]?(?:api|app)[_-]?key\s*[:=]\s*["']?([a-f0-9]{32,40})\b/i, riskLabel: "secret", redactReplacement: "[REDACTED:DATADOG-KEY]", markers: ["datadog"] },
  { type: "newrelic-key", pattern: /\bNRAK-[A-Z0-9]{27}\b|\b[a-f0-9]{40}NRAL\b/, riskLabel: "secret", redactReplacement: "[REDACTED:NEWRELIC-KEY]", markers: ["nrak-", "nral"] },
  { type: "pagerduty-key", pattern: /\bpagerduty[_-]?(?:api[_-]?)?(?:token|key)\s*[:=]\s*["']?([A-Za-z0-9_+-]{20,})/i, riskLabel: "secret", redactReplacement: "[REDACTED:PAGERDUTY-KEY]", markers: ["pagerduty"] },
  { type: "segment-write-key", pattern: /\bsegment[_-]?(?:write[_-]?)?key\s*[:=]\s*["']?([A-Za-z0-9]{32})\b/i, riskLabel: "secret", redactReplacement: "[REDACTED:SEGMENT-KEY]", markers: ["segment"] },
  { type: "airtable-token", pattern: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:AIRTABLE-TOKEN]", markers: ["pat"] },
  { type: "notion-token", pattern: /\bsecret_[A-Za-z0-9]{43}\b|\bntn_[A-Za-z0-9]{40,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:NOTION-TOKEN]", markers: ["secret_", "ntn_"] },
  { type: "linear-key", pattern: /\blin_(?:api|oauth)_[A-Za-z0-9]{40,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:LINEAR-KEY]", markers: ["lin_api_", "lin_oauth_"] },
  { type: "figma-token", pattern: /\bfigd_[A-Za-z0-9_-]{40,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:FIGMA-TOKEN]", markers: ["figd_"] },
  { type: "atlassian-api-token", pattern: /\bAT[AC]TT3[A-Za-z0-9_=-]{80,1024}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:ATLASSIAN-TOKEN]", markers: ["atatt3", "atctt3"] },

  // --- databases and infrastructure -----------------------------------------------------------
  // Every URI entry requires an inline "user:password@" authority. A connection string without
  // embedded credentials is configuration, not a secret, and flagging it would train operators
  // to ignore the finding.
  { type: "postgres-uri", pattern: /\bpostgres(?:ql)?:\/\/[^\s:@/]{1,64}:[^\s:@/]{1,128}@[^\s/?#]{1,255}/, riskLabel: "secret", redactReplacement: "[REDACTED:POSTGRES-URI]", markers: ["postgres"] },
  { type: "mysql-uri", pattern: /\bmysql:\/\/[^\s:@/]{1,64}:[^\s:@/]{1,128}@[^\s/?#]{1,255}/, riskLabel: "secret", redactReplacement: "[REDACTED:MYSQL-URI]", markers: ["mysql://"] },
  { type: "mongodb-uri", pattern: /\bmongodb(?:\+srv)?:\/\/[^\s:@/]{1,64}:[^\s:@/]{1,128}@[^\s/?#]{1,255}/, riskLabel: "secret", redactReplacement: "[REDACTED:MONGODB-URI]", markers: ["mongodb"] },
  { type: "redis-uri", pattern: /\brediss?:\/\/[^\s:@/]{0,64}:[^\s:@/]{1,128}@[^\s/?#]{1,255}/, riskLabel: "secret", redactReplacement: "[REDACTED:REDIS-URI]", markers: ["redis"] },
  { type: "amqp-uri", pattern: /\bamqps?:\/\/[^\s:@/]{1,64}:[^\s:@/]{1,128}@[^\s/?#]{1,255}/, riskLabel: "secret", redactReplacement: "[REDACTED:AMQP-URI]", markers: ["amqp"] },
  { type: "elastic-cloud-id", pattern: /\bcloud[_-]?id\s*[:=]\s*["']?[A-Za-z0-9_-]{1,64}:[A-Za-z0-9+/=]{40,}/i, riskLabel: "secret", redactReplacement: "[REDACTED:ELASTIC-CLOUD-ID]", markers: ["cloud_id", "cloud-id", "cloudid"] },
  { type: "kubernetes-credential", pattern: /\bkubernetes\.io\/serviceaccount\b|\bclient-key-data\s*:\s*[A-Za-z0-9+/=]{40,}/, riskLabel: "secret", redactReplacement: "[REDACTED:K8S-CREDENTIAL]", markers: ["kubernetes.io/serviceaccount", "client-key-data"] },
  { type: "vault-token", pattern: /\bhv[sb]\.[A-Za-z0-9_-]{24,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:VAULT-TOKEN]", markers: ["hvs.", "hvb."] },
  { type: "terraform-cloud-token", pattern: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,256}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:TERRAFORM-TOKEN]", markers: [".atlasv1."] },
  { type: "grafana-token", pattern: /\bgl(?:sa|c|api)_[A-Za-z0-9_]{32,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GRAFANA-TOKEN]", markers: ["glsa_", "glc_", "glapi_"] },

  // --- crypto wallets --------------------------------------------------------------------------
  // A seed phrase is spending authority, so it is a secret. An address is not authority but it
  // is a durable identifier that links a person to their entire transaction history, which puts
  // it with the PII rather than with the credentials.
  { type: "bip39-seed-phrase", pattern: /(?:^[ \t>*\-]{0,8}|\b(?:mnemonic|seed|recovery|passphrase|wallet)(?:[ \t]+(?:phrase|words))?[ \t]*[:=][ \t]*)(?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8}(?=[ \t]*$|[.,;])/m, riskLabel: "secret", redactReplacement: "[REDACTED:SEED-PHRASE]", validate: isBip39Shaped },
  { type: "btc-address", pattern: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{11,71})\b/, riskLabel: "pii", redactReplacement: "[REDACTED:BTC-ADDRESS]", validate: isBitcoinAddress },
  { type: "eth-address", pattern: /\b0x[0-9a-fA-F]{40}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:ETH-ADDRESS]", markers: ["0x"], validate: isEthereumAddress },
  { type: "sol-address", pattern: /\b[1-9A-HJ-NP-Za-km-z]{43,44}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:SOL-ADDRESS]", validate: isSolanaAddress },
  { type: "xmr-address", pattern: /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:XMR-ADDRESS]", validate: isMoneroAddress },

  // --- further personal data ---------------------------------------------------------------------
  { type: "iban", pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:IBAN]", validate: isValidIban },
  // Passport and licence numbers have no national format worth encoding and no check digit, so
  // both entries require the document to name itself. Unlabelled, they are just short
  // alphanumeric strings and any pattern that caught them would catch everything.
  { type: "passport-number", pattern: /\bpassport\s*(?:no\.?|number|#)?\s*[:#]\s*([A-Z0-9]{6,9})\b/i, riskLabel: "pii", redactReplacement: "[REDACTED:PASSPORT]", markers: ["passport"] },
  { type: "drivers-license", pattern: /\b(?:driver'?s?\s*licen[cs]e|dl\b)\s*(?:no\.?|number|#)?\s*[:#]\s*([A-Z0-9-]{5,20})\b/i, riskLabel: "pii", redactReplacement: "[REDACTED:DRIVERS-LICENSE]", markers: ["licen", "dl"] },
  { type: "ipv6-address", pattern: /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|(?<![:\w])(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?(?![:\w])/, riskLabel: "pii", redactReplacement: "[REDACTED:IPV6]", validate: isPlausibleIpv6 },
  { type: "mac-address", pattern: /\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:MAC]" },
  { type: "date-of-birth", pattern: /(?:d\.o\.b\.?|\bdob\b|\bdate\s+of\s+birth\b|\bbirth\s*date\b|\bborn\b)\s*(?:on\s+)?[:=]?\s*(?:\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}|\d{4}-\d{2}-\d{2}|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]{0,6}\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})/i, riskLabel: "pii", redactReplacement: "[REDACTED:DOB]", markers: ["dob", "d.o.b", "birth", "born"] },
];

interface CompiledPattern {
  readonly entry: DlpMatch;
  /** Same source with the global flag, reused across scans; `lastIndex` is reset on entry. */
  readonly scanner: RegExp;
}

const COMPILED_PATTERNS: readonly CompiledPattern[] = DLP_PATTERNS.map((entry) => ({
  entry,
  scanner: new RegExp(entry.pattern.source, entry.pattern.flags.includes("g") ? entry.pattern.flags : `${entry.pattern.flags}g`),
}));

export interface DlpPatternInfo {
  type: string;
  riskLabel: "secret" | "pii";
  redactReplacement: string;
  /** Empty when the pattern has no literal it can be pre-filtered on and therefore always runs. */
  markers: readonly string[];
  /** Whether a structural or checksum test gates the regex match. */
  validated: boolean;
}

const PATTERN_CATALOG: readonly DlpPatternInfo[] = Object.freeze(
  DLP_PATTERNS.map((entry) =>
    Object.freeze({
      type: entry.type,
      riskLabel: entry.riskLabel,
      redactReplacement: entry.redactReplacement,
      markers: Object.freeze(entry.markers ? [...entry.markers] : []),
      validated: entry.validate !== undefined,
    })
  )
);

/** Number of registered detectors. Exposed so callers and tests never hardcode the figure. */
export const DLP_PATTERN_COUNT = DLP_PATTERNS.length;

/**
 * Read-only view of the pattern table: what is detected, how it is redacted, and whether the
 * regex is backed by a validator. Deliberately does not expose the RegExp objects — they carry
 * mutable `lastIndex` state that a caller could corrupt mid-scan.
 */
export function dlpPatternCatalog(): readonly DlpPatternInfo[] {
  return PATTERN_CATALOG;
}

/**
 * Where one match was found, and what class it belongs to. Never what it was.
 *
 * This exists so an audit record can say "an AWS secret key started at byte 1042 of the
 * request body" without the record becoming a second copy of the credential. A ledger is
 * read by more people than the environment it protects, so the offset and the class are the
 * most that may ever leave this module about a live secret.
 */
export interface DlpLocation {
  /** Pattern type, e.g. "aws-access-key". The class, which is safe to log. */
  type: string;
  riskLabel: "secret" | "pii";
  /** Offset of the match in the scanned text, in UTF-16 code units. */
  start: number;
  end: number;
}

export interface DlpScanResult {
  secretTypes: string[];
  piiTypes: string[];
  containsSecrets: boolean;
  containsPII: boolean;
  redactedText?: string;
  /**
   * Present only when the caller asked to locate. Absent and present-but-empty mean
   * different things: absent is "nobody looked", empty is "looked and found nothing".
   */
  locations?: DlpLocation[];
}

export function defaultTrustForSource(source: ProvenanceSource): TrustLabel {
  if (source === "system") return "trusted";
  if (source === "memory" || source === "tool_metadata") return "derived";
  return "untrusted";
}

interface RedactionSpan {
  start: number;
  end: number;
  replacement: string;
}

function containsAnyMarker(lowered: string, markers: readonly string[]): boolean {
  for (let i = 0; i < markers.length; i += 1) {
    if (lowered.includes(markers[i])) return true;
  }
  return false;
}

/**
 * Rewrite every collected span in one pass over the original text.
 *
 * Spans are collected against the untouched input rather than applied one pattern at a time,
 * because sequential replacement lets an earlier substitution change the text a later pattern
 * sees — the redaction marker itself becomes scannable, and offsets stop meaning anything.
 * Overlapping spans merge into a single region so no fragment of a credential survives between
 * two neighbouring matches; the region takes the replacement of its leftmost span, which for
 * a labelled secret is the label-bearing match rather than the bare value inside it.
 */
function applyRedactions(text: string, spans: RedactionSpan[]): string {
  if (spans.length === 0) return text;
  spans.sort((a, b) => a.start - b.start || b.end - a.end);

  let out = "";
  let cursor = 0;
  let i = 0;
  while (i < spans.length) {
    const region = spans[i];
    let end = region.end;
    let j = i + 1;
    while (j < spans.length && spans[j].start < end) {
      if (spans[j].end > end) end = spans[j].end;
      j += 1;
    }
    out += text.slice(cursor, region.start) + region.replacement;
    cursor = end;
    i = j;
  }
  return out + text.slice(cursor);
}

/**
 * `locate` asks for the position and class of every match, which callers that build audit
 * records need and callers that only branch on a boolean do not. It is a third parameter
 * rather than a property of `redact` because the two answer different questions: redaction
 * rewrites the text for a downstream consumer, location describes the text for a ledger, and
 * a proxy scanning a request body wants the second without paying for the first. Both force
 * full enumeration, so the early break below survives only for the plain detection call.
 */
export function scanText(text: string, redact = false, locate = false): DlpScanResult {
  const secretTypes: string[] = [];
  const piiTypes: string[] = [];
  const spans: RedactionSpan[] = [];
  const locations: DlpLocation[] | undefined = locate ? [] : undefined;
  // One allocation, shared by every marker test below. Cheaper than a regex traversal per
  // pattern, and the scan is dominated by the patterns that survive the filter.
  const lowered = text.toLowerCase();

  for (const { entry, scanner } of COMPILED_PATTERNS) {
    if (entry.markers && !containsAnyMarker(lowered, entry.markers)) continue;

    scanner.lastIndex = 0;
    let hit = false;
    let match: RegExpExecArray | null;
    while ((match = scanner.exec(text)) !== null) {
      const value = match[0];
      if (value.length === 0) {
        scanner.lastIndex += 1;
        continue;
      }
      if (entry.validate && !entry.validate(value)) {
        scanner.lastIndex = match.index + 1;
        continue;
      }
      hit = true;
      if (locations) {
        locations.push({
          type: entry.type,
          riskLabel: entry.riskLabel,
          start: match.index,
          end: match.index + value.length,
        });
      }
      // Detection alone needs one hit; redaction and location have to enumerate every
      // occurrence. Enumerating for location matters as much as for redaction: an operator
      // reading "one secret" on a body that carried nine has been told the wrong size of
      // incident.
      if (!redact && !locate) break;
      if (redact) {
        spans.push({ start: match.index, end: match.index + value.length, replacement: entry.redactReplacement });
      }
    }

    if (!hit) continue;
    // Types are unique across the table, so no membership check is needed here.
    if (entry.riskLabel === "secret") secretTypes.push(entry.type);
    else piiTypes.push(entry.type);
  }

  return {
    secretTypes,
    piiTypes,
    containsSecrets: secretTypes.length > 0,
    containsPII: piiTypes.length > 0,
    redactedText: redact ? applyRedactions(text, spans) : undefined,
    locations,
  };
}

export function classifyContent(
  text: string,
  trustLabel?: TrustLabel,
  redact = true,
  source: ProvenanceSource = "user"
): ContentClassification {
  const scan = scanText(text, redact);
  const resolvedTrust = trustLabel ?? defaultTrustForSource(source);
  const labels: FlowLabel[] = [];

  let riskLevel: ContentClassification["riskLevel"] = "low";
  if (scan.containsSecrets) {
    riskLevel = "critical";
    labels.push("secret_material", "high_risk");
  } else if (scan.containsPII) {
    riskLevel = "high";
    labels.push("pii", "high_risk");
  }

  if (resolvedTrust !== "trusted") {
    labels.push("cross_boundary");
  }

  return {
    source,
    trustLabel: resolvedTrust,
    labels,
    containsSecrets: scan.containsSecrets,
    secretTypes: scan.secretTypes,
    containsPII: scan.containsPII,
    piiTypes: scan.piiTypes,
    riskLevel,
    redacted: redact && (scan.containsSecrets || scan.containsPII),
  };
}
