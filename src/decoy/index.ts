import { randomBytes, timingSafeEqual } from "crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "fs";
import { dirname } from "path";
import { z } from "zod";
import { emit } from "../audit/logger";
import { detectionsForRules } from "../policy/detections";
import { AgentContext, AuditEvent, PolicyResult } from "../types";

/**
 * Decoy tokens: the one detection here that is evidence rather than inference.
 *
 * Every other signal AgentWall produces is a judgement about traffic. A DLP scan says "this
 * looks like a credential". An injection scan says "this reads like an instruction". Both are
 * classifiers, both have an error rate, and both are tuned against a distribution the next agent
 * framework is free to violate.
 *
 * A decoy is not a classifier. It is a synthetic credential that is planted and then never used
 * by anything legitimate, so there exists no benign execution in which its exact bytes appear in
 * outbound traffic. A hit is therefore not a probability that something read the environment and
 * shipped it; it is a demonstration that something did. That is a different kind of statement,
 * and it is the reason this module refuses every convenience that would turn it back into a
 * heuristic.
 *
 * What it does NOT do, stated up front because the asymmetry is easy to forget: silence proves
 * nothing. A decoy fires only when something reads and transmits that specific value over a
 * surface AgentWall inspects. An exfiltration that reads a different file, or leaves over a path
 * with no gate on it, produces exactly the same quiet as no exfiltration at all.
 */

const DECOY_KIND_VALUES = ["aws-access-key", "github-pat", "openai-key", "generic-secret", "url"] as const;

export type DecoyKind = (typeof DECOY_KIND_VALUES)[number];

export const DECOY_KINDS: readonly DecoyKind[] = DECOY_KIND_VALUES;

export interface DecoyToken {
  id: string;
  value: string;
  kind: DecoyKind;
  createdAt: string;
  label?: string;
}

/** Where a hit was observed, when the caller knows. Attribution only; never affects the verdict. */
export interface DecoyTriggerContext {
  agentId?: string;
  sessionId?: string;
  /** Free-form note naming the inspecting surface, e.g. "proxy:connect" or "probe-api". */
  surface?: string;
}

export const DECOY_RULE_ID = "identity:deny-decoy-triggered";
export const DECOY_DETECTION_ID = "det.identity.decoy.triggered";

export function isDecoyKind(value: string): value is DecoyKind {
  return DECOY_KIND_VALUES.some((kind) => kind === value);
}

/**
 * Below this, a "decoy" is a coincidence generator.
 *
 * Zero-false-positive is a property of the value, not of the mechanism. A short or low-entropy
 * string will eventually appear in ordinary traffic, and the first false hit is unrecoverable in
 * a way an ordinary false positive is not: the entire operational value of a decoy is that an
 * operator treats a hit as proof and acts immediately, and that reflex does not survive being
 * wrong once. Hand-written entries in a decoy file get the same floor as generated ones.
 */
const MIN_DECOY_VALUE_LENGTH = 16;

// --- Minting ---------------------------------------------------------------------------------

/**
 * The central tension: a decoy has to look real enough to be worth stealing, and be provably
 * useless if it is.
 *
 * Look-real matters because the thief filters. Credential harvesters, prompt-injected agents, and
 * "collect anything that looks like a key" scrapers all run shape checks, and a token that fails
 * `AKIA[0-9A-Z]{16}` is silently dropped by the very code the decoy exists to catch. So every
 * value below is structurally valid for its kind: correct prefix, correct length, correct
 * alphabet, and for GitHub the correct trailing CRC-32 that the vendor's own validators check.
 *
 * Be-useless matters because the value is deliberately handed to hostile code. Safety here comes
 * from randomness, not from malformedness: the value occupies the same namespace as a real
 * credential but is drawn uniformly from it, so the odds of naming an issued key are the odds of
 * guessing one - 2^80 for AWS, 2^178 for GitHub, 2^285 for OpenAI. Nothing here is registered with
 * any provider and nothing here can authenticate; that claim is a counting argument, not a promise
 * from a vendor. The `url` kind takes the opposite route and is discussed at its minter.
 *
 * Both halves are load-bearing. A decoy that looks fake is never stolen and detects nothing; a
 * decoy that is a real credential is a breach you planted yourself.
 */

/** AWS encodes key ids in RFC 4648 base32, so a plausible one must not contain 0, 1, 8 or 9. */
const AWS_KEY_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const HEX = "0123456789abcdef";

const MINTERS: Record<DecoyKind, () => string> = {
  "aws-access-key": () => `AKIA${randomFromAlphabet(AWS_KEY_ID_ALPHABET, 16)}`,
  "github-pat": () => {
    // 30 random base62 characters followed by a 6-character base62 CRC-32 over those characters.
    // Computing the checksum honestly is what makes this survive a validator rather than only a
    // regex, and it costs nothing: the checksum is a function of the random body, so it adds no
    // predictability the body did not already lack.
    const body = randomFromAlphabet(BASE62, 30);
    return `ghp_${body}${base62(crc32(body), 6)}`;
  },
  "openai-key": () => `sk-${randomFromAlphabet(BASE62, 48)}`,
  "generic-secret": () => randomBytes(32).toString("hex"),
  // The URL decoy resolves nowhere on purpose. The classic design points at a host that logs the
  // hit, which means the operator's exfiltration signal is delivered to a third party's server -
  // and AgentWall runs no such server, so the alternative would be inventing a hostname somebody
  // else may already own. Detection here comes from AgentWall seeing the string in traffic it
  // inspects, which needs no callback, so `.invalid` (RFC 2606, guaranteed never to resolve) is
  // both safe and sufficient. The cost is honest: a human who inspects the URL can tell it is a
  // decoy, so this kind catches automated scrapers, not a careful reader.
  url: () =>
    `https://api-${randomFromAlphabet(HEX, 12)}.decoy.invalid/v1/collect/${randomBytes(16).toString("hex")}`,
};

export function generateDecoy(kind: DecoyKind, label?: string): DecoyToken {
  return {
    id: `dcoy_${randomBytes(6).toString("hex")}`,
    value: MINTERS[kind](),
    kind,
    createdAt: new Date().toISOString(),
    label,
  };
}

/**
 * Uniform selection from `alphabet`, by rejection rather than by modulo.
 *
 * The entire safety argument above is a count of equiprobable values, and `byte % n` only leaves
 * them equiprobable when n divides 256. It happens to for base32 and hex and does not for base62,
 * where the low eight characters would come up 5/4 as often as the rest. Rejecting the tail costs
 * about 3% of drawn bytes at the worst alphabet used here, which is cheaper than a helper that is
 * correct for two callers and quietly lossy for the third.
 */
function randomFromAlphabet(alphabet: string, length: number): string {
  const ceiling = 256 - (256 % alphabet.length);
  const out: string[] = [];
  while (out.length < length) {
    // Over-draw so the common case is one syscall: rejection wastes a few bytes, not a round trip.
    const draw = randomBytes(Math.max(32, (length - out.length) * 2));
    for (let i = 0; i < draw.length && out.length < length; i += 1) {
      const byte = draw[i];
      if (byte >= ceiling) continue;
      out.push(alphabet[byte % alphabet.length]);
    }
  }
  return out.join("");
}

const CRC32_TABLE = ((): Int32Array => {
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let bit = 0; bit < 8; bit += 1) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c;
  }
  return table;
})();

/**
 * CRC-32 (IEEE 802.3), inlined rather than taken from zlib.
 *
 * Node exposes `zlib.crc32`, but only from 22.2, and this file is otherwise free of version floors
 * a reader would have to know about. A dozen lines with a fixed polynomial is a smaller thing to
 * carry than a runtime capability check on the code path that mints credentials.
 */
function crc32(input: string): number {
  let crc = -1;
  for (let i = 0; i < input.length; i += 1) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ input.charCodeAt(i)) & 0xff];
  }
  return (crc ^ -1) >>> 0;
}

/** Big-endian base62 of a 32-bit value, left-padded: the tail encoding GitHub's own checksum uses. */
function base62(value: number, width: number): string {
  let out = "";
  let remaining = value;
  while (remaining > 0) {
    out = BASE62[remaining % 62] + out;
    remaining = Math.floor(remaining / 62);
  }
  return out.padStart(width, "0");
}

// --- Registry and matching -------------------------------------------------------------------

interface RegisteredDecoy {
  token: DecoyToken;
  /** Precomputed so the constant-time path does not allocate per comparison. */
  bytes: Buffer;
}

/**
 * Keyed by value, because the value is the identity as far as matching is concerned: two records
 * describing the same planted string are one decoy, however they were labelled.
 */
const registry = new Map<string, RegisteredDecoy>();

export function registerDecoy(token: DecoyToken): void {
  if (token.value.length < MIN_DECOY_VALUE_LENGTH) {
    throw new Error(
      `Decoy ${token.id} has a ${token.value.length}-character value; the minimum is ` +
        `${MIN_DECOY_VALUE_LENGTH}. A value this short will match traffic that has nothing to do ` +
        `with your decoy, and a decoy that cries wolf is worse than no decoy.`
    );
  }
  registry.set(token.value, { token, bytes: Buffer.from(token.value, "utf8") });
}

/** Tests only. Production has no reason to un-plant a decoy mid-process. */
export function clearDecoys(): void {
  registry.clear();
}

/**
 * Find every registered decoy whose exact value appears anywhere in `text`, and record each hit.
 *
 * Exact value, never a pattern. This is the single decision that gives the mechanism its worth:
 * the moment matching becomes `AKIA[0-9A-Z]{16}` it inherits the error rate of every other
 * detector in the system, fires on the operator's genuine keys, and stops being proof of anything.
 * There is no fuzzy mode, no prefix mode, and no "looks like the decoy" mode; adding one would
 * not be an enhancement, it would delete the feature and leave the name behind.
 *
 * "Anywhere in the input" is deliberate too. The value will arrive concatenated into a query
 * string, embedded in a JSON body, or surrounded by transport noise, and anchoring the match would
 * hand every exfiltration path a trivial evasion.
 *
 * On timing: the substring search is `indexOf` and is therefore data-dependent. That is not
 * hardenable at an acceptable price - a constant-time search means a fixed-cost comparison at
 * every offset of every request body, per decoy - and it would be theatre if it were, because a
 * caller who can see the boolean result already holds a far better oracle than the clock, and that
 * oracle still requires guessing 80+ bits. Callers holding one isolated candidate (a single header
 * value, a single query parameter) should use `matchesDecoyValue` instead.
 */
export function scanForDecoys(text: string, trigger?: DecoyTriggerContext): DecoyToken[] {
  if (registry.size === 0 || text.length === 0) return [];

  const hits: DecoyToken[] = [];
  for (const entry of registry.values()) {
    if (text.length < entry.token.value.length) continue;
    if (text.indexOf(entry.token.value) < 0) continue;
    hits.push(entry.token);
  }

  for (const token of hits) {
    reportDecoyTrigger(token, trigger);
  }
  return hits;
}

/**
 * Constant-time equality of one isolated candidate against every registered decoy.
 *
 * The loop does not break on a match, so its duration depends on the registry size and on the
 * candidate's length - neither of which is secret - and not on which decoy matched or how far
 * down the list it sits. Length is compared before the digest because `timingSafeEqual` throws on
 * a length mismatch; leaking the length of a decoy leaks a property of its kind, which is public.
 *
 * This does not emit. It is the primitive; `scanForDecoys` is the surface that records.
 */
export function matchesDecoyValue(candidate: string): DecoyToken | null {
  const probe = Buffer.from(candidate, "utf8");
  let hit: DecoyToken | null = null;
  for (const entry of registry.values()) {
    if (probe.length !== entry.bytes.length) continue;
    if (timingSafeEqual(probe, entry.bytes)) hit = entry.token;
  }
  return hit;
}

/**
 * Record a decoy hit in the audit chain.
 *
 * The value is not in this record and must never be. An audit log is read by more people than the
 * environment it protects - it gets tailed in a terminal, shipped to a SIEM, pasted into an
 * incident ticket - and writing the decoy into it hands anyone with log access the exact string
 * the exfiltration was after, plus the knowledge of which string to strip from future traffic in
 * order to go unnoticed. The id and label are enough to find the decoy in the operator's own
 * file, which is the only place the value belongs.
 *
 * `emit` does not copy `payload` into the event, but the payload is left empty anyway: relying on
 * a detail of another module to keep a secret out of the log is a coincidence, not a control.
 */
export function reportDecoyTrigger(token: DecoyToken, trigger?: DecoyTriggerContext): AuditEvent {
  const metadata: Record<string, string> = {
    decoyId: token.id,
    decoyKind: token.kind,
    decoyTriggered: "true",
  };
  if (token.label !== undefined) metadata.decoyLabel = token.label;
  if (trigger?.surface !== undefined) metadata.decoySurface = trigger.surface;

  const ctx: AgentContext = {
    agentId: trigger?.agentId ?? "unattributed",
    sessionId: trigger?.sessionId,
    plane: "identity",
    action: "decoy:triggered",
    payload: {},
    metadata,
  };

  const result: PolicyResult = {
    decision: "deny",
    riskLevel: "critical",
    matchedRules: [DECOY_RULE_ID],
    reasons: [
      `Decoy ${token.id} (${token.kind}) appeared in inspected content; this value is never legitimately used`,
    ],
    requiresApproval: false,
    highRiskFlow: true,
    detections: detectionsForRules([DECOY_RULE_ID]),
  };

  return emit(ctx, result);
}

// --- Persistence -----------------------------------------------------------------------------

const DECOY_FILE_MODE = 0o600;

const DecoyTokenSchema = z.object({
  id: z.string().min(1),
  value: z
    .string()
    .min(
      MIN_DECOY_VALUE_LENGTH,
      `a decoy value shorter than ${MIN_DECOY_VALUE_LENGTH} characters will match ordinary traffic`
    ),
  kind: z.enum(DECOY_KIND_VALUES),
  createdAt: z.string().min(1),
  label: z.string().optional(),
});

// A bare array is accepted alongside the wrapped form because operators hand-edit this file, and
// the outer object earns its keep only when there is a second field to version against.
const DecoyFileSchema = z.union([
  z.array(DecoyTokenSchema),
  z.object({ tokens: z.array(DecoyTokenSchema) }),
]);

/**
 * Write the decoy file, values included, at 0600.
 *
 * The values have to be on disk: the operator needs them to plant, and AgentWall needs them to
 * match, so there is no version of this that stores only digests. That makes the file a genuine
 * secret with an unusual threat model - an attacker who reads it gains access to nothing, but
 * gains the ability to recognise the trap and route around it, which costs the operator the
 * detection silently.
 *
 * The explicit chmod is not redundant with the `mode` option: `mode` applies at creation only, so
 * a second save into a file somebody had loosened to 0644 would write fresh secrets into a
 * world-readable file and report success.
 */
export function saveDecoys(path: string, tokens: DecoyToken[]): void {
  const dir = dirname(path);
  if (dir !== "" && dir !== ".") {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  writeFileSync(path, `${JSON.stringify({ version: 1, tokens }, null, 2)}\n`, { mode: DECOY_FILE_MODE });
  chmodSync(path, DECOY_FILE_MODE);
}

/**
 * Read a decoy file, refusing one that anybody but the owner can read.
 *
 * Refusing rather than warning: a warning is a line nobody reads, and a decoy the attacker has
 * already enumerated is worse than no decoy, because the operator still believes it is watching.
 * The check is a POSIX mode check and is only as meaningful as the filesystem carrying it - on a
 * mount that reports a synthetic mode (many network and container overlays do) it either always
 * passes or always fails, and it says nothing about ACLs layered on top of the mode bits.
 */
export function loadDecoys(path: string): DecoyToken[] {
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `Refusing to read decoy file ${path}: mode ${mode.toString(8).padStart(4, "0")} lets group or ` +
        `other read it. The file holds the plaintext decoy values, so anyone who can read it can ` +
        `recognise the decoys and strip them from outbound traffic without tripping anything. ` +
        `Run: chmod 600 ${path}`
    );
  }

  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(
      `Decoy file ${path} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const parsed = DecoyFileSchema.safeParse(json);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((issue) => `${issue.path.length === 0 ? "(root)" : issue.path.join(".")}: ${issue.message}`)
      .join("; ");
    throw new Error(`Decoy file ${path} is not a valid token list: ${detail}`);
  }

  return Array.isArray(parsed.data) ? parsed.data : parsed.data.tokens;
}

// --- Planting --------------------------------------------------------------------------------

/**
 * Which environment variable each kind impersonates.
 *
 * These are the names the theft is looking for. A decoy exported as `DECOY_TOKEN_1` is invisible
 * to anything that harvests by well-known name, which is most of what harvests, so the variable
 * name is as much a part of the disguise as the value's shape is.
 */
const ENV_NAME_BY_KIND: Record<DecoyKind, string> = {
  "aws-access-key": "AWS_ACCESS_KEY_ID",
  "github-pat": "GITHUB_TOKEN",
  "openai-key": "OPENAI_API_KEY",
  "generic-secret": "API_SECRET",
  url: "WEBHOOK_URL",
};

/**
 * Shell lines an operator can paste or `source` to plant these decoys in a process environment.
 *
 * Values are single-quoted, the one shell quoting with no escape processing inside it, so a value
 * can never be re-read as a command. Nothing minted here contains a single quote, but the escape
 * is still applied because this also takes hand-written tokens loaded from a file.
 */
export function decoyEnvBlock(tokens: DecoyToken[]): string {
  const used = new Set<string>();
  const lines: string[] = [
    "# AgentWall decoy tokens. Not real credentials: they authenticate nowhere.",
    "# If any of these values ever appears in outbound traffic, something read this environment",
    "# and shipped it. AgentWall records that as a critical deny.",
  ];

  for (const token of tokens) {
    const name = uniqueEnvName(token, used);
    const label = token.label === undefined ? "" : ` - ${token.label}`;
    lines.push("", `# ${token.id}${label} (${token.kind}, minted ${token.createdAt})`);
    lines.push(`export ${name}='${token.value.replace(/'/g, "'\\''")}'`);
  }

  return `${lines.join("\n")}\n`;
}

/**
 * Pick the variable name for one token, keeping a block with several decoys assignable.
 *
 * Two decoys of the same kind would otherwise both want `AWS_ACCESS_KEY_ID` and the second
 * export would silently overwrite the first, leaving a planted value that nothing in the
 * environment carries. The label disambiguates when there is one; a numeric tail covers the rest.
 */
function uniqueEnvName(token: DecoyToken, used: Set<string>): string {
  const base = ENV_NAME_BY_KIND[token.kind];
  const suffix =
    token.label === undefined
      ? ""
      : token.label
          .toUpperCase()
          .replace(/[^A-Z0-9]+/g, "_")
          .replace(/^_+|_+$/g, "");
  const preferred = suffix === "" ? base : `${base}_${suffix}`;

  let name = preferred;
  let attempt = 2;
  while (used.has(name)) {
    name = `${preferred}_${attempt}`;
    attempt += 1;
  }
  used.add(name);
  return name;
}

// --- CLI -------------------------------------------------------------------------------------

const DECOY_USAGE =
  "Usage: agentwall decoy generate --kind <kind> [--label <l>] [--out <path>]\n" +
  "       agentwall decoy list --file <path>\n" +
  `Kinds: ${DECOY_KINDS.join(", ")}`;

/**
 * `agentwall decoy <generate|list>`.
 *
 * Raw argv rather than the CLI's shared flag parser: every flag here takes a value and none are
 * boolean, so the shared parser's boolean allowlist has nothing to contribute, and a local parser
 * turns a mistyped `--kind` into an error here instead of a silently ignored positional there.
 */
export function runDecoyCommand(args: string[]): void {
  const [subcommand, ...rest] = args;
  const flags = parseDecoyFlags(rest);

  switch (subcommand) {
    case "generate":
      commandDecoyGenerate(flags);
      return;
    case "list":
      commandDecoyList(flags);
      return;
    default:
      throw new Error(
        subcommand === undefined ? DECOY_USAGE : `Unknown decoy subcommand "${subcommand}".\n${DECOY_USAGE}`
      );
  }
}

function parseDecoyFlags(args: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!arg.startsWith("--")) {
      throw new Error(`Unexpected argument "${arg}".\n${DECOY_USAGE}`);
    }
    const next = args[i + 1];
    if (next === undefined || next.startsWith("--")) {
      throw new Error(`${arg} needs a value.\n${DECOY_USAGE}`);
    }
    flags[arg.slice(2)] = next;
    i += 1;
  }
  return flags;
}

export function commandDecoyGenerate(flags: Record<string, string>): void {
  const kind = flags.kind;
  if (kind === undefined) {
    throw new Error(`decoy generate needs --kind.\n${DECOY_USAGE}`);
  }
  if (!isDecoyKind(kind)) {
    throw new Error(`Unknown decoy kind "${kind}". Supported: ${DECOY_KINDS.join(", ")}.`);
  }

  const token = generateDecoy(kind, flags.label);
  const out = flags.out;
  if (out !== undefined) {
    // Append rather than replace: running this twice means the operator wants two decoys, and
    // dropping the first would also drop AgentWall's only way to match it.
    saveDecoys(out, [...(existsSync(out) ? loadDecoys(out) : []), token]);
  }

  console.log(`id         ${token.id}`);
  console.log(`kind       ${token.kind}`);
  console.log(`label      ${token.label ?? "(none)"}`);
  console.log(`createdAt  ${token.createdAt}`);
  console.log(`value      ${token.value}`);
  console.log("");
  console.log(decoyEnvBlock([token]).trimEnd());
  console.log("");

  if (out !== undefined) {
    console.log(`Saved to ${out} (mode 0600).`);
  } else {
    console.log("Not saved. Without --out this value exists only in this terminal, and AgentWall");
    console.log("cannot match a decoy it was never told about.");
  }
}

export function commandDecoyList(flags: Record<string, string>): void {
  const file = flags.file;
  if (file === undefined) {
    throw new Error(`decoy list needs --file.\n${DECOY_USAGE}`);
  }

  const tokens = loadDecoys(file);
  if (tokens.length === 0) {
    console.log(`No decoys in ${file}.`);
    return;
  }

  console.log(`${"ID".padEnd(20)}${"KIND".padEnd(17)}${"CREATED".padEnd(27)}LABEL`);
  for (const token of tokens) {
    const row = `${token.id.padEnd(20)}${token.kind.padEnd(17)}${token.createdAt.padEnd(27)}${token.label ?? ""}`;
    console.log(row.trimEnd());
  }
  console.log("");
  // Values are withheld here for the same reason they are withheld from the audit log: a listing
  // gets pasted into tickets and chat rooms, and a decoy an attacker can read is one they avoid.
  console.log(`${tokens.length} decoy token(s). Values are not shown; read ${file} to plant them.`);
}
