import { createHash, randomBytes, timingSafeEqual } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { z } from "zod";

/**
 * Credential lifecycle for a fleet: issuance, rotation with a bounded overlap, revocation.
 *
 * Why this exists at all, stated first because it is the thing that scales and the thing
 * `docs/fleet.md` used to get wrong. A credential is the ONLY one of the three binding
 * signals that survives a host boundary. `uid` and `comm` are facts about one kernel, and
 * two hosts with a uid 1001 have two unrelated accounts. A credential is presented on the
 * proxy connection itself, so the same secret binds the same agent on every host that runs
 * an AgentWall. What was missing was never the identity. It was the lifecycle: a digest
 * hand-written into a config file cannot be rotated without an outage and cannot be revoked
 * without editing every host that names it.
 *
 * The store is that lifecycle, and it is deliberately NOT the config file:
 *
 *   - Config is written by a human, committed, and reviewed. Rewriting it from a CLI would
 *     destroy comments and turn a reviewed artefact into a generated one.
 *   - Rotation state is a timestamp. A window that closes at 14:32 is not something anyone
 *     hand-edits into YAML, and a config file that has to be re-read for a clock to advance
 *     is a clock nobody trusts.
 *   - Revocation must take effect without a restart. Config is read at boot.
 *
 * So the config declares WHO the agents are, and this file records WHICH secrets currently
 * speak for them. An agent binds by credential if either source names a digest that matches,
 * and declaring both for one agent is a boot failure rather than a precedence rule nobody
 * would remember.
 *
 * What is stored is a sha256 digest and never the secret. sha256 with no salt and no KDF is
 * the right primitive here and would be the wrong one for a password: the secret is 32 bytes
 * from the CSPRNG, so there is no dictionary to run and no work factor that would make 2^256
 * meaningfully harder. A human-chosen secret pasted into this store would not have that
 * property, which is one more reason `fleet issue` mints it rather than accepting one.
 *
 * Limits, plainly:
 *   - This is a shared secret, not mTLS and not a signed token. Any process that can read
 *     the secret can present it. On a single-uid host that means it separates cooperating
 *     agents and does not contain a hostile one, exactly as before.
 *   - A digest written by hand into `match.credential` has no lifecycle. It cannot be
 *     rotated with an overlap and cannot be revoked from here, because this file has never
 *     seen it. Use `agentwall fleet issue` to get a credential that can be.
 *   - Nothing here distributes the store between hosts. Copying it, or pointing several
 *     hosts at one shared path, is the operator's deployment decision.
 */

/** Bytes of CSPRNG output behind an issued secret. 256 bits, so the digest is unbreakable. */
const SECRET_BYTES = 32;

/**
 * The longest overlap `fleet rotate` will accept.
 *
 * Bounded on purpose. An overlap is a window during which two secrets both work, which is a
 * deliberate, temporary weakening of the control. An "overlap" measured in weeks is not a
 * rotation in progress, it is two live credentials with one of them forgotten.
 */
export const MAX_OVERLAP_SECONDS = 24 * 60 * 60;

/** Overlap used when `--overlap` is omitted. Long enough to redeploy, short enough to notice. */
export const DEFAULT_OVERLAP_SECONDS = 15 * 60;

/**
 * How stale a running process's view of the store may be, in milliseconds.
 *
 * This is the number that makes revocation real, so it is a hard bound rather than a hope.
 * The store is re-checked at most once per second on the egress path: one `stat` per second
 * under load, not one per connection. A revocation therefore takes effect on the first
 * connection more than one second after the file lands, with no restart and no signal.
 *
 * Deliberately a poll rather than fs.watch. A watcher is cheaper and can silently die: the
 * inode it holds is replaced by the atomic rename this file does on every write, and on some
 * filesystems it never fires at all. A watcher that stopped working would mean a revocation
 * that never takes effect and nothing on screen to say so, which is the exact failure mode
 * this whole change exists to remove.
 */
const RELOAD_CHECK_MS = 1000;

/** Default file name, resolved beside the config file that declared the fleet. */
export const DEFAULT_CREDENTIAL_STORE_FILE = "fleet-credentials.json";

/** A freshly minted credential. The secret exists here and nowhere else, ever. */
export interface MintedCredential {
  /** The secret the agent presents in Proxy-Authorization. Printed once, never stored. */
  secret: string;
  /** sha256 of `secret`, which is what the store and the registry hold. */
  digest: string;
}

/**
 * Characters an agent id may use if it is going to appear in a credential.
 *
 * Enforced at issuance and NOT in the fleet schema. Tightening the schema would invalidate
 * configs people already run for agents that may never want a credential, over a constraint
 * that only bites when one is minted.
 */
const CREDENTIAL_SAFE_AGENT_ID = /^[A-Za-z0-9._-]+$/;

/**
 * Mint a credential for one agent.
 *
 * The secret is `<agentId>:<token>` and that shape is load-bearing rather than decorative.
 * There are exactly two ways a client presents a proxy credential, and this is the only form
 * that hashes to the same digest down both:
 *
 *   Proxy-Authorization: Bearer <agentId>:<token>   parseProxyCredential returns it whole.
 *   http://<agentId>:<token>@proxy:3128             every HTTP client turns proxy-URL
 *                                                   userinfo into Basic base64("user:pass"),
 *                                                   and parseProxyCredential returns the
 *                                                   DECODED "user:pass", also whole.
 *
 * A bare token would work over Bearer and silently fail over the URL form, because the client
 * would send "<something>:<token>" and the registry would hash a string the store has never
 * seen. The agent would then fall through to the weaker signals or to the global allowlist:
 * a green config that binds nothing. The proxy URL is how most deployments will actually
 * carry this, so it is the case the format is chosen for.
 *
 * Hex rather than base64 for the token, so it survives a shell variable, a systemd unit, and
 * a URL without quoting or percent-encoding.
 */
export function mintCredential(agentId: string): MintedCredential {
  if (!CREDENTIAL_SAFE_AGENT_ID.test(agentId)) {
    throw new Error(
      `agentwall: agent id "${agentId}" cannot appear in a credential. A credential is presented as ` +
        `"<agentId>:<token>", including inside a proxy URL, so the id must be letters, digits, dot, ` +
        `underscore, or hyphen. Rename the agent, or bind it on uid instead of a credential.`
    );
  }
  const secret = `${agentId}:${randomBytes(SECRET_BYTES).toString("hex")}`;
  return { secret, digest: createHash("sha256").update(secret, "utf8").digest("hex") };
}

/** What a stored credential is doing right now. */
export type CredentialState = "active" | "overlap" | "expired" | "revoked";

const StoredCredentialSchema = z.object({
  /** The declared agent this credential speaks for. */
  agentId: z.string().min(1),
  /**
   * A name for this credential that is safe to print, log, and put in a ticket.
   *
   * Random, and unrelated to the digest. Deriving it from the digest would make every
   * `fleet list` output a partial preimage hint for the thing it identifies.
   */
  credentialId: z.string().min(1),
  digest: z.string().regex(/^[0-9a-f]{64}$/, "a credential digest must be 64 lowercase hex characters"),
  issuedAt: z.string().min(1),
  /** When this credential stops being accepted. Null means it is the current one. */
  expiresAt: z.string().min(1).nullable().default(null),
  revokedAt: z.string().min(1).nullable().default(null),
  revokedReason: z.string().min(1).nullable().default(null),
});

export type StoredCredential = z.infer<typeof StoredCredentialSchema>;

export const CredentialStoreFileSchema = z.object({
  version: z.literal(1),
  updatedAt: z.string().min(1),
  credentials: z.array(StoredCredentialSchema).default([]),
});

export type CredentialStoreFile = z.infer<typeof CredentialStoreFileSchema>;

/**
 * What one stored credential is worth at an instant.
 *
 * An unparseable `expiresAt` resolves to `expired`, not to `active`. A corrupted timestamp
 * must close the window rather than open it forever: the failure an operator can see is the
 * agent losing access, and the failure they cannot see is a rotation that never ended.
 */
export function credentialState(credential: StoredCredential, now: number = Date.now()): CredentialState {
  if (credential.revokedAt) return "revoked";
  if (credential.expiresAt === null) return "active";
  return Date.parse(credential.expiresAt) > now ? "overlap" : "expired";
}

/** A presented secret matched against the store. */
export interface CredentialMatch {
  credential: StoredCredential;
  state: CredentialState;
}

/**
 * The narrow view the registry needs.
 *
 * The registry takes this rather than a `CredentialStore` so that it depends on a lookup and
 * not on a file. A test can hand it three literal records; nothing in the egress path has to
 * touch a temp directory to be exercised.
 */
export interface CredentialSource {
  /** Match a presented digest. Returns the record whatever state it is in; the caller judges. */
  lookup(presented: Buffer): CredentialMatch | null;
  /** Every record for one agent, newest first, whatever state each is in. */
  listFor(agentId: string): readonly StoredCredential[];
  /** Every record, newest first. */
  list(): readonly StoredCredential[];
}

/**
 * Parse `15m`, `2h`, `90s`, `1d`, or a bare count of seconds.
 *
 * Rejects rather than guesses. `--overlap 15` meaning fifteen seconds when the operator
 * meant fifteen minutes is a rotation that becomes an outage four minutes in, so a bare
 * number is accepted only because it is unambiguous, and every other form needs its unit.
 */
export function parseDurationSeconds(input: string): number {
  const text = input.trim().toLowerCase();
  const match = /^(\d+)(s|m|h|d)?$/.exec(text);
  if (!match) {
    throw new Error(
      `agentwall: cannot read "${input}" as a duration. Use seconds (90s), minutes (15m), hours (2h), or days (1d).`
    );
  }
  const value = Number(match[1]);
  const unit = match[2] ?? "s";
  const scale = unit === "s" ? 1 : unit === "m" ? 60 : unit === "h" ? 3600 : 86400;
  return value * scale;
}

/**
 * Seconds rendered the way the CLI and doctor both print them.
 *
 * Carries the remainder rather than rounding to the nearest unit. A 90 second overlap
 * printed as "2m" is a security control lying about itself by 33 percent, and the operator
 * who reads it is the one deciding whether there is time to redeploy.
 */
export function formatDuration(seconds: number): string {
  const whole = Math.max(0, Math.round(seconds));
  if (whole < 60) return `${whole}s`;
  if (whole < 3600) {
    const rest = whole % 60;
    return rest === 0 ? `${whole / 60}m` : `${Math.floor(whole / 60)}m ${rest}s`;
  }
  if (whole < 86400) {
    const rest = Math.round((whole % 3600) / 60);
    return rest === 0 ? `${whole / 3600}h` : `${Math.floor(whole / 3600)}h ${rest}m`;
  }
  const rest = Math.round((whole % 86400) / 3600);
  return rest === 0 ? `${whole / 86400}d` : `${Math.floor(whole / 86400)}d ${rest}h`;
}

/**
 * Where the store lives for a given deployment.
 *
 * Resolved beside the config file that declared the fleet, not beside the process's cwd. The
 * CLI is run from wherever an operator happens to be standing and the server is started by a
 * unit file from `/`; anchoring on the config is the only choice that makes those two agree
 * without a flag.
 */
export function resolveCredentialStorePath(configSource: string | null, declared?: string): string {
  const base = configSource ? path.dirname(configSource) : process.cwd();
  return path.resolve(base, declared ?? DEFAULT_CREDENTIAL_STORE_FILE);
}

function indexByDigest(records: readonly StoredCredential[]): Map<string, { credential: StoredCredential; digest: Buffer }> {
  const index = new Map<string, { credential: StoredCredential; digest: Buffer }>();
  for (const credential of records) {
    index.set(credential.digest, { credential, digest: Buffer.from(credential.digest, "hex") });
  }
  return index;
}

/** Newest first, so `fleet list` and every doctor line agree on an order without sorting again. */
function newestFirst(records: StoredCredential[]): StoredCredential[] {
  return [...records].sort((a, b) => Date.parse(b.issuedAt) - Date.parse(a.issuedAt));
}

/**
 * The issued credentials for one host, on disk, re-read while the process runs.
 *
 * Read on the egress path and written by the CLI, which are different processes. That is why
 * every write is atomic (temp file plus rename) and every read is bounded-stale rather than
 * cached forever: the running proxy must observe a revocation the CLI made a second ago
 * without either process knowing the other exists.
 */
export class CredentialStore implements CredentialSource {
  readonly filePath: string;
  private records: StoredCredential[] = [];
  private byDigest = new Map<string, { credential: StoredCredential; digest: Buffer }>();
  /** Identity of the bytes currently loaded, or "absent". */
  private stamp = "absent";
  private lastCheck = 0;
  /**
   * The failure from the most recent reload attempt, if any.
   *
   * A store the process cannot read leaves the LAST GOOD records in force rather than
   * dropping every credential, because dropping them would turn a JSON typo or a blipping
   * network mount into a fleet-wide egress outage: under `minimumMatchTier: credential` with
   * `unmatched: deny`, every agent on the host loses its identity at once. Retention is also
   * not a security hole, because it cannot grant anything: a revocation is a tombstone
   * WRITTEN into the file, never a deletion of it, so nothing an operator revoked comes back
   * by the file becoming unreadable.
   *
   * That is the safe direction and it is a silent one, so the error is kept and `agentwall
   * doctor` reports it. Enforcement continues; visibility of the problem is what this buys.
   */
  private lastError: Error | null = null;
  /**
   * True once the file has been parsed successfully at least once.
   *
   * Distinguishes "nothing has been issued yet", which is the ordinary state of a fresh
   * install, from "the store I was enforcing has gone", which is an incident.
   */
  private loadedOnce = false;

  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
    this.reload();
  }

  /** The parse error from the last reload attempt, or null. */
  get error(): Error | null {
    return this.lastError;
  }

  /** True when no store file has ever been read, which is the state before anything is issued. */
  get absent(): boolean {
    return !this.loadedOnce;
  }

  private fileStamp(): string {
    try {
      const stat = fs.statSync(this.filePath);
      // mtime alone is not enough: two writes inside one millisecond would look identical.
      // The inode closes that, because every write here lands through a rename.
      return `${stat.mtimeMs}|${stat.size}|${stat.ino}`;
    } catch {
      return "absent";
    }
  }

  /**
   * Read the file unconditionally. Keeps the last good records if the new bytes are bad, or
   * if the file has gone.
   */
  reload(): void {
    const stamp = this.fileStamp();
    this.lastCheck = Date.now();
    if (stamp === "absent") {
      if (this.loadedOnce) {
        // The store was here and is not now: a delete, a rename, or a shared mount that
        // dropped. Every credential in it stays in force and the error is what gets reported,
        // for the reason `lastError` gives. `stamp` DOES advance to "absent" so the next
        // check is a single stat rather than a re-read of a file that is not there, and the
        // file reappearing produces a different stamp and reloads.
        this.stamp = "absent";
        this.lastError = new Error(
          `${this.filePath} has gone. The credentials it held are still being enforced from the last copy read.`
        );
        return;
      }
      this.records = [];
      this.byDigest = new Map();
      this.stamp = "absent";
      this.lastError = null;
      return;
    }
    try {
      const parsed = CredentialStoreFileSchema.parse(JSON.parse(fs.readFileSync(this.filePath, "utf8")));
      this.records = newestFirst(parsed.credentials);
      this.byDigest = indexByDigest(this.records);
      this.stamp = stamp;
      this.lastError = null;
      this.loadedOnce = true;
    } catch (error) {
      this.lastError = error instanceof Error ? error : new Error(String(error));
      // Deliberately does NOT advance `stamp`: the next check retries the same bytes, so a
      // half-written file that is repaired in place recovers without a restart.
    }
  }

  /**
   * What a MUTATOR reads before it writes, which is not the same contract as a reader.
   *
   * The reader above keeps enforcing what it last understood. A writer must not: every write
   * here replaces the whole file, so writing a merge of records that came from somewhere
   * other than the current file would silently destroy whatever the file actually contains.
   * An unreadable store is therefore a refusal with the path in it, not a recovery.
   *
   * A store that has simply never existed is not a failure. That is the first `fleet issue`.
   */
  private readForWrite(): void {
    this.reload();
    if (this.lastError) {
      throw new Error(
        `agentwall: ${this.filePath} could not be read (${this.lastError.message}). Refusing to write, because ` +
          `this command replaces the whole file and would destroy whatever is in it. Fix or move that file, then retry.`
      );
    }
  }

  /** Re-read if the file changed and we have not looked in the last RELOAD_CHECK_MS. */
  private refresh(): void {
    const now = Date.now();
    if (now - this.lastCheck < RELOAD_CHECK_MS) return;
    this.lastCheck = now;
    if (this.fileStamp() === this.stamp) return;
    this.reload();
  }

  list(): readonly StoredCredential[] {
    this.refresh();
    return this.records;
  }

  listFor(agentId: string): readonly StoredCredential[] {
    return this.list().filter((credential) => credential.agentId === agentId);
  }

  lookup(presented: Buffer): CredentialMatch | null {
    this.refresh();
    const found = this.byDigest.get(presented.toString("hex"));
    // Same shape as the registry's config-credential probe and for the same reason: the map
    // finds the candidate, and a constant-time compare is what decides the match. The length
    // guard stays because timingSafeEqual throws on a mismatch, and a throw inside a socket
    // handler would let a client take the proxy down with a malformed credential.
    if (!found || found.digest.length !== presented.length || !timingSafeEqual(found.digest, presented)) return null;
    return { credential: found.credential, state: credentialState(found.credential) };
  }

  /**
   * Mint a credential for an agent that has none active.
   *
   * Refuses when one is already active, because the alternative is silently orphaning a
   * credential a live agent is presenting right now. Replacing a working credential is
   * rotation, it has an overlap window, and it has its own verb.
   */
  issue(agentId: string): { credential: StoredCredential; secret: string } {
    this.readForWrite();
    const active = this.records.find(
      (credential) => credential.agentId === agentId && credentialState(credential) === "active"
    );
    if (active) {
      throw new Error(
        `agentwall: agent "${agentId}" already has an active credential (${active.credentialId}). ` +
          `Use "agentwall fleet rotate --agent ${agentId}" to replace it with an overlap window, or ` +
          `"agentwall fleet revoke --credential ${active.credentialId}" to end it first.`
      );
    }
    const minted = mintCredential(agentId);
    const credential: StoredCredential = {
      agentId,
      credentialId: this.freshCredentialId(),
      digest: minted.digest,
      issuedAt: new Date().toISOString(),
      expiresAt: null,
      revokedAt: null,
      revokedReason: null,
    };
    this.write([credential, ...this.records]);
    return { credential, secret: minted.secret };
  }

  /**
   * Replace an agent's active credential, keeping the old one valid for `overlapSeconds`.
   *
   * The overlap is the whole point. Without it, rotation is an outage: the instant the new
   * digest lands, every agent still presenting the old secret is refused, and on a fleet the
   * gap between "the digest landed" and "the last host restarted with the new secret" is
   * measured in minutes. With it, both work until a stated time and the old one then stops,
   * which is a rotation rather than a coordinated restart.
   *
   * `overlapSeconds: 0` is allowed and means an immediate cutover. That is a legitimate
   * choice when the credential is believed compromised, and it is spelled out rather than
   * inferred.
   */
  rotate(agentId: string, overlapSeconds: number): { previous: StoredCredential; credential: StoredCredential; secret: string } {
    if (!Number.isInteger(overlapSeconds) || overlapSeconds < 0) {
      throw new Error(`agentwall: an overlap must be a whole number of seconds and cannot be negative.`);
    }
    if (overlapSeconds > MAX_OVERLAP_SECONDS) {
      throw new Error(
        `agentwall: an overlap of ${formatDuration(overlapSeconds)} exceeds the ${formatDuration(MAX_OVERLAP_SECONDS)} ` +
          `maximum. Two credentials that both work for longer than a day are two live credentials, not a rotation.`
      );
    }
    this.readForWrite();
    const active = this.records.find(
      (credential) => credential.agentId === agentId && credentialState(credential) === "active"
    );
    if (!active) {
      throw new Error(
        `agentwall: agent "${agentId}" has no active credential to rotate. ` +
          `Use "agentwall fleet issue --agent ${agentId}" to mint its first one.`
      );
    }
    const minted = mintCredential(agentId);
    const now = Date.now();
    const previous: StoredCredential = { ...active, expiresAt: new Date(now + overlapSeconds * 1000).toISOString() };
    const credential: StoredCredential = {
      agentId,
      credentialId: this.freshCredentialId(),
      digest: minted.digest,
      issuedAt: new Date(now).toISOString(),
      expiresAt: null,
      revokedAt: null,
      revokedReason: null,
    };
    const next = this.records.map((record) => (record.credentialId === active.credentialId ? previous : record));
    this.write([credential, ...next]);
    return { previous, credential, secret: minted.secret };
  }

  /**
   * Revoke one credential by id, leaving every other credential in the store untouched.
   *
   * The record is kept, not deleted. A deleted credential is indistinguishable from one that
   * was never issued, and "this id was revoked at 14:32 because the laptop was lost" is the
   * sentence an incident review needs. A revoked record is also what makes the refusal
   * specific: an unknown digest and a revoked one produce different evidence.
   */
  revoke(credentialId: string, reason?: string): StoredCredential {
    this.readForWrite();
    const found = this.records.find((credential) => credential.credentialId === credentialId);
    if (!found) {
      throw new Error(`agentwall: no credential "${credentialId}" in ${this.filePath}.`);
    }
    if (found.revokedAt) {
      throw new Error(`agentwall: credential "${credentialId}" was already revoked at ${found.revokedAt}.`);
    }
    const revoked: StoredCredential = {
      ...found,
      revokedAt: new Date().toISOString(),
      revokedReason: reason?.trim() || null,
    };
    this.write(this.records.map((record) => (record.credentialId === credentialId ? revoked : record)));
    return revoked;
  }

  /** Revoke every credential an agent holds, including one mid-overlap. */
  revokeAgent(agentId: string, reason?: string): StoredCredential[] {
    this.readForWrite();
    const targets = this.records.filter((credential) => credential.agentId === agentId && !credential.revokedAt);
    if (targets.length === 0) {
      throw new Error(`agentwall: agent "${agentId}" holds no credential that is not already revoked.`);
    }
    const at = new Date().toISOString();
    const ids = new Set(targets.map((credential) => credential.credentialId));
    const revoked: StoredCredential[] = [];
    const next = this.records.map((record) => {
      if (!ids.has(record.credentialId)) return record;
      const updated: StoredCredential = { ...record, revokedAt: at, revokedReason: reason?.trim() || null };
      revoked.push(updated);
      return updated;
    });
    this.write(next);
    return revoked;
  }

  private freshCredentialId(): string {
    for (;;) {
      const candidate = `cred-${randomBytes(5).toString("hex")}`;
      if (!this.records.some((credential) => credential.credentialId === candidate)) return candidate;
    }
  }

  /**
   * Replace the file atomically.
   *
   * Temp file plus rename, so a reader never sees half a document and a crash mid-write
   * leaves the previous store intact. Mode 0600 because the digests are the only thing worth
   * protecting here and there is no reason for them to be world-readable.
   */
  private write(records: StoredCredential[]): void {
    const ordered = newestFirst(records);
    const file: CredentialStoreFile = {
      version: 1,
      updatedAt: new Date().toISOString(),
      credentials: ordered,
    };
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const temp = `${this.filePath}.tmp-${process.pid}`;
    fs.writeFileSync(temp, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temp, this.filePath);
    this.records = ordered;
    this.byDigest = indexByDigest(ordered);
    this.stamp = this.fileStamp();
    this.lastCheck = Date.now();
    this.lastError = null;
    this.loadedOnce = true;
  }
}

/**
 * A `CredentialSource` over a fixed list, for tests and for callers that already hold records.
 *
 * Separate from CredentialStore rather than a mode of it, so that nothing can accidentally
 * construct the file-backed one without a file and then wonder why revocation does nothing.
 */
export class StaticCredentialSource implements CredentialSource {
  private readonly records: readonly StoredCredential[];
  private readonly byDigest: Map<string, { credential: StoredCredential; digest: Buffer }>;

  constructor(records: readonly StoredCredential[]) {
    this.records = newestFirst([...records]);
    this.byDigest = indexByDigest(this.records);
  }

  list(): readonly StoredCredential[] {
    return this.records;
  }

  listFor(agentId: string): readonly StoredCredential[] {
    return this.records.filter((credential) => credential.agentId === agentId);
  }

  lookup(presented: Buffer): CredentialMatch | null {
    const found = this.byDigest.get(presented.toString("hex"));
    if (!found || found.digest.length !== presented.length || !timingSafeEqual(found.digest, presented)) return null;
    return { credential: found.credential, state: credentialState(found.credential) };
  }
}
