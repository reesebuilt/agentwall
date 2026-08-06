import { spawnSync } from "child_process";
import { createSecureContext, SecureContext } from "tls";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "fs";
import { isAbsolute, join, resolve } from "path";
import { tmpdir } from "os";
import { createHash, generateKeyPairSync, randomBytes } from "crypto";
import { isPlausibleHostname } from "./hostname";

/**
 * The local CA and the leaf certificates it signs: the only part of interception that mints
 * anything.
 *
 * X.509 issuance is done by `openssl`, not by Node. That is not a preference, it is what the
 * platform leaves available: `crypto.X509Certificate` parses certificates and exposes no
 * static constructor, and `crypto.Certificate` is the legacy SPKAC helper, not an issuer.
 * Minting in-process therefore needs a certificate library, which would be a fourth runtime
 * dependency, and the three-dependency floor (fastify, js-yaml, zod) exists to keep the npm
 * supply chain small because that is the surface that actually gets attacked: typosquats,
 * compromised maintainers, hallucinated package names resolving to whatever an attacker
 * parked there.
 *
 * A system binary the operator already has is a different risk class, and this project
 * already depends on several. `src/perimeter/index.ts` spawns `nft` at three sites (install at
 * 168, rollback at 260, reading the live table at 348), the dashboard route spawns `systemctl`,
 * the MCP wrapper spawns the server it wraps. `openssl` sits where
 * `nft` sits: a stated precondition of a feature, checked before the feature claims to work,
 * not a package resolved from a registry. Every invocation here passes an argv array with
 * `shell: false`, matching the `nft` calls exactly.
 *
 * WHAT THE CA KEY IS. Whoever holds `ca.key` can mint a certificate for any name on earth
 * that this host will then trust. It is the single most dangerous file this project creates.
 * It is written 0600, it is never logged, never put in an audit record, never returned from a
 * dashboard route, and interception refuses to start if its mode is wider than 0600. Those are
 * enforced below rather than documented and hoped for.
 */

/** The binary. A bare name, resolved through PATH exactly as `nft` is. */
const OPENSSL = "openssl";

/**
 * How long a spawned `openssl` may take before it is treated as a failure.
 *
 * Bounded because these run on the connection path's cold start. An `openssl` that hangs on
 * a blocked entropy source would otherwise hold the event loop for as long as it liked, and
 * a proxy that stops answering is worse than one that refuses a host.
 */
const OPENSSL_TIMEOUT_MS = 10_000;

/** Output cap. A malformed invocation must not be able to buffer without limit. */
const OPENSSL_MAX_BUFFER = 1024 * 1024;

const CA_CERT_FILE = "ca.crt";
const CA_KEY_FILE = "ca.key";

/** The only mode the CA key may have. Anything wider and interception refuses to start. */
const CA_KEY_MODE = 0o600;

/** Leaf lifetime. Short because a leaf is disposable: losing one costs a re-mint. */
const LEAF_DAYS = 30;

/**
 * CA lifetime.
 *
 * Long enough that an operator is not reinstalling trust every quarter, short enough that a
 * forgotten CA eventually stops being a skeleton key. An expiry is the only mitigation this
 * design has for a key that leaked without anyone noticing.
 */
const CA_DAYS = 825;

const CA_SUBJECT = "/O=AgentWall/CN=AgentWall Local Interception CA";

/** Where the CA lives when the operator names no directory. Relative to cwd, never $HOME. */
export const DEFAULT_CA_DIR = "./agentwall-ca";

export interface CaPaths {
  dir: string;
  certPath: string;
  keyPath: string;
}

/**
 * Resolve the CA directory, honouring the flag, then the environment, then the default.
 *
 * Same precedence the perimeter command uses for its uids, for the same reason: an operator
 * who set an environment variable and then passed a flag meant the flag.
 */
export function resolveCaPaths(dir?: string): CaPaths {
  const chosen = dir ?? process.env["AGENTWALL_CA_DIR"] ?? DEFAULT_CA_DIR;
  const abs = isAbsolute(chosen) ? chosen : resolve(process.cwd(), chosen);
  return { dir: abs, certPath: join(abs, CA_CERT_FILE), keyPath: join(abs, CA_KEY_FILE) };
}

export interface OpensslProbe {
  present: boolean;
  /** The first line of `openssl version`, or the reason it could not be run. */
  detail: string;
}

/**
 * Is `openssl` on this host, and which one?
 *
 * Checked by running it rather than by looking for a file. A binary that exists and cannot
 * execute, or one whose libraries are missing, fails here instead of failing later on a
 * connection an operator believed was being inspected.
 */
export function probeOpenssl(): OpensslProbe {
  const result = spawnSync(OPENSSL, ["version"], {
    encoding: "utf8",
    shell: false,
    // Explicit rather than inherited. spawnSync defaults to the ambient environ, which in a normal
    // process is the same thing, but a runtime that replaces `process.env` with its own object
    // (Jest does exactly this) would have the probe resolve against a PATH nothing in this process
    // can see. A precondition check that cannot be made to fail on purpose is not a check.
    env: process.env,
    timeout: OPENSSL_TIMEOUT_MS,
    maxBuffer: OPENSSL_MAX_BUFFER,
  });
  if (result.error) {
    const code = (result.error as NodeJS.ErrnoException).code;
    return {
      present: false,
      detail:
        code === "ENOENT"
          ? `no \`openssl\` on PATH (${process.env["PATH"] ?? "PATH unset"})`
          : `\`openssl version\` could not be run: ${result.error.message}`,
    };
  }
  if (result.status !== 0) {
    return { present: false, detail: `\`openssl version\` exited ${result.status}: ${(result.stderr ?? "").trim()}` };
  }
  return { present: true, detail: (result.stdout ?? "").trim().split("\n")[0] ?? "unknown version" };
}

/** A spawn that succeeded, or the reason it did not, with no partial output leaking through. */
type Run = { ok: true; stdout: string } | { ok: false; reason: string };

function runOpenssl(args: string[], input?: string): Run {
  const result = spawnSync(OPENSSL, args, {
    encoding: "utf8",
    shell: false,
    // Explicit for the same reason `probeOpenssl` is: the probe and every real invocation have to
    // resolve the binary the same way, or a passing precondition check would say nothing about
    // the mints that follow it.
    env: process.env,
    timeout: OPENSSL_TIMEOUT_MS,
    maxBuffer: OPENSSL_MAX_BUFFER,
    ...(input === undefined ? {} : { input }),
  });
  if (result.error) return { ok: false, reason: `\`openssl ${args[0]}\` failed to run: ${result.error.message}` };
  if (result.signal) return { ok: false, reason: `\`openssl ${args[0]}\` was killed by ${result.signal}` };
  if (result.status !== 0) {
    // stderr, trimmed to one line: openssl is verbose on failure and a multi-page error in
    // an operator-facing refusal buries the sentence that says what to do.
    const err = (result.stderr ?? "").trim().split("\n").filter(Boolean);
    return { ok: false, reason: `\`openssl ${args[0]}\` exited ${result.status}: ${err[err.length - 1] ?? "no output"}` };
  }
  return { ok: true, stdout: result.stdout ?? "" };
}

export type CaGenerateResult = { ok: true; paths: CaPaths; fingerprint: string } | { ok: false; reason: string };

/**
 * Create the CA. One `openssl` spawn, and the only place a CA private key is ever written.
 *
 * Refuses rather than overwrites. Replacing a CA silently would invalidate every leaf already
 * minted from it and, worse, leave the previous certificate installed in trust stores where it
 * is now a key nobody can account for. Rotation is a deliberate act: remove the directory.
 *
 * The key is written by `openssl` and then chmod'd, which leaves a window between creation and
 * 0600. It is narrowed by creating the directory 0700 FIRST, so for the whole of that window
 * the file sits inside a directory no other user can traverse.
 */
export function generateCa(dir?: string, opts?: { days?: number }): CaGenerateResult {
  const paths = resolveCaPaths(dir);
  const probe = probeOpenssl();
  if (!probe.present) return { ok: false, reason: probe.detail };

  if (existsSync(paths.keyPath) || existsSync(paths.certPath)) {
    return {
      ok: false,
      reason:
        `a CA already exists in ${paths.dir}. Refusing to overwrite it: every certificate minted from ` +
        `the old key would stop verifying, and the old certificate would stay installed in trust stores ` +
        `as a key nobody can account for. To rotate deliberately, remove that directory and re-run.`,
    };
  }

  // 0700 before anything is written into it, so the key is never readable by another user,
  // not even for the moment between openssl creating it and the chmod below.
  mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
  chmodSync(paths.dir, 0o700);

  const days = String(opts?.days ?? CA_DAYS);
  const run = runOpenssl([
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    paths.keyPath,
    "-out",
    paths.certPath,
    "-days",
    days,
    "-sha256",
    "-subj",
    CA_SUBJECT,
    // Explicit rather than inherited from openssl.cnf, which differs across distributions.
    // pathlen:0 means this CA can sign leaves and cannot sign another CA, so a stolen key
    // cannot be used to issue a sub-CA that outlives revoking this one.
    "-addext",
    "basicConstraints=critical,CA:TRUE,pathlen:0",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
  ]);
  if (!run.ok) return { ok: false, reason: run.reason };

  chmodSync(paths.keyPath, CA_KEY_MODE);
  chmodSync(paths.certPath, 0o644);

  const status = inspectCa(paths);
  if (!status.present) return { ok: false, reason: `openssl reported success but ${paths.certPath} is not readable` };
  return { ok: true, paths, fingerprint: status.fingerprint ?? "unavailable" };
}

export interface CaStatus {
  paths: CaPaths;
  present: boolean;
  /** SHA-256 of the DER certificate, colon-free lowercase hex. Safe to print; it is public. */
  fingerprint: string | null;
  notAfter: string | null;
  expired: boolean;
  /** Actual mode of the key file, or null when it is missing. */
  keyMode: number | null;
  /**
   * Why this CA may not be used, empty when it may be.
   *
   * A list rather than a first-failure, because an operator fixing one problem should see the
   * next one in the same output instead of re-running to discover it.
   */
  problems: string[];
}

/**
 * Everything knowable about the CA on disk without using it.
 *
 * The key is opened only to `stat` it. Its bytes are never read here, so no code path in
 * status, the CLI, or a dashboard route can accidentally serialise them.
 */
export function inspectCa(dir?: string | CaPaths): CaStatus {
  const paths = typeof dir === "object" && dir !== null ? dir : resolveCaPaths(dir);
  const problems: string[] = [];
  const certThere = existsSync(paths.certPath);
  const keyThere = existsSync(paths.keyPath);

  if (!certThere) problems.push(`no CA certificate at ${paths.certPath}`);
  if (!keyThere) problems.push(`no CA private key at ${paths.keyPath}`);
  if (!certThere || !keyThere) {
    return { paths, present: false, fingerprint: null, notAfter: null, expired: false, keyMode: null, problems };
  }

  let keyMode: number | null = null;
  const keyStat = statSync(paths.keyPath);
  if (!keyStat.isFile()) {
    problems.push(`${paths.keyPath} is not a regular file`);
  } else {
    keyMode = keyStat.mode & 0o777;
    // Any bit outside owner read/write. A key readable by the operator's group is a key
    // readable by every process running as any member of that group, which on a developer
    // box is most of them.
    if ((keyMode & ~CA_KEY_MODE) !== 0) {
      problems.push(
        `${paths.keyPath} is mode 0${keyMode.toString(8)}, wider than 0600. Anyone who can read it can ` +
          `impersonate every site to this host. Fix with: chmod 600 ${paths.keyPath}`
      );
    }
  }

  let fingerprint: string | null = null;
  let notAfter: string | null = null;
  let expired = false;
  try {
    const pem = readFileSync(paths.certPath, "utf8");
    const der = pemToDer(pem);
    if (der === null) {
      problems.push(`${paths.certPath} does not contain a PEM certificate`);
    } else {
      fingerprint = createHash("sha256").update(der).digest("hex");
    }
    // Dates come from openssl rather than a hand-rolled ASN.1 walk: the binary is already a
    // precondition, and a date parser written here would be a second thing to get wrong.
    const dates = runOpenssl(["x509", "-in", paths.certPath, "-noout", "-enddate"]);
    if (dates.ok) {
      const raw = dates.stdout.trim().replace(/^notAfter=/, "");
      notAfter = raw;
      const parsed = Date.parse(raw);
      if (!Number.isNaN(parsed) && parsed <= Date.now()) {
        expired = true;
        problems.push(`the CA certificate expired on ${raw}. Regenerate it and reinstall trust.`);
      }
    }
  } catch (err) {
    problems.push(`${paths.certPath} could not be read: ${(err as Error).message}`);
  }

  return { paths, present: true, fingerprint, notAfter, expired, keyMode, problems };
}

function pemToDer(pem: string): Buffer | null {
  const match = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem);
  if (!match || !match[1]) return null;
  return Buffer.from(match[1].replace(/\s+/g, ""), "base64");
}

/** IPv4 dotted quad. Cheaper and stricter than asking the resolver. */
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function isIpv4(name: string): boolean {
  if (!IPV4.test(name)) return false;
  return name.split(".").every((part) => Number(part) <= 255 && String(Number(part)) === part);
}

/**
 * The subjectAltName a name needs, or null when this name may not be minted for at all.
 *
 * This is the ONE gate in front of all THREE places a hostname escapes into something that
 * interprets it, and it is deliberately a single gate rather than three: `contextFor` calls this
 * before `mintLeaf`, and `mintLeaf` is what puts the name in an `openssl` argv AND the SAN in an
 * `-extfile` config stanza, and the cache is only ever written after both succeed. Three call sites,
 * one refusal, so they cannot drift apart.
 *
 * It is a gate rather than an escape because there is nothing to escape into: the charset allowlist
 * in `isPlausibleHostname` admits letters, digits, hyphen and underscore per label and nothing
 * else, with 253 characters total and 63 per label. No quote, no semicolon, no backtick, no slash,
 * no dot-dot, no NUL, no newline, no `=`, no `[` and no comment character. Combined with
 * `shell: false` and an argv array there is no shell to inject into, no config directive to append,
 * and no path component to traverse with.
 *
 * `parseHostPort` in forward-proxy.ts does no validation at all: it splits the CONNECT authority on
 * the last colon and hands back whatever remains. That is harmless while the string only reaches a
 * connect call and an allowlist, and it stops being harmless the moment it reaches a subprocess
 * argument or a config file. What actually arrives has been MEASURED by ForwardProxyTests, commit
 * 8561097, and two of the results are worth having in writing here because intuition gets them
 * wrong:
 *
 *   - A SLASH is not rejected by Node's parser. `example.internal/path:443` arrives as the host
 *     `example.internal/path` verbatim, and nothing decodes the authority, so percent-encoding is
 *     not a way back in either. That is exactly the shape that becomes a traversal in anything
 *     building a filename from a hostname, and it is why this gate is in front of the cache too.
 *   - A bare LF is ACCEPTED, not refused. It terminates the request line, the authority truncates
 *     at it, and the remainder parses as a valid header, so a decision is taken on the shortened
 *     host: `CONNECT exam\nple.internal:443` decides on `exam`. A bare CR is refused, as are NUL,
 *     space, tab and backslash. So no newline reaches a name this ever sees, but it holds by
 *     TRUNCATION rather than by refusal, which is a weaker mechanism than it first appears and is
 *     why the charset allowlist below is load-bearing rather than belt-and-braces. An earlier
 *     version of this comment claimed the parser refused both; it does not.
 *
 * IPv4 gets an IP SAN because a DNS SAN does not verify for a connection made to a literal
 * address, and an agent calling an IP-addressed endpoint is ordinary traffic. IPv6 is refused
 * on purpose rather than by accident: bracket stripping, zone identifiers and the several
 * legal spellings of one address are a cache-key correctness problem this slice is not
 * solving, so those connections tunnel and say they tunnelled.
 */
export function sanFor(name: string): string | null {
  if (isIpv4(name)) return `IP:${name}`;
  if (isPlausibleHostname(name)) return `DNS:${name}`;
  return null;
}

export interface Leaf {
  key: string;
  cert: string;
}

export interface MintStats {
  /** Distinct hostnames minted for since start. One `openssl` pair each, never more. */
  minted: number;
  /** Contexts served from cache. The number of connections that cost no spawn at all. */
  cacheHits: number;
  /** Names refused: unmintable shape, or an `openssl` failure. */
  refused: number;
}

export interface CertMinter {
  /**
   * A TLS context for this name, or null when there will never be one.
   *
   * Null is a decision, not an error: the caller tunnels the connection and records that it
   * tunnelled. A throw would take down a connection that policy already allowed.
   */
  contextFor(name: string): SecureContext | null;
  /** Why the last null happened, for the record and the operator log. */
  lastRefusal(): string | null;
  stats(): MintStats;
  /** The CA certificate PEM, for a caller that needs to trust its own leaves. Public data. */
  caCertPem(): string;
}

/**
 * Build a minter over an existing CA.
 *
 * The CA private key is NOT read here, and that is deliberate. `openssl` is given the PATH to it
 * and never its contents, so the most dangerous file on this host never enters this process's
 * heap where a heap dump, a core file, or an error serialiser could reach it. Its existence and
 * its permissions are proven by `stat`, which is all this needs to know.
 */
export function createCertMinter(paths: CaPaths): CertMinter {
  const caCert = readFileSync(paths.certPath, "utf8");
  statSync(paths.keyPath);

  const cache = new Map<string, SecureContext>();
  const stats: MintStats = { minted: 0, cacheHits: 0, refused: 0 };
  let refusal: string | null = null;

  return {
    caCertPem: () => caCert,
    lastRefusal: () => refusal,
    stats: () => ({ ...stats }),
    contextFor(name: string): SecureContext | null {
      /**
       * The cache key is the hostname itself, and that is safe for a specific reason worth
       * writing down: it is a Map key and NEVER a filesystem path, and an entry is only ever
       * inserted AFTER `sanFor` has passed. So a hostile authority cannot become a path, and it
       * cannot grow this Map either, because a name that fails validation is refused before any
       * insert. If this cache ever gains a disk tier, the key must become a hash of the name.
       *
       * The lookup runs before validation on purpose: a cache hit is the common case and it is
       * already a name that passed, so paying for revalidation on every connection would put the
       * gate on the hot path for no gain.
       */
      const key = name.toLowerCase();
      const hit = cache.get(key);
      if (hit) {
        stats.cacheHits += 1;
        return hit;
      }
      const san = sanFor(key);
      if (san === null) {
        stats.refused += 1;
        // Truncated before it reaches a log line. ForwardProxyTests measured that a CONNECT
        // authority arrives here unvalidated and can be ~2000 characters, and a refusal message is
        // a diagnostic, not a place to reproduce an agent's whole request line.
        const shown = name.length > 80 ? `${name.slice(0, 80)}... (${name.length} chars)` : name;
        refusal = `${JSON.stringify(shown)} is not a name this can mint for (not a plausible hostname or IPv4 literal)`;
        return null;
      }
      const leaf = mintLeaf(key, san, paths);
      if (leaf === null) {
        stats.refused += 1;
        return null;
      }
      let context: SecureContext;
      try {
        context = createSecureContext({ key: leaf.key, cert: leaf.cert });
      } catch (err) {
        stats.refused += 1;
        refusal = `minted a certificate for ${key} that Node would not load: ${(err as Error).message}`;
        return null;
      }
      stats.minted += 1;
      cache.set(key, context);
      return context;
    },
  };

  /**
   * Mint one leaf: Node makes the keypair, `openssl` signs the public half. One spawn.
   *
   * THE PRIVATE KEY NEVER LEAVES THIS PROCESS. Keypair generation IS in the Node standard
   * library (`crypto.generateKeyPairSync`); it is only X.509 ISSUANCE that is not, which is why
   * `openssl` is here at all and why it is handed nothing secret. It receives a public key and a
   * hostname. The two temporary files below hold exactly that: an SPKI public key and a config
   * stanza naming a host. Neither is a secret, and both are unlinked immediately.
   *
   * An earlier version of this piped the key and a CSR through `/dev/stdout`. That is a trap:
   * with `spawnSync` the child's stdout is a pipe, `/dev/stdout` resolves to `/proc/self/fd/1`
   * which resolves to `pipe:[N]`, and opening that by path fails ENXIO. It works from an
   * interactive shell where stdout is a file, which is exactly the kind of difference that
   * passes a manual check and then fails in the process that matters.
   *
   * `-extfile` means the hostname reaches a CONFIG PARSER and not only an argv, so the escaping
   * question is real: a newline in a SAN value would append a directive. `sanFor` is what makes
   * that impossible rather than unlikely. It admits letters, digits, hyphen and underscore per
   * label and nothing else, so there is no newline, no `=`, no `[`, and no comment character to
   * smuggle. The value written below has already passed it.
   */
  function mintLeaf(name: string, san: string, ca: CaPaths): Leaf | null {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    // 0700 by construction, and holding nothing private regardless.
    const scratch = mkdtempSync(join(tmpdir(), "agentwall-mint-"));
    const pubPath = join(scratch, "pub.pem");
    const extPath = join(scratch, "ext.cnf");
    try {
      writeFileSync(pubPath, publicKey);
      // A leaf that is explicitly CA:FALSE cannot be turned around and used to sign anything
      // else, so a leaf that leaks is one certificate rather than a second issuer.
      writeFileSync(
        extPath,
        `[leaf]\nsubjectAltName = ${san}\nbasicConstraints = critical,CA:FALSE\n` +
          `keyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\n`
      );

      // A random serial rather than a counter file: two AgentWall processes sharing a CA
      // directory must not mint two certificates with the same serial, and there is no lock
      // here that would make a counter safe.
      const signed = runOpenssl([
        "x509",
        "-new",
        "-force_pubkey",
        pubPath,
        "-CA",
        ca.certPath,
        "-CAkey",
        ca.keyPath,
        "-days",
        String(LEAF_DAYS),
        "-sha256",
        "-subj",
        `/CN=${name}`,
        "-extfile",
        extPath,
        "-extensions",
        "leaf",
        "-set_serial",
        `0x${randomBytes(8).toString("hex")}`,
      ]);
      if (!signed.ok) {
        refusal = `could not sign a certificate for ${name}: ${signed.reason}`;
        return null;
      }
      const certPem = extractPem(signed.stdout, "CERTIFICATE");
      if (certPem === null) {
        refusal = `openssl signed nothing usable for ${name}`;
        return null;
      }
      return { key: privateKey, cert: certPem };
    } finally {
      // Best-effort: a leftover public key in a temp directory is untidy, not dangerous, and a
      // cleanup failure must not fail a mint that already succeeded.
      try {
        rmSync(scratch, { recursive: true, force: true });
      } catch {
        /* untidy, not unsafe */
      }
    }
  }
}

/**
 * Pull one labelled PEM block out of openssl's stdout.
 *
 * Anchored on both markers rather than trusting the whole of stdout to be the certificate:
 * openssl writes advisory lines to stdout on some builds and configurations, and a certificate
 * with a stray line prepended is one Node refuses to load, several layers away from here.
 */
function extractPem(text: string, label: string): string | null {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  const from = text.indexOf(begin);
  if (from < 0) return null;
  const to = text.indexOf(end, from);
  if (to < 0) return null;
  return text.slice(from, to + end.length) + "\n";
}
