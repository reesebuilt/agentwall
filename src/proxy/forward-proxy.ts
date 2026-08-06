import { createServer as createHttpServer, IncomingMessage, ServerResponse, request as httpRequest } from "http";
import type { ClientRequest, IncomingHttpHeaders } from "http";
import { connect as netConnect, Socket, Server } from "net";
import { readdirSync, readFileSync, readlinkSync } from "fs";
import { brotliDecompressSync, constants as zlibConstants, gunzipSync, inflateSync } from "zlib";
import { MAX_SCAN_CHARS } from "../policy/injection";
import type { RiskLevel } from "../types";
import { MAX_CLIENT_HELLO_BYTES, peekClientHello } from "./tls-peek";
import { parseProxyCredential } from "../fleet/registry";

/**
 * CONNECT-aware forward proxy: the insertion mechanism.
 *
 * Why a proxy rather than harness hooks: egress is the one action plane with a
 * pre-existing universal insertion standard. Four environment variables and zero lines of
 * harness code, instead of patching each harness's tool path. The proxy is the whole
 * insertion surface: set the standard proxy environment variables and every cooperating
 * client is covered, with no per-framework adapter to maintain.
 *
 * Tier 1 only: this sees CONNECT host:port, absolute-URI hosts, and the SNI the client
 * negotiates inside the tunnel. It does NOT terminate TLS, so https paths, headers and
 * bodies stay opaque. Deliberate: MITM needs a CA in every runtime trust store, which
 * breaks the harness-agnostic property this exists for. Reading a ClientHello needs
 * neither, which is why the SNI cross-check below is affordable and interception is not.
 *
 * This file does not decide anything: `decide` is authoritative, and whatever it returns is
 * what happens to the connection. What this file guarantees is that a "deny" costs the
 * destination nothing — no upstream socket is opened, on either path — and that the client
 * is told why rather than being handed an unexplained failure.
 */

export type ProxyDecision = "allow" | "deny";

/**
 * What `decide` may return instead of a bare decision.
 *
 * Only `decision` and `reasons[0]` change what the proxy does; the rest is carried verbatim
 * onto the record. That exists so the caller's audit sink can write the evidence it already
 * computed instead of evaluating policy a second time on the record path, where it would be
 * working from a copy of the event and could reach a different answer than the one that was
 * actually enforced. Rule ids and risk are here because neither can be recovered from the
 * event; detections are not, because they follow from the rule ids.
 */
export interface ProxyVerdict {
  decision: ProxyDecision;
  /** Operator-facing explanation. The first entry becomes the block-reason header. */
  reasons?: readonly string[];
  matchedRules?: readonly string[];
  riskLevel?: RiskLevel;
  /**
   * Evidence the caller already computed, carried verbatim onto the record. Content
   * inspection puts the class and position of each finding here and never the matched value,
   * because a DLP record that leaks the secret it detected is worse than no record at all.
   */
  metadata?: Readonly<Record<string, string>>;
  /**
   * Per-connection facts the decision resolved, echoed verbatim onto the record.
   *
   * Which agent this was, on what signal, and against whose allowlist. Carried rather than
   * recomputed for the same reason the rule ids are: `decide` and `record` are one logical
   * event split across a socket lifetime, and a record path that re-derives identity can
   * disagree with the identity that was actually enforced.
   */
  attribution?: Readonly<Record<string, string>>;
  /**
   * Opaque handle the caller uses to charge this connection's bytes when it closes.
   *
   * The proxy never reads it. Unlike attribution it could not be recomputed even in
   * principle: it names a row in a sliding window that has moved on by the time the
   * connection ends.
   */
  budgetTicket?: number | null;
}

export type ProxyDecideResult = ProxyDecision | ProxyVerdict;

/**
 * One buffered message body, when the transport let the proxy read one.
 *
 * Structurally identical to `EgressAttempt`'s body on purpose: `src/index.ts` passes this
 * straight into the decision path, and a second shape between here and there would be one
 * more place for the two to disagree about what was inspected.
 */
export interface ProxyBody {
  direction: "request" | "response";
  /** What was buffered, decoded. A prefix, not the whole body, when `truncated` is true. */
  text: string;
  truncated: boolean;
  /** Wire bytes buffered, before any decompression. Not the body's real length when truncated. */
  bytes: number;
  /** Upstream status, on a response. */
  status?: number;
  /** Content-Encoding the body arrived under, when it was anything but identity. */
  encoding?: string;
  /**
   * Why the bytes were not inspected, when they were not, so a caller cannot mistake an
   * empty `text` for an empty body. `stream` is an event stream, deliberately never
   * buffered. `encoding` is a compressed body that would not decode inside its bound.
   */
  unscannable?: "stream" | "encoding";
}

/**
 * How much of this exchange's content the proxy could actually read.
 *
 * Recorded on every record because it is the difference between a clean scan that means
 * "nothing was there" and a clean scan that means "we could not look". A ledger full of
 * findings-free rows is reassuring only if you can tell which of those two it is.
 *
 *   tunneled:  CONNECT. Ciphertext; nothing below the authority was ever readable.
 *   unread:    the exchange ended before there was a body to read, or was refused first.
 *   stream:    an event stream, passed through without buffering, deliberately.
 *   partial:   read to the byte cap or a stall, and the remainder forwarded uninspected.
 *   plaintext: read whole and scanned.
 */
export type BodyVisibility = "tunneled" | "unread" | "stream" | "partial" | "plaintext";

/**
 * How much each state saw, so an exchange with several passes can report its weakest one.
 * `tunneled` and `unread` sit together at the bottom: both mean no content was inspected,
 * and a CONNECT connection never mixes with an HTTP pass, so they never have to be ordered
 * against each other.
 */
const VISIBILITY_ORDER: Record<BodyVisibility, number> = {
  tunneled: 0,
  unread: 0,
  stream: 1,
  partial: 2,
  plaintext: 3,
};

export interface ProxyEvent {
  host: string;
  port: number;
  scheme: "http" | "https";
  method: string;
  /** Resolved originating process and socket owner, or nulls when attribution failed. */
  client: { pid: number | null; comm: string | null; uid: number | null };
  /**
   * Secret the client presented in Proxy-Authorization, stripped of its auth scheme, or null.
   *
   * Passed to `decide` and NEVER to the destination: the header is hop-by-hop and is removed
   * before the upstream request is built. A fleet credential that leaks to every host the
   * agent talks to is a credential that has to be rotated.
   */
  credential: string | null;
  startedAt: number;
  /**
   * The hostname the client negotiated inside the tunnel, when one was readable.
   *
   * CONNECT connections only, and null-by-absence rather than by value: an https record
   * without this field means no name was recovered, which covers a client that omits SNI,
   * an encrypted ClientHello, a non-TLS tunnel, and a hello that never arrived whole.
   */
  sni?: string;
  /** Set only when `sni` was read AND differs from the host on the CONNECT line. */
  sniMismatch?: boolean;
  /**
   * Request target INCLUDING the query string, which is the whole point of it being here:
   * `decide` scans the query, and a credential smuggled out as `?api_key=...` is one of the
   * shapes this path exists to catch. Absent on CONNECT, which carries an authority and
   * nothing else. See `ProxyRecord.path`, which is deliberately not the same string.
   */
  path?: string;
  /** Headers of the message being decided on, names lowercased, repeats joined with ", ". */
  headers?: Readonly<Record<string, string>>;
  /** One buffered body. Present only on the calls made after a body has been read. */
  body?: ProxyBody;
  /**
   * True on every `decide` call after the first one for this connection.
   *
   * One connection is decided more than once because more of it becomes readable as it goes:
   * the name a tunnel negotiates arrives after the 200, and a plaintext HTTP exchange has a
   * request body and then a response body. Those are later looks at the same connection, and
   * only this file knows which call is which. A caller that meters connections has to be able
   * to tell the difference or it charges one exchange three times; a caller that does not care
   * ignores the field and behaves exactly as it did.
   */
  reDecision?: boolean;
}

/**
 * What gets written down.
 *
 * `headers` and `body` are removed from the shape rather than merely left unset, because
 * this object is handed to an audit chain AND serialised whole into a flat ledger file. A
 * field that a future maintainer could populate without noticing is a field that will
 * eventually carry a request body into a log, and a DLP record that leaks the secret it
 * detected is worse than no record. What the record carries about content is its
 * classification: `metadata` holds the class and position of each finding and never a value.
 *
 * `credential` is removed for the same reason and it is the sharpest case: it is the secret
 * an agent presents to identify itself, it is stripped from the upstream request precisely so
 * that no destination ever sees it, and writing it here would put it in cleartext into the
 * ledger and the audit chain instead. What a reader needs is already carried safely by
 * `attribution`: which agent this was and that the match came from a presented credential.
 * `reDecision` goes with it because it describes a call, not a connection.
 */
export interface ProxyRecord
  extends Omit<ProxyEvent, "headers" | "body" | "path" | "credential" | "reDecision"> {
  /**
   * The resource, pathname only, with the query string stripped. Not `ProxyEvent.path`: the
   * query is scanned in full and recorded never, because it is attacker-chosen content and
   * routinely carries the exact credential the scan just reported. `metadata.pathQueryBytes`
   * says how much of it there was.
   */
  path?: string;
  decision: ProxyDecision;
  /** Why, as returned by `decide`. Empty when the decision came back as a bare string. */
  reasons: readonly string[];
  matchedRules: readonly string[];
  riskLevel?: RiskLevel;
  /** Evidence from every decision made about this exchange, folded into one bag. */
  metadata?: Readonly<Record<string, string>>;
  bodyVisibility: BodyVisibility;
  /** Echoed from the verdict. Empty when the decision came back as a bare string. */
  attribution?: Readonly<Record<string, string>>;
  /** Echoed from the verdict. Null when nothing was charged to an agent's budget. */
  budgetTicket: number | null;
  durationMs: number;
  bytesUp: number;
  bytesDown: number;
}

export interface ForwardProxyOptions {
  port: number;
  host: string;
  /**
   * The decision seam, called at every point where more of the exchange has become visible.
   * Return "deny", or a verdict whose decision is "deny", to refuse. A bare string is
   * accepted for callers that have nothing to explain; a verdict carries the reason the
   * client is shown and the evidence the record keeps.
   *
   * A CONNECT tunnel is decided once, from host and port, before anything is opened
   * upstream. A plaintext HTTP exchange is decided up to three times, and the order is the
   * point of it:
   *
   *   1. the connection, from host, port, scheme, and method alone. First, and with no
   *      content, so a destination that was never going to be allowed is refused before the
   *      proxy pins a quarter-megabyte of its request body waiting to inspect it.
   *   2. the request, adding `path`, `headers`, and `body`. Still before anything is opened
   *      upstream, so a refusal here costs the destination nothing, not even a handshake.
   *   3. the response, adding the response headers and body, before a single byte is written
   *      back to the client, so a poisoned answer can still be turned into a real 403.
   *
   * Every verdict folds: any deny denies, reasons and matched rules union, the highest risk
   * wins, and metadata accumulates namespaced by direction. An implementation that ignores
   * the new fields behaves exactly as it did, at the cost of being asked more than once.
   */
  decide: (event: ProxyEvent) => ProxyDecideResult;
  record: (record: ProxyRecord) => void;
  onError?: (err: Error, context: string) => void;
}

/**
 * Map a proxy client socket back to the process, and the uid, that opened it.
 *
 * This is what lets the ledger name the process that actually made the call, rather than
 * "unknown", WITHOUT harness cooperation, which is the point of a harness-agnostic
 * design. /proc/net/tcp turns a local port into a socket inode; /proc/<pid>/fd finds the
 * owner. Linux-specific and best-effort by design: attribution failing must never break
 * egress.
 *
 * The uid comes out of the SAME /proc/net/tcp line as the inode (column 7), so it costs
 * nothing beyond a second array index and, unlike the pid, survives the case where the fd
 * walk finds nothing. That difference matters for identity: a uid is a kernel fact a process
 * cannot change without privilege, whereas `comm` is a 16-byte label the process writes
 * itself. Measured on this host: Node rewrites its own comm to "MainThread" at startup, and
 * `process.title = "aw-scraper"` sets it to anything the process likes. src/fleet/registry.ts
 * ranks the signals accordingly.
 */
/**
 * Attribution cost control.
 *
 * Resolving a connection to a process is two steps: read /proc/net/tcp to map the
 * client port to a socket inode (cheap), then find which process holds that inode
 * (expensive: walking every /proc/<pid>/fd measured ~44ms, scaling with total FDs).
 *
 * Caching the inode is useless: every connection has a fresh one, so it never hits.
 * What repeats is the PROCESS. An agent fleet is a handful of long-lived clients
 * opening many connections, so recently-seen pids are checked first; only a
 * genuinely new process pays the full walk.
 *
 * The walk is SYNCHRONOUS and blocks the event loop for its duration (~44ms cold,
 * ~1.6ms warm). An async-fs version was tried and reverted: per-fd awaits made it
 * roughly 4x worse (0.95s vs 0.38s per request) because microtask overhead dominates
 * a walk of thousands of descriptors. The hot-pid cache is what keeps the blocking
 * rare rather than async I/O, so a burst of connections from NEW processes will
 * serialise. That is a known cost, not an oversight.
 */
const HOT_PID_MAX = 16;
const hotPids: number[] = [];

function touchHotPid(pid: number): void {
  const i = hotPids.indexOf(pid);
  if (i !== -1) hotPids.splice(i, 1);
  hotPids.unshift(pid);
  if (hotPids.length > HOT_PID_MAX) hotPids.length = HOT_PID_MAX;
}

function readComm(pid: number): string | null {
  try {
    return readFileSync(`/proc/${pid}/comm`, "utf8").trim();
  } catch {
    return null;
  }
}

/** Does this pid hold the socket? One readdir of a single process. */
function pidHoldsInode(pid: number, target: string): boolean {
  let fds: string[];
  try {
    fds = readdirSync(`/proc/${pid}/fd`);
  } catch {
    return false;
  }
  for (const fd of fds) {
    try {
      if (readlinkSync(`/proc/${pid}/fd/${fd}`) === target) return true;
    } catch {
      /* fd vanished mid-scan */
    }
  }
  return false;
}

/**
 * Resolve one connection to the process, and the uid, that opened it.
 *
 * Both ends are required, and the row has to match both. A match on the client's port alone
 * names the wrong process, reliably rather than occasionally: /proc/net/tcp lists LISTENING
 * sockets before established ones, so any process listening on an address whose port happens
 * to equal this client's ephemeral source port is found first, and the ledger attributes the
 * call to it. Ephemeral ports and service ports come out of the same 16 bits, so the collision
 * arrives without anyone arranging it. A wrong pid is worse than no pid: an operator sees a
 * named process that never made the call, and the one that did is invisible.
 *
 * Where the evidence is ambiguous, nothing is named. Two rows can share both ports only if
 * they differ in an address, and addresses are not compared here, so a second candidate means
 * this function cannot tell which socket it was asked about. Declining is the honest answer and
 * it costs nothing: attribution is best-effort and the connection proceeds either way. That
 * covers the uid as well: it is read off the same row as the inode, so an ambiguous row makes
 * the owner as unknowable as the process.
 */
function attributeSocket(
  clientPort: number,
  proxyPort: number
): { pid: number | null; comm: string | null; uid: number | null } {
  if (!clientPort || !proxyPort) return { pid: null, comm: null, uid: null };
  try {
    const wantLocal = `:${clientPort.toString(16).toUpperCase().padStart(4, "0")}`;
    const wantRemote = `:${proxyPort.toString(16).toUpperCase().padStart(4, "0")}`;
    // Dynamic membership, and the count is the decision, so a keyed collection rather than a
    // lookup table. Inode to uid, because both come off the same row and the uid outlives the
    // fd walk: a socket whose owning process cannot be found still has an owning user.
    const candidates = new Map<string, number | null>();

    // Both tables, all the way through. Stopping at the first hit is what let a listening
    // socket stand in for a connection, and a v4 row and a v6 row that both match are two
    // candidates, not one answer.
    for (const table of ["/proc/net/tcp", "/proc/net/tcp6"]) {
      let content: string;
      try {
        content = readFileSync(table, "utf8");
      } catch {
        continue;
      }
      for (const line of content.split("\n").slice(1)) {
        const cols = line.trim().split(/\s+/);
        if (cols.length < 10) continue;
        if (cols[1].endsWith(wantLocal) && cols[2].endsWith(wantRemote)) {
          // Column 7 is the socket owner's uid. Parsed defensively rather than trusted: a
          // malformed row must degrade to "unknown", never to uid 0, which would hand a
          // root-scoped agent identity to whoever produced the bad line.
          const parsed = Number(cols[7]);
          candidates.set(cols[9], Number.isInteger(parsed) && parsed >= 0 ? parsed : null);
        }
      }
    }
    if (candidates.size !== 1) return { pid: null, comm: null, uid: null };
    const [[inode, uid]] = candidates;

    const target = `socket:[${inode}]`;

    for (const pid of [...hotPids]) {
      if (pidHoldsInode(pid, target)) {
        touchHotPid(pid);
        return { pid, comm: readComm(pid), uid };
      }
    }

    let entries: string[];
    try {
      entries = readdirSync("/proc");
    } catch {
      return { pid: null, comm: null, uid };
    }
    for (const entry of entries) {
      if (!/^\d+$/.test(entry)) continue;
      const pid = Number(entry);
      if (pidHoldsInode(pid, target)) {
        touchHotPid(pid);
        return { pid, comm: readComm(pid), uid };
      }
    }
    return { pid: null, comm: null, uid };
  } catch {
    return { pid: null, comm: null, uid: null };
  }
}

function parseHostPort(authority: string, fallbackPort: number): { host: string; port: number } {
  const lastColon = authority.lastIndexOf(":");
  // IPv6 literals contain colons, so only split on a trailing :port
  if (lastColon > authority.lastIndexOf("]")) {
    const port = Number(authority.slice(lastColon + 1));
    if (Number.isFinite(port)) {
      return { host: authority.slice(0, lastColon).replace(/^\[|\]$/g, ""), port };
    }
  }
  return { host: authority.replace(/^\[|\]$/g, ""), port: fallbackPort };
}

const NO_STRINGS: readonly string[] = [];
const EMPTY = Buffer.alloc(0);

/**
 * How long the client's own upstream direction waits for a first record to become readable.
 *
 * Almost never reached: a complete hello releases the instant its declared length is
 * satisfied, and a first byte that is not 0x16 releases on the first chunk. What is left is
 * a client that sends a partial record and then stops, and a client that opens a tunnel and
 * says nothing, and neither is sending traffic this delays.
 */
const PEEK_TIMEOUT_MS = 5000;

/**
 * The rule id a CONNECT/SNI disagreement is recorded under.
 *
 * A literal rather than something policy declares, because the proxy observes this itself
 * rather than evaluating a rule for it. It is in the detection catalog so the audit chain
 * carries the mapping, which is the only way this reaches an operator who is reading the
 * ledger rather than watching the logs.
 */
const SNI_MISMATCH_RULE = "net:sni-connect-mismatch";

/** A `decide` result with its optional parts filled in, ready to spread onto a record. */
export interface ResolvedVerdict {
  decision: ProxyDecision;
  reasons: readonly string[];
  matchedRules: readonly string[];
  riskLevel?: RiskLevel;
  metadata?: Readonly<Record<string, string>>;
  attribution?: Readonly<Record<string, string>>;
  budgetTicket: number | null;
}

function resolveVerdict(result: ProxyDecideResult): ResolvedVerdict {
  if (typeof result === "string") {
    return { decision: result, reasons: NO_STRINGS, matchedRules: NO_STRINGS, budgetTicket: null };
  }
  return {
    decision: result.decision,
    reasons: result.reasons ?? NO_STRINGS,
    matchedRules: result.matchedRules ?? NO_STRINGS,
    riskLevel: result.riskLevel,
    metadata: result.metadata,
    attribution: result.attribution,
    budgetTicket: result.budgetTicket ?? null,
  };
}

/** What the cross-check concluded, and whether the caller has to refuse. */
export interface NegotiatedNameCheck {
  /** The verdict to record, already merged with whatever `decide` said about the new name. */
  verdict: ResolvedVerdict;
  /** True when policy refused the negotiated name. HOW to refuse is the caller's business. */
  refuse: boolean;
}

/**
 * Cross-check the name a client actually negotiated against the one it named to the proxy.
 *
 * THE SINGLE IMPLEMENTATION OF THIS CHECK. Any path that learns a negotiated server name has
 * to call this rather than repeat it: two sites deciding the same fact is how one rule id
 * ends up meaning two different things, and this rule id is what an operator greps for. Today
 * the caller is the ClientHello peek on the tunnel path. An interception path learns the same
 * name from its TLS servername callback and belongs here too.
 *
 * It deliberately does NOT refuse anything itself. It reports `refuse` and leaves the
 * mechanism to the caller, because the mechanism is genuinely different and neither is
 * substitutable: on a tunnel the 200 has already gone out and all that is left is to destroy
 * both sockets, while a path that terminates TLS can fail the handshake before any session
 * exists and never spend the upstream connection at all.
 *
 * Both names are normalised here rather than being trusted to arrive that way, so a caller
 * that forgets cannot turn a difference in spelling into a reported bypass.
 *
 * `event` is mutated: `sni` is recorded whenever a name was read, and `sniMismatch` only when
 * it actually differs. That is deliberate, because the record is built from this object later
 * and the observation belongs to the connection, not to the verdict.
 */
export function crossCheckNegotiatedName(
  negotiated: string,
  connectAuthority: string,
  event: ProxyEvent,
  current: ResolvedVerdict,
  decide: (event: ProxyEvent) => ProxyDecideResult
): NegotiatedNameCheck {
  const observed = negotiated.toLowerCase();
  event.sni = observed;
  // Case-folded on both sides: SNI is lowercased on the way out of the parser, so a CONNECT
  // line that shouted its authority is a spelling difference and not a bypass.
  if (observed === connectAuthority.toLowerCase()) return { verdict: current, refuse: false };

  event.sniMismatch = true;
  // Re-decided against the name the client actually negotiated. `decide` stays the single
  // authority and is now being asked about the better-sourced of the two hostnames rather
  // than only the typed one. This can only ever ADD a denial: it runs after an allow, so it
  // can refuse what the CONNECT line was permitted and can never permit what it was refused.
  // Monitor mode is unaffected, because monitor mode's `decide` returns allow.
  // `reDecision` is what tells the caller this is a second look at one connection rather than
  // a new one. Without it a metered caller admits the same tunnel twice and its per-agent
  // request budget means half of what its operator wrote.
  const negotiatedVerdict = resolveVerdict(decide({ ...event, host: observed, reDecision: true }));
  return {
    verdict: {
      decision: negotiatedVerdict.decision,
      reasons: [
        `CONNECT named ${connectAuthority.toLowerCase()} but the ClientHello negotiated ${observed}`,
        ...current.reasons,
        ...negotiatedVerdict.reasons,
      ],
      matchedRules: [SNI_MISMATCH_RULE, ...current.matchedRules, ...negotiatedVerdict.matchedRules],
      riskLevel: negotiatedVerdict.riskLevel ?? current.riskLevel,
      // Unioned rather than replaced, for the same reason the reasons are. A verdict's
      // metadata is evidence its author already computed, and a second opinion that dropped
      // the first one's evidence would leave a record explaining half of its own decision.
      // The negotiated name wins a key collision, because it is the better-sourced of the
      // two hostnames and its pass ran last.
      metadata:
        current.metadata || negotiatedVerdict.metadata
          ? { ...current.metadata, ...negotiatedVerdict.metadata }
          : undefined,
      // The agent is the same agent either way; the later pass wins a key collision because
      // it was decided against the better-sourced hostname.
      attribution:
        current.attribution || negotiatedVerdict.attribution
          ? { ...current.attribution, ...negotiatedVerdict.attribution }
          : undefined,
      // The FIRST pass's ticket, always. It names the row that was opened when this
      // connection was admitted, and the bytes counted below belong to that row. The second
      // pass is a re-decision and admits nothing, so it has no ticket to offer; taking its
      // null here would leave the connection's bytes uncharged.
      budgetTicket: current.budgetTicket ?? negotiatedVerdict.budgetTicket,
    },
    refuse: negotiatedVerdict.decision === "deny",
  };
}

const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Every verdict this exchange produced, folded into the one the record carries.
 *
 * A plaintext HTTP exchange is decided up to three times and files one record, so the record
 * has to describe all three without letting the last one erase the first two. Deny wins over
 * allow because a refusal happened; reasons and rules union rather than replace, because
 * "blocked for reason A" that silently dropped reason B leaves an operator fixing half a
 * problem; risk takes the maximum, because the worst thing found is what the row is about.
 */
class VerdictLedger {
  decision: ProxyDecision = "allow";
  riskLevel: RiskLevel | undefined;
  readonly reasons: string[] = [];
  readonly matchedRules: string[] = [];
  readonly metadata: Record<string, string> = {};
  readonly attribution: Record<string, string> = {};
  /**
   * The ticket the FIRST pass came back with, and only that one.
   *
   * The later passes are re-decisions of one connection and admit nothing, so they have no
   * ticket to offer. Taking a later null would leave this exchange's bytes charged to
   * nobody, and taking a later non-null would charge them to a row that was never opened.
   */
  budgetTicket: number | null = null;

  fold(verdict: ResolvedVerdict): ResolvedVerdict {
    if (verdict.decision === "deny") this.decision = "deny";
    for (const reason of verdict.reasons) if (!this.reasons.includes(reason)) this.reasons.push(reason);
    for (const rule of verdict.matchedRules) if (!this.matchedRules.includes(rule)) this.matchedRules.push(rule);
    if (verdict.riskLevel && (this.riskLevel === undefined || RISK_ORDER[verdict.riskLevel] > RISK_ORDER[this.riskLevel])) {
      this.riskLevel = verdict.riskLevel;
    }
    if (verdict.metadata) this.absorb(verdict.metadata);
    // Later passes see the same agent, so a key collision is a re-statement rather than a
    // disagreement and the newest wins.
    if (verdict.attribution) Object.assign(this.attribution, verdict.attribution);
    if (this.budgetTicket === null) this.budgetTicket = verdict.budgetTicket;
    return verdict;
  }

  /**
   * Content evidence, namespaced by the direction it describes.
   *
   * The request pass and the response pass produce the same key names for different bodies,
   * so folding them flat would have the response quietly overwrite the request and a record
   * would report one finding where there were two. `contentSecretTypes` from the request pass
   * lands as `requestContentSecretTypes`; the direction key itself is dropped, because after
   * the rename it is saying the same thing twice.
   */
  private absorb(metadata: Readonly<Record<string, string>>): void {
    const prefix = metadata["contentDirection"] === "response" ? "response" : "request";
    for (const [key, value] of Object.entries(metadata)) {
      if (key === "contentDirection") continue;
      this.metadata[`${prefix}${key.charAt(0).toUpperCase()}${key.slice(1)}`] = value;
    }
  }
}

/**
 * Bytes of one request or response body the proxy will hold in memory to inspect it.
 *
 * An unbounded buffer in a proxy is a memory-exhaustion primitive handed to whoever can make
 * it fetch a URL, which in a security tool is a self-inflicted denial of service. The number
 * is the injection scanner's own work cap rather than a fresh guess: buffering more than the
 * scanner will read pins memory to scan nothing, and buffering less throws away bytes it
 * would have read. Deriving one from the other is what stops them drifting apart.
 *
 * Past the cap the exchange is not refused. The prefix is scanned, the remainder is streamed
 * through uninspected, and the record says `partial` and carries the byte count, because the
 * alternative, refusing every response over a quarter-megabyte, breaks ordinary agent
 * traffic to buy protection an attacker evades by using https, which is not inspected at all.
 * What is NOT acceptable is the third option: truncating quietly and reporting a clean scan.
 */
export const CONTENT_SCAN_MAX_BYTES = MAX_SCAN_CHARS;

/**
 * How long a body may go silent before the proxy stops waiting for the rest of it.
 *
 * Buffering is bounded by size and by time, and time is the one that matters more, because a
 * body that never ends is not large, it is open. Anything that pauses a full second mid-body
 * is a stream rather than a download, and holding a stream to scan it is how a proxy hangs
 * the agent it is protecting. The degradation is graceful: what arrived is scanned, the rest
 * flows, and the record says `partial`.
 */
const BODY_IDLE_MS = 1000;

/**
 * Content types whose body is an open stream rather than a document.
 *
 * These are exempt from buffering entirely, and the exemption is explicit rather than left to
 * the idle timer to discover a second late. MCP carries SSE, and an event stream that pauses
 * between events is behaving correctly; buffering it to scan it converts a working transport
 * into a hang. There is no half-measure worth taking here, because a stream cannot be
 * inspected whole without ceasing to be a stream, so it is passed through and the record
 * says so.
 */
function isStreamingType(value: string | undefined): boolean {
  if (value === undefined) return false;
  const type = value.split(";", 1)[0].trim().toLowerCase();
  return type === "text/event-stream" || type === "application/x-ndjson" || type === "multipart/x-mixed-replace";
}

/** Node hands back repeated headers as arrays; the scanners want one string per name. */
function flattenHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const flat: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    flat[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return flat;
}

/**
 * A body decoded for inspection, and nothing else.
 *
 * `text` is what the scanners read. The bytes that go downstream are always the originals:
 * this never rewrites a body, never strips `Accept-Encoding`, and never re-encodes anything,
 * so an allowed exchange is byte-identical to an unproxied one and a false positive cannot
 * corrupt a live response.
 *
 * `limit` is the scan extent, and it is applied here rather than at read time. A socket hands
 * over whatever arrived, so the last chunk before the cap routinely carries bytes past it,
 * and those bytes have to be kept for replay. Keeping them and scanning them would make the
 * real bound "the cap plus one socket read", which is not a bound anyone can state; the
 * chunks are kept whole and the scan is cut at exactly the cap. The cut can split a
 * multi-byte character at the boundary, which costs one replacement character in a quarter
 * of a megabyte and buys a limit that means what it says.
 *
 * Decompressing at all is not optional in practice. Any real server negotiates gzip, so a
 * scanner that read compressed bytes would find nothing in most bodies and would report that
 * nothing as a clean scan, which is the exact ambiguity this whole path exists to remove.
 * `maxOutputLength` is what makes it safe: a decompression bomb hits a ceiling and comes back
 * marked unscannable rather than taking the heap with it. `Z_SYNC_FLUSH` is what makes it
 * useful on a truncated body, where the deflate stream has no end marker because the cap cut
 * it off; without it every capped compressed body would decode to nothing.
 */
function decodeForScan(
  chunks: readonly Buffer[],
  limit: number,
  contentEncoding: string | undefined
): { text: string; encoding?: string; unscannable?: "encoding" } {
  const joined = Buffer.concat(chunks);
  const raw = joined.length > limit ? joined.subarray(0, limit) : joined;
  const encoding = contentEncoding?.trim().toLowerCase() ?? "";
  if (encoding === "" || encoding === "identity") return { text: raw.toString("utf8") };

  const options = { maxOutputLength: CONTENT_SCAN_MAX_BYTES, finishFlush: zlibConstants.Z_SYNC_FLUSH };
  try {
    if (encoding === "gzip" || encoding === "x-gzip") {
      return { text: gunzipSync(raw, options).toString("utf8"), encoding };
    }
    if (encoding === "deflate") return { text: inflateSync(raw, options).toString("utf8"), encoding };
    if (encoding === "br") {
      return { text: brotliDecompressSync(raw, { maxOutputLength: CONTENT_SCAN_MAX_BYTES }).toString("utf8"), encoding };
    }
  } catch {
    // A bomb that hit the ceiling, or a corrupt stream. Either way the bytes are forwarded
    // and the record says they were not read, which is the one answer that is never a lie.
    return { text: "", encoding, unscannable: "encoding" };
  }
  // An encoding nobody here knows, including `zstd` and any multi-layer value. Not guessed at.
  return { text: "", encoding, unscannable: "encoding" };
}

/** What a bounded read produced: the bytes read, to be both scanned and replayed downstream. */
interface BufferedBody {
  /**
   * The scan extent, capped at `CONTENT_SCAN_MAX_BYTES`. Not the length of `chunks`, which
   * can run past it by one socket read, and not the length of the body, which can run past
   * it without limit.
   */
  bytes: number;
  /** The read stopped at the cap or at a stall, and the source still has bytes in it. */
  truncated: boolean;
  chunks: Buffer[];
}

/**
 * Read a body up to the cap, the stall deadline, or its end, whichever comes first.
 *
 * The chunks are handed back rather than consumed because nothing may be dropped: whatever
 * was read has to be replayed downstream byte for byte, and on the truncated path the source
 * is left paused with its remainder intact for the caller to pipe.
 *
 * A chunk that crosses the cap is kept whole, because those bytes still have to be forwarded,
 * and `bytes` is capped so the SCAN does not silently extend past the stated limit with them.
 * Holding one extra socket read is a memory cost anyone can bound; scanning "the cap plus
 * however much arrived at once" is a limit nobody can state.
 */
function readBoundedBody(source: IncomingMessage, onReady: (body: BufferedBody) => void): void {
  const chunks: Buffer[] = [];
  let buffered = 0;
  let truncated = false;
  let settled = false;
  let idle: NodeJS.Timeout | undefined;

  const settle = (): void => {
    if (settled) return;
    settled = true;
    clearTimeout(idle);
    source.pause();
    source.removeListener("data", onData);
    source.removeListener("end", onEnd);
    source.removeListener("error", onEnd);
    source.removeListener("aborted", onEnd);
    onReady({ bytes: Math.min(buffered, CONTENT_SCAN_MAX_BYTES), truncated, chunks });
  };

  // Reset on every chunk rather than armed once: a slow but steady download should be read
  // to the cap, while a stream that goes quiet after its first event should be released.
  const arm = (): void => {
    clearTimeout(idle);
    idle = setTimeout(() => {
      truncated = true;
      settle();
    }, BODY_IDLE_MS);
    idle.unref();
  };

  const onData = (chunk: Buffer): void => {
    chunks.push(chunk);
    buffered += chunk.length;
    if (buffered >= CONTENT_SCAN_MAX_BYTES) {
      // Reported as truncated even for a body that lands exactly on the cap, because at this
      // instant nothing can distinguish that from one byte more. Over-reporting incomplete
      // coverage is the only direction of error this control is allowed to make.
      truncated = true;
      settle();
      return;
    }
    arm();
  };

  // An aborted or errored read settles with what it has. The caller's own error handling
  // decides what happens to the exchange; this function's job is only to stop waiting.
  const onEnd = (): void => settle();

  source.on("data", onData);
  source.on("end", onEnd);
  source.on("error", onEnd);
  source.on("aborted", onEnd);
  arm();
}

/**
 * A block reason, made safe to put in a header.
 *
 * The reason is built downstream from a destination the agent chose, so a bare CR or LF in
 * it would let that agent inject headers into the proxy's own 403 — and on the CONNECT path,
 * where the response is written to the socket by hand rather than through Node's header
 * encoder, an entire second response. Everything outside printable ASCII is collapsed to a
 * space, which also loses the punctuation the reason strings use; that is the right trade
 * for a debugging aid. The cap keeps a long chain of matched rules from pushing a client
 * past its own header size limit and turning a clear 403 into a connection reset.
 */
function headerSafe(reason: string): string {
  const cleaned = reason.replace(/[^\x20-\x7e]+/g, " ").replace(/ {2,}/g, " ").trim();
  return cleaned.length > 200 ? `${cleaned.slice(0, 197)}...` : cleaned;
}

export function createForwardProxy(opts: ForwardProxyOptions): Server {
  const server = createHttpServer();

  // HTTPS and anything else tunnelled: the majority of agent traffic.
  server.on("connect", (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
    const { host, port } = parseHostPort(req.url ?? "", 443);
    // A client FIN ends the tunnel, both directions.
    //
    // http.Server builds its sockets with allowHalfOpen because its own parser decides when a
    // connection is done. On a CONNECT the socket is handed over and the parser is out of the
    // picture, and inheriting that setting means a client that goes away leaves a socket that
    // never emits 'close': the FIN is forwarded to the destination and both descriptors stay
    // open for as long as the destination tolerates a half-closed peer, with nothing recorded.
    // Reproduced on this file before this line existed, with both a graceful end() and a hard
    // destroy() from the client, and the destination could still write into the tunnel
    // afterwards. An agent and a cooperating destination can hold one pair of descriptors per
    // connection that way, and the ledger shows none of them.
    //
    // The cost is real and worth naming: a client that shuts down only its write side and
    // expects to keep reading gets cut off. Nothing an agent's HTTPS client does looks like
    // that, and squid defaults `half_closed_clients` to off for the same reason, so the
    // resource the ambiguity costs is worth more than the pattern it forbids.
    clientSocket.allowHalfOpen = false;
    // Attribution is deliberately NOT done here. Walking /proc costs ~44ms and scales
    // with total fds on the box; paying that before the tunnel opens taxes every single
    // model API call. It is resolved after the connection is established instead: the
    // socket is still in /proc/net/tcp for the life of the connection, so the data is
    // identical and the latency is off the critical path.
    const event: ProxyEvent = {
      host,
      port,
      scheme: "https",
      method: "CONNECT",
      client: { pid: null, comm: null, uid: null },
      // Read here rather than after the tunnel opens: the header only exists on the CONNECT
      // request, and the request object is not kept alive for the life of the tunnel.
      credential: parseProxyCredential(req.headers["proxy-authorization"]),
      startedAt: Date.now(),
    };
    const clientPort = clientSocket.remotePort ?? 0;
    const proxyPort = clientSocket.localPort ?? 0;
    // Defaulted rather than left unset: the catch-all below can reach finish() before
    // decide() has run, and a record with no decision at all is worse evidence than one
    // that says the connection was never gated.
    let verdict: ResolvedVerdict = { decision: "allow", reasons: NO_STRINGS, matchedRules: NO_STRINGS, budgetTicket: null };
    let bytesUp = 0;
    let bytesDown = 0;
    let recorded = false;
    const finish = () => {
      if (recorded) return;
      recorded = true;
      // Always `tunneled`, never anything else. The plaintext path can say what it read of a
      // body; this one never can, and the record must say so rather than leave a reader to
      // infer opacity from the absence of findings.
      //
      // This one still spreads `event`, deliberately and unlike the HTTP handler below, which
      // names every field. A tunnel has no content by construction, so there is nothing here
      // for a spread to smuggle, and the spread is what lets a destination fact discovered
      // after construction reach the record without this line having to know about it. The
      // condition attached to that convenience: `src/index.ts` serialises this whole object
      // into the flat ledger at runtime, so anything added to `ProxyEvent` lands in an
      // operator's JSONL whether or not `ProxyRecord`'s type admits it. Destination facts are
      // welcome. Anything read out of a message body is not, and would have to be named
      // rather than spread, as the HTTP handler does.
      //
      // Which is exactly why these two are destructured off first. `credential` is the secret
      // the agent presented to identify itself: it is deliberately withheld from every
      // destination, and a spread would put it in cleartext in the operator's ledger instead,
      // in the very record that exists to prove who the agent was. The type excludes it and
      // a spread does not respect the type, so it has to leave here. `reDecision` describes a
      // call rather than a connection and has no business in a record at all.
      const { credential: _credential, reDecision: _reDecision, ...connection } = event;
      opts.record({
        ...connection,
        ...verdict,
        bodyVisibility: "tunneled",
        durationMs: Date.now() - event.startedAt,
        bytesUp,
        bytesDown,
      });
    };

    void (async () => {
    // Attribution is best-effort: a /proc race (ESRCH/EACCES) must degrade to
    // "unattributed", never take the proxy down. decide() still runs, so an
    // enforce policy sees a null client and can fail closed on its own terms.
    try {
      event.client = attributeSocket(clientPort, proxyPort);
    } catch {
      event.client = { pid: null, comm: null, uid: null };
    }
    verdict = resolveVerdict(opts.decide(event));

    if (verdict.decision === "deny") {
      // No upstream socket is opened: netConnect is below this return, so a denied CONNECT
      // costs the destination nothing, not even a TCP handshake it could log.
      //
      // end() rather than write()+destroy(): destroy() tears the socket down without any
      // guarantee that buffered bytes reached the wire, and the entire value of the 403 and
      // its reason header is that a developer staring at a broken agent actually sees them.
      // The error listener is attached first because a client that gave up mid-denial emits
      // 'error' on a socket that has no other listener yet, which would take the process
      // down over a request that was already refused.
      clientSocket.on("error", () => { /* the client hung up on its own refusal */ });
      const reason = verdict.reasons[0] ? headerSafe(verdict.reasons[0]) : "";
      clientSocket.end(
        "HTTP/1.1 403 Forbidden\r\n" +
          (reason ? `X-Agentwall-Block-Reason: ${reason}\r\n` : "") +
          "Connection: close\r\n\r\n"
      );
      finish();
      return;
    }

    // The peek below owns the client-to-upstream direction until it has named the first
    // record, and while it does it is holding bytes the client already handed over. The
    // client 'close' teardown further down has to know that: see the comment there.
    let peekHolding = true;
    let closedEarly = false;

    const upstream = netConnect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      // The head is bytes the client pipelined with its CONNECT. They are relayed, so they
      // are counted: bytes that reach the destination and appear in no record are an evidence
      // gap a client can open on purpose by sending its first record early. Both the relay
      // and the count now happen inside the peek below, which owns this direction until the
      // first record has been named.
      upstream.on("data", (c) => (bytesDown += c.length));
      // Downstream is piped NOW, before the ClientHello peek below, and that ordering is
      // load-bearing. A server-speaks-first protocol tunnelled over CONNECT (SMTP, IMAP, a
      // bare TCP relay) sends its greeting before the client says anything at all. Holding
      // this direction back until the peek resolved would deadlock every one of them
      // against a handshake their client is waiting on the greeting to begin.
      upstream.pipe(clientSocket);
      observeClientHello();
    });

    /**
     * Read the first record the client sends, name it, and cross-check that name.
     *
     * This is not interception and nothing here is decrypted. The ClientHello is plaintext
     * by construction, and SNI is the hostname the client puts on the wire so the server
     * knows which certificate to serve. What it buys is a SECOND source for the destination:
     * the CONNECT line is a claim the client typed, and this is what the client then went on
     * to negotiate. A client that names an allowlisted host to the proxy and then negotiates
     * a different one has contradicted itself, and the contradiction is worth acting on.
     *
     * WHAT THIS IS NOT: domain-fronting detection. ATT&CK T1090.004 is SNI disagreeing with
     * the HTTP Host header INSIDE the session, and that header is encrypted. Real fronting
     * through this proxy agrees at every layer it can see (CONNECT cdn.example.com, SNI
     * cdn.example.com, inner Host evil.example.com) and passes silently. Nothing short of
     * terminating TLS changes that, which is why the detection this raises is left unmapped
     * rather than filed under a technique it cannot actually observe.
     *
     * The peek is an enrichment, not a gate, and it fails open by construction: the CONNECT
     * destination was already authorised by `decide` above, so a hello this cannot read
     * leaves that decision exactly as it was. The re-decision below can only ever ADD a
     * denial: it runs after an allow, so a second opinion can refuse what the first permitted
     * and can never permit what the first refused.
     */
    function observeClientHello(): void {
      // Seeded with `head`: bytes the client pipelined with its CONNECT, before the 200.
      // A client that does not wait puts its ENTIRE hello here, and those bytes never arrive
      // as a 'data' event, so the seed has to be evaluated in its own right further down. A
      // peek driven only by 'data' would stall such a connection until its timeout and then
      // report no name for one that stated a name perfectly clearly.
      let peeked: Buffer = head?.length ? head : EMPTY;
      let settled = false;

      // Counted, including the head. These bytes are relayed to the destination, and bytes
      // that arrive somewhere while appearing in no record are an evidence gap a client can
      // open on purpose by sending its first record early.
      if (peeked.length) bytesUp += peeked.length;

      const evaluate = (): void => {
        const hello = peekClientHello(peeked);
        if (hello.status === "incomplete") {
          // Bounded by one maximal TLS record. Past that it is not a hello, whatever it is.
          if (peeked.length >= MAX_CLIENT_HELLO_BYTES) release(null);
          return;
        }
        release(hello.status === "complete" ? hello.sni : null);
      };

      const onPeekData = (chunk: Buffer) => {
        bytesUp += chunk.length;
        peeked = peeked.length === 0 ? chunk : Buffer.concat([peeked, chunk]);
        evaluate();
      };

      // A client that opens a tunnel and never speaks must not hold its own upstream
      // direction shut forever. unref'd: a pending peek is not a reason to keep the
      // process alive.
      const timer = setTimeout(() => release(null), PEEK_TIMEOUT_MS);
      timer.unref?.();

      function release(sni: string | null): void {
        if (settled) return;
        settled = true;
        // The peek is done holding this direction from here on, on every exit below,
        // including the refusal that never reaches the handover.
        peekHolding = false;
        clearTimeout(timer);
        clientSocket.off("data", onPeekData);

        try {
          if (sni !== null) {
            const checked = crossCheckNegotiatedName(sni, host, event, verdict, opts.decide);
            verdict = checked.verdict;
            if (checked.refuse) {
              // Torn down rather than refused politely: the 200 has already gone out, so
              // there is no status line left to send. The honest cost of deciding this late
              // is that the destination saw a TCP handshake, which a CONNECT-level deny never
              // spends. Zero payload bytes reach it either way, because the hello that
              // triggered this is still sitting in `peeked`, unforwarded.
              clientSocket.destroy();
              upstream.destroy();
              finish();
              return;
            }
          }
        } catch (err) {
          // A throw here is a bug in the peek or in a caller's `decide`, and the connection
          // it would take down is one that policy already allowed. Report it and hand the
          // tunnel over: a parser defect must not become an egress outage.
          opts.onError?.(err as Error, "client-hello-peek");
        }

        clientSocket.on("data", (c) => (bytesUp += c.length));
        // Buffered bytes go first, then the pipe. Both are synchronous, so no chunk can
        // arrive between the two and be reordered behind the hello it belongs in front of.
        if (peeked.length) upstream.write(peeked);
        clientSocket.pipe(upstream);
        // The client left while this still held its bytes, so the teardown it was owed was
        // deferred to here. end() rather than destroy(): the hello has only just entered the
        // write queue, and a destroy() can discard it or turn the close into a reset, which
        // would throw away the one thing the deferral exists to deliver. The descriptor is
        // released when the destination answers the FIN, and by the deadline the 'close'
        // handler armed when it does not.
        if (closedEarly) upstream.end();
      }

      // Flushed rather than dropped when the client hangs up mid-hello: those bytes were
      // accepted from the client and the tunnel was open, so the ledger and the destination
      // should agree on what was sent.
      clientSocket.once("end", () => release(null));
      clientSocket.on("data", onPeekData);

      // The pipelined case, and it has to run AFTER the listeners above rather than before.
      // `release` detaches onPeekData and installs the pipe, so evaluating the seed first
      // would let the line above re-attach a peek listener on a socket already handed over.
      // A client that pipelined its whole hello is complete right here and may never send a
      // 'data' event at all, so without this it waits out the timeout and is never named.
      if (peeked.length) evaluate();
    }

    const bail = (err: Error, where: string) => {
      opts.onError?.(err, where);
      clientSocket.destroy();
      upstream.destroy();
      finish();
    };
    upstream.on("error", (e) => bail(e as Error, `upstream ${host}:${port}`));
    clientSocket.on("error", (e) => bail(e as Error, "client"));
    upstream.on("close", finish);
    // Registered outside the connect callback so it also covers a client that gave up while the
    // upstream connect was still in flight. Nothing else releases the destination when a client
    // leaves without erroring, because a FIN is not an error: the line above is what turns the
    // client's FIN into a 'close' at all, and this is what the 'close' has to do. Measured
    // before both existed, on a destination that tolerates a half-closed peer: three socket
    // descriptors stayed open after the client was gone, the destination could still write into
    // the tunnel, and no record was ever filed. An agent can abandon connections as fast as it
    // can open them.
    //
    // Deferred, never skipped, when the peek is still holding bytes the client pipelined
    // with its CONNECT. That client sends its hello and its FIN in one segment, so this
    // fires while the upstream connect is still in flight: destroying here drops bytes the
    // tunnel had already accepted and files a record that names nothing, which is the whole
    // observation the peek exists to make. Nothing is owed when the client pipelined
    // nothing, so the common abandonment case keeps the immediate teardown above.
    clientSocket.on("close", () => {
      if (peekHolding && head?.length) {
        closedEarly = true;
        // The backstop, and unconditional: whatever the peek and the destination go on to
        // do, this releases the descriptor and files the record within one peek window of
        // the client leaving, so the deferral is bounded by this proxy rather than by the
        // kernel's connect timeout or by a destination that never answers a FIN. A no-op
        // when the tunnel already closed on its own. unref'd, because a deferred teardown
        // is not a reason to keep the process alive.
        const deadline = setTimeout(() => {
          upstream.destroy();
          finish();
        }, PEEK_TIMEOUT_MS);
        deadline.unref?.();
        return;
      }
      upstream.destroy();
      finish();
    });
    })().catch((err: unknown) => {
      // Last line of defence. Node exits on unhandled rejections, and this proxy
      // is the single egress path for 35 cron jobs, so one bad connection must
      // never become a fleet-wide outage.
      opts.onError?.(err as Error, "connect-handler");
      try { clientSocket.destroy(); } catch { /* already gone */ }
      finish();
    });
  });

  // Plain HTTP arrives as an absolute-URI request rather than CONNECT, and is the one scheme
  // this proxy can read. Everything below exists because it can: the path, the headers, and
  // both bodies are handed to `decide` before they are forwarded.
  server.on("request", (req: IncomingMessage, res: ServerResponse) => {
    let parsed: URL;
    try {
      parsed = new URL(req.url ?? "");
    } catch {
      res.writeHead(400).end("agentwall: absolute-URI required\n");
      return;
    }
    const port = Number(parsed.port || 80);
    const path = parsed.pathname + parsed.search;
    /**
     * The connection, with no content on it.
     *
     * `path` is deliberately absent here and added only to the two calls that carry a body.
     * Putting it on the base event scans the path twice, once at each decision, which files a
     * decoy sighting twice for one appearance and lets the first pass refuse a request before
     * its body has been read, leaving a record that names the URL finding and knows nothing
     * about what was in the body of the same request. One pass over the content, one story.
     */
    const event: ProxyEvent = {
      host: parsed.hostname,
      port,
      scheme: "http",
      method: req.method ?? "GET",
      client: attributeSocket(req.socket.remotePort ?? 0, req.socket.localPort ?? 0),
      credential: parseProxyCredential(req.headers["proxy-authorization"]),
      startedAt: Date.now(),
    };


    const ledger = new VerdictLedger();
    let bytesUp = 0;
    let bytesDown = 0;
    let visibility: BodyVisibility | undefined;
    let upstream: ClientRequest | undefined;
    let recorded = false;
    let abandoned = false;

    /**
     * The weakest visibility any pass achieved, because that is the honest summary. An
     * exchange whose request was read whole and whose response was an event stream reports
     * `stream`: some of its content went by uninspected, and a row that said `plaintext`
     * would invite a reader to trust a scan that did not cover everything. Which pass was
     * which is in the direction-namespaced metadata.
     */
    const observed = (level: BodyVisibility): void => {
      if (visibility === undefined || VISIBILITY_ORDER[level] < VISIBILITY_ORDER[visibility]) visibility = level;
    };

    /**
     * One record per exchange, filed exactly once. Every exit reaches this: a refusal, an
     * upstream failure, a completed response, and a client that walked away mid-flight.
     *
     * Every field is named rather than spread from `event`, and that is a control, not a
     * style choice. `src/index.ts` writes this object to the flat ledger with
     * `JSON.stringify({ ts, ...r })`, which serialises whatever is on it at RUNTIME.
     * `ProxyRecord` omitting `headers` and `body` shapes the type and stops nothing there: a
     * spread carries excess properties without tripping excess-property checking, so a field
     * added to `ProxyEvent` later would reach the JSONL sink silently while still compiling.
     * An allowlist of named fields is the only version of this that cannot rot, because
     * adding a field to `ProxyEvent` now does nothing here until somebody writes it down.
     */
    const finish = (): void => {
      if (recorded) return;
      recorded = true;
      opts.record({
        host: event.host,
        port: event.port,
        scheme: event.scheme,
        method: event.method,
        client: event.client,
        startedAt: event.startedAt,
        // The pathname, without the query. The full target including the query is handed to
        // `decide` on the two content calls, because a credential smuggled out as
        // `?api_key=AKIA...` is precisely the shape this path was built to catch. It must not
        // be written down: that would put the live credential into the audit chain and into
        // the flat ledger as the evidence for its own detection. The size goes instead,
        // enough to know a query was there and how big, and `metadata.contentSites` already
        // says what class of thing was found in it and at what offset.
        path: parsed.pathname,
        decision: ledger.decision,
        reasons: ledger.reasons,
        matchedRules: ledger.matchedRules,
        riskLevel: ledger.riskLevel,
        metadata: { ...ledger.metadata, pathQueryBytes: String(parsed.search.length) },
        // Which agent, on what evidence, judged against whose allowlist. Named like every
        // other field here rather than spread from the event: this is the decision's own
        // account of the connection, and the credential it was resolved from stays out.
        attribution: ledger.attribution,
        budgetTicket: ledger.budgetTicket,
        bodyVisibility: visibility ?? "unread",
        durationMs: Date.now() - event.startedAt,
        bytesUp,
        bytesDown,
      });
    };

    /**
     * Refuse the exchange with a 403 the client can actually read.
     *
     * `Connection: close` rather than destroying the request stream. `IncomingMessage`'s
     * destroy() tears down the socket the response is about to be written to, so refusing a
     * request whose body was still arriving would kill its own 403 and leave a developer
     * staring at a reset instead of a reason. The header lets Node flush the response first
     * and close after; `resume()` then drains whatever the client is still sending straight
     * to the floor so a large upload cannot hold the socket open behind the refusal.
     */
    const refuse = (verdict: ResolvedVerdict, body: string): void => {
      const reason = verdict.reasons[0] ? headerSafe(verdict.reasons[0]) : "";
      const headers: Record<string, string> = { connection: "close" };
      if (reason) headers["x-agentwall-block-reason"] = reason;
      if (!res.headersSent) res.writeHead(403, headers);
      res.end(body);
      req.resume();
      finish();
    };

    // Decision 1: the destination, from host and port alone, before a single body byte is
    // buffered. Deciding this first is what stops a request to a destination that was never
    // going to be allowed from pinning a quarter-megabyte of memory on its way to a refusal.
    const connection = ledger.fold(resolveVerdict(opts.decide(event)));
    if (connection.decision === "deny") {
      refuse(connection, "agentwall: destination not allowed\n");
      return;
    }

    // A client that hangs up mid-exchange must not leave the upstream request open forever
    // and unrecorded. Inspection widens that window by design, since the proxy now waits for
    // a body before opening anything, so the release is explicit rather than incidental.
    // `abandoned` is set first because destroying the outgoing request makes it emit its own
    // error, and a teardown we performed ourselves must not be reported as the destination
    // failing: that would put a fictional upstream fault in the operator's error log every
    // time a client pressed ctrl-c.
    const abandon = (): void => {
      abandoned = true;
      upstream?.destroy();
      finish();
    };
    req.on("aborted", abandon);
    res.on("close", abandon);

    const forward = (buffered: BufferedBody): void => {
      // Hop-by-hop headers are addressed to this proxy and must not be relayed. Forwarding
      // req.headers wholesale sent Proxy-Authorization to the destination, which means every
      // host a fleet agent talks to received the credential that identifies that agent to
      // AgentWall. Deleted from a copy: req.headers is shared with the event above and with
      // Node's own parser state, and the scan is entitled to see the credential even though
      // the destination is not.
      const upstreamHeaders = { ...req.headers };
      delete upstreamHeaders["proxy-authorization"];
      delete upstreamHeaders["proxy-connection"];

      const outbound = httpRequest(
        {
          host: parsed.hostname,
          port,
          path,
          method: req.method,
          // Otherwise forwarded exactly as they arrived. The scan reads a copy; it never
          // rewrites what the destination sees, so an allowed request differs from an
          // unproxied one only by the two hop-by-hop names stripped above.
          headers: upstreamHeaders,
        },
        (upRes) => respond(upRes)
      );
      upstream = outbound;
      outbound.on("error", (err) => {
        if (abandoned) return;
        opts.onError?.(err, `upstream ${parsed.hostname}:${port}`);
        if (!res.headersSent) res.writeHead(502);
        res.end();
        finish();
      });

      for (const chunk of buffered.chunks) {
        bytesUp += chunk.length;
        outbound.write(chunk);
      }
      if (buffered.truncated) {
        // The read stopped at the cap or at a stall; the rest of the request still has to
        // reach the destination, uninspected and counted.
        req.on("data", (chunk: Buffer) => (bytesUp += chunk.length));
        req.pipe(outbound);
      } else {
        outbound.end();
      }
    };

    const respond = (upRes: IncomingMessage): void => {
      const headers = flattenHeaders(upRes.headers);
      const status = upRes.statusCode ?? 502;

      const relay = (chunks: readonly Buffer[], rest: boolean): void => {
        res.writeHead(status, upRes.headers);
        for (const chunk of chunks) {
          bytesDown += chunk.length;
          res.write(chunk);
        }
        if (!rest) {
          res.end();
          finish();
          return;
        }
        upRes.on("data", (chunk: Buffer) => (bytesDown += chunk.length));
        upRes.pipe(res);
        upRes.on("end", finish);
      };

      // An event stream is exempt from buffering, explicitly, rather than half-buffered until
      // the idle timer notices. MCP carries SSE and an event stream that pauses between
      // events is behaving correctly; holding one to scan it converts a working transport
      // into a hang. Its headers are still decided on, so this is not a hole a `Content-Type`
      // opens on the whole exchange, only on the body it names.
      if (isStreamingType(headers["content-type"])) {
        observed("stream");
        const verdict = ledger.fold(
          resolveVerdict(
            opts.decide({
              ...event,
              path,
              headers,
              reDecision: true,
              body: { direction: "response", text: "", truncated: false, bytes: 0, status, unscannable: "stream" },
            })
          )
        );
        if (verdict.decision === "deny") {
          upRes.destroy();
          refuse(verdict, "agentwall: response not allowed\n");
          return;
        }
        relay([], true);
        return;
      }

      readBoundedBody(upRes, (buffered) => {
        if (recorded) return;
        observed(buffered.truncated ? "partial" : "plaintext");
        const decoded = decodeForScan(buffered.chunks, buffered.bytes, headers["content-encoding"]);
        // Decision 3: the response, before one byte of it is written back. This is the pass
        // that catches the poisoned tool result, which is the shape a control that inspects
        // only egress never sees at all.
        const verdict = ledger.fold(
          resolveVerdict(
            opts.decide({
              ...event,
              path,
              headers,
              reDecision: true,
              body: {
                direction: "response",
                text: decoded.text,
                truncated: buffered.truncated,
                bytes: buffered.bytes,
                status,
                encoding: decoded.encoding,
                unscannable: decoded.unscannable,
              },
            })
          )
        );
        if (verdict.decision === "deny") {
          // Nothing has been written downstream yet, so a poisoned response is still a real
          // 403 with a reason rather than a truncated body the client has to guess about.
          upRes.destroy();
          refuse(verdict, "agentwall: response content not allowed\n");
          return;
        }
        relay(buffered.chunks, buffered.truncated);
      });
    };

    readBoundedBody(req, (buffered) => {
      if (recorded) return;
      observed(buffered.truncated ? "partial" : "plaintext");
      const headers = flattenHeaders(req.headers);
      const decoded = decodeForScan(buffered.chunks, buffered.bytes, headers["content-encoding"]);
      // Decision 2: the request, with everything the proxy can read of it, and still before
      // anything is opened upstream. A refusal here costs the destination nothing at all.
      const verdict = ledger.fold(
        resolveVerdict(
          opts.decide({
            ...event,
            path,
            headers,
            reDecision: true,
            body: {
              direction: "request",
              text: decoded.text,
              truncated: buffered.truncated,
              bytes: buffered.bytes,
              encoding: decoded.encoding,
              unscannable: decoded.unscannable,
            },
          })
        )
      );
      if (verdict.decision === "deny") {
        // No req.destroy() here: it destroys the socket the 403 is about to be written to.
        // refuse() closes the connection through the header instead, after the reason has
        // reached the wire.
        refuse(verdict, "agentwall: request content not allowed\n");
        return;
      }
      forward(buffered);
    });
  });

  server.listen(opts.port, opts.host);
  return server;
}
