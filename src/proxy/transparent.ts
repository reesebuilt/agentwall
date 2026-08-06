import { connect as netConnect, createServer as createNetServer, Server, Socket } from "net";
import type { ProxyDecision, ProxyEvent, ProxyRecord, ProxyVerdict } from "./forward-proxy";
import type { RiskLevel } from "../types";
import { IPV6_CHARS, isPlausibleHostname } from "./hostname";
import { peekClientHello } from "./tls-peek";

/**
 * Transparent listener: the egress path that does not need the agent's cooperation.
 *
 * The forward proxy next door is opt-in by construction. It works because the client reads
 * `HTTPS_PROXY` and speaks `CONNECT`, which means a process that simply does not read those
 * variables — or deliberately unsets them — walks straight past the control. That is
 * cooperative capture, and a control an agent can decline is not a control.
 *
 * This listener closes that. The agent runs as its own unprivileged UID and nftables
 * owner-matches that UID, redirecting its outbound TCP here and dropping everything else it
 * attempts. The kernel does the capturing, so the client's configuration stops mattering:
 * connections arrive here whether or not anything cooperated.
 *
 * WHAT THAT COSTS: a redirected connection carries no destination. There is no `CONNECT`
 * line and no absolute-URI request line, because the client believes it is talking directly
 * to the origin. The kernel does know the original address — it is retrievable with
 * `getsockopt(SO_ORIGINAL_DST)` — but Node exposes no such call, and a native addon is off
 * the table: this package's runtime dependency list is exactly three packages and keeping it
 * there is a deliberate supply-chain property, not an accident.
 *
 * So the destination is recovered from the stream itself: SNI for TLS, `Host:` for plain
 * HTTP. The limits of that are real and are enforced rather than papered over:
 *
 *   - A TLS connection to an IP literal, or from a client that omits SNI, cannot be named.
 *     It is DENIED. A destination that cannot be named cannot be policed, and an
 *     unpoliceable hole in the middle of an enforcement control is worse than a refusal.
 *   - SNI carries no port, so the TLS destination port is `defaultTlsPort` (443). With
 *     REDIRECT the socket's local port is the proxy's own, so there is nothing better
 *     available from the connection; a perimeter that redirects a different TLS port has to
 *     say so, or every such connection is delivered to the wrong service on the right host.
 *   - A ClientHello fragmented across TLS records, or larger than `maxPeekBytes`, is not
 *     reassembled and is denied. Both are rare; both fail closed.
 *   - HTTP/2 with prior knowledge is denied: its preface is not an HTTP/1 request line and
 *     parsing h2 frames to find `:authority` is a protocol stack this does not carry.
 *
 * As with the forward proxy, nothing here decides anything. `decide` is authoritative and a
 * deny costs the destination nothing — no upstream socket is opened on any path. The one
 * decision this file makes on its own is the structural refusal above, and it is recorded so
 * the refusal appears in the ledger rather than looking like a network glitch.
 *
 * Tier 1 only, same as the forward proxy: TLS is never terminated, so https bodies stay
 * opaque. That is what keeps this harness-agnostic — MITM would need a CA in every runtime
 * trust store.
 *
 * ROBUSTNESS IS A SECURITY PROPERTY HERE. The kernel redirects to this port whether or not
 * anything is listening on it, and there is no fallback behind it: a crashed listener is not
 * a degraded control, it is a total loss of egress. Every socket handler, every parser and
 * every caller-supplied callback below is therefore wrapped so that no input can throw out
 * of the listener.
 */

/** One connection the kernel redirected here, named from its own first bytes. */
export interface TransparentAttempt {
  host: string;
  port: number;
  scheme: "http" | "https";
}

export interface TransparentProxyOptions {
  port: number;
  host?: string;
  /**
   * Called once per connection, after the destination is recovered and before anything is
   * opened upstream. Return "deny", or a verdict whose decision is "deny", to refuse.
   *
   * NOT called for a connection whose destination could not be recovered at all: there is
   * no attempt to hand it, and there would be nowhere to connect even if it came back
   * "allow". That case is refused structurally and recorded.
   */
  decide: (a: TransparentAttempt) => ProxyDecision | ProxyVerdict;
  record: (r: ProxyRecord) => void;
  onError?: (err: Error) => void;
  /** How long to wait for enough bytes to name a destination. Default 5000ms. */
  peekTimeoutMs?: number;
  /** How many bytes to buffer while trying to name a destination. Default 8192. */
  maxPeekBytes?: number;
  /**
   * The port a TLS destination is assumed to be on. Default 443.
   *
   * SNI names a host and nothing else, and REDIRECT has already replaced the socket's local
   * port with this proxy's, so the original port is genuinely not in the connection. 443 is
   * right for a perimeter that redirects only :80 and :443, which is the ruleset this is
   * built for — destination recovery only works for those two protocols, so redirecting
   * anything else produces connections this listener has to refuse anyway. A deployment that
   * redirects a different TLS port sets this, because the alternative is every such
   * connection being quietly delivered to :443 of the right host: the wrong service, allowed.
   */
  defaultTlsPort?: number;
}

const DEFAULT_PEEK_TIMEOUT_MS = 5000;
const DEFAULT_MAX_PEEK_BYTES = 8192;
const DEFAULT_TLS_PORT = 443;

const NO_STRINGS: readonly string[] = [];
const EMPTY = Buffer.alloc(0);

/**
 * What a record says when the destination was never recoverable.
 *
 * Angle brackets are not legal in a DNS name, so this sentinel can never collide with a
 * real destination an operator might grep the ledger for.
 */
const UNNAMED_HOST = "<unknown>";
const UNNAMED_REASON = "no SNI or Host header: the destination could not be named";

const DENY_BODY = "agentwall: destination not allowed\n";

/** A destination recovered from the stream, plus the method to put on the record. */
interface Destination {
  host: string;
  port: number;
  scheme: "http" | "https";
  method: string;
}

/** A `decide` result with its optional parts filled in, ready to spread onto a record. */
interface ResolvedVerdict {
  decision: ProxyDecision;
  reasons: readonly string[];
  matchedRules: readonly string[];
  riskLevel?: RiskLevel;
}

function resolveVerdict(result: ProxyDecision | ProxyVerdict): ResolvedVerdict {
  if (typeof result === "string") {
    return { decision: result, reasons: NO_STRINGS, matchedRules: NO_STRINGS };
  }
  return {
    decision: result.decision,
    reasons: result.reasons ?? NO_STRINGS,
    matchedRules: result.matchedRules ?? NO_STRINGS,
    riskLevel: result.riskLevel,
  };
}

/**
 * A block reason, made safe to put in a header.
 *
 * Identical in behaviour to the forward proxy's: printable ASCII only, collapsed runs, and a
 * 200-character cap. It is spelled out again rather than shared because the forward proxy's
 * copy is module-private and that file is not in scope for this change. The two must not
 * drift — a reason that is safe on one egress path and injectable on the other is the worst
 * of both. The reason text originates from a destination the agent chose, so a bare CR or LF
 * would otherwise let that agent inject headers, or an entire second response, into the 403
 * written here by hand.
 */
function headerSafe(reason: string): string {
  const cleaned = reason.replace(/[^\x20-\x7e]+/g, " ").replace(/ {2,}/g, " ").trim();
  return cleaned.length > 200 ? `${cleaned.slice(0, 197)}...` : cleaned;
}

const HTTP_METHOD = /^[A-Z]{1,16}$/;
const HTTP_VERSION = /^HTTP\/1\.[01]$/;
const AUTHORITY_CHARS = /^[A-Za-z0-9._\-[\]:]+$/;
const PORT_DIGITS = /^[0-9]{1,5}$/;

/**
 * Pull the destination out of an origin-form HTTP request head, or return null.
 *
 * A redirected client sends `GET /path HTTP/1.1` with a `Host:` header, because it believes
 * it is talking to the origin. `Host:` is therefore the only statement of destination in the
 * stream, and HTTP/1.1 requires it — its absence is a protocol error, so treating it as one
 * rather than inventing a fallback is both correct and the fail-closed direction.
 *
 * Null means: the head is not complete yet (no CRLFCRLF, so the caller keeps buffering), the
 * request line is not plausibly HTTP/1, `Host:` is missing, `Host:` appears more than once,
 * a header is obs-folded, or the authority contains characters that do not belong in one.
 * The last three are refused rather than resolved: picking one of two `Host:` headers is the
 * exact ambiguity request smuggling is built on, and this component's answer determines what
 * gets policed.
 */
export function extractHttpHost(head: Buffer): { host: string; port: number; method: string } | null {
  const terminator = head.indexOf("\r\n\r\n", 0, "latin1");
  if (terminator === -1) return null;

  const lines = head.toString("latin1", 0, terminator).split("\r\n");
  const parts = lines[0].split(" ");
  if (parts.length !== 3) return null;
  const [method, target, version] = parts;
  if (!HTTP_METHOD.test(method)) return null;
  // The version token is what actually separates an HTTP request from arbitrary bytes that
  // happen to contain two spaces. It also excludes the HTTP/2 prior-knowledge preface, which
  // this listener cannot route and must not half-understand.
  if (!HTTP_VERSION.test(version)) return null;
  if (target.length === 0) return null;

  let authority: string | null = null;
  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i];
    // Obs-fold: a continuation line. Deprecated by RFC 7230 and a parser-disagreement
    // primitive, so a head containing one is refused rather than interpreted.
    if (line.startsWith(" ") || line.startsWith("\t")) return null;
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    if (line.slice(0, colon).toLowerCase() !== "host") continue;
    if (authority !== null) return null;
    authority = line.slice(colon + 1).trim();
  }
  if (authority === null || authority.length === 0) return null;
  if (!AUTHORITY_CHARS.test(authority)) return null;

  let hostPart = authority;
  let port = 80;
  // IPv6 literals are full of colons, so only a colon after the closing bracket is a port.
  const lastColon = authority.lastIndexOf(":");
  if (lastColon > authority.lastIndexOf("]")) {
    const rawPort = authority.slice(lastColon + 1);
    if (!PORT_DIGITS.test(rawPort)) return null;
    port = Number(rawPort);
    if (port < 1 || port > 65535) return null;
    hostPart = authority.slice(0, lastColon);
  }

  if (hostPart.startsWith("[")) {
    if (!hostPart.endsWith("]")) return null;
    const inner = hostPart.slice(1, -1);
    return IPV6_CHARS.test(inner) && inner.includes(":") ? { host: inner, port, method } : null;
  }
  if (hostPart.includes("[") || hostPart.includes("]") || hostPart.includes(":")) return null;
  if (!isPlausibleHostname(hostPart)) return null;
  return { host: hostPart.toLowerCase(), port, method };
}

/** First byte decides which parser gets a look; neither is asked to guess at the other's input. */
function destinationFrom(peek: Buffer, tlsPort: number): Destination | null {
  const hello = peekClientHello(peek);
  if (hello.status !== "not-tls") {
    // Incomplete and complete-but-nameless both come back null, which the caller reads as
    // "keep buffering". That is correct for the first and merely harmless for the second:
    // this listener has no other source of a destination, so a hello with no SNI is going
    // to be refused when the peek window closes either way.
    return hello.status === "complete" && hello.sni !== null
      ? { host: hello.sni, port: tlsPort, scheme: "https", method: "CONNECT" }
      : null;
  }
  const parsed = extractHttpHost(peek);
  return parsed === null ? null : { ...parsed, scheme: "http" };
}

/** An error sink that throws must not be able to take the listener down with it. */
function report(opts: TransparentProxyOptions, err: unknown): void {
  try {
    opts.onError?.(err instanceof Error ? err : new Error(String(err)));
  } catch {
    /* nothing above this is allowed to fail */
  }
}

function handleConnection(client: Socket, opts: TransparentProxyOptions): void {
  const peekTimeoutMs = opts.peekTimeoutMs ?? DEFAULT_PEEK_TIMEOUT_MS;
  const maxPeekBytes = opts.maxPeekBytes ?? DEFAULT_MAX_PEEK_BYTES;
  const tlsPort = opts.defaultTlsPort ?? DEFAULT_TLS_PORT;
  const startedAt = Date.now();

  const event: ProxyEvent = {
    host: UNNAMED_HOST,
    port: 0,
    scheme: "http",
    method: "UNKNOWN",
    // Always unattributed on this path. The /proc attribution the forward proxy performs
    // lives in a module-private helper in forward-proxy.ts; it is not exported, and that
    // file is out of scope for this change. Copying the implementation would create a second
    // copy of a security-relevant lookup to drift, so transparent records honestly say
    // "unknown" instead. Lifting the helper into a shared module is the follow-up.
    client: { pid: null, comm: null },
    startedAt,
  };

  /**
   * Defaulted to the structural refusal rather than to allow.
   *
   * A connection that closes before it ever names a destination reaches `finish()` with this
   * still in place, and "denied, never named a destination" is the truth about it. Defaulting
   * to allow here would put rows in the ledger claiming connections were permitted that were
   * never even routed.
   */
  let verdict: ResolvedVerdict = {
    decision: "deny",
    reasons: [UNNAMED_REASON],
    matchedRules: NO_STRINGS,
    riskLevel: "high",
  };

  let peek: Buffer = EMPTY;
  let bytesUp = 0;
  let bytesDown = 0;
  let recorded = false;
  let piped = false;
  let upstream: Socket | null = null;

  const finish = (): void => {
    if (recorded) return;
    recorded = true;
    try {
      opts.record({
        ...event,
        ...verdict,
        // This listener relays raw TCP: it peeks only far enough to name the destination and
        // never parses a message, so no body on either scheme is inspected here. Recorded as
        // such rather than left to look like a clean scan. `tunneled` for a captured TLS
        // connection, which could not be read; `unread` for a redirected plaintext one, which
        // could have been and is not, because content inspection lives on the forward proxy.
        bodyVisibility: event.scheme === "https" ? "tunneled" : "unread",
        durationMs: Date.now() - startedAt,
        bytesUp,
        bytesDown,
      });
    } catch (err) {
      report(opts, err);
    }
  };

  const destroyAll = (): void => {
    try {
      client.destroy();
    } catch {
      /* already gone */
    }
    if (upstream !== null) {
      try {
        upstream.destroy();
      } catch {
        /* already gone */
      }
    }
  };

  const timer = setTimeout(() => refuse(), peekTimeoutMs);

  /**
   * Stop buffering, without losing anything the client sends next.
   *
   * `pause()` comes before the listener is removed because dropping the last "data" handler
   * does NOT take a socket out of flowing mode: bytes would keep being read and thrown away
   * during the upstream connect. Paused, they stay in the socket's read buffer until the
   * pipe below resumes it.
   */
  const stopPeeking = (): void => {
    clearTimeout(timer);
    client.pause();
    client.removeListener("data", onPeek);
  };

  /**
   * The structural refusal: nothing in the stream named a destination inside the limits.
   *
   * `decide` is not consulted. There is no attempt to hand it, and an "allow" would be
   * unusable anyway because there is nowhere to connect. Nothing is written back either: the
   * peer has not produced a parseable HTTP head, so it is not known to speak HTTP, and a 403
   * pushed into an unidentified protocol is noise rather than an explanation. The refusal is
   * recorded so that it shows up in the ledger as a decision rather than as a network glitch
   * someone has to go and diagnose.
   */
  const refuse = (): void => {
    if (recorded) return;
    stopPeeking();
    // Labelled https on the record even though it was never named: "not-tls" is the only
    // status that rules a handshake out, so a truncated hello still counts as one.
    if (peek.length > 0 && peekClientHello(peek).status !== "not-tls") event.scheme = "https";
    verdict = { decision: "deny", reasons: [UNNAMED_REASON], matchedRules: NO_STRINGS, riskLevel: "high" };
    finish();
    destroyAll();
  };

  const deny = (): void => {
    if (event.scheme === "http") {
      const reason = verdict.reasons[0] ? headerSafe(verdict.reasons[0]) : "";
      // Resumed with no "data" listener, which reads and discards. The socket was paused to
      // hand its buffered bytes to the pipe that now will not exist, and closing a socket
      // that still holds unread received data makes the kernel send an RST — which on Linux
      // can discard the 403 out of the client's receive buffer before the client reads it.
      // The whole value of this response is that a developer staring at a broken agent sees
      // the reason, so it is drained rather than left sitting there.
      client.resume();
      try {
        client.end(
          "HTTP/1.1 403 Forbidden\r\n" +
            (reason ? `X-Agentwall-Block-Reason: ${reason}\r\n` : "") +
            "Connection: close\r\n" +
            `Content-Length: ${DENY_BODY.length}\r\n\r\n` +
            DENY_BODY
        );
      } catch {
        /* the client hung up on its own refusal */
      }
    } else {
      // TLS, pre-handshake. The ClientHello has not been answered, so there is no session and
      // no application layer to carry an error over; writing plaintext here would be a
      // protocol violation the client reads as corruption. The connection is closed with zero
      // bytes written, and the honest consequence is that the client sees a connection reset
      // with no reason attached. That is the ceiling of a refusal made before the handshake,
      // not an oversight — the alternative is terminating TLS, which needs a CA in every
      // runtime trust store and is exactly what this design exists to avoid. The reason lives
      // in the ledger record instead, which is where an operator diagnosing the reset looks.
      client.destroy();
    }
    finish();
  };

  const connectUpstream = (destination: Destination): void => {
    const socket = netConnect(destination.port, destination.host, () => {
      // Replay. These bytes were consumed to name the destination and the origin has never
      // seen them; without this every allowed connection loses its ClientHello or its request
      // head and hangs until something times out.
      if (peek.length > 0) {
        socket.write(peek);
        bytesUp += peek.length;
      }
      // Both counters and both pipes are attached inside this one synchronous tick. Adding a
      // "data" listener schedules the resume rather than performing it, so no byte can be
      // delivered before the pipe that forwards it exists.
      client.on("data", (chunk: Buffer) => (bytesUp += chunk.length));
      socket.on("data", (chunk: Buffer) => (bytesDown += chunk.length));
      client.pipe(socket);
      socket.pipe(client);
      piped = true;
    });
    upstream = socket;

    socket.on("error", (err: Error) => {
      // An unreachable or refusing origin is worth reporting: it is the destination's
      // behaviour, not the client's, and it is what an operator debugging a broken agent
      // needs to see. The record still says "allow" because the connection genuinely was
      // permitted; it simply did not survive.
      report(opts, err);
      finish();
      destroyAll();
    });
    socket.once("close", finish);
  };

  const route = (destination: Destination): void => {
    event.host = destination.host;
    event.port = destination.port;
    event.scheme = destination.scheme;
    event.method = destination.method;

    try {
      verdict = resolveVerdict(
        opts.decide({ host: destination.host, port: destination.port, scheme: destination.scheme })
      );
    } catch (err) {
      // A decision function that throws is a failed control, and the only safe reading of a
      // failed control is deny. Allowing on error would make every bug in policy evaluation
      // an open door.
      report(opts, err);
      verdict = {
        decision: "deny",
        reasons: ["egress decision failed"],
        matchedRules: NO_STRINGS,
        riskLevel: "high",
      };
    }

    if (verdict.decision === "deny") {
      deny();
      return;
    }
    connectUpstream(destination);
  };

  function onPeek(chunk: Buffer): void {
    peek = peek.length === 0 ? chunk : Buffer.concat([peek, chunk]);
    let destination: Destination | null = null;
    try {
      destination = destinationFrom(peek, tlsPort);
    } catch (err) {
      // The parsers are written not to throw. This is the belt to that suspenders: they are
      // fed the first packet of a connection from an untrusted process, and an escaping throw
      // here is a dead listener rather than a failed connection.
      report(opts, err);
      refuse();
      return;
    }
    if (destination !== null) {
      stopPeeking();
      route(destination);
      return;
    }
    // Buffering forever on a stream that never names a destination is a resource exhaustion
    // primitive, so the byte ceiling refuses just as the deadline does.
    if (peek.length >= maxPeekBytes) refuse();
  }

  // Attached before anything else can emit. A client that resets mid-peek emits "error" on a
  // socket with no other listener, which is an uncaught exception. Client-side errors are not
  // reported: a peer hanging up is normal traffic, not a fault of this proxy.
  client.on("error", () => {
    finish();
    destroyAll();
  });
  client.once("close", () => {
    clearTimeout(timer);
    // Once piped, the upstream's close is the authoritative end of the connection and carries
    // the final byte counts; recording here as well would file a row with a half-counted
    // download.
    if (!piped) finish();
  });
  client.on("data", onPeek);
}

export function createTransparentProxy(opts: TransparentProxyOptions): Server {
  const server = createNetServer((client) => {
    try {
      handleConnection(client, opts);
    } catch (err) {
      report(opts, err);
      try {
        client.destroy();
      } catch {
        /* already gone */
      }
    }
  });
  // A net.Server with no "error" listener throws on EADDRINUSE and takes the process down.
  // The kernel redirects to this port whether or not the bind succeeded, so a failed listen
  // has to surface through onError as a control that is not running — not as a crash.
  server.on("error", (err: Error) => report(opts, err));
  server.listen(opts.port, opts.host ?? "127.0.0.1");
  return server;
}
