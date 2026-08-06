import { createServer as createHttpServer, IncomingMessage, ServerResponse, request as httpRequest } from "http";
import { connect as netConnect, Socket, Server } from "net";
import { readdirSync, readFileSync, readlinkSync } from "fs";
import type { RiskLevel } from "../types";

/**
 * CONNECT-aware forward proxy: the insertion mechanism.
 *
 * Why a proxy rather than harness hooks: egress is the one action plane with a
 * pre-existing universal insertion standard. Four environment variables and zero lines of
 * harness code, instead of patching each harness's tool path. The proxy is the whole
 * insertion surface: set the standard proxy environment variables and every cooperating
 * client is covered, with no per-framework adapter to maintain.
 *
 * Tier 1 only: this sees CONNECT host:port and absolute-URI hosts. It does NOT terminate
 * TLS, so https bodies stay opaque. Deliberate: MITM needs a CA in every runtime trust
 * store, which breaks the harness-agnostic property this exists for.
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
}

export type ProxyDecideResult = ProxyDecision | ProxyVerdict;

export interface ProxyEvent {
  host: string;
  port: number;
  scheme: "http" | "https";
  method: string;
  /** Resolved originating process, or nulls when attribution failed. */
  client: { pid: number | null; comm: string | null };
  startedAt: number;
}

export interface ProxyRecord extends ProxyEvent {
  decision: ProxyDecision;
  /** Why, as returned by `decide`. Empty when the decision came back as a bare string. */
  reasons: readonly string[];
  matchedRules: readonly string[];
  riskLevel?: RiskLevel;
  durationMs: number;
  bytesUp: number;
  bytesDown: number;
}

export interface ForwardProxyOptions {
  port: number;
  host: string;
  /**
   * Called once per connection, before anything is opened upstream. Return "deny", or a
   * verdict whose decision is "deny", to refuse. A bare string is accepted for callers that
   * have nothing to explain; a verdict carries the reason the client is shown.
   */
  decide: (event: ProxyEvent) => ProxyDecideResult;
  record: (record: ProxyRecord) => void;
  onError?: (err: Error, context: string) => void;
}

/**
 * Map a proxy client socket back to the process that opened it.
 *
 * This is what lets the ledger name the process that actually made the call, rather than
 * "unknown", WITHOUT harness cooperation, which is the point of a harness-agnostic
 * design. /proc/net/tcp turns a local port into a socket inode; /proc/<pid>/fd finds the
 * owner. Linux-specific and best-effort by design: attribution failing must never break
 * egress.
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
 * Resolve one connection to the process that opened it.
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
 * it costs nothing: attribution is best-effort and the connection proceeds either way.
 */
function attributeSocket(clientPort: number, proxyPort: number): { pid: number | null; comm: string | null } {
  if (!clientPort || !proxyPort) return { pid: null, comm: null };
  try {
    const wantLocal = `:${clientPort.toString(16).toUpperCase().padStart(4, "0")}`;
    const wantRemote = `:${proxyPort.toString(16).toUpperCase().padStart(4, "0")}`;
    // Dynamic membership, and the count is the decision, so a Set rather than a lookup table.
    const candidates = new Set<string>();

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
        if (cols[1].endsWith(wantLocal) && cols[2].endsWith(wantRemote)) candidates.add(cols[9]);
      }
    }
    if (candidates.size !== 1) return { pid: null, comm: null };
    const [inode] = candidates;

    const target = `socket:[${inode}]`;

    for (const pid of [...hotPids]) {
      if (pidHoldsInode(pid, target)) {
        touchHotPid(pid);
        return { pid, comm: readComm(pid) };
      }
    }

    let entries: string[];
    try {
      entries = readdirSync("/proc");
    } catch {
      return { pid: null, comm: null };
    }
    for (const entry of entries) {
      if (!/^\d+$/.test(entry)) continue;
      const pid = Number(entry);
      if (pidHoldsInode(pid, target)) {
        touchHotPid(pid);
        return { pid, comm: readComm(pid) };
      }
    }
    return { pid: null, comm: null };
  } catch {
    return { pid: null, comm: null };
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

/** A `decide` result with its optional parts filled in, ready to spread onto a record. */
interface ResolvedVerdict {
  decision: ProxyDecision;
  reasons: readonly string[];
  matchedRules: readonly string[];
  riskLevel?: RiskLevel;
}

function resolveVerdict(result: ProxyDecideResult): ResolvedVerdict {
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
      client: { pid: null, comm: null },
      startedAt: Date.now(),
    };
    const clientPort = clientSocket.remotePort ?? 0;
    const proxyPort = clientSocket.localPort ?? 0;
    // Defaulted rather than left unset: the catch-all below can reach finish() before
    // decide() has run, and a record with no decision at all is worse evidence than one
    // that says the connection was never gated.
    let verdict: ResolvedVerdict = { decision: "allow", reasons: NO_STRINGS, matchedRules: NO_STRINGS };
    let bytesUp = 0;
    let bytesDown = 0;
    let recorded = false;
    const finish = () => {
      if (recorded) return;
      recorded = true;
      opts.record({ ...event, ...verdict, durationMs: Date.now() - event.startedAt, bytesUp, bytesDown });
    };

    void (async () => {
    // Attribution is best-effort: a /proc race (ESRCH/EACCES) must degrade to
    // "unattributed", never take the proxy down. decide() still runs, so an
    // enforce policy sees a null client and can fail closed on its own terms.
    try {
      event.client = attributeSocket(clientPort, proxyPort);
    } catch {
      event.client = { pid: null, comm: null };
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

    const upstream = netConnect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      // The head is bytes the client pipelined with its CONNECT. They are relayed, so they
      // are counted: bytes that reach the destination and appear in no record are an evidence
      // gap a client can open on purpose by sending its first record early.
      if (head?.length) {
        upstream.write(head);
        bytesUp += head.length;
      }
      // Counters attach HERE, not earlier. Adding a "data" listener puts the socket into
      // flowing mode immediately; doing that before the pipe exists means any bytes a
      // client sends before the 200 are counted and then dropped on the floor.
      clientSocket.on("data", (c) => (bytesUp += c.length));
      upstream.on("data", (c) => (bytesDown += c.length));
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    });

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
    clientSocket.on("close", () => {
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

  // Plain HTTP arrives as an absolute-URI request rather than CONNECT.
  server.on("request", (req: IncomingMessage, res: ServerResponse) => {
    let parsed: URL;
    try {
      parsed = new URL(req.url ?? "");
    } catch {
      res.writeHead(400).end("agentwall: absolute-URI required\n");
      return;
    }
    const port = Number(parsed.port || 80);
    const event: ProxyEvent = {
      host: parsed.hostname,
      port,
      scheme: "http",
      method: req.method ?? "GET",
      client: attributeSocket(req.socket.remotePort ?? 0, req.socket.localPort ?? 0),
      startedAt: Date.now(),
    };
    const verdict = resolveVerdict(opts.decide(event));
    let bytesDown = 0;
    // One record per attempt, from one place. This exchange can end four ways, three of them
    // filed their own copy, so a response that ended and then errored was recorded twice, and
    // the fourth, a client that gives up, was recorded not at all.
    let recorded = false;
    let abandoned = false;
    const finish = () => {
      if (recorded) return;
      recorded = true;
      opts.record({ ...event, ...verdict, durationMs: Date.now() - event.startedAt, bytesUp: 0, bytesDown });
    };

    if (verdict.decision === "deny") {
      const reason = verdict.reasons[0] ? headerSafe(verdict.reasons[0]) : "";
      const headers: Record<string, string> = {};
      if (reason) headers["x-agentwall-block-reason"] = reason;
      res.writeHead(403, headers).end("agentwall: destination not allowed\n");
      finish();
      return;
    }

    const upstream = httpRequest(
      {
        host: parsed.hostname,
        port,
        path: parsed.pathname + parsed.search,
        method: req.method,
        headers: req.headers,
      },
      (upRes) => {
        res.writeHead(upRes.statusCode ?? 502, upRes.headers);
        upRes.on("data", (c) => (bytesDown += c.length));
        upRes.pipe(res);
        upRes.on("end", finish);
      }
    );
    upstream.on("error", (err) => {
      // A teardown this proxy performed itself is not a destination failure. Reporting it as
      // one would put an error naming the destination in the operator's log for something the
      // client did.
      if (abandoned) {
        finish();
        return;
      }
      opts.onError?.(err as Error, `upstream ${parsed.hostname}:${port}`);
      if (!res.headersSent) res.writeHead(502);
      res.end();
      finish();
    });
    // The client giving up is the only signal this proxy gets that a destination which
    // accepted and then said nothing is never going to answer: there is no deadline here, so
    // the client's own timeout is what ends the wait. Nothing recorded by now means the
    // exchange never completed, since both completion paths record. Until this released the
    // outgoing request, it outlived the client that asked for it, holding a live connection to
    // the destination that no record mentioned.
    res.on("close", () => {
      if (!recorded) {
        abandoned = true;
        upstream.destroy();
      }
      finish();
    });
    req.pipe(upstream);
  });

  server.listen(opts.port, opts.host);
  return server;
}
