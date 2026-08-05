import { createServer as createHttpServer, IncomingMessage, ServerResponse, request as httpRequest } from "http";
import { connect as netConnect, Socket, Server } from "net";
import { readdirSync, readFileSync, readlinkSync } from "fs";

/**
 * CONNECT-aware forward proxy — the insertion mechanism.
 *
 * Why a proxy rather than harness hooks: egress is the one action plane with a
 * pre-existing universal insertion standard. Four environment variables and zero lines of
 * harness code, instead of patching each harness's tool path. The proxy is the whole
 * insertion surface: set the standard proxy environment variables and every cooperating
 * client is covered, with no per-framework adapter to maintain.
 *
 * Tier 1 only: this sees CONNECT host:port and absolute-URI hosts. It does NOT terminate
 * TLS, so https bodies stay opaque. Deliberate — MITM needs a CA in every runtime trust
 * store, which breaks the harness-agnostic property this exists for.
 *
 * Monitor mode records and always allows. Nothing in this file blocks.
 */

export type ProxyDecision = "allow" | "deny";

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
  durationMs: number;
  bytesUp: number;
  bytesDown: number;
}

export interface ForwardProxyOptions {
  port: number;
  host: string;
  /** Return "deny" to refuse. Monitor mode always returns "allow". */
  decide: (event: ProxyEvent) => ProxyDecision;
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
 * (expensive — walking every /proc/<pid>/fd measured ~44ms, scaling with total FDs).
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

function attributeSocket(remotePort: number): { pid: number | null; comm: string | null } {
  if (!remotePort) return { pid: null, comm: null };
  try {
    const want = `:${remotePort.toString(16).toUpperCase().padStart(4, "0")}`;
    let inode: string | null = null;

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
        if (cols[1].endsWith(want)) {
          inode = cols[9];
          break;
        }
      }
      if (inode) break;
    }
    if (!inode) return { pid: null, comm: null };

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

export function createForwardProxy(opts: ForwardProxyOptions): Server {
  const server = createHttpServer();

  // HTTPS and anything else tunnelled: the majority of agent traffic.
  server.on("connect", (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
    const { host, port } = parseHostPort(req.url ?? "", 443);
    // Attribution is deliberately NOT done here. Walking /proc costs ~44ms and scales
    // with total fds on the box; paying that before the tunnel opens taxes every single
    // model API call. It is resolved after the connection is established instead — the
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
    let decision: ProxyDecision = "allow";
    let bytesUp = 0;
    let bytesDown = 0;
    let recorded = false;
    const finish = () => {
      if (recorded) return;
      recorded = true;
      opts.record({ ...event, decision, durationMs: Date.now() - event.startedAt, bytesUp, bytesDown });
    };

    void (async () => {
    // Attribution is best-effort: a /proc race (ESRCH/EACCES) must degrade to
    // "unattributed", never take the proxy down. decide() still runs, so an
    // enforce policy sees a null client and can fail closed on its own terms.
    try {
      event.client = attributeSocket(clientPort);
    } catch {
      event.client = { pid: null, comm: null };
    }
    decision = opts.decide(event);

    if (decision === "deny") {
      clientSocket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      clientSocket.destroy();
      finish();
      return;
    }

    const upstream = netConnect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) upstream.write(head);
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
      client: attributeSocket(req.socket.remotePort ?? 0),
      startedAt: Date.now(),
    };
    const decision = opts.decide(event);
    let bytesDown = 0;

    if (decision === "deny") {
      res.writeHead(403).end("agentwall: destination not allowed\n");
      opts.record({ ...event, decision, durationMs: Date.now() - event.startedAt, bytesUp: 0, bytesDown: 0 });
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
        upRes.on("end", () =>
          opts.record({ ...event, decision, durationMs: Date.now() - event.startedAt, bytesUp: 0, bytesDown })
        );
      }
    );
    upstream.on("error", (err) => {
      opts.onError?.(err as Error, `upstream ${parsed.hostname}:${port}`);
      if (!res.headersSent) res.writeHead(502);
      res.end();
      opts.record({ ...event, decision, durationMs: Date.now() - event.startedAt, bytesUp: 0, bytesDown });
    });
    req.pipe(upstream);
  });

  server.listen(opts.port, opts.host);
  return server;
}
