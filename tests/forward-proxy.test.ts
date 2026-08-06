import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { createHash, randomBytes } from "crypto";
import * as nodeFs from "fs";
import { createServer as createHttpServer, request as httpRequest } from "http";
import type { Server as HttpServer } from "http";
import { connect as netConnect, createServer as createNetServer, Socket } from "net";
import type { AddressInfo, Server as NetServer } from "net";
import { PolicyEngine } from "../src/policy/engine";
import { createForwardProxy } from "../src/proxy/forward-proxy";
import type { ProxyDecideResult, ProxyEvent, ProxyRecord } from "../src/proxy/forward-proxy";
import { decideEgress, setEgressPolicy } from "../src/runtime/enforcement";
import { resetLockdown } from "../src/runtime/lockdown";

/**
 * What reads of `/proc/net/tcp` return, when a test wants to choose. `null` reads the real
 * table, which is what every other test in the file does.
 *
 * A spy is not available here: on Node 24 the `fs` exports are non-configurable, so
 * `jest.spyOn(fs, "readFileSync")` fails outright. The factory delegates everything else to
 * the real module, so the only thing supplied is the table.
 */
let mockProcNetTcp: string | Error | null = null;

jest.mock("fs", () => {
  const actual = jest.requireActual<typeof nodeFs>("fs");
  return {
    ...actual,
    readFileSync: (path: unknown, options?: unknown) => {
      if (typeof path === "string" && path.startsWith("/proc/net/tcp") && mockProcNetTcp !== null) {
        if (mockProcNetTcp instanceof Error) throw mockProcNetTcp;
        return mockProcNetTcp;
      }
      return (actual.readFileSync as unknown as (p: unknown, o?: unknown) => unknown)(path, options);
    },
  };
});

/**
 * The forward proxy, driven the way a client drives it: real sockets, real CONNECT, real bytes.
 *
 * This file exists because the proxy was reachable only through the harness API tests, which
 * exercise `/inspect/network` and `/evaluate` and never open a socket. Everything the proxy is
 * actually responsible for lives below those routes: the tunnel, the lifecycle of two sockets
 * that can die in either order, the byte counts the ledger reports, and the attribution that
 * names the process behind a connection. None of that is observable from a rendered decision,
 * so nothing here mocks a socket. The destination is a listener on loopback, the client is a
 * socket, and every failure is produced by doing to the proxy what a broken client or a broken
 * destination would do.
 *
 * The one mock in the file replaces reads of `/proc/net/tcp`, because the attribution race the
 * source promises to survive is a row that is already gone by the time the table is read, and a
 * real socket is by definition still in the table. The connection under those tests is real;
 * only the table is supplied.
 *
 * NO SLEEPS. Every wait is an event the proxy already emits: a decision taken, a byte
 * delivered, a socket closed, a record filed. `settle()` is the exception and it is a tick
 * barrier rather than a duration, used only where the assertion is that something did NOT
 * happen and there is no event to wait for.
 *
 * No external network. The only names dialled are loopback literals, so this suite passes on a
 * box with no route out.
 */

// Bodies come from randomBytes. Every assertion compares a digest against the buffer that was
// sent in the same run, so nothing needs the bytes to be reproducible across runs, and random
// content is the stronger choice anyway: it is incompressible and never repeats, so a dropped,
// doubled or reordered chunk always changes the digest. A hand-rolled generator was tried first
// and reverted: a 32M-iteration JS loop costs 12 seconds inside Jest's VM context against 46ms
// for randomBytes, which put 25 seconds of arithmetic into a test about socket behaviour.

/** Both sides of every transfer assertion have to agree on the algorithm, so it lives once. */
function digest(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * Received bytes are kept as chunks and joined only when asserted.
 *
 * Concatenating on every `data` event is quadratic, which turns the multi-megabyte transfer
 * test from a second into minutes and would hide a real hang behind an accumulator that was
 * never under test.
 */
interface Collected {
  chunks: Buffer[];
  length: number;
}

function collect(into: Collected, chunk: Buffer): void {
  into.chunks.push(chunk);
  into.length += chunk.length;
}

/** Everything the proxy wrote up to and including the response terminator. */
function responseHead(received: Collected): string {
  const joined = Buffer.concat(received.chunks);
  const end = joined.indexOf("\r\n\r\n");
  return end === -1 ? joined.toString("latin1") : joined.subarray(0, end + 4).toString("latin1");
}

/** Everything after the response terminator, which is where relayed tunnel bytes begin. */
function tunnelBody(received: Collected): Buffer {
  const joined = Buffer.concat(received.chunks);
  const end = joined.indexOf("\r\n\r\n");
  return end === -1 ? Buffer.alloc(0) : joined.subarray(end + 4);
}

interface ProxyClient {
  socket: Socket;
  received: Collected;
  /** Resolves on a FIN or a reset: both mean the proxy is done with this connection. */
  closed: Promise<void>;
}

interface ProxiedResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

describe("forward proxy", () => {
  const servers: Array<NetServer | HttpServer> = [];
  const sockets: Socket[] = [];
  const children: ChildProcess[] = [];
  let records: ProxyRecord[];
  let events: ProxyEvent[];
  let errors: Array<{ err: Error; context: string }>;
  let rejections: unknown[];
  let gates: Array<{ ready: () => boolean; settle: () => void }>;
  let upstream: NetServer;
  let upstreamPort: number;
  let upstreamSockets: Socket[];
  let upstreamReceived: Collected[];
  let upstreamEnded: number;
  let upstreamConnections: number;
  let onRejection: (reason: unknown) => void;

  function track<T extends NetServer | HttpServer>(server: T): T {
    servers.push(server);
    return server;
  }

  // Executor form throughout. `Promise.withResolvers` reads better but is ES2024, and this
  // project compiles against lib ES2022, so the type does not exist here. None of these
  // helpers carries a timeout of its own: something that never arrives fails through Jest's
  // deadline rather than through a duration of ours that would go stale.
  function listening(server: NetServer | HttpServer): Promise<number> {
    return new Promise((resolve, reject) => {
      server.once("error", reject);
      if (server.listening) {
        resolve((server.address() as AddressInfo).port);
        return;
      }
      server.once("listening", () => resolve((server.address() as AddressInfo).port));
    });
  }

  /**
   * Wait for a condition that a socket event will make true. Registered, never polled:
   * `pump()` runs from the handlers that change the state, so a wait ends on the byte or the
   * close that satisfies it, and a genuine hang fails at Jest's deadline.
   */
  function until(ready: () => boolean): Promise<void> {
    if (ready()) return Promise.resolve();
    return new Promise((resolve) => {
      gates.push({ ready, settle: resolve });
    });
  }

  function pump(): void {
    gates = gates.filter((gate) => {
      if (!gate.ready()) return true;
      gate.settle();
      return false;
    });
  }

  /** A tick barrier, for asserting that something did not happen. Not a duration. */
  async function settle(): Promise<void> {
    for (let i = 0; i < 3; i += 1) await new Promise((resolve) => setImmediate(resolve));
  }

  function startProxy(decide: (event: ProxyEvent) => ProxyDecideResult): Promise<number> {
    // Bound to THIS test's arrays rather than read at call time: a connection still open when
    // a test ends files its record while afterEach tears it down, and that would land after
    // the next beforeEach had installed fresh arrays.
    const ownRecords = records;
    const ownEvents = events;
    const ownErrors = errors;
    const proxy = track(
      createForwardProxy({
        port: 0,
        host: "127.0.0.1",
        decide: (event) => {
          ownEvents.push({ ...event, client: { ...event.client } });
          pump();
          return decide(event);
        },
        record: (record) => {
          ownRecords.push(record);
          pump();
        },
        onError: (err, context) => {
          ownErrors.push({ err, context });
          pump();
        },
      })
    );
    return listening(proxy);
  }

  /** Open a client socket to the proxy and collect every byte it writes back. */
  function client(proxyPort: number, options: { localPort?: number } = {}): ProxyClient {
    const received: Collected = { chunks: [], length: 0 };
    const socket = netConnect({
      port: proxyPort,
      host: "127.0.0.1",
      ...(options.localPort ? { localPort: options.localPort, localAddress: "127.0.0.1" } : {}),
    });
    sockets.push(socket);
    socket.on("data", (chunk) => {
      collect(received, chunk);
      pump();
    });
    const closed = new Promise<void>((resolve) => {
      socket.on("error", () => {
        pump();
        resolve();
      });
      socket.on("close", () => {
        pump();
        resolve();
      });
    });
    return { socket, received, closed };
  }

  /** CONNECT through the proxy, optionally pipelining bytes into the same write. */
  async function connectTunnel(
    proxyPort: number,
    authority: string,
    options: { pipelined?: Buffer; localPort?: number } = {}
  ): Promise<ProxyClient> {
    const conn = client(proxyPort, { localPort: options.localPort });
    await new Promise<void>((resolve, reject) => {
      conn.socket.once("connect", () => resolve());
      conn.socket.once("error", reject);
    });
    const request = Buffer.from(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`, "latin1");
    conn.socket.write(options.pipelined ? Buffer.concat([request, options.pipelined]) : request);
    return conn;
  }

  /**
   * Wait for the tunnel to be open before writing into it.
   *
   * The destination accepting is not the same event as the proxy answering: the accept happens
   * on the far side of the connect, so waiting on the accepted socket and then asserting on the
   * 200 races the write that produces it.
   */
  function tunnelOpen(conn: ProxyClient): Promise<void> {
    return until(() => responseHead(conn.received).endsWith("\r\n\r\n"));
  }

  /** One plain HTTP request, in the absolute-URI form a proxy client sends. */
  function proxiedGet(proxyPort: number, url: string, hostHeader?: string): Promise<ProxiedResponse> {
    return new Promise((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port: proxyPort,
          method: "GET",
          path: url,
          agent: false,
          ...(hostHeader ? { headers: { host: hostHeader } } : {}),
        },
        (res) => {
          let body = "";
          res.on("data", (chunk) => (body += chunk));
          res.on("end", () => {
            pump();
            resolve({ status: res.statusCode ?? 0, headers: res.headers, body });
          });
        }
      );
      req.on("error", reject);
      req.end();
    });
  }

  /** A port nothing is listening on, obtained by taking one and giving it straight back. */
  async function closedPort(host = "127.0.0.1"): Promise<number> {
    const probe = createNetServer();
    probe.listen(0, host);
    const port = await listening(probe);
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    return port;
  }

  function acceptUpstream(socket: Socket): void {
    const index = upstreamConnections;
    upstreamConnections += 1;
    upstreamSockets[index] = socket;
    upstreamReceived[index] = { chunks: [], length: 0 };
    socket.on("data", (chunk) => {
      collect(upstreamReceived[index] as Collected, chunk);
      pump();
    });
    socket.on("end", () => {
      upstreamEnded += 1;
      pump();
    });
    // Listened for, not counted: a socket with no 'error' listener throws when the peer resets
    // it, and a reset is the expected end of several of these connections.
    socket.on("error", () => pump());
    pump();
  }

  /**
   * Swap in a destination that tolerates a half-closed peer.
   *
   * A default listener ends its own side as soon as it reads a FIN, which closes the proxy's
   * upstream socket for it and would hide a proxy that never released anything. A destination
   * that keeps a half-closed connection open is where a leak is visible, so the leak tests ask
   * for one explicitly.
   */
  async function useHalfOpenUpstream(): Promise<void> {
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
    upstreamConnections = 0;
    upstream = track(createNetServer({ allowHalfOpen: true }, acceptUpstream));
    upstream.listen(0, "127.0.0.1");
    upstreamPort = await listening(upstream);
  }

  beforeEach(async () => {
    records = [];
    events = [];
    errors = [];
    rejections = [];
    gates = [];
    upstreamSockets = [];
    upstreamReceived = [];
    upstreamEnded = 0;
    upstreamConnections = 0;
    resetLockdown();
    setEgressPolicy({ hosts: [], ports: [] });
    onRejection = (reason: unknown) => {
      rejections.push(reason);
      pump();
    };
    // The proxy wraps its CONNECT handler in a catch because Node exits on an unhandled
    // rejection and this process is the single egress path for every agent on the box. That
    // guarantee is worth something only if something checks it.
    process.on("unhandledRejection", onRejection);
    upstream = track(createNetServer(acceptUpstream));
    upstream.listen(0, "127.0.0.1");
    upstreamPort = await listening(upstream);
  });

  afterEach(async () => {
    process.off("unhandledRejection", onRejection);
    mockProcNetTcp = null;
    jest.restoreAllMocks();
    resetLockdown();
    setEgressPolicy({ hosts: [], ports: [] });
    for (const socket of sockets.splice(0)) socket.destroy();
    for (const socket of upstreamSockets.splice(0)) socket?.destroy();
    for (const child of children.splice(0)) child.kill("SIGKILL");
    await Promise.all(
      servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve())))
    );
  });

  describe("CONNECT tunnel", () => {
    it("relays bytes in both directions and files one record with exact counts", async () => {
      const proxyPort = await startProxy(() => "allow");
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`);
      await tunnelOpen(conn);
      await until(() => upstreamConnections > 0);

      // Asymmetric payloads on purpose: equal lengths would let transposed counters pass.
      const up = Buffer.from("client-to-destination", "latin1");
      const down = Buffer.from("destination-to-client-and-then-some", "latin1");
      conn.socket.write(up);
      await until(() => (upstreamReceived[0] as Collected).length >= up.length);
      (upstreamSockets[0] as Socket).write(down);
      await until(() => tunnelBody(conn.received).length >= down.length);

      expect(responseHead(conn.received)).toBe("HTTP/1.1 200 Connection Established\r\n\r\n");
      expect(digest(Buffer.concat((upstreamReceived[0] as Collected).chunks))).toBe(digest(up));
      expect(digest(tunnelBody(conn.received))).toBe(digest(down));

      conn.socket.end();
      await conn.closed;
      await until(() => records.length > 0);

      expect(records).toHaveLength(1);
      const record = records[0] as ProxyRecord;
      expect(record.decision).toBe("allow");
      expect(record.host).toBe("127.0.0.1");
      expect(record.port).toBe(upstreamPort);
      expect(record.scheme).toBe("https");
      expect(record.method).toBe("CONNECT");
      expect(record.bytesUp).toBe(up.length);
      expect(record.bytesDown).toBe(down.length);
      expect(record.durationMs).toBeGreaterThanOrEqual(0);
      expect(rejections).toEqual([]);
    });

    it("counts the bytes a client pipelined with the CONNECT request", async () => {
      // A client may send its first record in the same segment as the CONNECT, and Node hands
      // those bytes to the handler as `head` rather than as socket data. They are relayed
      // either way, so the only place their absence shows is the ledger. Bytes that reach the
      // destination and appear in no record are exactly the evidence gap an agent would pick
      // on purpose.
      const proxyPort = await startProxy(() => "allow");
      const pipelined = randomBytes(4096);
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`, { pipelined });
      await until(() => upstreamConnections > 0);
      await tunnelOpen(conn);
      await until(() => (upstreamReceived[0] as Collected).length >= pipelined.length);

      expect(digest(Buffer.concat((upstreamReceived[0] as Collected).chunks))).toBe(digest(pipelined));

      conn.socket.end();
      await conn.closed;
      await until(() => records.length > 0);

      expect((records[0] as ProxyRecord).bytesUp).toBe(pipelined.length);
    });

    it("reads the destination out of a CONNECT authority without dialling it", async () => {
      // Both branches of the authority parser, observed where it matters: on the event the
      // decision is taken from. An IPv6 literal is full of colons, so a naive split on the
      // first or the last one either loses the address or keeps the brackets and dials a host
      // that cannot resolve. The port-less form has to reach 443, since that is the number the
      // port allowlist will be compared against.
      const proxyPort = await startProxy(() => "deny");

      const six = await connectTunnel(proxyPort, "[::1]:8443");
      await six.closed;
      const bare = await connectTunnel(proxyPort, "example.internal");
      await bare.closed;
      await until(() => events.length === 2);

      expect(events[0]).toMatchObject({ host: "::1", port: 8443 });
      expect(events[1]).toMatchObject({ host: "example.internal", port: 443 });
      expect(upstreamConnections).toBe(0);
    });

    it("never decides on a host containing a CR or an LF", async () => {
      // Downstream slices are relying on this, so it is measured here rather than reasoned
      // about. The authority is unvalidated, and a host string that could carry a newline would
      // be a live injection into anything that later writes it into a line-oriented format: a
      // log, an argv, or the openssl config file that a leaf certificate's SAN has to go
      // through, where a newline appends a directive.
      //
      // The guarantee holds, but by two different mechanisms and NOT the one that reads as
      // obvious. A bare CR is refused by the parser outright, as are NUL, space, tab and
      // backslash, and no decision is taken at all. A bare LF is ACCEPTED: it terminates the
      // request line, so the authority is truncated at it and the remainder is parsed as a
      // header, which happens to be syntactically valid. Either way no newline survives into
      // the host, which is the property that matters, and it is worth knowing that the LF case
      // reaches a decision on a SHORTER host rather than being rejected.
      //
      // Percent-encoding is not a way back in, because nothing decodes the authority.
      const refused = [
        "exam\rple.internal:443",
        "exam\u0000ple.internal:443",
        "exam ple.internal:443",
        "exam\tple.internal:443",
        "exam\\ple.internal:443",
      ];
      // Measured, not assumed: a slash and the sub-delims DO reach the decision verbatim, so a
      // consumer that builds a path or a filename from a host has to refuse them itself.
      const reaching: Array<[string, string]> = [
        ["exam\nple.internal:443", "exam"],
        ["exam\r\nple.internal:443", "exam"],
        ["example.internal/path:443", "example.internal/path"],
        ["a=b;c.internal:443", "a=b;c.internal"],
        // Both parse branches, because they build the host separately: with a port, and without
        // one where the whole authority is the host. Mutation testing found the second
        // uncovered, and a decode added to either is the plausible way a newline gets in.
        ["exam%0d%0aple.internal:443", "exam%0d%0aple.internal"],
        ["exam%0d%0aple.internal", "exam%0d%0aple.internal"],
      ];
      const proxyPort = await startProxy(() => "deny");

      // Counted by delta rather than by clearing `events`. The proxy holds a reference to the
      // array it was started with, so reassigning the binding here would leave it pushing into
      // the old one and every count below would read zero.
      for (const authority of refused) {
        const before = events.length;
        const conn = client(proxyPort);
        await new Promise<void>((resolve, reject) => {
          conn.socket.once("connect", () => resolve());
          conn.socket.once("error", reject);
        });
        conn.socket.write(Buffer.from(`CONNECT ${authority} HTTP/1.1\r\nHost: h\r\n\r\n`, "latin1"));
        await conn.closed;
        // A request line the parser refuses never becomes an egress decision. Node answers it
        // with its own 400 and destroys the socket, which is its business rather than the proxy's.
        expect(events).toHaveLength(before);
        expect(responseHead(conn.received)).not.toContain("200 Connection Established");
      }

      for (const [authority, host] of reaching) {
        const before = events.length;
        const conn = client(proxyPort);
        await new Promise<void>((resolve, reject) => {
          conn.socket.once("connect", () => resolve());
          conn.socket.once("error", reject);
        });
        conn.socket.write(Buffer.from(`CONNECT ${authority} HTTP/1.1\r\nHost: h\r\n\r\n`, "latin1"));
        await conn.closed;
        expect(events).toHaveLength(before + 1);
        expect((events[before] as ProxyEvent).host).toBe(host);
      }

      // The property the whole test exists for, asserted once over everything that got through.
      for (const event of events) {
        expect(event.host).not.toMatch(/[\r\n]/);
      }

      expect(upstreamConnections).toBe(0);
    });

    it("relays a multi-megabyte transfer byte for byte while the peer stalls", async () => {
      // The bug this defends against is a relay that ignores a full write buffer. Bytes get
      // dropped, doubled or reordered only once a peer stops reading, which never happens in a
      // test that moves a few hundred bytes, so each direction here is stalled deliberately
      // and the transfer is larger than every kernel and stream buffer in the chain put
      // together (this kernel caps a socket at 4M send and 6M receive, and there are three
      // sockets between the two endpoints).
      //
      // The stall is asserted, not assumed: if the write completed while the peer was paused,
      // the proxy had buffered the whole transfer in memory instead of applying backpressure,
      // and the digest below would say nothing about backpressure at all.
      const proxyPort = await startProxy(() => "allow");
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`);
      await tunnelOpen(conn);
      await until(() => upstreamConnections > 0);
      const destination = upstreamSockets[0] as Socket;

      const up = randomBytes(32 * 1024 * 1024);
      destination.pause();
      let upFlushed = false;
      conn.socket.write(up, () => {
        upFlushed = true;
        pump();
      });
      await settle();
      expect(upFlushed).toBe(false);
      destination.resume();
      await until(() => upFlushed && (upstreamReceived[0] as Collected).length >= up.length);
      expect(digest(Buffer.concat((upstreamReceived[0] as Collected).chunks))).toBe(digest(up));

      // The response head is already in the accumulator, so the down direction is complete when
      // that many more bytes have arrived. Counted rather than sliced: joining the chunks to
      // measure them would run once per delivered chunk and make the wait quadratic, which
      // reads as a slow proxy rather than as a slow test.
      const headBytes = conn.received.length;
      const down = randomBytes(32 * 1024 * 1024);
      conn.socket.pause();
      let downFlushed = false;
      destination.write(down, () => {
        downFlushed = true;
        pump();
      });
      await settle();
      expect(downFlushed).toBe(false);
      conn.socket.resume();
      await until(() => downFlushed && conn.received.length >= headBytes + down.length);
      expect(digest(tunnelBody(conn.received))).toBe(digest(down));

      conn.socket.end();
      await conn.closed;
      await until(() => records.length > 0);
      const record = records[0] as ProxyRecord;
      expect(record.bytesUp).toBe(up.length);
      expect(record.bytesDown).toBe(down.length);
      expect(rejections).toEqual([]);
    }, 60000);
  });

  describe("client goes away mid-tunnel", () => {
    /**
     * The socket descriptors this process holds, by socket identity.
     *
     * This is the assertion these two tests exist for, and it is the only observable that
     * separates a released connection from a leaked one. A FIN reaching the destination proves
     * nothing: the proxy's pipe forwards the client's FIN whether or not it then releases
     * anything, and a destination that allows half-open keeps its own socket after reading one.
     * Asking the destination to write is not much better, because the reset that answers a
     * released socket arrives a round trip after the write that provokes it. The descriptor
     * table needs no round trip: either the proxy closed its sockets or it did not.
     *
     * The proxy runs in this process, so its descriptors are these descriptors. Identities
     * rather than a count, because Jest reuses a worker process across test files and an
     * unrelated socket closing mid-test would move a count. A socket that was never in the set
     * this tunnel opened cannot move a difference of that set.
     */
    function socketLinks(): Set<string> {
      const links = new Set<string>();
      for (const fd of nodeFs.readdirSync("/proc/self/fd")) {
        try {
          const link = nodeFs.readlinkSync(`/proc/self/fd/${fd}`);
          if (link.startsWith("socket:[")) links.add(link);
        } catch {
          /* the descriptor closed while the table was being read, so it is not one of ours */
        }
      }
      return links;
    }

    it("releases both sockets and records the attempt when the client hangs up", async () => {
      // A hard destroy from the client, which is what a process that exited leaves behind.
      await useHalfOpenUpstream();
      const proxyPort = await startProxy(() => "allow");
      const before = socketLinks();
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`);
      await tunnelOpen(conn);
      await until(() => upstreamConnections > 0);
      conn.socket.write(Buffer.from("half a request", "latin1"));
      await until(() => (upstreamReceived[0] as Collected).length > 0);

      // Four sockets stand between the two endpoints: this client, the proxy's accepted client
      // socket, the proxy's socket to the destination, and the destination's accepted socket.
      // Asserted so that the difference below is known to be able to see them.
      const opened = [...socketLinks()].filter((link) => !before.has(link));
      expect(opened).toHaveLength(4);

      conn.socket.destroy();
      await until(() => records.length > 0);
      await settle();

      // One of the four survives, and it is the destination stub's own accepted socket, which
      // this test holds rather than the proxy. Before the proxy released anything this was three
      // survivors: two descriptors and one live connection out of the box per abandoned request,
      // with nothing recorded, and an agent can abandon connections as fast as it opens them.
      const survivors = socketLinks();
      expect(opened.filter((link) => survivors.has(link))).toHaveLength(1);
      expect(records).toHaveLength(1);
      expect(rejections).toEqual([]);
    });

    it("releases both sockets and records the attempt when the client half-closes", async () => {
      // A FIN rather than a reset, which is what a client that finished writing sends. Nothing
      // errors on this path, and the socket an http.Server hands over allows half-open, so a
      // proxy that cleans up only from its error handler holds both descriptors for as long as
      // the destination tolerates a half-closed peer, which is to say indefinitely, and files
      // no record at all.
      await useHalfOpenUpstream();
      const proxyPort = await startProxy(() => "allow");
      const before = socketLinks();
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`);
      await tunnelOpen(conn);
      await until(() => upstreamConnections > 0);
      conn.socket.write(Buffer.from("a whole request", "latin1"));
      await until(() => (upstreamReceived[0] as Collected).length > 0);
      const opened = [...socketLinks()].filter((link) => !before.has(link));
      expect(opened).toHaveLength(4);

      conn.socket.end();
      await until(() => upstreamEnded > 0);
      await until(() => records.length > 0);
      await settle();

      const survivors = socketLinks();
      expect(opened.filter((link) => survivors.has(link))).toHaveLength(1);
      expect(records).toHaveLength(1);
      expect((records[0] as ProxyRecord).bytesUp).toBe("a whole request".length);
      expect(rejections).toEqual([]);
    });
  });

  describe("destination failures", () => {
    it("fails a CONNECT promptly and names the destination when the connect is refused", async () => {
      const proxyPort = await startProxy(() => "allow");
      const dead = await closedPort();
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${dead}`);

      // The contract is that the client is released rather than left waiting on a tunnel that
      // will never open. `closed` resolves on a FIN or a reset.
      await conn.closed;
      await until(() => records.length > 0);

      expect(responseHead(conn.received)).not.toContain("200 Connection Established");
      expect(errors.map((entry) => entry.context)).toContain(`upstream 127.0.0.1:${dead}`);
      expect(records).toHaveLength(1);
      const record = records[0] as ProxyRecord;
      expect(record.port).toBe(dead);
      expect(record.bytesUp).toBe(0);
      expect(record.bytesDown).toBe(0);
      expect(rejections).toEqual([]);
    });

    it("answers 502 on the HTTP path when the destination refuses the connection", async () => {
      const proxyPort = await startProxy(() => "allow");
      const dead = await closedPort();

      const response = await proxiedGet(proxyPort, `http://127.0.0.1:${dead}/data`);

      expect(response.status).toBe(502);
      expect(errors.map((entry) => entry.context)).toContain(`upstream 127.0.0.1:${dead}`);
      await until(() => records.length > 0);
      expect(records).toHaveLength(1);
      expect(rejections).toEqual([]);
    });

    it("releases the destination connection and records the attempt when an HTTP client aborts", async () => {
      // A destination that accepts and then says nothing is the case the proxy cannot resolve
      // on its own: it sets no deadline, so the client's own timeout is what ends the wait.
      // When that happens the proxy owes two things that only it can do: drop the connection
      // to the destination, and file the attempt. Otherwise every agent-side timeout leaves a
      // live connection out of the box that the ledger has no record of, and an agent can open
      // those as fast as it can time them out.
      //
      // Worth knowing what this defect looks like from the outside, because it does not look
      // like a leak. Against a source without the fix, this suite runs to completion and then
      // Jest cannot exit, because the connection the proxy is still holding keeps the stalling
      // server's close() from returning. It cost 900 seconds here on the first run. A second
      // agent working the same file hit the identical hang twice on their own branch before
      // either of us connected the two, and read it as socket-heavy tests being slow, which is
      // the reading that lets a leak like this live for months. A suite that hangs after the
      // last assertion is a resource nobody released, not a slow test.
      const stalling = track(createHttpServer(() => { /* headers are never sent */ }));
      let stallingSockets = 0;
      let stallingClosed = 0;
      stalling.on("connection", (socket) => {
        stallingSockets += 1;
        socket.on("close", () => {
          stallingClosed += 1;
          pump();
        });
        pump();
      });
      stalling.listen(0, "127.0.0.1");
      const stallingPort = await listening(stalling);

      const proxyPort = await startProxy(() => "allow");
      const req = httpRequest({
        host: "127.0.0.1",
        port: proxyPort,
        method: "GET",
        path: `http://127.0.0.1:${stallingPort}/hang`,
        agent: false,
      });
      req.on("error", () => pump());
      req.end();
      await until(() => stallingSockets > 0);

      req.destroy();
      await until(() => stallingClosed > 0);
      await until(() => records.length > 0);
      await settle();

      expect(stallingClosed).toBe(1);
      expect(records).toHaveLength(1);
      expect((records[0] as ProxyRecord).port).toBe(stallingPort);
      expect(rejections).toEqual([]);
    });

    it("rejects a request that is not in absolute-URI form", async () => {
      const proxyPort = await startProxy(() => "allow");

      const response = await proxiedGet(proxyPort, "/not-absolute");

      expect(response.status).toBe(400);
      expect(response.body).toContain("absolute-URI required");
      // Nothing was decided and nothing was opened. An unusable request line is not an egress
      // attempt, and recording it as one would put noise in the ledger.
      expect(events).toEqual([]);
      expect(records).toEqual([]);
      expect(upstreamConnections).toBe(0);
    });
  });

  describe("process attribution", () => {
    it("names the process that opened the connection", async () => {
      // The positive control for everything below. Per-process attribution with no harness
      // cooperation is the reason this proxy reads /proc at all, and nothing tested it.
      const proxyPort = await startProxy(() => "allow");
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`);
      await until(() => events.length > 0);

      expect((events[0] as ProxyEvent).client.pid).toBe(process.pid);
      expect((events[0] as ProxyEvent).client.comm).toBe(
        nodeFs.readFileSync("/proc/self/comm", "utf8").trim()
      );
      conn.socket.destroy();
    }, 30000);

    it("does not name a process that merely shares the client's local port number", async () => {
      // The misattribution case, and it is not hypothetical. /proc/net/tcp lists LISTENING
      // sockets before established ones, so when any process on the box listens on an address
      // whose port equals this client's ephemeral source port, a match on the port alone finds
      // that listener first and the ledger names the process that owns it. Ephemeral ports and
      // service ports come out of the same 16 bits, so the collision arrives on its own.
      //
      // A wrong pid is worse than no pid. An operator reading the ledger sees a named process
      // that never made the call, and the one that did is invisible.
      const decoyPort = await closedPort("127.0.0.2");
      const child = spawn(
        process.execPath,
        [
          "-e",
          "const net=require('net');const s=net.createServer(()=>{});" +
            "s.listen(Number(process.argv[1]),'127.0.0.2',()=>process.stdout.write('ready\\n'));",
          String(decoyPort),
        ],
        { stdio: ["ignore", "pipe", "ignore"] }
      );
      children.push(child);
      await new Promise<void>((resolve, reject) => {
        child.stdout?.on("data", (chunk: Buffer) => {
          if (chunk.toString().includes("ready")) resolve();
        });
        child.once("exit", (code) => reject(new Error(`decoy listener exited early: ${String(code)}`)));
      });

      const proxyPort = await startProxy(() => "allow");
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`, { localPort: decoyPort });
      await until(() => events.length > 0);

      // Naming this process is the right answer, since this process opened the socket.
      // Declining to name anything is also honest. Naming the decoy is neither.
      expect((events[0] as ProxyEvent).client.pid).not.toBe(child.pid);
      expect([process.pid, null]).toContain((events[0] as ProxyEvent).client.pid);
      conn.socket.destroy();
    }, 30000);

    it("names nothing when two connections match both ends of the client's", async () => {
      // Two rows can carry the same pair of ports as long as an address differs, and this
      // function does not compare addresses, so a second candidate means it cannot tell which
      // socket it was asked about. It names nothing rather than taking whichever row came first,
      // because the row that comes first is not the row that asked.
      //
      // If a later version compares the addresses too, it will be able to tell these apart, and
      // then this test should assert this process rather than null. What must not change is that
      // a guess is never recorded as a fact.
      const proxyPort = await startProxy(() => "allow");
      // Same port as the proxy on a different loopback address, which the kernel allows, and a
      // connection to it from the source port the real client is about to use.
      const twin = track(createNetServer((socket) => sockets.push(socket)));
      twin.listen(proxyPort, "127.0.0.3");
      await listening(twin);
      const sharedPort = await closedPort("127.0.0.2");
      const collider = netConnect({
        port: proxyPort,
        host: "127.0.0.3",
        localAddress: "127.0.0.2",
        localPort: sharedPort,
      });
      sockets.push(collider);
      await new Promise<void>((resolve, reject) => {
        collider.once("connect", () => resolve());
        collider.once("error", reject);
      });

      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`, { localPort: sharedPort });
      await until(() => events.length > 0);

      expect((events[0] as ProxyEvent).client).toEqual({ pid: null, comm: null, uid: null });
      conn.socket.destroy();
    }, 30000);

    it("degrades to unattributed when the socket is not in /proc/net/tcp", async () => {
      // The race the source promises to survive: by the time the table is read, the row can be
      // gone. This table is a real table with real columns and no row for this connection, plus
      // two lines that are not rows at all, because a parser that throws on a short line takes
      // the whole proxy down rather than one attribution.
      const table = [
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 ffff 100 0 0 10 0",
        "   1: truncated",
        "",
      ].join("\n");
      mockProcNetTcp = table;

      const proxyPort = await startProxy(() => "allow");
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`);
      await tunnelOpen(conn);

      expect((events[0] as ProxyEvent).client).toEqual({ pid: null, comm: null, uid: null });
      // Attribution failing must never cost egress: the decision still ran and the tunnel
      // still opened. That is what makes it safe for attribution to stay best-effort.
      expect(responseHead(conn.received)).toBe("HTTP/1.1 200 Connection Established\r\n\r\n");
      expect(rejections).toEqual([]);
      conn.socket.destroy();
    });

    it("degrades to unattributed when /proc cannot be read at all", async () => {
      const denied = new Error("EACCES: permission denied, open '/proc/net/tcp'") as NodeJS.ErrnoException;
      denied.code = "EACCES";
      mockProcNetTcp = denied;

      const proxyPort = await startProxy(() => "allow");
      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`);
      await tunnelOpen(conn);

      expect((events[0] as ProxyEvent).client).toEqual({ pid: null, comm: null, uid: null });
      expect(responseHead(conn.received)).toBe("HTTP/1.1 200 Connection Established\r\n\r\n");
      expect(rejections).toEqual([]);
      conn.socket.destroy();
    });

    it("attributes the HTTP path as well as the tunnel", async () => {
      const origin = track(
        createHttpServer((_req, res) => {
          res.writeHead(200, { "content-type": "text/plain" }).end("ok\n");
        })
      );
      origin.listen(0, "127.0.0.1");
      const originPort = await listening(origin);
      const proxyPort = await startProxy(() => "allow");

      const response = await proxiedGet(proxyPort, `http://127.0.0.1:${originPort}/thing`);

      expect(response.status).toBe(200);
      expect((events[0] as ProxyEvent).client.pid).toBe(process.pid);
      expect((events[0] as ProxyEvent).method).toBe("GET");
      expect((events[0] as ProxyEvent).scheme).toBe("http");
    }, 30000);
  });

  describe("policy binding", () => {
    /** The proxy as index.ts wires it: the real decision function, not a stub. */
    function policyDecide(mode: "guarded" | "strict", engine: PolicyEngine) {
      return (event: ProxyEvent): ProxyDecideResult => {
        const verdict = decideEgress(
          {
            host: event.host,
            port: event.port,
            scheme: event.scheme,
            method: event.method,
            comm: event.client.comm,
            pid: event.client.pid,
          },
          mode,
          engine
        );
        return {
          decision: verdict.decision === "allow" ? "allow" : "deny",
          reasons: verdict.reasons,
          matchedRules: verdict.matchedRules,
          riskLevel: verdict.riskLevel,
        };
      };
    }

    it("blocks a guarded CONNECT with a reason header and opens nothing", async () => {
      const proxyPort = await startProxy(policyDecide("guarded", new PolicyEngine()));

      const conn = await connectTunnel(proxyPort, "10.1.2.3:443");
      await conn.closed;
      await until(() => records.length > 0);

      const response = responseHead(conn.received);
      const record = records[0] as ProxyRecord;
      expect(response.startsWith("HTTP/1.1 403 Forbidden\r\n")).toBe(true);
      expect(record.decision).toBe("deny");
      expect(record.matchedRules).toContain("net:block-ssrf-private");
      // The header carries the verdict's own first reason rather than a sentence invented on
      // the socket path: the developer reading the header and the operator reading the ledger
      // have to be looking at the same finding.
      expect(response).toContain(`X-Agentwall-Block-Reason: ${record.reasons[0] as string}\r\n`);
      expect(record.reasons[0]).toContain("private");
      expect(upstreamConnections).toBe(0);
    });

    it("blocks a guarded HTTP request with a reason header and opens nothing", async () => {
      const proxyPort = await startProxy(policyDecide("guarded", new PolicyEngine()));

      const response = await proxiedGet(proxyPort, "http://10.1.2.3/admin");

      expect(response.status).toBe(403);
      await until(() => records.length > 0);
      const record = records[0] as ProxyRecord;
      expect(response.headers["x-agentwall-block-reason"]).toBe(record.reasons[0]);
      expect(record.decision).toBe("deny");
      expect(record.matchedRules).toContain("net:block-ssrf-private");
      // The same claim the source makes for CONNECT, checked on this path too: a denial costs
      // the destination nothing, not even a handshake it could log.
      expect(upstreamConnections).toBe(0);
    });

    it("blocks a strict CONNECT to a host that is not on the allowlist", async () => {
      setEgressPolicy({ hosts: ["127.0.0.1"], ports: [upstreamPort] });
      const proxyPort = await startProxy(policyDecide("strict", new PolicyEngine([])));

      const conn = await connectTunnel(proxyPort, "api.example.com:443");
      await conn.closed;
      await until(() => records.length > 0);

      expect(responseHead(conn.received)).toContain("HTTP/1.1 403 Forbidden");
      expect((records[0] as ProxyRecord).matchedRules).toContain("net:deny-egress-not-allowlisted");
      expect(upstreamConnections).toBe(0);
    });

    it("fails closed on a hostile CONNECT authority and keeps the block reason bounded", async () => {
      // The authority parser validates nothing: no charset allowlist and no length cap, unlike
      // extractHttpHost on the transparent side. That is safe only because of what happens
      // downstream, so this pins the two places it has to hold. Strict mode refuses an authority
      // it cannot match, and the reason that reaches the client's headers is bounded and
      // flattened, even though it is built from a string the agent chose and is 2000 characters
      // long here. No CR and no LF can reach that string, which the test above measures rather
      // than assumes, so length and charset are the vector and both are covered here.
      const hostile = `${"a".repeat(2000)}!$&'()*+,;=`;
      setEgressPolicy({ hosts: ["127.0.0.1"], ports: [upstreamPort] });
      const proxyPort = await startProxy(policyDecide("strict", new PolicyEngine([])));

      const conn = await connectTunnel(proxyPort, hostile);
      await conn.closed;
      await until(() => records.length > 0);

      const response = responseHead(conn.received);
      const reason = /X-Agentwall-Block-Reason: (.*)\r\n/.exec(response)?.[1] ?? "";
      const record = records[0] as ProxyRecord;
      expect(response.startsWith("HTTP/1.1 403 Forbidden\r\n")).toBe(true);
      // One header terminator, at the very end: the client received one response and nothing
      // after it.
      expect(response.indexOf("\r\n\r\n")).toBe(response.length - 4);
      expect(reason.length).toBeLessThanOrEqual(200);
      expect(reason.endsWith("...")).toBe(true);
      // The ledger keeps the authority whole, where it is JSON-encoded rather than interpolated.
      expect(record.host).toBe(hostile);
      expect(record.port).toBe(443);
      expect(record.decision).toBe("deny");
      expect(upstreamConnections).toBe(0);
      expect(rejections).toEqual([]);
    });

    it("gates the port on the CONNECT path, not just the host", async () => {
      // The regression. `egress.allowedPorts` read as a control and enforced nothing on the
      // proxy path: with the host allowlisted and the port allowlist set to 443, a CONNECT to
      // port 80 on that host was opened and served. Host and port are one destination.
      const otherPort = await closedPort();
      setEgressPolicy({ hosts: ["127.0.0.1"], ports: [upstreamPort] });
      const proxyPort = await startProxy(policyDecide("strict", new PolicyEngine([])));

      const conn = await connectTunnel(proxyPort, `127.0.0.1:${otherPort}`);
      await conn.closed;
      await until(() => records.length > 0);

      const record = records[0] as ProxyRecord;
      expect(responseHead(conn.received)).toContain("HTTP/1.1 403 Forbidden");
      expect(record.decision).toBe("deny");
      expect(record.matchedRules).toContain("net:deny-egress-port-not-allowlisted");
      expect(record.reasons.some((reason) => reason.includes(`port ${otherPort}`))).toBe(true);
      expect(upstreamConnections).toBe(0);
    });

    it("gates the port on the HTTP path, including the port the request never spells out", async () => {
      // The reported shape exactly: an authority carrying :80 against an allowlist of 443. The
      // proxy takes the port from the request line, so the case worth pinning is the one where
      // nobody wrote a port at all and the default still has to be gated.
      setEgressPolicy({ hosts: ["127.0.0.1"], ports: [upstreamPort] });
      const proxyPort = await startProxy(policyDecide("strict", new PolicyEngine([])));

      const response = await proxiedGet(proxyPort, "http://127.0.0.1/data", "127.0.0.1:80");

      expect(response.status).toBe(403);
      await until(() => records.length > 0);
      const record = records[0] as ProxyRecord;
      expect(record.port).toBe(80);
      expect(record.matchedRules).toContain("net:deny-egress-port-not-allowlisted");
      expect(record.reasons.some((reason) => reason.includes("port 80"))).toBe(true);
      expect(upstreamConnections).toBe(0);
    });

    it("still allows the allowlisted host on the allowlisted port", async () => {
      // The control for all four denials above. A proxy that denied everything would pass
      // every one of them.
      setEgressPolicy({ hosts: ["127.0.0.1"], ports: [upstreamPort] });
      const proxyPort = await startProxy(policyDecide("strict", new PolicyEngine([])));

      const conn = await connectTunnel(proxyPort, `127.0.0.1:${upstreamPort}`);
      await tunnelOpen(conn);
      await until(() => upstreamConnections > 0);

      expect(responseHead(conn.received)).toBe("HTTP/1.1 200 Connection Established\r\n\r\n");
      expect(upstreamConnections).toBe(1);
      conn.socket.destroy();
    });
  });
});
