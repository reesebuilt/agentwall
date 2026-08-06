import { afterEach, describe, expect, it } from "@jest/globals";
import { connect as netConnect, createServer as createNetServer, Socket } from "net";
import type { AddressInfo, Server as NetServer } from "net";
import { MAX_CLIENT_HELLO_BYTES, extractSni, peekClientHello } from "../src/proxy/tls-peek";
import { createForwardProxy } from "../src/proxy/forward-proxy";
import type { ProxyDecideResult, ProxyEvent, ProxyRecord } from "../src/proxy/forward-proxy";

/**
 * Reading the ClientHello on the CONNECT path.
 *
 * What is under test is NOT interception. Nothing here decrypts anything, and the assertions
 * are deliberately written so that they could not pass if it did: the bytes the client sends
 * must arrive at the upstream stub byte-identical and in order, because the whole hazard of
 * peeking at a stream you are also relaying is consuming bytes to look at them and then never
 * replaying them. That failure reads perfectly at the unit level and produces a tunnel that is
 * allowed and then silently broken, so every end-to-end case below checks the relayed bytes
 * and not just the verdict.
 *
 * The classifier gets its own unit tests because it is the piece that decides how long a
 * connection waits. `extractSni` answers null to a truncated hello and to a hello with no
 * name in it, and those two need opposite handling: one must keep reading, the other must be
 * released immediately or every TLS client that omits SNI eats the peek timeout. A test that
 * only checked "returns null" would not notice the difference.
 *
 * NO SLEEPS. Every wait is an event the code already emits: a record filed, a socket closed,
 * a byte delivered. Executor-form promises throughout, matching the rest of this suite:
 * `Promise.withResolvers` reads better but is ES2024 and this project compiles against
 * lib ES2022.
 */

const EMPTY = Buffer.alloc(0);

const TLS_VERSION = Buffer.from([0x03, 0x03]);
const CIPHER_SUITES = Buffer.from([0x00, 0x02, 0x13, 0x01]);
const COMPRESSION_METHODS = Buffer.from([0x01, 0x00]);

/** One `server_name` extension, with hooks for the malformed variants the parser must survive. */
function sniExtension(
  name: string | Buffer,
  overrides: { nameType?: number; declaredExtensionLength?: number } = {}
): Buffer {
  const nameBytes = Buffer.isBuffer(name) ? name : Buffer.from(name, "latin1");
  const entry = Buffer.alloc(3);
  entry[0] = overrides.nameType ?? 0x00;
  entry.writeUInt16BE(nameBytes.length, 1);
  const list = Buffer.concat([entry, nameBytes]);
  const listHeader = Buffer.alloc(2);
  listHeader.writeUInt16BE(list.length, 0);
  const data = Buffer.concat([listHeader, list]);
  const header = Buffer.alloc(4);
  header.writeUInt16BE(0x0000, 0);
  header.writeUInt16BE(overrides.declaredExtensionLength ?? data.length, 2);
  return Buffer.concat([header, data]);
}

/** A complete TLS record carrying a ClientHello whose extensions block is `extensions`. */
function clientHello(extensions: Buffer): Buffer {
  const extensionsLength = Buffer.alloc(2);
  extensionsLength.writeUInt16BE(extensions.length, 0);
  const body = Buffer.concat([
    TLS_VERSION,
    Buffer.alloc(32, 0xab),
    Buffer.from([0x00]),
    CIPHER_SUITES,
    COMPRESSION_METHODS,
    extensionsLength,
    extensions,
  ]);
  const handshake = Buffer.concat([
    Buffer.from([0x01, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]),
    body,
  ]);
  const record = Buffer.alloc(5);
  record[0] = 0x16;
  record.writeUInt16BE(0x0301, 1);
  record.writeUInt16BE(handshake.length, 3);
  return Buffer.concat([record, handshake]);
}

const helloFor = (name: string): Buffer => clientHello(sniExtension(name));

describe("peekClientHello", () => {
  it("separates a truncated hello from one that simply carries no name", () => {
    // The distinction the whole peek loop is built on. Both give extractSni null.
    const named = helloFor("api.example.com");
    expect(peekClientHello(named)).toEqual({ status: "complete", sni: "api.example.com" });
    expect(peekClientHello(named.subarray(0, named.length - 4))).toEqual({ status: "incomplete" });
    expect(peekClientHello(clientHello(Buffer.alloc(0)))).toEqual({ status: "complete", sni: null });
  });

  it("never reports a name from any prefix of a real hello", () => {
    // Exhaustive over every split point, which is the deterministic form of the fragmentation
    // case: a parser that guessed early would surface a truncated or wrong hostname here, and
    // one that never released would show up as a "complete" that arrived before the last byte.
    const full = helloFor("api.example.com");
    for (let n = 0; n < full.length; n += 1) {
      expect(peekClientHello(full.subarray(0, n))).toEqual({ status: "incomplete" });
    }
    expect(peekClientHello(full)).toEqual({ status: "complete", sni: "api.example.com" });
  });

  it("rules out a handshake on the first byte, before trusting any length", () => {
    expect(peekClientHello(Buffer.from("GET / HTTP/1.1\r\n", "latin1"))).toEqual({ status: "not-tls" });
    // A single non-0x16 byte is already decisive: a plain-TCP tunnel must not buffer toward a
    // handshake that is never coming, and must not wait for four more bytes to say so.
    expect(peekClientHello(Buffer.from([0x47]))).toEqual({ status: "not-tls" });
    expect(peekClientHello(Buffer.alloc(0))).toEqual({ status: "incomplete" });
  });

  it("treats a zero-length record as finished rather than pending", () => {
    // No quantity of further bytes can repair a record that declared itself empty, so
    // reporting "incomplete" would hang the caller until its timeout for nothing.
    const empty = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x00]);
    expect(peekClientHello(empty)).toEqual({ status: "complete", sni: null });
  });

  it("stays pending for a record it does not have all of, up to the protocol maximum", () => {
    // The bound exists so the caller has a stopping condition that no legitimate hello can
    // exceed: a TLS record cannot declare more than 16384 bytes of payload.
    const oversized = Buffer.concat([Buffer.from([0x16, 0x03, 0x01, 0xff, 0xff]), Buffer.alloc(64)]);
    expect(peekClientHello(oversized)).toEqual({ status: "incomplete" });
    expect(MAX_CLIENT_HELLO_BYTES).toBe(5 + 16384);
  });

  it("survives malformed input without throwing and without naming anything", () => {
    const hostile = [
      clientHello(sniExtension("a", { declaredExtensionLength: 0x7fff })),
      clientHello(sniExtension(Buffer.from("exam\u0000ple.com", "latin1"))),
      clientHello(sniExtension("api.example.com", { nameType: 0x02 })),
      clientHello(sniExtension("host name.example.com")),
      clientHello(sniExtension(`${"a".repeat(64)}.example.com`)),
      Buffer.concat([Buffer.from([0x16, 0x03, 0x01, 0x00, 0x08]), Buffer.alloc(8, 0xff)]),
    ];
    for (const buf of hostile) {
      expect(() => peekClientHello(buf)).not.toThrow();
      const result = peekClientHello(buf);
      expect(result.status === "complete" ? result.sni : null).toBeNull();
    }
  });

  it("agrees with extractSni on every complete record", () => {
    // The two must not drift: the peek is a framing decision layered over the same parse, not
    // a second parser with its own opinion about what a name is.
    for (const buf of [helloFor("api.example.com"), clientHello(Buffer.alloc(0))]) {
      const result = peekClientHello(buf);
      expect(result.status === "complete" ? result.sni : "unreachable").toBe(extractSni(buf));
    }
  });
});

/** An upstream that records everything it is handed, and can speak first if asked. */
interface Stub {
  server: NetServer;
  port: number;
  received: () => Buffer;
  sockets: Socket[];
}

function startStub(greeting?: Buffer): Promise<Stub> {
  const chunks: Buffer[] = [];
  const sockets: Socket[] = [];
  const server = createNetServer((socket) => {
    sockets.push(socket);
    socket.on("error", () => {
      /* the proxy tearing a denied tunnel down is not a stub failure */
    });
    socket.on("data", (c) => chunks.push(c));
    if (greeting) socket.write(greeting);
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({
        server,
        port: (server.address() as AddressInfo).port,
        received: () => Buffer.concat(chunks),
        sockets,
      })
    );
  });
}

interface Harness {
  proxy: NetServer;
  port: number;
  events: ProxyEvent[];
  records: ProxyRecord[];
  nextRecord: () => Promise<ProxyRecord>;
}

function startProxy(decide: (e: ProxyEvent) => ProxyDecideResult): Promise<Harness> {
  const events: ProxyEvent[] = [];
  const records: ProxyRecord[] = [];
  let notify: ((r: ProxyRecord) => void) | null = null;
  const proxy = createForwardProxy({
    port: 0,
    host: "127.0.0.1",
    decide: (e) => {
      // Snapshotted, because the proxy mutates the live event object as the peek resolves and
      // a stored reference would show every call the final state instead of its own arguments.
      events.push({ ...e });
      return decide(e);
    },
    record: (r) => {
      records.push(r);
      notify?.(r);
    },
    onError: () => {
      /* upstream teardown during a denial is expected */
    },
  });
  return new Promise((resolve) => {
    proxy.on("listening", () =>
      resolve({
        proxy,
        port: (proxy.address() as AddressInfo).port,
        events,
        records,
        nextRecord: () =>
          new Promise<ProxyRecord>((res) => {
            if (records.length) return res(records[records.length - 1]);
            notify = res;
          }),
      })
    );
  });
}

interface Tunnel {
  socket: Socket;
  status: string;
  /**
   * Whatever arrived in the same read as the status line.
   *
   * Not an oddity to assert away: an upstream that speaks first can have its greeting
   * relayed before the client has read the 200, and on loopback the two land in one segment.
   * Discarding it would lose real tunnel payload, and asserting it is empty would make the
   * server-speaks-first test fail for the exact reason it is supposed to pass.
   */
  leftover: Buffer;
}

/** Open a CONNECT tunnel and resolve once the proxy has answered with its status line. */
function connectTunnel(proxyPort: number, authority: string): Promise<Tunnel> {
  return new Promise((resolve, reject) => {
    const socket = netConnect(proxyPort, "127.0.0.1", () => {
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    });
    socket.on("error", reject);
    let head = EMPTY;
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf("\r\n\r\n", 0, "latin1");
      if (end === -1) return;
      socket.off("data", onData);
      resolve({
        socket,
        status: head.toString("latin1", 0, head.indexOf("\r\n", 0, "latin1")),
        leftover: head.subarray(end + 4),
      });
    };
    socket.on("data", onData);
  });
}

const closed = (socket: Socket): Promise<void> => new Promise((res) => socket.on("close", () => res()));

describe("CONNECT-path ClientHello observation", () => {
  const openStubs: Stub[] = [];
  const openProxies: NetServer[] = [];

  const stub = async (greeting?: Buffer): Promise<Stub> => {
    const s = await startStub(greeting);
    openStubs.push(s);
    return s;
  };
  const proxy = async (decide: (e: ProxyEvent) => ProxyDecideResult): Promise<Harness> => {
    const h = await startProxy(decide);
    openProxies.push(h.proxy);
    return h;
  };

  afterEach(async () => {
    for (const s of openStubs.splice(0)) {
      for (const socket of s.sockets) socket.destroy();
      await new Promise((res) => s.server.close(res));
    }
    for (const p of openProxies.splice(0)) await new Promise((res) => p.close(res));
  });

  it("names the negotiated host and relays the hello byte-identically", async () => {
    const upstream = await stub();
    const harness = await proxy(() => "allow");
    const hello = helloFor("localhost");

    const { socket, status } = await connectTunnel(harness.port, `localhost:${upstream.port}`);
    expect(status).toBe("HTTP/1.1 200 Connection Established");
    socket.end(hello);
    const record = await harness.nextRecord();

    expect(record.sni).toBe("localhost");
    expect(record.sniMismatch).toBeUndefined();
    expect(record.decision).toBe("allow");
    // The peek must not eat what it read. This is the assertion that fails if the buffered
    // hello is never replayed, which is the defect a verdict-only test cannot see.
    expect(upstream.received().equals(hello)).toBe(true);
    expect(record.bytesUp).toBe(hello.length);
  });

  it("flags a CONNECT authority that disagrees with the negotiated name", async () => {
    const upstream = await stub();
    const harness = await proxy(() => "allow");
    const hello = helloFor("evil.example.com");

    const { socket } = await connectTunnel(harness.port, `localhost:${upstream.port}`);
    socket.end(hello);
    const record = await harness.nextRecord();

    expect(record.host).toBe("localhost");
    expect(record.sni).toBe("evil.example.com");
    expect(record.sniMismatch).toBe(true);
    expect(record.matchedRules).toContain("net:sni-connect-mismatch");
    expect(record.reasons[0]).toBe(
      "CONNECT named localhost but the ClientHello negotiated evil.example.com"
    );
    // `decide` is asked a second time, and asked about the better-sourced name.
    expect(harness.events.map((e) => e.host)).toEqual(["localhost", "evil.example.com"]);
    // Still allowed, because `decide` allowed it. The mismatch is evidence, not a verdict.
    expect(record.decision).toBe("allow");
    expect(upstream.received().equals(hello)).toBe(true);
  });

  it("does not flag a mismatch on case alone", async () => {
    const upstream = await stub();
    const harness = await proxy(() => "allow");

    const { socket } = await connectTunnel(harness.port, `LOCALHOST:${upstream.port}`);
    socket.end(helloFor("localhost"));
    const record = await harness.nextRecord();

    expect(record.sni).toBe("localhost");
    expect(record.sniMismatch).toBeUndefined();
    expect(harness.events).toHaveLength(1);
  });

  it("tears the tunnel down when policy refuses the negotiated name", async () => {
    const upstream = await stub();
    // Allowlists the CONNECT authority and refuses what the client actually asked for: a
    // client contradicting itself, which is the whole thing this cross-check can see.
    const harness = await proxy((e) =>
      e.host === "evil.example.com" ? { decision: "deny", reasons: ["host not allowed"] } : "allow"
    );

    const { socket, status } = await connectTunnel(harness.port, `localhost:${upstream.port}`);
    expect(status).toBe("HTTP/1.1 200 Connection Established");
    socket.write(helloFor("evil.example.com"));
    const record = await harness.nextRecord();
    await closed(socket);

    expect(record.decision).toBe("deny");
    expect(record.sniMismatch).toBe(true);
    expect(record.matchedRules).toContain("net:sni-connect-mismatch");
    expect(record.reasons).toContain("host not allowed");
    // The honest limit, asserted rather than described: the destination did get a TCP
    // handshake, because the name arrives after the connection is up. What it must never get
    // is payload, and the hello that triggered the denial dies in the peek buffer.
    expect(upstream.sockets).toHaveLength(1);
    expect(upstream.received()).toHaveLength(0);
  });

  it("cannot turn a CONNECT-level denial into an allow", async () => {
    // The safety property the re-decision rests on. The second opinion runs only after the
    // first said allow, so it is strictly additive: it can refuse what was permitted and can
    // never permit what was refused. A `decide` that denies the CONNECT host and would allow
    // the SNI host must still produce a refused connection with no upstream contact at all.
    const upstream = await stub();
    const harness = await proxy((e) =>
      e.host === "localhost" ? { decision: "deny", reasons: ["host not allowed"] } : "allow"
    );

    const { socket, status } = await connectTunnel(harness.port, `localhost:${upstream.port}`);
    expect(status).toBe("HTTP/1.1 403 Forbidden");
    await closed(socket);
    const record = await harness.nextRecord();

    expect(record.decision).toBe("deny");
    // Never reached the peek, so no second opinion was ever sought.
    expect(harness.events).toHaveLength(1);
    expect(upstream.sockets).toHaveLength(0);
  });

  it("registers an IP-literal CONNECT authority as a disagreement", async () => {
    // Not a false positive, and deliberately not special-cased: an IP literal can never equal
    // an SNI hostname, so this always fires. It is also always true and always worth knowing.
    // A client that dials an address and then negotiates a name has stepped around name-based
    // policy on the CONNECT line, and the re-decision is what puts the name back in front of
    // it. What an operator must not do is read this flag as "someone lied": on this path it
    // means "the CONNECT line carried no name to compare".
    const upstream = await stub();
    const seen: string[] = [];
    const harness = await proxy((e) => {
      seen.push(e.host);
      return "allow";
    });

    const { socket } = await connectTunnel(harness.port, `127.0.0.1:${upstream.port}`);
    socket.end(helloFor("api.example.com"));
    const record = await harness.nextRecord();

    expect(record.host).toBe("127.0.0.1");
    expect(record.sni).toBe("api.example.com");
    expect(record.sniMismatch).toBe(true);
    expect(seen).toEqual(["127.0.0.1", "api.example.com"]);
  });

  it("releases a non-TLS tunnel immediately instead of waiting out the peek", async () => {
    const upstream = await stub();
    const harness = await proxy(() => "allow");
    const payload = Buffer.from("SSH-2.0-OpenSSH_9.6\r\n", "latin1");

    const { socket } = await connectTunnel(harness.port, `localhost:${upstream.port}`);
    const delivered = new Promise<void>((res) => upstream.sockets[0]?.on("data", () => res()));
    socket.write(payload);
    // Resolves only if the first byte released the peek. The peek timeout is 5s and jest's
    // default is 5s, so a held tunnel fails here rather than passing slowly.
    await delivered;
    socket.end();
    const record = await harness.nextRecord();

    expect(record.sni).toBeUndefined();
    expect(record.sniMismatch).toBeUndefined();
    expect(upstream.received().equals(payload)).toBe(true);
  });

  it("does not hold the upstream direction while waiting for a hello", async () => {
    // A server-speaks-first protocol over CONNECT: the client is waiting for the greeting
    // before it says anything, so a peek that gated both directions would deadlock it. The
    // client below sends nothing at all, so the greeting can only arrive if the downstream
    // pipe was attached without waiting on a hello.
    const greeting = Buffer.from("220 mail.example.com ESMTP\r\n", "latin1");
    const upstream = await stub(greeting);
    const harness = await proxy(() => "allow");

    const { socket, leftover } = await connectTunnel(harness.port, `localhost:${upstream.port}`);
    // Usually already here, riding the same segment as the 200. Falling back to one more read
    // rather than requiring either shape keeps the test about the deadlock, not the framing.
    const received = leftover.length
      ? leftover
      : await new Promise<Buffer>((res) => socket.once("data", res));

    expect(received.equals(greeting)).toBe(true);
    socket.destroy();
  });

  it("reassembles a hello split across writes and forwards it in order", async () => {
    const upstream = await stub();
    const harness = await proxy(() => "allow");
    const hello = helloFor("localhost");
    const split = 3; // shorter than the 5-byte record header, so nothing is decidable yet

    const { socket } = await connectTunnel(harness.port, `localhost:${upstream.port}`);
    socket.write(hello.subarray(0, split));
    // Separate event-loop turns, so the two halves are separate writes. TCP may still coalesce
    // them on loopback; the deterministic proof that a prefix is never named early is the
    // exhaustive prefix test above, and what this asserts is the end-to-end outcome.
    await new Promise((res) => setImmediate(res));
    socket.end(hello.subarray(split));
    const record = await harness.nextRecord();

    expect(record.sni).toBe("localhost");
    expect(upstream.received().equals(hello)).toBe(true);
  });

  it("forwards a malformed hello unchanged rather than failing the connection", async () => {
    // Fail open, deliberately: the CONNECT destination was already authorised, so a hello this
    // cannot read leaves that decision exactly as it was. A parser defect must not become an
    // egress outage.
    const upstream = await stub();
    const harness = await proxy(() => "allow");
    const garbage = Buffer.concat([Buffer.from([0x16, 0x03, 0x01, 0x00, 0x08]), Buffer.alloc(8, 0xff)]);

    const { socket } = await connectTunnel(harness.port, `localhost:${upstream.port}`);
    socket.end(garbage);
    const record = await harness.nextRecord();

    expect(record.decision).toBe("allow");
    expect(record.sni).toBeUndefined();
    expect(upstream.received().equals(garbage)).toBe(true);
  });

  it("keeps the CONNECT-level denial free of any upstream contact", async () => {
    // The peek changed the allow path; this pins that it changed nothing about the deny path.
    const upstream = await stub();
    const harness = await proxy(() => ({ decision: "deny", reasons: ["host not allowed"] }));

    const { socket, status } = await connectTunnel(harness.port, `localhost:${upstream.port}`);
    expect(status).toBe("HTTP/1.1 403 Forbidden");
    await closed(socket);
    const record = await harness.nextRecord();

    expect(record.decision).toBe("deny");
    expect(record.sni).toBeUndefined();
    expect(upstream.sockets).toHaveLength(0);
  });
});
