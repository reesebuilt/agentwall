import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { connect as netConnect, createServer as createNetServer, Socket } from "net";
import type { AddressInfo, Server as NetServer } from "net";
import { createTransparentProxy, extractHttpHost, extractSni } from "../src/proxy/transparent";
import type { TransparentAttempt } from "../src/proxy/transparent";
import type { ProxyDecision, ProxyRecord, ProxyVerdict } from "../src/proxy/forward-proxy";

/**
 * The transparent listener, driven over real sockets.
 *
 * The parsers are tested against buffers assembled byte by byte rather than against captures,
 * because the inputs that matter here are the ones no real client sends: a length field that
 * overruns its container, a record cut off mid-extension, a name with a NUL in it. A parser
 * that throws on those is a dead listener, and the kernel redirects traffic at this port with
 * nothing behind it, so "dead listener" means every outbound connection fails at once.
 *
 * The end-to-end tests use a stub upstream rather than a mock, because the failure this class
 * of proxy actually produces is a connection that is allowed and then silently broken: the
 * peeked bytes are consumed to name the destination and never replayed, so the origin waits
 * for a request head that already went past. That reads perfectly at the unit level, and only
 * a listener that would have noticed can catch it.
 *
 * NO SLEEPS AND NO POLLING. Every wait below is an event the code under test already emits —
 * a record filed, a decision taken, a byte delivered, a socket closed. The single duration in
 * the file is the proxy's own `peekTimeoutMs`, injected short, because a deadline is the
 * behaviour that one test asserts.
 *
 * `defaultTlsPort` is injected the same way for the TLS paths. A TLS destination is normally
 * :443, which no unprivileged process can bind and no test here may require root for, so the
 * knob that exists for a perimeter redirecting a non-standard TLS port also lets the stub
 * upstream sit on an ephemeral one.
 */

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

describe("extractSni", () => {
  it("returns the host_name from a well-formed ClientHello", () => {
    expect(extractSni(clientHello(sniExtension("api.example.com")))).toBe("api.example.com");
  });

  it("lower-cases the name so one destination has one spelling", () => {
    expect(extractSni(clientHello(sniExtension("API.Example.COM")))).toBe("api.example.com");
  });

  it("returns null for a truncated record", () => {
    const full = clientHello(sniExtension("api.example.com"));
    expect(extractSni(full.subarray(0, full.length - 4))).toBeNull();
  });

  it("returns null for a non-TLS first byte", () => {
    expect(extractSni(Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "latin1"))).toBeNull();
  });

  it("returns null for a ClientHello with no SNI extension", () => {
    expect(extractSni(clientHello(Buffer.alloc(0)))).toBeNull();
  });

  it("returns null when an extension length overruns the buffer", () => {
    // The extension claims 0x7fff bytes inside an extensions block that holds ten. Skipping
    // past a lie like that would mean parsing whatever follows as the next extension header.
    expect(extractSni(clientHello(sniExtension("a", { declaredExtensionLength: 0x7fff })))).toBeNull();
  });

  it("returns null for a name containing a NUL", () => {
    expect(extractSni(clientHello(sniExtension(Buffer.from("exam\u0000ple.com", "latin1"))))).toBeNull();
  });

  it("returns null for a server_name entry that is not a host_name", () => {
    expect(extractSni(clientHello(sniExtension("api.example.com", { nameType: 0x02 })))).toBeNull();
  });

  it("returns null for names DNS could not carry", () => {
    expect(extractSni(clientHello(sniExtension("api.example.com.")))).toBeNull();
    expect(extractSni(clientHello(sniExtension("api..example.com")))).toBeNull();
    expect(extractSni(clientHello(sniExtension("host name.example.com")))).toBeNull();
    expect(extractSni(clientHello(sniExtension(`${"a".repeat(64)}.example.com`)))).toBeNull();
    expect(extractSni(clientHello(sniExtension("evil.example.com/../x")))).toBeNull();
  });

  it("never throws on any prefix of a valid ClientHello", () => {
    // Every truncation point leaves the cursor in front of a different length field. This is
    // the hostile-first-packet case in bulk: an out-of-range read at any one of them is a
    // crash in the component that has nothing behind it.
    const full = clientHello(sniExtension("api.example.com"));
    for (let length = 0; length < full.length; length += 1) {
      const prefix = full.subarray(0, length);
      expect(() => extractSni(prefix)).not.toThrow();
      expect(extractSni(prefix)).toBeNull();
    }
  });

  it("never throws on noise that begins like a handshake", () => {
    for (let seed = 0; seed < 200; seed += 1) {
      const noise = Buffer.alloc(1 + (seed % 97));
      for (let i = 0; i < noise.length; i += 1) noise[i] = (seed * 31 + i * 17) & 0xff;
      noise[0] = 0x16;
      expect(() => extractSni(noise)).not.toThrow();
    }
  });
});

describe("extractHttpHost", () => {
  it("reads the method and authority from an origin-form request", () => {
    const head = Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "latin1");
    expect(extractHttpHost(head)).toEqual({ host: "example.com", port: 80, method: "GET" });
  });

  it("splits an explicit port off the authority", () => {
    const head = Buffer.from("POST /x HTTP/1.1\r\nHost: example.com:8443\r\n\r\n", "latin1");
    expect(extractHttpHost(head)).toEqual({ host: "example.com", port: 8443, method: "POST" });
  });

  it("finds Host regardless of header casing or position", () => {
    const head = Buffer.from("GET / HTTP/1.1\r\nUser-Agent: x\r\nhOsT:  example.com \r\n\r\n", "latin1");
    expect(extractHttpHost(head)).toEqual({ host: "example.com", port: 80, method: "GET" });
  });

  it("keeps a bracketed IPv6 authority as a bare address", () => {
    const head = Buffer.from("GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", "latin1");
    expect(extractHttpHost(head)).toEqual({ host: "::1", port: 8080, method: "GET" });
  });

  it("returns null for an incomplete head", () => {
    expect(extractHttpHost(Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\n", "latin1"))).toBeNull();
  });

  it("returns null when Host is absent", () => {
    expect(extractHttpHost(Buffer.from("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", "latin1"))).toBeNull();
  });

  it("returns null for a garbage request line", () => {
    expect(extractHttpHost(Buffer.from("\x16\x03\x01 nonsense here\r\nHost: example.com\r\n\r\n", "latin1"))).toBeNull();
    expect(extractHttpHost(Buffer.from("hello\r\nHost: example.com\r\n\r\n", "latin1"))).toBeNull();
    expect(extractHttpHost(Buffer.from("get / HTTP/1.1\r\nHost: example.com\r\n\r\n", "latin1"))).toBeNull();
    // The HTTP/2 prior-knowledge preface. Not routable here, and half-understanding it would
    // be worse than refusing it.
    expect(extractHttpHost(Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "latin1"))).toBeNull();
  });

  it("refuses two Host headers rather than picking one", () => {
    const head = Buffer.from("GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n", "latin1");
    expect(extractHttpHost(head)).toBeNull();
  });

  it("refuses an obs-folded header", () => {
    const head = Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\n\tevil.example.com\r\n\r\n", "latin1");
    expect(extractHttpHost(head)).toBeNull();
  });

  it("refuses an authority that could not be a destination", () => {
    const authorities = [
      "exa mple.com",
      "example.com:0",
      "example.com:99999",
      "example.com:80x",
      "ex\u0000ample.com",
      "example.com/path",
      "[::1",
      "-example.com",
    ];
    for (const authority of authorities) {
      expect(extractHttpHost(Buffer.from(`GET / HTTP/1.1\r\nHost: ${authority}\r\n\r\n`, "latin1"))).toBeNull();
    }
  });
});

describe("transparent proxy", () => {
  const servers: NetServer[] = [];
  const sockets: Socket[] = [];
  let records: ProxyRecord[] = [];
  let attempts: TransparentAttempt[] = [];
  let errors: Error[] = [];
  let gates: Array<{ ready: () => boolean; settle: () => void }> = [];
  let upstream: NetServer;
  let upstreamConnections: number;
  let upstreamPort: number;
  let upstreamReceived: Buffer;
  let upstreamReply: Buffer | null;

  function track<T extends NetServer>(server: T): T {
    servers.push(server);
    return server;
  }

  // Executor form throughout: Promise.withResolvers reads better but is ES2024, and this
  // project compiles against lib ES2022. None of these helpers carry a timeout of their own —
  // something that never arrives fails through Jest's deadline rather than through a tuned
  // duration of ours that would eventually go stale.
  function listening(server: NetServer): Promise<number> {
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
   * Wait for a condition that a socket event will make true.
   *
   * Registered rather than polled: `pump()` runs from the handlers that change the state, so
   * the wait ends on the byte that satisfies it instead of on the next tick of some timer.
   * That keeps the suite off the wall clock, and a genuine hang then fails at Jest's own
   * deadline instead of at a duration of ours that would need retuning.
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

  function nextRecord(): Promise<ProxyRecord> {
    return until(() => records.length > 0).then(() => records[0] as ProxyRecord);
  }

  function nextAttempt(): Promise<TransparentAttempt> {
    return until(() => attempts.length > 0).then(() => attempts[0] as TransparentAttempt);
  }

  /** Open a client socket to the proxy, write `payload`, and collect everything written back. */
  function speak(proxyPort: number, payload: Buffer): { socket: Socket; received: () => Buffer; closed: Promise<void> } {
    let received = Buffer.alloc(0);
    const socket = netConnect(proxyPort, "127.0.0.1", () => socket.write(payload));
    sockets.push(socket);
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);
      pump();
    });
    const closed = new Promise<void>((resolve) => {
      // A pre-handshake refusal is a destroy(), which the peer sees as ECONNRESET rather than
      // a clean FIN. Both mean the same thing here: the proxy is done with this connection.
      socket.on("error", () => resolve());
      socket.on("close", () => resolve());
    });
    return { socket, received: () => received, closed };
  }

  function startProxy(
    decide: (attempt: TransparentAttempt) => ProxyDecision | ProxyVerdict,
    options: { peekTimeoutMs?: number; maxPeekBytes?: number; defaultTlsPort?: number } = {}
  ): Promise<number> {
    // Bound to THIS test's arrays, not re-read at call time. A connection left open when a
    // test ends is still alive while afterEach tears it down, and the record it files on
    // close lands after beforeEach has already installed fresh arrays — which showed up as
    // one test asserting against the previous test's upstream port.
    const ownAttempts = attempts;
    const ownRecords = records;
    const ownErrors = errors;
    const proxy = track(
      createTransparentProxy({
        port: 0,
        host: "127.0.0.1",
        decide: (attempt) => {
          ownAttempts.push(attempt);
          pump();
          return decide(attempt);
        },
        record: (record) => {
          ownRecords.push(record);
          pump();
        },
        onError: (err) => {
          ownErrors.push(err);
          pump();
        },
        ...options,
      })
    );
    return listening(proxy);
  }

  beforeEach(async () => {
    records = [];
    attempts = [];
    errors = [];
    gates = [];
    upstreamConnections = 0;
    upstreamReceived = Buffer.alloc(0);
    upstreamReply = null;
    upstream = track(
      createNetServer((socket) => {
        upstreamConnections += 1;
        sockets.push(socket);
        socket.on("error", () => {
          /* the proxy tearing this down is the test ending, not an upstream failure */
        });
        socket.on("data", (chunk) => {
          upstreamReceived = Buffer.concat([upstreamReceived, chunk]);
          if (upstreamReply) {
            socket.write(upstreamReply);
            upstreamReply = null;
          }
          pump();
        });
      })
    );
    upstream.listen(0, "127.0.0.1");
    upstreamPort = await listening(upstream);
  });

  afterEach(async () => {
    for (const socket of sockets.splice(0)) socket.destroy();
    await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  });

  it("replays the peeked bytes to the upstream byte-for-byte and pipes the reply back", async () => {
    const proxyPort = await startProxy(() => "allow");
    const request = Buffer.from(
      `POST /submit HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\nContent-Length: 11\r\n\r\nhello world`,
      "latin1"
    );
    upstreamReply = Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "latin1");

    const client = speak(proxyPort, request);
    await until(() => upstreamReceived.length >= request.length);

    // Head and body, byte for byte. The head was consumed to name the destination and the
    // origin has never seen it; an unreplayed peek is an allowed connection that silently
    // hangs, which no unit-level assertion would catch.
    expect(upstreamReceived.toString("latin1")).toBe(request.toString("latin1"));
    expect(upstreamConnections).toBe(1);
    expect(attempts).toEqual([{ host: "127.0.0.1", port: upstreamPort, scheme: "http" }]);

    await until(() => client.received().length > 0);
    expect(client.received().toString("latin1")).toContain("200 OK");
    expect(client.received().toString("latin1")).toContain("ok");
  });

  it("records an allowed connection with its byte counts once it closes", async () => {
    const proxyPort = await startProxy(() => "allow");
    const request = Buffer.from(`GET /x HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`, "latin1");
    upstreamReply = Buffer.from("HTTP/1.1 204 No Content\r\n\r\n", "latin1");

    const client = speak(proxyPort, request);
    await until(() => client.received().length > 0);
    client.socket.destroy();

    const record = await nextRecord();
    expect(record.decision).toBe("allow");
    expect(record.host).toBe("127.0.0.1");
    expect(record.port).toBe(upstreamPort);
    expect(record.scheme).toBe("http");
    expect(record.method).toBe("GET");
    // Attribution is not available on a redirected connection: the /proc helper the forward
    // proxy uses is module-private to it. The record says so rather than guessing.
    expect(record.client).toEqual({ pid: null, comm: null });
    expect(record.bytesUp).toBeGreaterThanOrEqual(request.length);
    expect(record.bytesDown).toBeGreaterThan(0);
    expect(record.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("routes a TLS-shaped connection by its SNI and replays the ClientHello intact", async () => {
    const proxyPort = await startProxy(() => "allow", { defaultTlsPort: upstreamPort });
    const hello = clientHello(sniExtension("127.0.0.1"));

    speak(proxyPort, hello);
    await until(() => upstreamReceived.length >= hello.length);

    // The destination came from SNI, and the handshake the client opened with arrived whole.
    // Losing a byte here would not fail visibly: the origin would simply never complete a
    // handshake, and every https call would hang.
    expect(await nextAttempt()).toEqual({ host: "127.0.0.1", port: upstreamPort, scheme: "https" });
    expect(upstreamReceived.toString("latin1")).toBe(hello.toString("latin1"));
    expect(upstreamConnections).toBe(1);
  });

  it("names a TLS destination only once the whole ClientHello has arrived", async () => {
    const proxyPort = await startProxy(() => "allow", { defaultTlsPort: upstreamPort });
    const hello = clientHello(sniExtension("127.0.0.1"));
    const firstCut = 12;
    const secondCut = Math.floor(hello.length / 2);

    // Fragmented the way a real ClientHello can be. Each write is chained off the previous
    // one's flush callback, so the fragments leave as separate segments without a sleep. A
    // peek buffer that reassembled wrongly would either never resolve, or resolve to a
    // destination the client never asked for, or replay a mangled handshake.
    const socket = netConnect(proxyPort, "127.0.0.1", () => {
      socket.setNoDelay(true);
      socket.write(hello.subarray(0, firstCut), () => {
        socket.write(hello.subarray(firstCut, secondCut), () => {
          socket.write(hello.subarray(secondCut));
        });
      });
    });
    sockets.push(socket);
    socket.on("error", () => {
      /* teardown in afterEach is not a failure */
    });

    await until(() => upstreamReceived.length >= hello.length);
    expect(await nextAttempt()).toEqual({ host: "127.0.0.1", port: upstreamPort, scheme: "https" });
    expect(attempts).toHaveLength(1);
    expect(upstreamReceived.toString("latin1")).toBe(hello.toString("latin1"));
  });

  it("assumes 443 for a TLS destination when no port is configured", async () => {
    // SNI carries no port, so the only honest default is the one the perimeter's own ruleset
    // redirects. 127.0.0.2 keeps the resolver out of it; nothing can be listening on the
    // ephemeral upstream's port here, which is the point.
    const proxyPort = await startProxy(() => "allow");
    const client = speak(proxyPort, clientHello(sniExtension("127.0.0.2")));

    expect(await nextAttempt()).toEqual({ host: "127.0.0.2", port: 443, scheme: "https" });
    expect(upstreamConnections).toBe(0);
    client.socket.destroy();
  });

  it("answers a denied HTTP connection with a 403 carrying the block reason", async () => {
    const proxyPort = await startProxy(() => ({
      decision: "deny",
      reasons: ["blocked.example is not in the egress allowlist"],
      matchedRules: ["net:deny-egress-not-allowlisted"],
      riskLevel: "high",
    }));

    const client = speak(proxyPort, Buffer.from(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`, "latin1"));
    await client.closed;

    const response = client.received().toString("latin1");
    expect(response).toContain("HTTP/1.1 403 Forbidden");
    expect(response).toContain("X-Agentwall-Block-Reason: blocked.example is not in the egress allowlist");
    expect(response).toContain("destination not allowed");
    // No upstream socket is opened on the deny path, so the destination cannot even log the
    // attempt as a TCP handshake.
    expect(upstreamConnections).toBe(0);
    expect(records).toHaveLength(1);
    expect(records[0]?.decision).toBe("deny");
    expect(records[0]?.matchedRules).toEqual(["net:deny-egress-not-allowlisted"]);
    expect(records[0]?.bytesUp).toBe(0);
  });

  it("cannot be made to inject headers through the block reason", async () => {
    const proxyPort = await startProxy(() => ({ decision: "deny", reasons: ["blocked\r\nX-Injected: yes"] }));

    const client = speak(proxyPort, Buffer.from(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`, "latin1"));
    await client.closed;

    const response = client.received().toString("latin1");
    expect(response).toContain("X-Agentwall-Block-Reason: blocked X-Injected: yes");
    expect(response).not.toContain("\r\nX-Injected: yes\r\n");
  });

  it("closes a denied TLS connection without writing a byte", async () => {
    const proxyPort = await startProxy(() => ({ decision: "deny", reasons: ["not allowlisted"], riskLevel: "high" }), {
      defaultTlsPort: upstreamPort,
    });

    const client = speak(proxyPort, clientHello(sniExtension("blocked.example.com")));
    await client.closed;

    // Nothing can be said before the handshake, so the client sees a reset. The reason lives
    // in the record instead; that is the ceiling of a pre-handshake refusal, not an oversight.
    expect(client.received()).toHaveLength(0);
    expect(upstreamConnections).toBe(0);
    expect(records).toHaveLength(1);
    expect(records[0]?.decision).toBe("deny");
    expect(records[0]?.host).toBe("blocked.example.com");
    expect(records[0]?.scheme).toBe("https");
  });

  it("denies and records a connection that never names a destination, on the peek deadline", async () => {
    const proxyPort = await startProxy(() => "allow", { peekTimeoutMs: 60 });

    const client = speak(proxyPort, Buffer.from("junk-without-a-header", "latin1"));
    const record = await nextRecord();

    expect(record.decision).toBe("deny");
    expect(record.reasons[0]).toContain("no SNI or Host header");
    expect(record.host).toBe("<unknown>");
    expect(record.port).toBe(0);
    // `decide` is never consulted: there is no attempt to hand it, and an "allow" would have
    // nowhere to go. The refusal is structural, and it reaches the ledger instead of looking
    // like a network glitch someone has to go and diagnose.
    expect(attempts).toHaveLength(0);
    expect(upstreamConnections).toBe(0);
    // Nothing is left holding a socket open waiting for bytes that are never coming.
    await client.closed;
    expect(client.socket.destroyed).toBe(true);
  });

  it("denies a connection that exceeds the peek ceiling without naming a destination", async () => {
    const proxyPort = await startProxy(() => "allow", { maxPeekBytes: 64, peekTimeoutMs: 30_000 });

    const client = speak(proxyPort, Buffer.alloc(4096, 0x41));
    const record = await nextRecord();

    expect(record.decision).toBe("deny");
    expect(record.reasons[0]).toContain("no SNI or Host header");
    expect(attempts).toHaveLength(0);
    expect(upstreamConnections).toBe(0);
    await client.closed;
  });

  it("reports an upstream that refuses the connection and closes the client", async () => {
    const dead = createNetServer();
    dead.listen(0, "127.0.0.1");
    const deadPort = await listening(dead);
    await new Promise<void>((resolve) => dead.close(() => resolve()));

    const proxyPort = await startProxy(() => "allow");
    const client = speak(proxyPort, Buffer.from(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${deadPort}\r\n\r\n`, "latin1"));

    const record = await nextRecord();
    await client.closed;

    // Allowed, and then it failed: the record says what the control decided, not what the
    // network did. The failure surfaces through onError rather than as a thrown exception,
    // because a throw out of a socket handler here takes the whole listener with it.
    expect(record.decision).toBe("allow");
    expect(record.host).toBe("127.0.0.1");
    expect(record.port).toBe(deadPort);
    expect(errors).toHaveLength(1);
    expect(client.socket.destroyed).toBe(true);
  });

  it("denies when the decision function throws", async () => {
    const proxyPort = await startProxy(() => {
      throw new Error("policy engine unavailable");
    });

    const client = speak(proxyPort, Buffer.from(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`, "latin1"));
    await client.closed;

    // A failed control is a denial. Allowing on error would turn every bug in policy
    // evaluation into an open door.
    expect(client.received().toString("latin1")).toContain("403 Forbidden");
    expect(upstreamConnections).toBe(0);
    expect(records[0]?.decision).toBe("deny");
    expect(errors).toHaveLength(1);
  });

  it("survives a client that hangs up mid-peek", async () => {
    const proxyPort = await startProxy(() => "allow", { peekTimeoutMs: 30_000 });

    const socket = netConnect(proxyPort, "127.0.0.1", () => {
      socket.write("GET / HTTP/1.1\r\nHost: exam");
      socket.destroy();
    });
    sockets.push(socket);
    socket.on("error", () => {
      /* the hangup is the point of the test */
    });

    const record = await nextRecord();
    expect(record.decision).toBe("deny");
    expect(record.host).toBe("<unknown>");
    expect(attempts).toHaveLength(0);
  });
});
