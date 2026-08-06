import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import {
  IncomingHttpHeaders,
  IncomingMessage,
  Server,
  ServerResponse,
  createServer,
  request as httpRequest,
} from "http";
import { AddressInfo } from "net";
import { PassThrough } from "stream";

import { resetAuditChain } from "../src/audit/logger";
import { McpHttpHandle, startMcpHttpListener } from "../src/mcp/http";
import { FrameAction, JsonRpcFrame, MCP_BLOCKED_ERROR_CODE } from "../src/mcp/types";
import { runMcpHttpWrap, runMcpWrap } from "../src/mcp/wrap";
import { AuditEvent } from "../src/types";

/**
 * The Streamable HTTP transport, against a stub upstream on an ephemeral port.
 *
 * Everything here is real except the server being wrapped: a real listener, real sockets, real
 * JSON-RPC bodies, real SSE framing. The stub records what it was handed, which is the only way to
 * prove the claim that actually matters about a block - not that the client got an error, but that
 * the upstream never saw the call. A test that only checked the client's error would pass just as
 * happily against a listener that forwarded the frame and then lied about it.
 *
 * Interceptors are stubbed rather than driven through the gates, matching tests/mcp-wrap.test.ts:
 * this file is about what the transport does with a verdict, and feeding it real gate verdicts
 * would tie assertions about HTTP behaviour to the current pattern set. The one exception is the
 * wrap-wiring block at the end, which runs the real gates precisely to show the HTTP path reaches
 * them and records what it found.
 */

interface UpstreamCall {
  method: string;
  headers: IncomingHttpHeaders;
  body: string;
}

interface StubUpstream {
  url: string;
  /** Every request the upstream actually received, in order. */
  received: UpstreamCall[];
  close(): Promise<void>;
}

interface HttpReply {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
}

const upstreams: StubUpstream[] = [];
const listeners: McpHttpHandle[] = [];

/** Start a stub MCP server that records what it receives and answers however the test says. */
async function startUpstream(
  handler: (call: UpstreamCall, res: ServerResponse) => void
): Promise<StubUpstream> {
  const received: UpstreamCall[] = [];
  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const call: UpstreamCall = {
        method: req.method ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      received.push(call);
      handler(call, res);
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const stub: StubUpstream = {
    url: `http://127.0.0.1:${port}/mcp`,
    received,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
  upstreams.push(stub);
  return stub;
}

/** Answer with one JSON-RPC result per frame received, so a round trip is observable. */
function echoJsonRpc(call: UpstreamCall, res: ServerResponse): void {
  const parsed: unknown = JSON.parse(call.body);
  const answer = (frame: JsonRpcFrame): JsonRpcFrame => ({
    jsonrpc: "2.0",
    id: frame.id ?? null,
    result: { saw: frame.method ?? null },
  });
  const payload = Array.isArray(parsed)
    ? (parsed as JsonRpcFrame[]).map(answer)
    : answer(parsed as JsonRpcFrame);
  const body = JSON.stringify(payload);
  res.writeHead(200, { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) });
  res.end(body);
}

async function startListener(opts: Parameters<typeof startMcpHttpListener>[0]): Promise<McpHttpHandle> {
  const handle = await startMcpHttpListener(opts);
  listeners.push(handle);
  return handle;
}

/** One request against the listener. Headers are overridable so Host and Authorization can be forged. */
function call(
  port: number,
  init: { method?: string; body?: string; headers?: Record<string, string> } = {}
): Promise<HttpReply> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/mcp",
        method: init.method ?? "POST",
        headers: { "content-type": "application/json", ...init.headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    if (init.body !== undefined) req.write(init.body);
    req.end();
  });
}

/** The `data` payload of every complete SSE event in a response body. */
function sseData(body: string): string[] {
  return body
    .split("\n\n")
    .map((block) => block.trim())
    .filter((block) => block.length > 0)
    .map((block) =>
      block
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice("data:".length).trim())
        .join("\n")
    )
    .filter((data) => data.length > 0);
}

const forwardEverything = async (frame: JsonRpcFrame): Promise<FrameAction> => ({ kind: "forward", frame });

/** Block frames the predicate selects; forward the rest. */
function blockWhen(predicate: (frame: JsonRpcFrame) => boolean, message = "refused by policy") {
  return async (frame: JsonRpcFrame): Promise<FrameAction> =>
    predicate(frame)
      ? { kind: "block", error: { code: MCP_BLOCKED_ERROR_CODE, message, data: { gate: "policy" } } }
      : { kind: "forward", frame };
}

beforeEach(() => {
  resetAuditChain();
});

afterEach(async () => {
  while (listeners.length > 0) await listeners.pop()!.close();
  while (upstreams.length > 0) await upstreams.pop()!.close();
  resetAuditChain();
});

describe("mcp http transport", () => {
  it("round-trips a clean frame to the upstream and back", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      onClientFrame: forwardEverything,
      onServerFrame: forwardEverything,
    });

    const reply = await call(listener.port, {
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });

    expect(reply.status).toBe(200);
    expect(JSON.parse(reply.body)).toEqual({ jsonrpc: "2.0", id: 1, result: { saw: "tools/list" } });
    expect(upstream.received).toHaveLength(1);
    expect(JSON.parse(upstream.received[0].body)).toEqual({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  });

  it("answers a blocked frame with a JSON-RPC error on the same id, and the upstream never sees it", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      onClientFrame: blockWhen((frame) => frame.method === "tools/call", "tool write_file is not approved"),
      onServerFrame: forwardEverything,
    });

    const reply = await call(listener.port, {
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 42,
        method: "tools/call",
        params: { name: "write_file", arguments: { path: "/etc/passwd" } },
      }),
    });

    // HTTP 200: the refusal is a JSON-RPC response, and a transport error would invite the client
    // to retry a decision that will not change.
    expect(reply.status).toBe(200);
    const body = JSON.parse(reply.body) as JsonRpcFrame;
    expect(body.id).toBe(42);
    expect(body.error?.code).toBe(MCP_BLOCKED_ERROR_CODE);
    expect(body.error?.message).toContain("write_file");
    expect(body.result).toBeUndefined();
    expect(upstream.received).toHaveLength(0);
  });

  it("evaluates a JSON array batch frame by frame", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      onClientFrame: blockWhen((frame) => frame.id === 2),
      onServerFrame: forwardEverything,
    });

    const reply = await call(listener.port, {
      body: JSON.stringify([
        { jsonrpc: "2.0", id: 1, method: "tools/list" },
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "rm" } },
        { jsonrpc: "2.0", id: 3, method: "resources/list" },
      ]),
    });

    expect(reply.status).toBe(200);
    const frames = JSON.parse(reply.body) as JsonRpcFrame[];
    expect(Array.isArray(frames)).toBe(true);
    expect(frames).toHaveLength(3);

    const byId = new Map(frames.map((frame) => [frame.id, frame]));
    expect(byId.get(2)?.error?.code).toBe(MCP_BLOCKED_ERROR_CODE);
    expect(byId.get(1)?.result).toEqual({ saw: "tools/list" });
    expect(byId.get(3)?.result).toEqual({ saw: "resources/list" });

    // Only the surviving two reached the upstream, as one batch.
    expect(upstream.received).toHaveLength(1);
    const forwarded = JSON.parse(upstream.received[0].body) as JsonRpcFrame[];
    expect(forwarded.map((frame) => frame.id)).toEqual([1, 3]);
  });

  it("streams SSE events through and terminates the stream at the first blocked event", async () => {
    const upstream = await startUpstream((_call, res) => {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
      res.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { text: "first" } })}\n\n`);
      res.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id: 2, result: { text: "exfiltrate" } })}\n\n`);
      res.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id: 3, result: { text: "third" } })}\n\n`);
      res.end();
    });
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      onClientFrame: forwardEverything,
      onServerFrame: blockWhen((frame) => frame.id === 2, "response carries an exfiltration directive"),
    });

    const reply = await call(listener.port, {
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "fetch" } }),
      headers: { accept: "text/event-stream" },
    });

    expect(reply.status).toBe(200);
    expect(reply.headers["content-type"]).toContain("text/event-stream");

    const events = sseData(reply.body).map((data) => JSON.parse(data) as JsonRpcFrame);
    // Event one passed, event two was refused, and the stream stopped there: the third event the
    // upstream sent is never delivered, which is the whole point of failing closed mid-stream.
    expect(events).toHaveLength(2);
    expect(events[0].result).toEqual({ text: "first" });
    expect(events[1].id).toBe(2);
    expect(events[1].error?.code).toBe(MCP_BLOCKED_ERROR_CODE);
    expect(reply.body).not.toContain("third");
  });

  it("refuses to start on a non-loopback host without a token, and names the flag", async () => {
    const upstream = await startUpstream(echoJsonRpc);

    await expect(
      startMcpHttpListener({
        listenHost: "0.0.0.0",
        listenPort: 0,
        upstreamUrl: upstream.url,
        onClientFrame: forwardEverything,
        onServerFrame: forwardEverything,
      })
    ).rejects.toThrow(/--http-auth-token-file/);

    await expect(
      startMcpHttpListener({
        listenHost: "0.0.0.0",
        listenPort: 0,
        upstreamUrl: upstream.url,
        onClientFrame: forwardEverything,
        onServerFrame: forwardEverything,
      })
    ).rejects.toThrow(/--http-host "0\.0\.0\.0" is not a loopback address/);
  });

  it("requires the bearer token when one is configured, and never forwards it upstream", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      authToken: "s3cret-token-value",
      onClientFrame: forwardEverything,
      onServerFrame: forwardEverything,
    });
    const body = JSON.stringify({ jsonrpc: "2.0", id: 5, method: "tools/list" });

    const missing = await call(listener.port, { body });
    expect(missing.status).toBe(401);
    expect(missing.headers["www-authenticate"]).toContain("Bearer");

    const wrong = await call(listener.port, { body, headers: { authorization: "Bearer wrong-token-value" } });
    expect(wrong.status).toBe(401);

    // Same length as the real token, so the constant-time path is the one being exercised rather
    // than the length guard in front of it.
    const nearMiss = await call(listener.port, { body, headers: { authorization: "Bearer s3cret-token-valuf" } });
    expect(nearMiss.status).toBe(401);

    expect(upstream.received).toHaveLength(0);

    const accepted = await call(listener.port, {
      body,
      headers: { authorization: "Bearer s3cret-token-value" },
    });
    expect(accepted.status).toBe(200);
    expect((JSON.parse(accepted.body) as JsonRpcFrame).result).toEqual({ saw: "tools/list" });
    expect(upstream.received).toHaveLength(1);
    // The listener's own credential stops here. Replaying it to the remote server would hand a
    // local token to a third party.
    expect(upstream.received[0].headers.authorization).toBeUndefined();
  });

  it("rejects a foreign Host authority on a tokenless loopback listener", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      onClientFrame: forwardEverything,
      onServerFrame: forwardEverything,
    });
    const body = JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" });

    const rebound = await call(listener.port, { body, headers: { host: "rebind.example.com" } });
    expect(rebound.status).toBe(403);
    expect(upstream.received).toHaveLength(0);

    // A loopback name on the wrong port is still a mismatch: it aims at a different local service.
    const wrongPort = await call(listener.port, {
      body,
      headers: { host: `127.0.0.1:${listener.port + 1}` },
    });
    expect(wrongPort.status).toBe(403);

    const local = await call(listener.port, { body, headers: { host: `localhost:${listener.port}` } });
    expect(local.status).toBe(200);
  });

  it("returns 413 for a body over the ceiling and forwards nothing", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      maxBodyBytes: 512,
      onClientFrame: forwardEverything,
      onServerFrame: forwardEverything,
    });

    const oversized = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "write_file", arguments: { text: "x".repeat(2048) } },
    });
    const reply = await call(listener.port, { body: oversized });

    expect(reply.status).toBe(413);
    expect((JSON.parse(reply.body) as JsonRpcFrame).error?.message).toContain("512");
    expect(upstream.received).toHaveLength(0);

    // The ceiling is a size limit, not a shutdown: a normal frame still works afterwards.
    const ok = await call(listener.port, { body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }) });
    expect(ok.status).toBe(200);
  });

  it("refuses a client body that is not JSON-RPC rather than letting the upstream decide", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const malformed: string[] = [];
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      onClientFrame: forwardEverything,
      onServerFrame: forwardEverything,
      onMalformed: (raw) => malformed.push(raw),
    });

    const notJson = await call(listener.port, { body: "{not json" });
    expect(notJson.status).toBe(400);
    expect((JSON.parse(notJson.body) as JsonRpcFrame).error?.code).toBe(-32700);

    const notJsonRpc = await call(listener.port, { body: JSON.stringify({ hello: "world" }) });
    expect(notJsonRpc.status).toBe(400);
    expect((JSON.parse(notJsonRpc.body) as JsonRpcFrame).error?.code).toBe(-32600);

    expect(upstream.received).toHaveLength(0);
    expect(malformed).toHaveLength(2);
  });

  it("blocks when an interceptor throws instead of forwarding an unscanned frame", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      onClientFrame: async () => {
        throw new Error("scanner exploded");
      },
      onServerFrame: forwardEverything,
    });

    const reply = await call(listener.port, {
      body: JSON.stringify({ jsonrpc: "2.0", id: 11, method: "tools/list" }),
    });

    expect(reply.status).toBe(200);
    const frame = JSON.parse(reply.body) as JsonRpcFrame;
    expect(frame.id).toBe(11);
    expect(frame.error?.message).toContain("scanner exploded");
    expect(upstream.received).toHaveLength(0);
  });

  it("scans the server-initiated GET stream and passes keepalive comments through", async () => {
    const upstream = await startUpstream((_call, res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(": keepalive\n\n");
      res.write(`data: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/message", params: { level: "info" } })}\n\n`);
      res.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id: 4, method: "sampling/createMessage" })}\n\n`);
      res.end();
    });
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      onClientFrame: forwardEverything,
      onServerFrame: blockWhen((frame) => frame.method === "sampling/createMessage", "unsolicited sampling"),
    });

    const reply = await call(listener.port, { method: "GET", headers: { accept: "text/event-stream" } });

    expect(reply.status).toBe(200);
    expect(upstream.received[0].method).toBe("GET");
    // The comment carries no frame and survives; the notification is forwarded; the refused frame
    // ends the stream, so the client sees exactly three blocks and no more.
    expect(reply.body).toContain(": keepalive");
    const events = sseData(reply.body).map((data) => JSON.parse(data) as JsonRpcFrame);
    expect(events).toHaveLength(2);
    expect(events[0].method).toBe("notifications/message");
    expect(events[1].id).toBe(4);
    expect(events[1].error?.code).toBe(MCP_BLOCKED_ERROR_CODE);
  });

  it("refuses a method that is not part of the transport", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const listener = await startListener({
      listenPort: 0,
      upstreamUrl: upstream.url,
      onClientFrame: forwardEverything,
      onServerFrame: forwardEverything,
    });

    const reply = await call(listener.port, { method: "PUT", body: "{}" });

    expect(reply.status).toBe(405);
    expect(reply.headers.allow).toBe("POST, GET, DELETE");
    expect(upstream.received).toHaveLength(0);
  });
});

describe("mcp http wrap wiring", () => {
  it("gates HTTP frames through the same pipeline and records the transport", async () => {
    const upstream = await startUpstream(echoJsonRpc);
    const events: AuditEvent[] = [];
    const listener = await runMcpHttpWrap({
      listenPort: 0,
      upstreamUrl: upstream.url,
      serverName: "remote-server",
      agentId: "http-agent",
      onAuditEvent: (event) => events.push(event as AuditEvent),
    });
    listeners.push(listener);

    const clean = await call(listener.port, {
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(clean.status).toBe(200);
    expect((JSON.parse(clean.body) as JsonRpcFrame).result).toEqual({ saw: "tools/list" });

    // A response frame carrying neither result nor error fails the frame_integrity gate, which is a
    // real verdict from the real gates rather than a stubbed one: this is the assertion that the
    // HTTP path reaches them at all.
    const broken = await call(listener.port, { body: JSON.stringify({ jsonrpc: "2.0", id: 7 }) });
    expect(broken.status).toBe(200);
    const refused = JSON.parse(broken.body) as JsonRpcFrame;
    expect(refused.id).toBe(7);
    expect(refused.error?.code).toBe(MCP_BLOCKED_ERROR_CODE);

    const transports = new Set(events.map((event) => event.metadata?.mcpTransport));
    expect(transports).toEqual(new Set(["http"]));
    expect(events.every((event) => event.metadata?.mcpServer === "remote-server")).toBe(true);
    expect(events.every((event) => event.metadata?.mcpUpstream === `${upstream.url}`)).toBe(true);
    // Nothing was launched here, so there is no binary to pin and the field is absent rather than
    // present and meaningless.
    expect(events.every((event) => event.metadata?.commandHash === undefined)).toBe(true);
    expect(events.some((event) => event.metadata?.direction === "server_to_client")).toBe(true);
    expect(events.some((event) => event.decision === "deny")).toBe(true);
  });
});

/** A minimal stdio MCP server: one JSON-RPC result per request, newline delimited. */
const STDIO_ECHO_SERVER = `
let buffered = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffered += chunk;
  for (;;) {
    const newline = buffered.indexOf("\\n");
    if (newline === -1) break;
    const line = buffered.slice(0, newline).trim();
    buffered = buffered.slice(newline + 1);
    if (line.length === 0) continue;
    const frame = JSON.parse(line);
    if (frame.id === undefined || frame.id === null) continue;
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: frame.id, result: { saw: frame.method } }) + "\\n");
  }
});
process.stdin.on("end", () => process.exit(0));
`;

describe("mcp stdio wrap regression guard", () => {
  it("still gates, forwards and records a stdio session unchanged", async () => {
    const client = new PassThrough();
    const toClient = new PassThrough();
    const childErrors = new PassThrough();
    childErrors.resume();

    const frames: JsonRpcFrame[] = [];
    const waiting: Array<{ count: number; resolve: () => void }> = [];
    let buffered = "";
    toClient.setEncoding("utf8");
    toClient.on("data", (chunk: string) => {
      buffered += chunk;
      for (;;) {
        const newline = buffered.indexOf("\n");
        if (newline === -1) break;
        const line = buffered.slice(0, newline).trim();
        buffered = buffered.slice(newline + 1);
        if (line.length > 0) frames.push(JSON.parse(line) as JsonRpcFrame);
      }
      for (let i = waiting.length - 1; i >= 0; i -= 1) {
        if (frames.length >= waiting[i].count) waiting.splice(i, 1)[0].resolve();
      }
    });

    const events: AuditEvent[] = [];
    const finished = runMcpWrap({
      command: [process.execPath, "-e", STDIO_ECHO_SERVER],
      serverName: "regression-server",
      agentId: "stdio-agent",
      onAuditEvent: (event) => events.push(event as AuditEvent),
      stdin: client,
      stdout: toClient,
      stderr: childErrors,
    });
    // Observed either way, so the loser of the race below never surfaces as an unhandled rejection.
    const exitedEarly = finished.then((code) => {
      throw new Error(`server exited with status ${code} before the response arrived`);
    });
    exitedEarly.catch(() => {});

    client.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })}\n`);
    await Promise.race([
      new Promise<void>((resolve) => waiting.push({ count: 1, resolve })),
      exitedEarly,
    ]);

    expect(frames[0]).toEqual({ jsonrpc: "2.0", id: 1, result: { saw: "tools/list" } });

    client.end();
    await expect(finished).resolves.toBe(0);

    const transports = new Set(events.map((event) => event.metadata?.mcpTransport));
    expect(transports).toEqual(new Set(["stdio"]));
    expect(events.every((event) => event.metadata?.mcpServer === "regression-server")).toBe(true);
    // The launched binary is still fingerprinted on this path; that is what the field is for.
    expect(events.every((event) => typeof event.metadata?.commandHash === "string")).toBe(true);
    expect(events.map((event) => event.metadata?.direction)).toEqual([
      "client_to_server",
      "server_to_client",
    ]);
    expect(events.every((event) => event.decision === "allow")).toBe(true);
  }, 20000);
});
