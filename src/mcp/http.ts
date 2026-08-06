import { timingSafeEqual } from "crypto";
import {
  ClientRequest,
  IncomingMessage,
  OutgoingHttpHeaders,
  Server,
  ServerResponse,
  createServer,
  request as httpRequest,
} from "http";
import { request as httpsRequest } from "https";
import { AddressInfo } from "net";
import { StringDecoder } from "string_decoder";

import { FrameAction, FrameDirection, JsonRpcFrame, MCP_BLOCKED_ERROR_CODE } from "./types";

/**
 * The Streamable HTTP interception point.
 *
 * The stdio wrapper owns both ends of a pipe it created; there is no equivalent here, because a
 * remote MCP server was never ours to launch. What is available is the one thing a client can be
 * pointed at instead: a local listener that speaks the same transport, evaluates every frame with
 * the same callbacks the stdio path uses, and forwards what survives. The client changes a URL;
 * the remote server is untouched and does not know this is here.
 *
 * The reason this file exists at all is that a decision must not depend on which transport carried
 * the frame. A tool call the gates refuse over stdio has to be refused over HTTP too, and the only
 * way to guarantee that is for both transports to hand frames to the same interceptors rather than
 * growing a second, subtly different opinion of their own. So, exactly like ./stdio, this file owns
 * no policy: it parses, calls back, and does what the returned FrameAction says.
 *
 * Failure posture is closed, in the three places HTTP makes that non-obvious:
 *   - A body that will not parse as JSON-RPC is refused rather than forwarded, because bytes we
 *     could not read are bytes we could not scan.
 *   - An interceptor that throws blocks. A scanner crashing is the moment you least want an
 *     unscanned frame to go through.
 *   - A blocked event on a streaming response ends the stream instead of skipping the event; see
 *     the comment on pumpSse for why continuing would be theatre.
 *
 * Scope limits worth stating plainly. This wraps the Streamable HTTP transport - the client's POST
 * of one frame or a batch, the JSON or `text/event-stream` response to it, and the GET stream a
 * server uses to push frames the client did not ask for. It does not wrap WebSocket transports, it
 * does not terminate TLS between the client and this listener (bind loopback, or put a token on it
 * and a TLS terminator in front), and it says nothing about what the remote server does out of
 * band. Like the stdio wrapper, this buys visibility into a protocol, not a sandbox around a server.
 */

/** Where the listener binds when the caller did not say. Loopback, because a wide bind is a decision. */
const DEFAULT_LISTEN_HOST = "127.0.0.1";

/**
 * Ceiling on one request body: 8 MiB, matching the stdio framing ceiling.
 *
 * The number is the same on both transports on purpose - a payload too large to be a frame should
 * not become acceptable by arriving over a different socket. Configurable because the ceiling is a
 * resource decision rather than a security one, and an operator wrapping a server that legitimately
 * moves large documents should be able to raise it knowingly instead of meeting it as a mysterious
 * 413.
 */
const DEFAULT_MAX_BODY_BYTES = 8 * 1024 * 1024;

/**
 * How long the upstream has to produce response headers.
 *
 * Only headers. Once a stream is open, silence is normal on SSE - a server may hold a stream open
 * for minutes between events - so an inactivity timeout over the whole response would kill healthy
 * streams. What must not be unbounded is the window in which a client request holds a socket here
 * waiting on an upstream that will never answer.
 */
const UPSTREAM_HEADERS_TIMEOUT_MS = 30_000;

/** JSON-RPC reserved codes. Used only for bodies that never became frames. */
const JSONRPC_PARSE_ERROR = -32700;
const JSONRPC_INVALID_REQUEST = -32600;
const JSONRPC_INTERNAL_ERROR = -32603;

/**
 * Request headers that travel upstream, and nothing else.
 *
 * An allowlist rather than a denylist of hop-by-hop names. A denylist has to be right about every
 * header a client might send, including ones that did not exist when it was written; an allowlist
 * is wrong only in the direction of dropping something, which surfaces as a broken feature rather
 * than as a leak. `authorization` is handled separately below because it needs a condition, not a
 * yes or no.
 */
const FORWARDED_REQUEST_HEADERS = [
  "content-type",
  "accept",
  "mcp-session-id",
  "mcp-protocol-version",
  "last-event-id",
] as const;

/** Response headers that come back to the client. Same reasoning, other direction. */
const FORWARDED_RESPONSE_HEADERS = ["content-type", "mcp-session-id", "cache-control"] as const;

export interface McpHttpOptions {
  /** Interface to bind (`--http-host`). Defaults to loopback; anything else requires `authToken`. */
  listenHost?: string;
  /** Port to bind (`--http-port`). 0 takes an ephemeral port, which is what a test should use. */
  listenPort: number;
  /** Absolute `http:` or `https:` URL of the MCP server being wrapped (`--http-upstream`). */
  upstreamUrl: string;
  /** Called for every frame the client sent, before anything is forwarded. */
  onClientFrame: (frame: JsonRpcFrame) => Promise<FrameAction>;
  /** Called for every frame the upstream returned, before anything reaches the client. */
  onServerFrame: (frame: JsonRpcFrame) => Promise<FrameAction>;
  /** Bearer token clients must present (`--http-auth-token-file`). Required unless `listenHost` is loopback. */
  authToken?: string;
  /** Request-body ceiling in bytes. Defaults to 8 MiB. */
  maxBodyBytes?: number;
  /**
   * Called with a body or event that could not be parsed into a frame, so a refusal at the
   * transport is still evidence. Without it a malformed body is refused silently, and the audit
   * chain shows a gap where a request was rather than a record of why nothing came of it.
   */
  onMalformed?: (raw: string, direction: FrameDirection) => void;
}

export interface McpHttpHandle {
  /** The bound port. Meaningful when `listenPort` was 0. */
  port: number;
  /** Stop listening and drop live connections. Resolves once the socket is closed. */
  close(): Promise<void>;
}

/** One parsed server-sent event: its non-data field lines, and its data payload if it had one. */
interface SseEvent {
  /** `event:`, `id:`, `retry:` and comment lines, verbatim and in order. */
  prelude: string[];
  /** The `data` payload, `\n`-joined per the SSE rules, or undefined for an event with no data. */
  data?: string;
}

/** What a client POST body turned out to be. */
type ParsedBody =
  | { kind: "single"; frames: JsonRpcFrame[] }
  | { kind: "batch"; frames: JsonRpcFrame[] }
  | { kind: "malformed"; code: number; message: string };

/**
 * Is this a loopback address by name?
 *
 * Used for two different questions: may this listener run without a token, and is this `Host`
 * header local. Both want the same answer, and both are answered from the literal text rather than
 * from a resolver, because a resolver is precisely what an attacker gets to influence. The known
 * cost is that a name which is not spelled like loopback but resolves to it - a host's own hostname,
 * for instance - is treated as remote and needs a token. That is the safe direction to be wrong in.
 */
function isLoopbackHostname(host: string): boolean {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  const lower = bare.toLowerCase();
  if (lower === "localhost" || lower === "::1" || lower === "0:0:0:0:0:0:0:1") return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lower)) return true;
  // IPv4-mapped IPv6, which is how a dual-stack listener spells a v4 loopback address.
  if (lower.startsWith("::ffff:")) return isLoopbackHostname(lower.slice("::ffff:".length));
  return false;
}

/**
 * Does the `Host` authority name this listener on loopback?
 *
 * This is the DNS-rebinding check, and it is the reason a tokenless localhost service is not
 * automatically safe. A page in the operator's browser can be served from a name the attacker
 * controls, whose DNS answer flips to 127.0.0.1 after the page loads; the browser then sends
 * requests to this listener while treating them as same-origin with the attacker's page. Everything
 * about such a request looks local - the peer address genuinely is 127.0.0.1 - except the `Host`
 * header, which still carries the attacker's name because that is the name the page asked for.
 * Pinning `Host` to a loopback literal on the port we actually bound is what breaks it.
 *
 * The port must match too: a listener on 9000 that accepted a `Host` of `127.0.0.1:80` would accept
 * a request aimed at a different local service, which is the same confusion one layer down.
 */
function hostHeaderIsLocal(hostHeader: string | undefined, boundPort: number): boolean {
  if (hostHeader === undefined || hostHeader.length === 0) return false;

  let hostname: string;
  let portText: string | undefined;

  if (hostHeader.startsWith("[")) {
    const close = hostHeader.indexOf("]");
    if (close === -1) return false;
    hostname = hostHeader.slice(1, close);
    const rest = hostHeader.slice(close + 1);
    if (rest.length > 0 && !rest.startsWith(":")) return false;
    portText = rest.startsWith(":") ? rest.slice(1) : undefined;
  } else {
    const colon = hostHeader.lastIndexOf(":");
    if (colon === -1) {
      hostname = hostHeader;
    } else {
      hostname = hostHeader.slice(0, colon);
      portText = hostHeader.slice(colon + 1);
    }
  }

  if (!isLoopbackHostname(hostname)) return false;
  // An absent port means the scheme default, which for a listener that is not on 80 is a mismatch.
  if (portText === undefined) return boundPort === 80;
  return /^\d+$/.test(portText) && Number(portText) === boundPort;
}

/** The bearer credential in an `Authorization` header, or undefined when there is not one. */
function bearerToken(header: string | string[] | undefined): string | undefined {
  const value = Array.isArray(header) ? header[0] : header;
  if (typeof value !== "string") return undefined;
  const match = /^bearer[ \t]+(.+)$/i.exec(value.trim());
  return match === null ? undefined : match[1].trim();
}

/**
 * Constant-time token comparison.
 *
 * timingSafeEqual throws on buffers of different length, so the length check has to come first -
 * and that check is itself variable-time, which leaks the token's length. That leak is accepted: an
 * attacker who learns a token is 32 characters long has learned nothing that shortens a search over
 * its contents, whereas a byte-at-a-time comparison would let them recover it one character per
 * round trip.
 */
function tokenMatches(expected: string, presented: string | undefined): boolean {
  if (presented === undefined) return false;
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(presented, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** A JSON-RPC error response against an id. */
function errorFrame(
  id: JsonRpcFrame["id"],
  error: { code: number; message: string; data?: unknown }
): JsonRpcFrame {
  return { jsonrpc: "2.0", id: id === undefined ? null : id, error };
}

/**
 * Structural admission test, mirroring the stdio framing parser.
 *
 * Same question, same answer, so a payload rejected as "not protocol" on one transport is not
 * quietly accepted on the other. Whether an admitted envelope is a well-formed request, response or
 * notification is the frame_integrity gate's decision and stays there, so that every protocol-level
 * rejection carries a gate outcome the audit trail can show.
 */
function asFrame(value: unknown): JsonRpcFrame | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  if (!("jsonrpc" in value) || value.jsonrpc !== "2.0") return undefined;
  return value as JsonRpcFrame;
}

/** Interpret a POST body as one frame or a batch of them. */
function parseBody(raw: string): ParsedBody {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return { kind: "malformed", code: JSONRPC_PARSE_ERROR, message: "Request body is not valid JSON." };
  }

  if (Array.isArray(value)) {
    const frames: JsonRpcFrame[] = [];
    for (const entry of value) {
      const frame = asFrame(entry);
      if (frame === undefined) {
        return {
          kind: "malformed",
          code: JSONRPC_INVALID_REQUEST,
          message: "Batch contains an entry that is not a JSON-RPC 2.0 frame.",
        };
      }
      frames.push(frame);
    }
    return { kind: "batch", frames };
  }

  const frame = asFrame(value);
  if (frame === undefined) {
    return {
      kind: "malformed",
      code: JSONRPC_INVALID_REQUEST,
      message: "Request body is not a JSON-RPC 2.0 frame.",
    };
  }
  return { kind: "single", frames: [frame] };
}

/**
 * Run an interceptor without letting it decide by crashing.
 *
 * Matching the stdio wrapper: a callback that throws produces a block, not a pass. The alternative
 * is that a bug in a scanner becomes an open door, and an open door that reports itself as
 * inspected is worse than no door at all.
 */
async function runInterceptor(
  interceptor: (frame: JsonRpcFrame) => Promise<FrameAction>,
  frame: JsonRpcFrame
): Promise<FrameAction> {
  try {
    return await interceptor(frame);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return {
      kind: "block",
      error: {
        code: JSONRPC_INTERNAL_ERROR,
        message: `AgentWall could not evaluate this frame and refused it: ${detail}`,
      },
    };
  }
}

/** Write and respect backpressure, so a slow client cannot make this grow without bound. */
function writeChunk(res: ServerResponse, text: string): Promise<void> {
  return new Promise((resolve) => {
    if (res.writableEnded || res.destroyed) {
      resolve();
      return;
    }
    if (res.write(text)) {
      resolve();
      return;
    }
    res.once("drain", resolve);
  });
}

/** Render an event back onto the wire. */
function serializeSseEvent(event: SseEvent): string {
  const lines = [...event.prelude];
  if (event.data !== undefined) {
    for (const line of event.data.split("\n")) lines.push(`data: ${line}`);
  }
  return `${lines.join("\n")}\n\n`;
}

/** Split one event block into its data payload and everything else. */
function parseSseBlock(block: string): SseEvent {
  const prelude: string[] = [];
  const data: string[] = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("data:")) {
      const value = line.slice("data:".length);
      data.push(value.startsWith(" ") ? value.slice(1) : value);
      continue;
    }
    prelude.push(line);
  }
  return data.length === 0 ? { prelude } : { prelude, data: data.join("\n") };
}

/**
 * Stateful event splitter for one stream.
 *
 * Line terminators are normalised because SSE permits CR, LF and CRLF, and a scanner that knew only
 * one of them would read a whole stream as a single unterminated event and scan nothing. A chunk
 * ending in a bare CR is held back rather than normalised, since the byte that follows decides
 * whether it was a line terminator or half of a CRLF, and guessing produces a phantom blank line
 * that splits one event into two.
 */
function createSseParser(): { push(chunk: Buffer): SseEvent[]; flush(): SseEvent[] } {
  const decoder = new StringDecoder("utf8");
  let buffered = "";

  const drainEvents = (): SseEvent[] => {
    const events: SseEvent[] = [];
    for (;;) {
      const boundary = buffered.indexOf("\n\n");
      if (boundary === -1) break;
      const block = buffered.slice(0, boundary);
      buffered = buffered.slice(boundary + 2);
      if (block.length > 0) events.push(parseSseBlock(block));
    }
    return events;
  };

  return {
    push(chunk: Buffer): SseEvent[] {
      let text = decoder.write(chunk);
      let held = "";
      if (text.endsWith("\r")) {
        held = "\r";
        text = text.slice(0, -1);
      }
      buffered += text.replace(/\r\n?/g, "\n");
      const events = drainEvents();
      buffered += held;
      return events;
    },
    flush(): SseEvent[] {
      buffered += decoder.end().replace(/\r\n?/g, "\n");
      const events = drainEvents();
      // A trailing block with no blank line after it was still an event as far as the sender was
      // concerned. Dropping it would lose a frame unscanned and unreported, which reads as data
      // loss rather than as the truncation it is.
      const rest = buffered.replace(/\n+$/, "");
      buffered = "";
      if (rest.length > 0) events.push(parseSseBlock(rest));
      return events;
    },
  };
}

/**
 * Read a body under a ceiling.
 *
 * The declared length is checked before a byte is read, so an oversized upload is refused at once
 * rather than after it has been buffered, and the running total is checked as well because a
 * chunked body declares nothing.
 */
function readBody(stream: IncomingMessage, limit: number): Promise<{ ok: true; body: string } | { ok: false }> {
  return new Promise((resolve) => {
    const declared = Number(stream.headers["content-length"]);
    if (Number.isFinite(declared) && declared > limit) {
      resolve({ ok: false });
      return;
    }

    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const finish = (outcome: { ok: true; body: string } | { ok: false }): void => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };

    stream.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        finish({ ok: false });
        return;
      }
      chunks.push(chunk);
    });
    stream.on("end", () => finish({ ok: true, body: Buffer.concat(chunks).toString("utf8") }));
    // A connection that dies mid-body is not worth its own path: there is nothing left to answer,
    // and an empty body fails the parse that follows anyway.
    stream.on("error", () => finish({ ok: true, body: "" }));
    stream.on("aborted", () => finish({ ok: true, body: "" }));
  });
}

/** Send a JSON body and close the exchange. */
function respondJson(
  res: ServerResponse,
  status: number,
  payload: unknown,
  extra: OutgoingHttpHeaders = {}
): void {
  if (res.writableEnded) return;
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  res.writeHead(status, {
    ...extra,
    "content-type": "application/json",
    "content-length": String(body.length),
  });
  res.end(body);
}

/**
 * Refuse at the transport, with a JSON-RPC error as the body.
 *
 * The HTTP status carries the transport-level meaning - unauthenticated, too large, wrong method -
 * and the body stays JSON-RPC so a client that only knows how to read this protocol still gets a
 * message it can show a human instead of an opaque failure.
 */
function refuse(res: ServerResponse, status: number, message: string, extra: OutgoingHttpHeaders = {}): void {
  respondJson(res, status, errorFrame(null, { code: MCP_BLOCKED_ERROR_CODE, message }), {
    ...extra,
    connection: "close",
  });
}

/** Copy the allowlisted headers from an incoming request onto an upstream request. */
function upstreamRequestHeaders(req: IncomingMessage, tokenConfigured: boolean): OutgoingHttpHeaders {
  const headers: OutgoingHttpHeaders = {};
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = req.headers[name];
    if (value === undefined) continue;
    headers[name] = Array.isArray(value) ? value[0] : value;
  }

  // The listener's own credential must never reach the remote server. When a token is configured,
  // the only Authorization header that got this far is the one that satisfied our check, so it is
  // ours and it is dropped: a local token replayed to a third party is a credential leak nothing
  // downstream would notice. When no token is configured, an Authorization header cannot be ours,
  // so it belongs to the upstream and is passed through untouched - that is how an operator gives
  // the remote server credentials without this listener ever holding them.
  if (!tokenConfigured) {
    const authorization = req.headers.authorization;
    if (authorization !== undefined) {
      headers.authorization = Array.isArray(authorization) ? authorization[0] : authorization;
    }
  }

  return headers;
}

/** Copy the allowlisted headers from the upstream response back to the client. */
function clientResponseHeaders(upstream: IncomingMessage): OutgoingHttpHeaders {
  const headers: OutgoingHttpHeaders = {};
  for (const name of FORWARDED_RESPONSE_HEADERS) {
    const value = upstream.headers[name];
    if (value === undefined) continue;
    headers[name] = Array.isArray(value) ? value[0] : value;
  }
  return headers;
}

/**
 * Start a listener that wraps a remote MCP server on the Streamable HTTP transport.
 *
 * Resolves once the socket is bound, with the port it actually took, so a caller that asked for an
 * ephemeral port can tell a client where to look. Rejects rather than starting degraded: an
 * unusable upstream URL or a non-loopback bind without a token are both configuration errors that
 * an operator should meet at the command they just ran, not in a log the next morning.
 */
export function startMcpHttpListener(opts: McpHttpOptions): Promise<McpHttpHandle> {
  const listenHost = opts.listenHost ?? DEFAULT_LISTEN_HOST;
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const token = opts.authToken !== undefined && opts.authToken.length > 0 ? opts.authToken : undefined;

  let upstreamUrl: URL;
  try {
    upstreamUrl = new URL(opts.upstreamUrl);
  } catch {
    return Promise.reject(
      new Error(`MCP HTTP listener: --http-upstream "${opts.upstreamUrl}" is not an absolute URL.`)
    );
  }
  if (upstreamUrl.protocol !== "http:" && upstreamUrl.protocol !== "https:") {
    return Promise.reject(
      new Error(`MCP HTTP listener: --http-upstream must be http: or https:, got "${upstreamUrl.protocol}".`)
    );
  }

  // Refusing to start is the whole point of this check.
  //
  // A listener on a routable interface is reachable by anything that can route to it, and an
  // unauthenticated one is an open proxy into the wrapped server for every one of them. Starting
  // anyway with a warning would put the burden on someone reading logs after the fact; the failure
  // has to land while the operator is still looking at the command they just typed, and the message
  // has to say what to do rather than only what is missing.
  if (!isLoopbackHostname(listenHost) && token === undefined) {
    return Promise.reject(
      new Error(
        `MCP HTTP listener refuses to start: --http-host "${listenHost}" is not a loopback address, ` +
          "so a token is required. Set --http-auth-token-file (the authToken option) to authenticate " +
          "clients, or bind --http-host 127.0.0.1 to run tokenless on loopback."
      )
    );
  }

  const requester = upstreamUrl.protocol === "https:" ? httpsRequest : httpRequest;
  // Tracked so close() can drop streams that are, by design, open indefinitely. An SSE pump waiting
  // on a server that will never send anything else would otherwise keep the process alive.
  const liveUpstream = new Set<ClientRequest>();
  let boundPort = 0;

  /**
   * Send a request upstream and hand back the response.
   *
   * Rejects only when the connection itself failed. An upstream that answers 4xx or 5xx is a
   * response like any other and is scanned and relayed, because that body is still server-controlled
   * text the agent may read.
   */
  const callUpstream = (
    method: string,
    headers: OutgoingHttpHeaders,
    body: string | undefined
  ): Promise<IncomingMessage> =>
    new Promise((resolve, reject) => {
      const request = requester({
        protocol: upstreamUrl.protocol,
        hostname: upstreamUrl.hostname,
        port: upstreamUrl.port,
        path: `${upstreamUrl.pathname}${upstreamUrl.search}`,
        method,
        headers:
          body === undefined
            ? headers
            : { ...headers, "content-length": String(Buffer.byteLength(body, "utf8")) },
      });
      liveUpstream.add(request);

      const headersTimer = setTimeout(() => {
        request.destroy(
          new Error(`upstream did not send response headers within ${UPSTREAM_HEADERS_TIMEOUT_MS}ms`)
        );
      }, UPSTREAM_HEADERS_TIMEOUT_MS);
      headersTimer.unref();

      request.on("response", (response) => {
        clearTimeout(headersTimer);
        resolve(response);
      });
      request.on("error", (err) => {
        clearTimeout(headersTimer);
        liveUpstream.delete(request);
        reject(err);
      });
      request.on("close", () => {
        clearTimeout(headersTimer);
        liveUpstream.delete(request);
      });

      if (body !== undefined) request.write(body);
      request.end();
    });

  /**
   * Relay a streaming response, scanning every event on the way past.
   *
   * A block ends the stream. Skipping the offending event and carrying on would look like
   * enforcement without being any: the events are pieces of one response, so whatever a later event
   * completes has usually already been delivered by the earlier ones, and a client that keeps
   * receiving a stream reads it as a stream that was fine. Ending it is the only signal this
   * transport has for "the rest of this response is not coming", and it is the one a client can act
   * on. The cost is real and worth naming: a false positive kills a whole response rather than one
   * event of it.
   */
  const pumpSse = async (
    upstream: IncomingMessage,
    res: ServerResponse,
    pending: JsonRpcFrame[]
  ): Promise<void> => {
    res.writeHead(upstream.statusCode ?? 200, {
      ...clientResponseHeaders(upstream),
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "close",
    });

    // Errors for client frames this listener already refused. They belong in the stream because the
    // client is waiting on those ids, and sending them first keeps a refusal from arriving after the
    // responses to the calls that were allowed.
    for (const frame of pending) {
      await writeChunk(res, serializeSseEvent({ prelude: [], data: JSON.stringify(frame) }));
    }

    const parser = createSseParser();

    /** Relay one event. False means the stream is over: this event was refused. */
    const relay = async (event: SseEvent): Promise<boolean> => {
      if (event.data === undefined) {
        // A comment or a bare field line. SSE keepalives look like this and carry no frame.
        await writeChunk(res, serializeSseEvent(event));
        return true;
      }

      const endStream = async (message: string, id: JsonRpcFrame["id"] = null): Promise<false> => {
        await writeChunk(
          res,
          serializeSseEvent({ prelude: [], data: JSON.stringify(errorFrame(id, { code: MCP_BLOCKED_ERROR_CODE, message })) })
        );
        return false;
      };

      let payload: unknown;
      try {
        payload = JSON.parse(event.data);
      } catch {
        opts.onMalformed?.(event.data, "server_to_client");
        return endStream("AgentWall ended this stream: an event body was not JSON and could not be scanned.");
      }

      const entries = Array.isArray(payload) ? payload : [payload];
      const forwarded: JsonRpcFrame[] = [];
      for (const entry of entries) {
        const frame = asFrame(entry);
        if (frame === undefined) {
          opts.onMalformed?.(event.data, "server_to_client");
          return endStream(
            "AgentWall ended this stream: an event carried something that is not a JSON-RPC frame."
          );
        }

        const action = await runInterceptor(opts.onServerFrame, frame);
        if (action.kind === "forward") {
          forwarded.push(action.frame);
          continue;
        }
        await writeChunk(
          res,
          serializeSseEvent({ prelude: [], data: JSON.stringify(errorFrame(frame.id, action.error)) })
        );
        return false;
      }

      await writeChunk(
        res,
        serializeSseEvent({
          prelude: event.prelude,
          data: JSON.stringify(Array.isArray(payload) ? forwarded : forwarded[0]),
        })
      );
      return true;
    };

    // `for await` rather than a data handler: it pauses the socket while an interceptor runs, so a
    // slow scanner applies backpressure to the upstream instead of queueing unscanned events in
    // memory, and it makes "stop at the first block" a plain early return.
    // Typed at the boundary rather than cast at each use: Node describes a response body as an
    // iterable of untyped chunks, and it is a stream of Buffers.
    const chunks: AsyncIterable<Buffer> = upstream;
    try {
      for await (const chunk of chunks) {
        for (const event of parser.push(chunk)) {
          if (!(await relay(event))) {
            upstream.destroy();
            res.end();
            return;
          }
        }
      }
      for (const event of parser.flush()) {
        if (!(await relay(event))) {
          upstream.destroy();
          res.end();
          return;
        }
      }
    } catch {
      // The upstream connection failed mid-stream. Nothing more is coming, and the client learns
      // that from the stream ending rather than from a status it can no longer be sent.
    }
    res.end();
  };

  /** Scan a complete (non-streaming) upstream body and answer the client with what survives. */
  const relayJsonResponse = async (
    upstream: IncomingMessage,
    res: ServerResponse,
    pending: JsonRpcFrame[],
    singleFrameRequest: boolean
  ): Promise<void> => {
    const read = await readBody(upstream, maxBodyBytes);
    if (!read.ok) {
      refuse(res, 502, "AgentWall refused the upstream response: it exceeded the body ceiling and was not scanned.");
      return;
    }

    const raw = read.body.trim();
    if (raw.length === 0) {
      // A 202 with no body is how MCP acknowledges notifications. There is nothing to scan; if this
      // listener refused part of the batch, those errors are still owed to the client.
      if (pending.length > 0) {
        respondJson(res, 200, singleFrameRequest && pending.length === 1 ? pending[0] : pending);
        return;
      }
      res.writeHead(upstream.statusCode ?? 204, clientResponseHeaders(upstream));
      res.end();
      return;
    }

    let payload: unknown;
    try {
      payload = JSON.parse(raw);
    } catch {
      opts.onMalformed?.(raw, "server_to_client");
      refuse(res, 502, "AgentWall refused the upstream response: it was not JSON and could not be scanned.");
      return;
    }

    const entries = Array.isArray(payload) ? payload : [payload];
    const out: JsonRpcFrame[] = [...pending];
    for (const entry of entries) {
      const frame = asFrame(entry);
      if (frame === undefined) {
        opts.onMalformed?.(raw, "server_to_client");
        refuse(res, 502, "AgentWall refused the upstream response: it was not JSON-RPC and could not be scanned.");
        return;
      }

      const action = await runInterceptor(opts.onServerFrame, frame);
      if (action.kind === "forward") {
        out.push(action.frame);
        continue;
      }
      // A blocked response frame becomes an error against the id the client is waiting on. A frame
      // with no id is a server notification: there is nothing to answer, so it is dropped and the
      // audit record is the only place it appears, exactly as on stdio.
      if (frame.id !== undefined && frame.id !== null) out.push(errorFrame(frame.id, action.error));
    }

    const upstreamStatus = upstream.statusCode ?? 200;
    const status = upstreamStatus >= 400 ? upstreamStatus : 200;
    if (out.length === 0) {
      res.writeHead(status, clientResponseHeaders(upstream));
      res.end();
      return;
    }
    respondJson(res, status, singleFrameRequest && !Array.isArray(payload) && out.length === 1 ? out[0] : out);
  };

  const handlePost = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const read = await readBody(req, maxBodyBytes);
    if (!read.ok) {
      refuse(res, 413, `Request body exceeds the ${maxBodyBytes}-byte ceiling; nothing was forwarded.`);
      return;
    }

    const parsed = parseBody(read.body);
    if (parsed.kind === "malformed") {
      // Refused at the transport, not scanned and not forwarded: a body we could not parse is a body
      // we could not inspect, and sending it upstream to see what the server makes of it is exactly
      // the delegation this listener exists to prevent.
      opts.onMalformed?.(read.body, "client_to_server");
      respondJson(res, 400, errorFrame(null, { code: parsed.code, message: parsed.message }), {
        connection: "close",
      });
      return;
    }

    const forward: JsonRpcFrame[] = [];
    const refused: JsonRpcFrame[] = [];
    for (const frame of parsed.frames) {
      const action = await runInterceptor(opts.onClientFrame, frame);
      if (action.kind === "forward") {
        forward.push(action.frame);
        continue;
      }
      // A blocked frame is answered with a JSON-RPC error and HTTP 200, not an HTTP error status.
      // A JSON-RPC-level refusal is a valid JSON-RPC response, and that is exactly what this is -
      // the transport worked perfectly. Returning 4xx or 5xx would tell the client the exchange
      // failed, and clients retry failed exchanges, which would mean retrying a decision that will
      // not change and turning one refusal into a loop against a server that never sees any of it.
      if (frame.id !== undefined && frame.id !== null) refused.push(errorFrame(frame.id, action.error));
    }

    if (forward.length === 0) {
      // Nothing survived, so the upstream is never contacted at all.
      if (refused.length === 0) {
        // Everything blocked was a notification, and a notification has no id to answer on.
        res.writeHead(202, { connection: "close" });
        res.end();
        return;
      }
      respondJson(res, 200, parsed.kind === "single" && refused.length === 1 ? refused[0] : refused);
      return;
    }

    const body = JSON.stringify(parsed.kind === "single" ? forward[0] : forward);
    const upstream = await callUpstream("POST", upstreamRequestHeaders(req, token !== undefined), body);
    res.on("close", () => upstream.destroy());

    const contentType = upstream.headers["content-type"] ?? "";
    if (contentType.includes("text/event-stream")) {
      await pumpSse(upstream, res, refused);
      return;
    }
    await relayJsonResponse(upstream, res, refused, parsed.kind === "single");
  };

  /**
   * GET opens the server-to-client stream; DELETE ends a session.
   *
   * Neither carries a request body, so there is nothing to scan on the way out - but the GET
   * response is a stream of frames the server chose to send unprompted, which is the least trusted
   * traffic on this transport, and it goes through the same response scanning as everything else.
   */
  const handleBodilessMethod = async (
    req: IncomingMessage,
    res: ServerResponse,
    method: "GET" | "DELETE"
  ): Promise<void> => {
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > 0) {
      refuse(res, 400, `A ${method} to the MCP endpoint must not carry a body; nothing was forwarded.`);
      return;
    }

    const upstream = await callUpstream(method, upstreamRequestHeaders(req, token !== undefined), undefined);
    res.on("close", () => upstream.destroy());

    const contentType = upstream.headers["content-type"] ?? "";
    if (contentType.includes("text/event-stream")) {
      await pumpSse(upstream, res, []);
      return;
    }
    await relayJsonResponse(upstream, res, [], false);
  };

  const server: Server = createServer((req, res) => {
    void (async () => {
      try {
        const method = req.method ?? "";
        if (method !== "POST" && method !== "GET" && method !== "DELETE") {
          refuse(res, 405, `Method ${method || "(none)"} is not part of the MCP HTTP transport.`, {
            allow: "POST, GET, DELETE",
          });
          return;
        }

        if (token !== undefined) {
          if (!tokenMatches(token, bearerToken(req.headers.authorization))) {
            refuse(res, 401, "A valid bearer token is required by this AgentWall MCP listener.", {
              "www-authenticate": "Bearer",
            });
            return;
          }
        } else if (!hostHeaderIsLocal(req.headers.host, boundPort)) {
          // Only on the tokenless path. A configured token already defeats rebinding - the
          // attacker's page cannot present a credential it was never given - so demanding both would
          // break a legitimate deployment behind a reverse proxy for no additional protection.
          refuse(res, 403, "This AgentWall MCP listener is tokenless and accepts only loopback Host authorities.");
          return;
        }

        if (method === "POST") {
          await handlePost(req, res);
          return;
        }
        await handleBodilessMethod(req, res, method);
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        if (!res.headersSent) {
          refuse(res, 502, `AgentWall could not reach the wrapped MCP server: ${detail}`);
          return;
        }
        // Headers are already out, so the only honest signal left is ending the response.
        res.end();
      }
    })();
  });

  return new Promise<McpHttpHandle>((resolve, reject) => {
    const onStartupError = (err: Error): void => reject(err);
    server.once("error", onStartupError);
    server.listen(opts.listenPort, listenHost, () => {
      server.removeListener("error", onStartupError);
      const address = server.address() as AddressInfo | null;
      boundPort = address === null ? opts.listenPort : address.port;
      resolve({
        port: boundPort,
        close: () =>
          new Promise<void>((resolveClose) => {
            for (const request of liveUpstream) request.destroy();
            liveUpstream.clear();
            server.close(() => resolveClose());
            // Streams that are open by design would otherwise keep close() pending forever, which
            // is a hang rather than a shutdown.
            server.closeAllConnections();
          }),
      });
    });
  });
}
