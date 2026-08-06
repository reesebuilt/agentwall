import type { Socket } from "net";
import { TLSSocket, connect as tlsConnect, createServer as createTlsServer, type SecureContext } from "tls";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "http";
import { request as httpsRequest } from "https";
import type { Writable } from "stream";
import { brotliDecompressSync, gunzipSync, inflateSync } from "zlib";
import { normalizeHostname } from "../planes/network/ssrf";
import { createCertMinter, inspectCa, probeOpenssl, resolveCaPaths, sanFor, type CertMinter, type MintStats } from "./mitm-ca";
import type { BodyVisibility, ProxyBody, ProxyDecideResult, ProxyEvent, ProxyRecord, ProxyVerdict } from "./forward-proxy";
import type { RiskLevel } from "../types";

/**
 * TLS interception: the only path in AgentWall that can read an https body.
 *
 * Everything else in the egress plane sees a destination and stops. The transparent listener
 * sees an SNI name, the forward proxy sees a CONNECT authority, and both stop there because the
 * session is encrypted. That is the honest limit of an observer, and it is why a clean DLP
 * history over https has meant nothing up to now: it could not distinguish "nothing was
 * exfiltrated" from "we could not see". This file removes that ambiguity for the hosts an
 * operator has explicitly decided to intercept, and it removes it by terminating TLS.
 *
 * INTERCEPTION IS OFF UNLESS AN OPERATOR TURNED IT ON. Not off in the sense of a conservative
 * default a config file might drift past: absent config means absent capability, there is no CA,
 * and nothing here runs. A security tool that decrypts its operator's traffic because it shipped
 * that way has not earned the trust it is asking for.
 *
 * WHAT TURNING IT ON COSTS, stated next to the code and not only in a document: a CA in a trust
 * store is a key that can impersonate every site to this host. AgentWall becomes a party to
 * every https session the agent makes, and the CA private key becomes the most valuable file on
 * the box. `mitm-ca.ts` is how that file is handled; `docs/tls-interception.md` is what the
 * operator is signing up for.
 *
 * REFUSING IS THE FAILURE MODE, NOT DEGRADING. If `openssl` is missing, or the CA is missing, or
 * its key is readable by anyone else, or nothing trusts it, interception does not start and the
 * process says which. It never falls back to blind tunnelling while the operator believes bodies
 * are being read. That exact shape of failure, a control that looks active and is not, has cost
 * this project twice already: an nftables ruleset that never loaded because `redirect` is a
 * reserved word, and a gitleaks config that reported a clean tree because it inherited no rules.
 * Both looked like passing controls. The same principle governs every partial read below: a body
 * this could not fully scan is recorded as partial or unscannable, never as clean.
 */

/** Buffer cap per body, matching the plaintext content-scan path so one number governs both. */
const MAX_BODY_BYTES = 256 * 1024;

/**
 * Ceiling on decompressed output.
 *
 * A response body is compressed and attacker-influenced, so a few bytes on the wire can ask for
 * an unbounded number in this heap. The bound is handed to zlib rather than checked afterwards:
 * `maxOutputLength` makes the decompressor refuse, which is the only place a bomb can be stopped
 * before the allocation happens.
 */
const MAX_DECOMPRESSED_BYTES = 4 * 1024 * 1024;

/**
 * Content types that are never buffered.
 *
 * An event stream has no end until the server says so, and waiting for the end before forwarding
 * anything turns a working stream into a hang. These are forwarded unread and recorded as
 * `stream`, which is an admission rather than a pass.
 */
const UNBUFFERABLE_TYPES = ["text/event-stream", "application/x-ndjson", "application/grpc"];

/**
 * How long a body may go quiet before what has arrived is treated as all this will scan.
 *
 * Reaching it does NOT truncate the traffic. The prefix is what gets scanned and the unread
 * remainder is piped on untouched, so the destination and the client both receive every byte
 * that was sent. What the timer bounds is how long inspection waits, not how much data survives.
 */
const BODY_STALL_MS = 1000;

/** The name the trust probe mints for. `.invalid` is reserved by RFC 2606 and never resolves. */
const TRUST_PROBE_HOST = "agentwall-trust-probe.invalid";

/**
 * Headers that describe a connection rather than a message, plus the framing pair.
 *
 * Hop-by-hop headers must not be relayed: they belong to the leg they arrived on. The framing
 * pair is stripped because this code decides framing itself, from what it actually forwards.
 * `host` is deliberately NOT in this list: it names the virtual host the client asked for, and
 * dropping it would send every request to a server's default vhost.
 */
const NOT_FORWARDED = new Set(["connection", "proxy-connection", "keep-alive", "te", "trailer", "upgrade", "transfer-encoding", "content-length"]);

const NO_STRINGS: readonly string[] = [];

export interface InterceptionConfig {
  enabled: boolean;
  caDir?: string;
  /**
   * Hosts to tunnel rather than intercept: the escape hatch for certificate-pinned clients.
   *
   * Exact match after normalisation, with no wildcard or suffix support, matching the egress
   * allowlist exactly. A looser convention beside that one would be a bypass waiting to happen:
   * an operator who writes `*.example.com` in one list and has it read as a literal by the other
   * half of the codebase silently gets nothing, or silently gets everything.
   */
  bypassHosts?: readonly string[];
  /**
   * Runtimes the operator states they installed the CA into.
   *
   * The trust probe below can only speak for this Node process. An agent written in Python
   * trusts certifi, Go trusts its own bundle, curl trusts the system store, and none of those
   * are visible from here. A non-empty list is the operator asserting they did an install this
   * cannot check, and it is what lets interception start when the probe fails for a reason that
   * is not a mistake. It is an assertion, logged as one. It proves nothing.
   */
  trustInstalledFor?: readonly string[];
}

export type InterceptorResolution =
  | { ok: true; interceptor: Interceptor; notes: readonly string[] }
  | { ok: false; reason: string; remedy: readonly string[] };

/** What `shouldIntercept` decided, and the visibility a record must therefore claim. */
export interface InterceptChoice {
  intercept: boolean;
  visibility: BodyVisibility;
  reason: string | null;
}

export interface InterceptStats extends MintStats {
  intercepted: number;
  bypassed: number;
  /** Connections that could not be intercepted after the decision to try. Never silent. */
  failed: number;
}

export interface InterceptArgs {
  clientSocket: Socket;
  /** Bytes that arrived after the CONNECT line and before the 200. Replayed, never dropped. */
  head: Buffer;
  host: string;
  port: number;
  /** The connection-level event, already attributed and already allowed by `decide`. */
  event: ProxyEvent;
  /** The single inspection seam. Called once per inner request and once per inner response. */
  decide: (event: ProxyEvent) => ProxyDecideResult;
  /** One record per inner HTTP exchange, on top of the connection record the caller files. */
  record: (record: ProxyRecord) => void;
  onError?: (err: Error, where: string) => void;
}

export interface Interceptor {
  shouldIntercept(host: string, port: number): InterceptChoice;
  intercept(args: InterceptArgs): void;
  stats(): InterceptStats;
  /** One line for the boot log: what is on, and what it still cannot see. */
  describe(): string;
}

/**
 * Check every precondition, then build an interceptor, or explain the refusal.
 *
 * Async only because the trust probe is a real TLS handshake, and that probe is why this runs at
 * boot rather than lazily: an operator who mistyped a path finds out when the process starts, in
 * front of the terminal they started it from, rather than on the first request of a deployment
 * they believed was inspecting.
 */
export async function resolveInterceptor(config: InterceptionConfig): Promise<InterceptorResolution> {
  const paths = resolveCaPaths(config.caDir);

  const openssl = probeOpenssl();
  if (!openssl.present) {
    return {
      ok: false,
      reason: `interception needs \`openssl\` to mint certificates and ${openssl.detail}`,
      remedy: [
        "Install it: apt-get install openssl, or dnf install openssl.",
        "`openssl` is a precondition of interception in the same way root and Linux are preconditions of the perimeter.",
        "AgentWall does not bundle a certificate library. X.509 issuance is not in the Node standard library, and a fourth npm dependency is a larger risk than a system binary you already have.",
      ],
    };
  }

  const ca = inspectCa(paths);
  if (!ca.present) {
    return {
      ok: false,
      reason: `interception is enabled but there is no CA to sign with: ${ca.problems.join("; ")}`,
      remedy: [`Create one: agentwall intercept init --ca-dir ${paths.dir}`, "Then install trust: agentwall intercept trust"],
    };
  }
  if (ca.problems.length > 0) {
    return {
      ok: false,
      reason: `the interception CA in ${paths.dir} cannot be used: ${ca.problems.join("; ")}`,
      remedy: ["Fix the problems above, then restart. None of them are safe to ignore."],
    };
  }

  const minter = createCertMinter(paths);

  // Proves the CA can actually sign and that Node will load what it signed. A CA that exists and
  // cannot mint is the same class of failure as a ruleset that exists and never loaded.
  if (minter.contextFor(TRUST_PROBE_HOST) === null) {
    return {
      ok: false,
      reason: `the CA in ${paths.dir} exists but could not sign a test certificate: ${minter.lastRefusal() ?? "no reason recorded"}`,
      remedy: [`Check the CA is intact: openssl x509 -in ${paths.certPath} -noout -text`],
    };
  }

  const trust = await probeTrust(minter);
  const declared = (config.trustInstalledFor ?? []).filter((entry) => entry.trim().length > 0);
  const notes: string[] = [
    `openssl: ${openssl.detail}`,
    `CA sha256: ${ca.fingerprint ?? "unavailable"}`,
    `CA expires: ${ca.notAfter ?? "unknown"}`,
  ];

  if (!trust.trusted && declared.length === 0) {
    return {
      ok: false,
      reason:
        `nothing on this host trusts the interception CA, so every intercepted connection would fail certificate ` +
        `verification inside the agent: ${trust.detail}`,
      remedy: [
        `Print the install instructions: agentwall intercept trust --ca-dir ${paths.dir}`,
        `For this Node process: export NODE_EXTRA_CA_CERTS=${paths.certPath} and restart. Node reads that variable once at startup, so a running process will not pick it up.`,
        "If you installed trust into a runtime this cannot see (Python certifi, Go, a container image), declare it with interception.trustInstalledFor and this check will take your word for it.",
      ],
    };
  }
  notes.push(
    trust.trusted
      ? "trust probe: this Node process verified a certificate minted by the CA"
      : `trust probe FAILED (${trust.detail}); starting anyway because interception.trustInstalledFor declares ${declared.join(", ")}. That is your assertion, not a measurement.`
  );

  const bypass = new Set((config.bypassHosts ?? []).map((entry) => normalizeHostname(entry)).filter((entry) => entry.length > 0));
  if (bypass.size > 0) notes.push(`bypassed, tunnelled with bodies still opaque: ${[...bypass].join(", ")}`);

  return { ok: true, interceptor: buildInterceptor(minter, bypass, notes), notes };
}

export interface TrustProbeResult {
  trusted: boolean;
  detail: string;
}

/**
 * Does anything on this host actually trust the CA?
 *
 * Answered by handshaking, not by looking for files in trust store directories. Every runtime
 * keeps its bundle somewhere different and several rebuild it on install, so a file check would
 * be a guess. A handshake against a leaf this CA just signed, using the ambient trust store with
 * no `ca` override, is the real question.
 *
 * WHAT IT DOES NOT PROVE, and this is the whole caveat: it speaks for this Node process only. The
 * agent being proxied may be Python, Go, curl, or a container with its own bundle, and this probe
 * cannot see any of them. Necessary condition, not sufficient one.
 */
export async function probeTrust(minter: CertMinter): Promise<TrustProbeResult> {
  const context = minter.contextFor(TRUST_PROBE_HOST);
  if (context === null) return { trusted: false, detail: "could not mint a probe certificate" };

  const settled = deferred<TrustProbeResult>();
  // Built from the same SecureContext the interceptor would serve, so this tests the real
  // artifact rather than a second certificate minted some other way.
  const server = createTlsServer({ SNICallback: (_name, cb) => cb(null, context) });
  server.on("secureConnection", (socket: TLSSocket) => socket.end());
  server.on("error", (err: Error) => settled.resolve({ trusted: false, detail: `probe server failed: ${err.message}` }));
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    const port = typeof address === "object" && address !== null ? address.port : 0;
    // servername rather than host: the probe name is reserved and never resolves, and Node
    // checks the certificate against servername when one is supplied.
    const client = tlsConnect({ host: "127.0.0.1", port, servername: TRUST_PROBE_HOST }, () => {
      const trusted = client.authorized;
      client.destroy();
      server.close();
      settled.resolve({
        trusted,
        detail: trusted ? "verified against the ambient trust store" : `not trusted: ${client.authorizationError?.message ?? "unknown reason"}`,
      });
    });
    // A verification failure arrives as a socket error, and its message is the reason.
    client.on("error", (err: Error) => {
      client.destroy();
      server.close();
      settled.resolve({ trusted: false, detail: err.message });
    });
  });
  return settled.promise;
}

function buildInterceptor(minter: CertMinter, bypass: ReadonlySet<string>, notes: readonly string[]): Interceptor {
  const counts = { intercepted: 0, bypassed: 0, failed: 0 };

  // One HTTP parser for every intercepted connection in the process, fed the decrypted socket.
  // Node's own parser is what makes this slice cost no dependency: an HTTP/1.1 parser is the
  // other thing a hand-rolled interceptor usually pulls in from a registry.
  const inner = createHttpServer();
  const contexts = new Map<TLSSocket, InnerContext>();

  inner.on("request", (req, res) => {
    const ctx = contexts.get(req.socket as TLSSocket);
    if (!ctx) {
      // Unreachable while `intercept` below is the only producer. If it ever happens the request
      // must not be forwarded unexamined: an unexamined body on the intercept path is exactly
      // the failure this file exists to prevent.
      res.writeHead(500).end("agentwall: intercepted request with no context\n");
      return;
    }
    handleInnerRequest(ctx, req, res);
  });
  inner.on("clientError", (_err: Error, socket: Socket) => {
    // A malformed request inside a tunnel this terminated. Nothing is open upstream and there is
    // nothing to forward, so closing is the whole correct response.
    try {
      socket.destroy();
    } catch {
      /* already gone */
    }
  });

  return {
    stats: () => ({ ...minter.stats(), ...counts }),
    describe: () => notes.join("; "),

    shouldIntercept(host: string, _port: number): InterceptChoice {
      const normalized = normalizeHostname(host);
      if (bypass.has(normalized)) {
        counts.bypassed += 1;
        return {
          intercept: false,
          visibility: "bypassed",
          reason: `${normalized} is on interception.bypassHosts, so this connection was tunnelled and its body was never read`,
        };
      }
      if (sanFor(normalized) === null) {
        return {
          intercept: false,
          visibility: "tunneled",
          reason: `no certificate can be minted for ${JSON.stringify(host)}, which is neither a plausible hostname nor an IPv4 literal, so this connection was tunnelled and its body was never read`,
        };
      }
      return { intercept: true, visibility: "intercepted", reason: null };
    },

    intercept(args: InterceptArgs): void {
      const { clientSocket, head, host, port } = args;
      const fallbackName = normalizeHostname(host);

      const defaultContext = minter.contextFor(fallbackName);
      if (defaultContext === null) {
        // `shouldIntercept` already refused unmintable names, so reaching here means the mint
        // itself failed: openssl broke, or the CA became unusable since boot. The connection is
        // refused rather than tunnelled. Tunnelling here would produce a body nobody read on a
        // connection whose record had already claimed interception.
        counts.failed += 1;
        const why = minter.lastRefusal() ?? "unknown mint failure";
        args.onError?.(new Error(`refusing ${fallbackName}: ${why}`), "tls-intercept-mint");
        clientSocket.on("error", () => {
          /* the client hung up on its own refusal */
        });
        clientSocket.destroy();
        return;
      }

      // The 200 goes out before the wrap, because the client will not send a ClientHello until
      // it believes the tunnel is open. No upstream socket is opened here: on this path upstream
      // is connected per inner request, against the real destination, verified against the real
      // trust store, so a decrypted request is re-encrypted rather than downgraded.
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

      let sniSeen: string | null = null;
      let mintFailure: string | null = null;

      const tlsSocket = new TLSSocket(clientSocket, {
        isServer: true,
        // Serves the name the client asked for rather than the one it typed on the CONNECT line.
        // Node parses the ClientHello for this, so there is no second TLS parser here:
        // `tls-peek.ts` reads a hello on the tunnelled path, and on this path the TLS stack that
        // is already terminating the connection reports the same field.
        SNICallback: (servername: string, cb: (err: Error | null, ctx?: SecureContext) => void) => {
          const wanted = normalizeHostname(servername ?? "");
          if (wanted.length === 0) {
            cb(null, defaultContext);
            return;
          }
          sniSeen = wanted;
          const context = minter.contextFor(wanted);
          if (context === null) {
            mintFailure = minter.lastRefusal() ?? `could not mint for ${wanted}`;
            // The handshake is refused rather than served under the wrong name. A certificate
            // for the CONNECT authority presented to a client that asked for something else
            // fails verification anyway, and refusing here puts the reason in this log.
            cb(new Error(`agentwall: ${mintFailure}`));
            return;
          }
          cb(null, context);
        },
      });

      tlsSocket.on("error", (err: Error) => {
        // A client that rejects the certificate lands here, and that is the pinned-client
        // symptom an operator needs named rather than left as a bare connection reset.
        counts.failed += 1;
        args.onError?.(err, `tls-intercept ${fallbackName}${mintFailure ? ` (${mintFailure})` : ""}`);
        try {
          clientSocket.destroy();
        } catch {
          /* already gone */
        }
      });

      tlsSocket.on("secure", () => {
        counts.intercepted += 1;
        const negotiated = sniSeen ?? (typeof tlsSocket.servername === "string" ? tlsSocket.servername : null);
        contexts.set(tlsSocket, {
          host: fallbackName,
          port,
          sni: negotiated !== null && negotiated.length > 0 ? negotiated : null,
          base: args.event,
          decide: args.decide,
          record: args.record,
          ...(args.onError ? { onError: args.onError } : {}),
        });
        tlsSocket.once("close", () => contexts.delete(tlsSocket));
        inner.emit("connection", tlsSocket);
      });

      // Pipelined bytes: rare, because a client normally waits for the 200 before speaking, but a
      // client that did not put its whole ClientHello here. Pushed back so the TLS stack reads
      // them as its first bytes. Safe to unshift because nothing on this path ever attached a
      // `data` listener to the raw socket, so it was never put into flowing mode.
      if (head.length > 0) clientSocket.unshift(head);
    },
  };
}

interface InnerContext {
  host: string;
  port: number;
  sni: string | null;
  base: ProxyEvent;
  decide: (event: ProxyEvent) => ProxyDecideResult;
  record: (record: ProxyRecord) => void;
  onError?: (err: Error, where: string) => void;
}

/**
 * One decrypted HTTP exchange: read it, ask policy about it twice, forward every byte of it.
 *
 * The two questions are asked at the two moments where the answer can still change what happens.
 * The request is inspected before anything is opened upstream, so a denial costs the destination
 * nothing, not even a TCP handshake. The response is inspected before any byte is written back to
 * the client, so a denial is a real 403 rather than a warning about data the agent already has.
 * The response pass is the one that matters most for a tool-using agent: a poisoned tool result
 * arrives in a response body, and a control that only reads requests cannot see it at all.
 */
function handleInnerRequest(ctx: InnerContext, req: IncomingMessage, res: ServerResponse): void {
  const startedAt = Date.now();
  const path = req.url ?? "/";
  const method = req.method ?? "GET";
  const requestHeaders = flattenHeaders(req.headers);

  readBody(req, "request", requestHeaders["content-type"])
    .then((requestBody) => {
      const requestEvent: ProxyEvent = {
        ...ctx.base,
        host: ctx.host,
        port: ctx.port,
        scheme: "https",
        method,
        startedAt,
        path,
        headers: requestHeaders,
        body: requestBody.scanned,
      };
      const requestVerdict = resolveVerdict(ctx.decide(requestEvent), requestBody.note);

      // Filed whether or not it was denied, and this is the point of the whole slice landing as
      // EVIDENCE rather than as a feature. A reviewer reading the ledger needs one row per
      // message, each carrying its own body and its own findings. Folding both directions into a
      // single row would leave a record whose `body` was the response while its matched rules
      // named a finding in the request, and a reviewer would have to guess which text the
      // finding was in. Byte counts are split so the two rows never double count: the request
      // row carries bytesUp, the response row carries bytesDown.
      ctx.record(finalise(requestEvent, requestVerdict, requestBody.scanned.bytes, 0, startedAt, requestBody.visibility));

      if (requestVerdict.decision === "deny") {
        // Denied before an upstream socket exists, so the destination never learns the request
        // was attempted. The unread remainder of the body is discarded with the connection.
        refuse(res, requestVerdict);
        return;
      }
      forward(ctx, requestEvent, requestVerdict, requestBody, res, startedAt);
    })
    .catch((err: unknown) => {
      ctx.onError?.(err as Error, `tls-intercept read ${ctx.host}${path}`);
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
}

function forward(
  ctx: InnerContext,
  requestEvent: ProxyEvent,
  requestVerdict: ResolvedVerdict,
  requestBody: ReadBody,
  res: ServerResponse,
  startedAt: number
): void {
  // Re-encrypted to the real destination and verified against the ambient trust store. There is
  // no `ca` override and no `rejectUnauthorized: false` anywhere on this path: interception must
  // not quietly become the thing that stops checking upstream certificates, which would turn a
  // visibility feature into a downgrade the operator installed themselves.
  const upstream = httpsRequest(
    {
      host: ctx.host,
      port: ctx.port,
      path: requestEvent.path ?? "/",
      method: requestEvent.method,
      headers: { ...forwardable(requestEvent.headers), ...framingFor(requestEvent.headers, requestBody) },
      // Only when the destination is a name. RFC 6066 forbids an IP literal in SNI, and Node
      // already warns that it will start ignoring one. `sanFor` is reused as the classifier
      // rather than a second address test written here: it is the same gate that decided this
      // host was mintable, so the two can never disagree about what counts as a hostname.
      ...(sanFor(ctx.sni ?? ctx.host)?.startsWith("DNS:") ? { servername: ctx.sni ?? ctx.host } : {}),
    },
    (upRes) => {
      const status = upRes.statusCode ?? 502;
      const responseHeaders = flattenHeaders(upRes.headers);
      readBody(upRes, "response", responseHeaders["content-type"], status)
        .then((responseBody) => {
          const responseEvent: ProxyEvent = { ...requestEvent, headers: responseHeaders, body: responseBody.scanned };
          const responseVerdict = fold(requestVerdict, resolveVerdict(ctx.decide(responseEvent), responseBody.note));
          const visibility = worseVisibility(requestBody.visibility, responseBody.visibility);

          if (responseVerdict.decision === "deny") {
            // Denied before a single response byte reached the client. This is the point of
            // inspecting responses at all: a poisoned tool result the agent never sees. The
            // unread remainder is dropped with the upstream socket, which is correct here
            // because the exchange is being refused rather than relayed.
            upRes.destroy();
            refuse(res, responseVerdict);
            ctx.record(finalise(responseEvent, responseVerdict, 0, responseBody.scanned.bytes, startedAt, visibility));
            return;
          }

          const headers = { ...forwardable(responseHeaders), ...framingFor(responseHeaders, responseBody) };
          res.writeHead(status, headers);
          sendBody(res, responseBody);
          ctx.record(finalise(responseEvent, responseVerdict, 0, responseBody.scanned.bytes, startedAt, visibility));
        })
        .catch((err: unknown) => {
          ctx.onError?.(err as Error, `tls-intercept response ${ctx.host}`);
          if (!res.headersSent) res.writeHead(502);
          res.end();
        });
    }
  );
  upstream.on("error", (err: Error) => {
    ctx.onError?.(err, `upstream ${ctx.host}:${ctx.port}`);
    if (!res.headersSent) res.writeHead(502);
    res.end();
    // Zero bytes on both sides: the request row above already carries what was buffered, and
    // this row exists to say the exchange failed, not to count the same bytes twice.
    ctx.record(finalise(requestEvent, requestVerdict, 0, 0, startedAt, requestBody.visibility));
  });
  sendBody(upstream, requestBody);
}

/**
 * Write a body onward: the prefix that was scanned, then whatever was never read.
 *
 * The prefix and the remainder together are byte-identical to what arrived. Inspection buffers a
 * bounded prefix; it does NOT decide how much of the body survives. A cap hit or a stall means
 * less was scanned, never that less was delivered, which is why `rest` is piped rather than
 * abandoned. Getting this wrong would silently truncate uploads, which is the same class of
 * quiet failure as a control that reports clean because it never ran.
 */
function sendBody(sink: Writable, body: ReadBody): void {
  if (body.prefix.length > 0) sink.write(body.prefix);
  if (body.rest === null) {
    sink.end();
    return;
  }
  body.rest.pipe(sink);
}

/**
 * The framing headers for what is about to be written, derived from what is about to be written.
 *
 * Fully buffered, so the exact length is known: state it, and let the de-chunked buffer be framed
 * by content-length regardless of how it arrived. Not fully buffered, so the total is whatever
 * the original said it was, because prefix plus remainder is the original: pass the original
 * framing through. Neither header present and not fully buffered means a close-delimited or
 * chunk-framed message whose length nobody stated, so nothing is stated here either and Node
 * frames it.
 */
function framingFor(original: Readonly<Record<string, string>> | undefined, body: ReadBody): Record<string, string> {
  if (body.rest === null) return { "content-length": String(body.prefix.length) };
  const chunked = original?.["transfer-encoding"];
  if (chunked) return { "transfer-encoding": chunked };
  const length = original?.["content-length"];
  return length ? { "content-length": length } : {};
}

function forwardable(headers: Readonly<Record<string, string>> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (NOT_FORWARDED.has(name)) continue;
    out[name] = value;
  }
  return out;
}

function refuse(res: ServerResponse, verdict: ResolvedVerdict): void {
  if (res.headersSent) {
    res.end();
    return;
  }
  const reason = verdict.reasons[0] ?? "denied by policy";
  // The reason reaches a header, and it can carry text an untrusted upstream influenced, so
  // anything outside printable ASCII is collapsed rather than trusted not to contain a CR.
  const safe = reason.replace(/[^\x20-\x7e]+/g, " ").slice(0, 180);
  res.writeHead(403, { "content-type": "text/plain", "x-agentwall-block-reason": safe }).end(`agentwall: ${safe}\n`);
}

interface ResolvedVerdict {
  decision: "allow" | "deny";
  reasons: readonly string[];
  matchedRules: readonly string[];
  riskLevel?: RiskLevel;
  metadata?: Readonly<Record<string, string>>;
  /** Which agent the decision resolved, echoed onto the record like the rest of the verdict. */
  attribution?: Readonly<Record<string, string>>;
  /**
   * Null on every inner exchange. Each one is a re-decision of a connection the CONNECT pass
   * already admitted, so the bytes are charged once, against the ticket that pass was handed.
   */
  budgetTicket?: number | null;
}

/**
 * Normalise a `decide` result, and attach the reason a body could not be fully read.
 *
 * The note rides on the verdict metadata rather than being dropped. A body this could not
 * decompress or could not finish reading has to reach the ledger as a stated limit, because a
 * record that says "scanned, nothing found" about bytes nobody decoded is the ambiguity this
 * whole slice exists to remove.
 */
function resolveVerdict(result: ProxyDecideResult, note: string | null): ResolvedVerdict {
  const base: ResolvedVerdict =
    result === "allow" || result === "deny"
      ? { decision: result, reasons: NO_STRINGS, matchedRules: NO_STRINGS }
      : normaliseVerdict(result);
  if (note === null) return base;
  return {
    ...base,
    reasons: [...base.reasons, note],
    metadata: { ...base.metadata, interceptBodyLimit: note },
  };
}

function normaliseVerdict(verdict: ProxyVerdict): ResolvedVerdict {
  return {
    decision: verdict.decision,
    reasons: verdict.reasons ?? NO_STRINGS,
    matchedRules: verdict.matchedRules ?? NO_STRINGS,
    ...(verdict.riskLevel ? { riskLevel: verdict.riskLevel } : {}),
    ...(verdict.metadata ? { metadata: verdict.metadata } : {}),
    ...(verdict.attribution ? { attribution: verdict.attribution } : {}),
    budgetTicket: verdict.budgetTicket ?? null,
  };
}

const RISK_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** Deny wins, reasons and rules union, highest risk survives. The plaintext path folds the same. */
function fold(first: ResolvedVerdict, second: ResolvedVerdict): ResolvedVerdict {
  const rank = (level?: RiskLevel): number => (level ? RISK_ORDER[level] ?? 0 : -1);
  const worst = rank(second.riskLevel) > rank(first.riskLevel) ? second.riskLevel : first.riskLevel;
  return {
    decision: first.decision === "deny" || second.decision === "deny" ? "deny" : "allow",
    reasons: [...first.reasons, ...second.reasons],
    matchedRules: [...new Set([...first.matchedRules, ...second.matchedRules])],
    ...(worst ? { riskLevel: worst } : {}),
    ...(first.metadata || second.metadata ? { metadata: { ...first.metadata, ...second.metadata } } : {}),
  };
}

/**
 * The weaker of two visibility claims, because a record describes one exchange.
 *
 * A whole request body and a truncated response body is not an intercepted exchange, it is a
 * partial one, and the record has to say the weaker thing or it overstates what was seen.
 */
const VISIBILITY_ORDER: Record<string, number> = { intercepted: 0, plaintext: 0, partial: 1, stream: 2, bypassed: 3, tunneled: 4 };

function worseVisibility(first: BodyVisibility, second: BodyVisibility): BodyVisibility {
  return (VISIBILITY_ORDER[second] ?? 0) > (VISIBILITY_ORDER[first] ?? 0) ? second : first;
}

/**
 * Turn an inspected event into a ledger record, leaving the content behind.
 *
 * `headers` and `body` are destructured out and DROPPED rather than being left to a type that
 * merely says they are absent. The record is serialised whole into the flat ledger and onto the
 * audit chain, so carrying them would write the credential a DLP rule just detected into the
 * evidence for its own detection, and put a request's `Authorization` header there beside it.
 * A type-level `Omit` would not have stopped that: spreading an event into an object literal is
 * not excess-property checked, so the fields would have travelled at runtime with the compiler
 * silent.
 *
 * The query string goes with them. A scanner has to see `?api_key=live_...` because that is where
 * a leaked key hides, and the ledger must not, for exactly the same reason.
 */
function finalise(
  event: ProxyEvent,
  verdict: ResolvedVerdict,
  bytesUp: number,
  bytesDown: number,
  startedAt: number,
  visibility: BodyVisibility
): ProxyRecord {
  // `credential` and `reDecision` leave with the content fields. The first is the secret the
  // agent presented to identify itself, withheld from every destination on purpose, so writing
  // it into the ledger would defeat the point of withholding it; the second describes a call
  // rather than a connection.
  const {
    headers: _headers,
    body: _body,
    credential: _credential,
    reDecision: _reDecision,
    path: target,
    ...rest
  } = event;
  void _headers;
  void _body;
  void _credential;
  void _reDecision;
  return {
    ...rest,
    ...(target === undefined ? {} : { path: stripQuery(target) }),
    decision: verdict.decision,
    reasons: [...verdict.reasons],
    matchedRules: [...verdict.matchedRules],
    ...(verdict.riskLevel ? { riskLevel: verdict.riskLevel } : {}),
    ...(verdict.metadata ? { metadata: verdict.metadata } : {}),
    durationMs: Date.now() - startedAt,
    bytesUp,
    bytesDown,
    bodyVisibility: visibility,
    // Echoed from the verdict, like the rest of it. Each inner exchange is a re-decision of a
    // connection the CONNECT pass already admitted, so its ticket is null and the bytes are
    // charged once, on the connection record the tunnel files when it closes.
    ...(verdict.attribution ? { attribution: verdict.attribution } : {}),
    budgetTicket: verdict.budgetTicket ?? null,
  };
}

/**
 * The pathname of a request target, without the query or the fragment.
 *
 * Deliberately a string split rather than `new URL`: the target on an intercepted request is
 * origin-form (`/v1/thing?x=1`), which `new URL` cannot parse without a base, and inventing a base
 * to satisfy a parser is how an absolute-form target would end up rewritten. The first `?` or `#`
 * ends the path in origin-form by definition.
 */
function stripQuery(target: string): string {
  const cut = target.search(/[?#]/);
  return cut < 0 ? target : target.slice(0, cut);
}

export interface ReadBody {
  /** The bytes that were buffered and scanned. A byte-exact prefix of the real body. */
  prefix: Buffer;
  /** The unread remainder, still open, or null when the whole body was buffered. */
  rest: IncomingMessage | null;
  scanned: ProxyBody;
  visibility: BodyVisibility;
  /** Why this body was not fully scannable, or null when it was. Reaches the record. */
  note: string | null;
}

/**
 * Buffer a bounded prefix of a message body and produce text a scanner can read.
 *
 * Four outcomes, and the record says which. `intercepted` means the whole body was read and what
 * was scanned is what was sent. `partial` means the cap or the stall timer won, so a clean scan
 * covers a prefix and the record says so. `stream` means the body was never buffered on purpose,
 * because buffering an event stream converts it into a hang. And a body whose content-encoding
 * could not be decoded comes back with a note and no text, recorded as a stated limit rather than
 * as a clean read.
 *
 * In none of those outcomes is a byte of traffic lost: the unread remainder is handed back for
 * the caller to pipe. Inspection is bounded; delivery is not.
 *
 * The text is DECOMPRESSED when it has to be, and that is not a nicety. A decrypted https body is
 * very often gzip, so a scanner handed raw bytes would report a clean scan of compressed noise
 * for most of the traffic this slice exists to read. That is the same lie as blind tunnelling,
 * arriving by a different route. What gets forwarded is always the original bytes; decompression
 * happens for inspection only, so upstream and client see exactly what they would have seen.
 */
async function readBody(
  message: IncomingMessage,
  direction: "request" | "response",
  contentType: string | undefined,
  status?: number
): Promise<ReadBody> {
  const withStatus = status === undefined ? {} : { status };
  const type = (contentType ?? "").toLowerCase();

  if (UNBUFFERABLE_TYPES.some((candidate) => type.startsWith(candidate))) {
    return {
      prefix: Buffer.alloc(0),
      rest: message,
      scanned: {
        direction,
        text: "",
        truncated: true,
        bytes: 0,
        // Not an empty body. A consumer that scanned "" here would file a clean result for a body
        // nobody read, which reads identically in the ledger to a real clean scan.
        unscannable: "stream",
        ...withStatus,
      },
      visibility: "stream",
      note: `${type} is never buffered, because buffering a stream converts it into a hang, so this body was forwarded unread`,
    };
  }

  const drained = await drain(message);
  const encoding = String(message.headers["content-encoding"] ?? "");
  const decoded = decodeForInspection(drained.prefix, encoding);
  const partial = drained.rest !== null;

  return {
    prefix: drained.prefix,
    rest: drained.rest,
    scanned: {
      direction,
      text: decoded.text,
      truncated: partial || !decoded.complete,
      bytes: drained.prefix.length,
      ...(encoding.trim() === "" ? {} : { encoding: encoding.trim() }),
      // An encoding this could not decode is marked, not silently handed over as empty text, for
      // the same reason as the stream case above.
      ...(decoded.complete ? {} : { unscannable: "encoding" as const }),
      ...withStatus,
    },
    visibility: partial || !decoded.complete ? "partial" : "intercepted",
    note: decoded.note ?? drained.note,
  };
}

interface Drained {
  prefix: Buffer;
  /** Non-null when reading stopped early. The stream is paused and safe to pipe. */
  rest: IncomingMessage | null;
  note: string | null;
}

/**
 * Read up to the cap, then stop reading WITHOUT stopping the traffic.
 *
 * Two things make this correct, and the second one is a bug that a small-body test cannot find.
 *
 * First, when the cap is hit mid-chunk the part beyond the cap has already been emitted and would
 * be lost, so it is pushed back with `unshift`. A version that simply stopped listening would
 * silently truncate every upload larger than the cap: the destination would receive a body cut to
 * 256 KiB and framed as if it were whole.
 *
 * Second, the ORDER. `unshift` on a stream that is still flowing with a live `data` listener
 * re-emits synchronously into that same listener, which unshifts again, which re-emits: a stack
 * overflow on the first body big enough to reach the cap. So the listener is detached and the
 * stream is paused BEFORE anything is pushed back, and only then does the caller's `pipe` resume
 * it. This is the whole reason `stopReading` exists as a separate step from settling.
 */
function drain(message: IncomingMessage): Promise<Drained> {
  const settled = deferred<Drained>();
  const chunks: Buffer[] = [];
  let buffered = 0;
  let done = false;

  /** Leave flowing mode with no listener attached, so an `unshift` cannot re-enter `onData`. */
  function stopReading(): void {
    clearTimeout(stall);
    message.off("data", onData);
    message.pause();
  }

  // A body that goes quiet must not hold inspection open forever. Reaching this forwards the
  // remainder unread; it does not drop it.
  const stall = setTimeout(() => {
    if (done) return;
    done = true;
    stopReading();
    settled.resolve({
      prefix: Buffer.concat(chunks),
      rest: message,
      note: `the body went quiet for ${BODY_STALL_MS}ms, so only the first ${buffered} bytes were scanned`,
    });
  }, BODY_STALL_MS);
  stall.unref?.();

  function complete(note: string | null): void {
    if (done) return;
    done = true;
    clearTimeout(stall);
    message.off("data", onData);
    settled.resolve({ prefix: Buffer.concat(chunks), rest: null, note });
  }

  function onData(chunk: Buffer): void {
    const room = MAX_BODY_BYTES - buffered;
    if (chunk.length >= room) {
      if (room > 0) {
        chunks.push(chunk.subarray(0, room));
        buffered += room;
      }
      const tail = chunk.subarray(room > 0 ? room : 0);
      done = true;
      // Detach and pause FIRST. See the ordering note above: reversing these two lines is a
      // stack overflow, not a style question.
      stopReading();
      if (tail.length > 0) message.unshift(tail);
      settled.resolve({
        prefix: Buffer.concat(chunks),
        rest: message,
        note: `the body ran past the ${MAX_BODY_BYTES} byte inspection cap, so only the first ${buffered} bytes were scanned`,
      });
      return;
    }
    chunks.push(chunk);
    buffered += chunk.length;
    stall.refresh?.();
  }

  message.on("data", onData);
  message.once("end", () => complete(null));
  message.once("aborted", () => complete("the body was aborted before it finished, so what was scanned may be incomplete"));
  message.once("error", (err: Error) => complete(`the body could not be read to the end (${err.message}), so what was scanned may be incomplete`));
  return settled.promise;
}

export interface DecodedBody {
  text: string;
  /** False when the bytes could not be turned into scannable text. Never reported as clean. */
  complete: boolean;
  note: string | null;
}

/**
 * Turn body bytes into text a scanner can read, decompressing when the encoding says to.
 *
 * Bounded with `maxOutputLength` rather than by a check afterwards: a compression bomb has to be
 * refused by the decompressor, because by the time there is a buffer to measure the allocation
 * has already happened. An encoding zlib does not implement, and a body that trips the bound,
 * both return `complete: false` with a reason, and the caller records that as a stated limit.
 * Neither is ever reported as a clean scan.
 */
export function decodeForInspection(raw: Buffer, encoding: string): DecodedBody {
  if (raw.length === 0) return { text: "", complete: true, note: null };
  const name = (encoding.split(",")[0] ?? "").trim().toLowerCase();
  if (name === "" || name === "identity") return { text: raw.toString("utf8"), complete: true, note: null };

  const limit = { maxOutputLength: MAX_DECOMPRESSED_BYTES };
  try {
    if (name === "gzip" || name === "x-gzip") return { text: gunzipSync(raw, limit).toString("utf8"), complete: true, note: null };
    if (name === "deflate") return { text: inflateSync(raw, limit).toString("utf8"), complete: true, note: null };
    if (name === "br") return { text: brotliDecompressSync(raw, limit).toString("utf8"), complete: true, note: null };
  } catch (err) {
    return { text: "", complete: false, note: `content-encoding ${name} could not be decoded, so this body was not scanned: ${(err as Error).message}` };
  }
  return { text: "", complete: false, note: `content-encoding ${name} is not one this can decode, so this body was not scanned` };
}

/**
 * Collapse Node's header bag to one string per name, lowercased.
 *
 * Repeated values are joined rather than having one win: a scanner shown only the first of two
 * `x-api-key` headers reports a clean read of a value it never looked at.
 */
function flattenHeaders(headers: IncomingMessage["headers"]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    out[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return out;
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}

/**
 * A settled-once promise handle over Node's event callbacks.
 *
 * `Promise.withResolvers` is what this should be, and it is what the runtime has: the engines
 * floor is Node 22.12. The compiler is the blocker, because tsconfig sets `lib: ES2022` and
 * withResolvers is ES2024. Written once here rather than inlining the executor at each of the
 * three event bridges below, and safe to delete the moment that `lib` moves.
 */
function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}
