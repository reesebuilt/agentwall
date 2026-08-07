import { randomBytes } from "crypto";
import { spawn } from "child_process";
import { createServer } from "http";
import type { IncomingMessage, Server, ServerResponse } from "http";
import type { AddressInfo } from "net";
import { readFileSync } from "fs";
import { loadConfig, resolveConfigSource } from "../config";
import { attributeSocket, listenerPids, processComm } from "../proxy/socket-attribution";
import type { SocketOwner } from "../proxy/socket-attribution";
import type { AgentMatchSignal, FleetAgentConfig } from "../fleet/registry";

/**
 * `agentwall verify-capture` - prove that one declared agent's traffic actually passes
 * through AgentWall, instead of assuming it because the configuration looks right.
 *
 * Why this command exists at all. Configuration is not the hard part; proof of capture is.
 * Three controls in this repository shipped green and non-functional: `perimeter install`
 * never installed anything because nft refused the socket it was handed, the gitleaks config
 * scanned nothing because it inherited no rules, and content inspection ran on zero proxied
 * traffic because the egress attempt could not carry a body. Every one of them passed its own
 * check. The integration story fails the same way unless something measures the traffic.
 *
 * The measurement, in three parts, reported separately because they fail separately:
 *
 *   1. A record for this exact request exists in the audit chain. This is the weakest of the
 *      three on its own: a chain record proves the proxy saw SOMETHING, not that everything
 *      went through it.
 *
 *   2. That record binds the request to the agent the operator named, and it says on what
 *      evidence. "Captured" and "captured, bound by comm only" are materially different
 *      claims, because comm is a 16-byte label the process writes itself; an operator told
 *      only the first has been misled by omission.
 *
 *   3. The canary was not reached directly. THIS is the point of the command. A request that
 *      arrives at the canary with no corresponding chain record is an agent that reached the
 *      network without passing through AgentWall, and a check that looked only for a chain
 *      record would report "captured" while half that agent's traffic went around the proxy.
 *
 * What the canary is: a single-use HTTP listener on an ephemeral loopback port, carrying a
 * 256-bit token in its path so no other traffic on this host can be mistaken for it. The port
 * is one AgentWall is not proxying, so a connection arriving there has taken exactly one of
 * two routes, and this command's job is to say which.
 *
 * The limits are in docs/verify-capture.md and repeated in every report, because the largest
 * one cannot be engineered away: this proves the path the agent used DURING the check. It
 * says nothing about an egress path the agent did not use while being watched.
 */

/** Every request reached the chain, bound to the named agent, and nothing went around. */
export const EXIT_CAPTURED = 0;
/** A real negative: no record, the wrong agent, or a bypass. */
export const EXIT_NOT_CAPTURED = 1;
/** The check could not be completed, so neither answer would be honest. */
export const EXIT_INCOMPLETE = 2;

/** Path prefix the canary serves. Fixed so an operator can recognise one in their own logs. */
export const CANARY_PATH_PREFIX = "/agentwall-canary/";

/**
 * How strong a binding tier actually is, and why.
 *
 * Ordering follows src/fleet/registry.ts. The sentences are printed verbatim next to the
 * result because the tier name alone does not tell an operator what it is worth: "comm" reads
 * like an identity and is a string the process chose.
 */
const TIER_STRENGTH: Record<AgentMatchSignal, CaptureTierStrength> = {
  credential: "strong",
  "uid+comm": "moderate",
  uid: "moderate",
  comm: "weak",
  none: "none",
};

const TIER_NOTE: Record<AgentMatchSignal, string> = {
  credential:
    "a secret presented on the proxy connection. Unforgeable by a process that cannot read " +
    "the secret, and forgeable by any process that can, which on a single-uid host is most " +
    "of them. This separates cooperating agents; it does not contain a hostile one.",
  "uid+comm":
    "the kernel's owner of the socket, narrowed by a process name. The uid half cannot be " +
    "changed without privilege; the comm half is self-declared, so the pair is exactly as " +
    "strong as its uid.",
  uid:
    "the kernel's owner of the socket. A process cannot change its own uid without privilege, " +
    "so this is real, and it is coarse: every agent sharing this uid is indistinguishable.",
  comm:
    "the process name, and nothing else. WEAK. comm is a 16-byte label the process writes " +
    "itself: process.title sets it to any string the process likes. This tells apart agents " +
    "you launched and is worth nothing against one that lies.",
  none: "no signal bound this connection to a declared agent.",
};

export type CaptureTierStrength = "strong" | "moderate" | "weak" | "none";
export type CaptureOutcome = "captured" | "bypass" | "not-captured" | "inconclusive";
export type AssertionStatus = "pass" | "fail" | "unproven";

/** One request the canary saw, and everything measurable about who opened it. */
export interface CanaryHit {
  at: string;
  method: string;
  path: string;
  /** Carried this check's token. Anything else is unrelated noise arriving on the port. */
  token: boolean;
  /** The token had already been spent. A second presentation is recorded and never served. */
  replay: boolean;
  peer: {
    address: string | null;
    port: number | null;
  } & SocketOwner;
}

/** The fields of an audit record this check reasons about. Everything else stays in the file. */
export interface MatchedRecord {
  id: string;
  timestamp: string;
  chainIndex: number;
  agentId: string;
  decision: string;
  matchedOn: AgentMatchSignal;
  declared: boolean;
  host: string;
  port: string;
  path: string;
  comm: string;
  pid: string;
  uid: string;
  transportMode: string;
  enforcementMode: string;
  reasons: string[];
}

export interface CaptureAssertion {
  id: "chain-record" | "agent-binding" | "no-bypass";
  title: string;
  status: AssertionStatus;
  detail: string;
}

/**
 * The independent second opinion on assertion 3.
 *
 * `unavailable` is a first-class answer, not a failure. attributeSocket is best-effort by
 * contract: a /proc race, an unreadable /proc/<pid>/fd on another uid, or a non-Linux host all
 * yield a null pid. Treating "could not tell" as "not the proxy" would turn every attribution
 * failure into a loud false BYPASS against a correctly captured agent, which is the worst
 * error this command could make.
 */
export interface Corroboration {
  status: "confirmed" | "contradicted" | "unavailable";
  detail: string;
  /**
   * Pids holding a listening socket on the proxy port, when they were readable.
   *
   * Carried alongside the verdict so the bypass message can name only the connections that
   * did NOT come from AgentWall. Empty means unknown, and a report that cannot tell the two
   * apart names every hit rather than accusing the wrong one.
   */
  proxyPids: number[];
}

/**
 * The check's own environment having already decided the answer.
 *
 * NO_PROXY is a list of destinations a client is TOLD to reach without a proxy. A canary on an
 * exempted address is therefore fetched directly by construction, and a bypass report would be
 * accusing the operator of a hole their own configuration opened. Where the exemption is
 * unambiguous the check cannot distinguish "this agent escapes the proxy" from "you told it to
 * for this address", so it says neither.
 *
 * `certainty` exists because NO_PROXY is honoured by the client, not enforced by anything.
 * Measured on this host rather than assumed, because the first version of this file asserted
 * the opposite from memory and was wrong. Two independent rigs, one here and one built by the
 * onboarding work, agreed:
 *
 *   curl 8.5.0            entry "127.0.0.1" exempts. Entry "127.0.0.1:<other port>" exempts
 *                         NOTHING: the port IS compared.
 *   python requests 2.31  identical on both counts.
 *   node 24 global fetch  does not read HTTP_PROXY at all by default, so it never proxies and
 *                         never exempts. With NODE_USE_ENV_PROXY=1 it proxies, honours
 *                         NO_PROXY, and compares the port like the other two.
 *
 * Go was NOT tested by either rig, so nothing here claims anything about it.
 *
 * So a bare host, or `*`, is `exempted`: every runtime measured skips the proxy, and reporting
 * a bypass would be a false alarm. A port-qualified entry naming some OTHER port is `possible`:
 * inert in all three, so the verdict STANDS, and it is still reported because three runtimes
 * are not every runtime and an operator chasing a bypass deserves to know the entry is there.
 *
 * None of this forgives the exemption. Every address NO_PROXY covers is one the agent is told
 * to reach without AgentWall, which on a real host means local databases, anything forwarded to
 * loopback over SSH, and any local proxy that itself reaches the internet.
 */
export interface ProxyExemption {
  /** The NO_PROXY entry that covers the canary. */
  entry: string;
  /** Which variable it came from, so the operator edits the right one. */
  source: string;
  /**
   * `exempted`: every client measured skips the proxy for this entry, so a direct hit proves
   * nothing and the verdict degrades to unproven. `possible`: it may or may not apply depending
   * on the client, so the verdict stands and the report says what is uncertain.
   */
  certainty: "exempted" | "possible";
  detail: string;
}

export interface CaptureReport {
  agentId: string;
  canaryUrl: string;
  token: string;
  auditPath: string;
  configPath: string | null;
  /** Strongest tier the config declares for this agent, or null when it declares none. */
  declaredTier: AgentMatchSignal | null;
  /** Tier the chain says actually bound the request. */
  observedTier: AgentMatchSignal | null;
  tierStrength: CaptureTierStrength;
  tierNote: string;
  /** Set when the agent is configured for a stronger tier than the one that bound it. */
  tierShortfall: string | null;
  assertions: CaptureAssertion[];
  corroboration: Corroboration;
  /** Set when NO_PROXY exempts the canary, which makes a direct hit configuration, not escape. */
  exemption: ProxyExemption | null;
  hits: CanaryHit[];
  records: MatchedRecord[];
  /** Present in --command mode. A fetch that never ran explains an inconclusive result. */
  fetch: {
    mode: "command" | "interactive";
    command?: string;
    commandArgv?: string[];
    exitCode?: number | null;
    stdout?: string;
    stderr?: string;
  };
  outcome: CaptureOutcome;
  captured: boolean;
  limits: string[];
}

export interface VerifyCaptureOptions {
  agentId: string;
  auditPath: string;
  configPath?: string;
  /** Shell string run to make the agent fetch the canary. Absent selects interactive mode. */
  command?: string;
  /** Typed argv used by the operator API. This path never starts a shell. */
  commandArgv?: string[];
  /** Interface the canary binds. Loopback unless the agent reaches this host by another address. */
  host: string;
  /** Proxy the agent is configured to use, for the peer-pid corroboration only. */
  proxyUrl?: string;
  /** How long interactive mode waits for the agent to fetch. */
  timeoutMs: number;
  /** How long to wait for the chain to catch up after the fetch completes. */
  settleMs: number;
  /** Where the report's own progress lines go. Kept off stdout so --json stays parseable. */
  log?: (line: string) => void;
  /** Interactive mode's "I am done" channel. Injectable so a test does not need a TTY. */
  stdin?: NodeJS.ReadableStream | null;
}

const LIMITS: readonly string[] = [
  "This proves the path the agent used for THIS request. It does not prove the agent has no " +
    "other egress path it simply did not use during the check.",
  "The canary is plain HTTP, so the token travels in a URL the proxy can read. An https " +
    "destination is a CONNECT tunnel with no visible path, which is why the check does not use " +
    "one, and an agent that honours HTTP_PROXY while ignoring HTTPS_PROXY passes this and " +
    "bypasses on https.",
  "Presence in the chain is checked, not chain integrity. Run `agentwall verify` for that.",
  "Peer attribution is best-effort and Linux-only. Where it is unavailable the result rests on " +
    "the chain record alone, and the report says so rather than guessing.",
];

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (err: unknown) => void;
}

/**
 * A settled-once promise handle over Node's event callbacks.
 *
 * `Promise.withResolvers` is what this should be, and it is what the runtime has: the engines
 * floor is Node 22.12. The compiler is the blocker, because tsconfig sets `lib: ES2022` and
 * withResolvers is ES2024. The same stand-in exists in src/proxy/tls-intercept.ts for the same
 * reason, and both are safe to delete the moment that `lib` moves.
 */
function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function sleep(ms: number): Promise<void> {
  const gate = deferred<void>();
  setTimeout(gate.resolve, ms);
  return gate.promise;
}

/**
 * 256 bits from the CSPRNG, hex encoded.
 *
 * Unguessable is the requirement, and it is load-bearing in both directions: an attacker who
 * could predict the token could satisfy the check without the agent making the call, and any
 * other process on this host that happened to probe the port must not be counted as the agent.
 * Hex rather than base64url so the token survives every shell, log format and URL parser it
 * passes through without an encoding question.
 */
export function mintCanaryToken(): string {
  return randomBytes(32).toString("hex");
}

/** The single-use listener, and the record of everything that arrived on it. */
export interface Canary {
  url: string;
  port: number;
  token: string;
  hits: CanaryHit[];
  /** Resolves on the first request carrying the token. Later replays do not re-fire it. */
  firstTokenHit: Promise<CanaryHit>;
  close(): Promise<void>;
}

/**
 * Bind the canary.
 *
 * Single-use means the TOKEN is spent, not that the listener stops: a second presentation is
 * answered 410 and recorded as a replay. Closing on the first hit would hide the case this
 * command exists to find, where an agent is captured AND also goes around, because only the
 * first of the two connections would ever be seen.
 */
export async function startCanary(host: string, token: string): Promise<Canary> {
  const hits: CanaryHit[] = [];
  let spent = false;
  const firstHit = deferred<CanaryHit>();

  const wanted = CANARY_PATH_PREFIX + token;

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // Resolved here, inside the request handler, because the socket has to still be open: the
    // /proc row that maps its ports to an inode exists only for the life of the connection.
    const peer: SocketOwner =
      req.socket.remotePort && req.socket.localPort
        ? attributeSocket(req.socket.remotePort, req.socket.localPort)
        : { pid: null, comm: null, uid: null };

    const path = (req.url ?? "").split("?")[0];
    const token_ = path === wanted;
    const replay = token_ && spent;
    const hit: CanaryHit = {
      at: new Date().toISOString(),
      method: req.method ?? "GET",
      path,
      token: token_,
      replay,
      peer: { address: req.socket.remoteAddress ?? null, port: req.socket.remotePort ?? null, ...peer },
    };
    hits.push(hit);

    req.resume();
    if (!token_) {
      res.writeHead(404, { "content-type": "text/plain", connection: "close" });
      res.end("agentwall canary: no such token\n");
      return;
    }
    if (replay) {
      res.writeHead(410, { "content-type": "text/plain", connection: "close" });
      res.end("agentwall canary: token already spent\n");
      return;
    }
    spent = true;
    res.writeHead(200, { "content-type": "text/plain", connection: "close" });
    res.end("agentwall canary: reached\n");
    firstHit.resolve(hit);
  });

  const listening = deferred<void>();
  server.once("error", listening.reject);
  server.listen(0, host, () => {
    server.removeListener("error", listening.reject);
    listening.resolve();
  });
  await listening.promise;

  const port = (server.address() as AddressInfo).port;
  const authority = host.includes(":") ? `[${host}]` : host;

  return {
    url: `http://${authority}:${port}${wanted}`,
    port,
    token,
    hits,
    firstTokenHit: firstHit.promise,
    close: () => {
      const closed = deferred<void>();
      server.close(() => closed.resolve());
      return closed.promise;
    },
  };
}

/**
 * Every egress record in the chain whose path carries this token.
 *
 * Read fresh on every poll rather than tailed: the writer is another process appending to the
 * same file, and a partially flushed final line is normal. Unparseable lines are skipped
 * instead of failing the read, because the alternative is a check that reports "no record"
 * whenever it happens to read mid-append.
 */
export function findChainRecords(auditPath: string, token: string): MatchedRecord[] {
  let content: string;
  try {
    content = readFileSync(auditPath, "utf8");
  } catch {
    return [];
  }
  const needle = CANARY_PATH_PREFIX + token;
  const found: MatchedRecord[] = [];
  for (const line of content.split("\n")) {
    if (!line.includes(token)) continue;
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    const action = typeof event["action"] === "string" ? (event["action"] as string) : "";
    if (!action.startsWith("egress:")) continue;
    const metadata = (event["metadata"] ?? {}) as Record<string, string>;
    if (metadata["path"] !== needle) continue;
    const integrity = (event["integrity"] ?? {}) as Record<string, unknown>;
    const reasons = Array.isArray(event["reasons"]) ? (event["reasons"] as string[]) : [];
    found.push({
      id: String(event["id"] ?? ""),
      timestamp: String(event["timestamp"] ?? ""),
      chainIndex: typeof integrity["chainIndex"] === "number" ? (integrity["chainIndex"] as number) : -1,
      agentId: String(event["agentId"] ?? ""),
      decision: String(event["decision"] ?? ""),
      // The chain is the source of truth for the tier, and an unrecognised value degrades to
      // "none" rather than being trusted: a record whose tier this build does not know is a
      // record whose binding this build cannot vouch for.
      matchedOn: normalizeTier(metadata["agentMatchedOn"]),
      declared: metadata["agentDeclared"] === "true",
      host: metadata["host"] ?? "",
      port: metadata["port"] ?? "",
      path: metadata["path"] ?? "",
      comm: metadata["comm"] ?? "unknown",
      pid: metadata["pid"] ?? "unknown",
      uid: metadata["uid"] ?? "unknown",
      transportMode: metadata["transportMode"] ?? "unknown",
      enforcementMode: metadata["enforcementMode"] ?? "unknown",
      reasons,
    });
  }
  return found;
}

function normalizeTier(value: string | undefined): AgentMatchSignal {
  switch (value) {
    case "credential":
    case "uid+comm":
    case "uid":
    case "comm":
      return value;
    default:
      return "none";
  }
}

/** The strongest tier this agent's declaration could produce, by the registry's precedence. */
export function declaredTierOf(agent: FleetAgentConfig): AgentMatchSignal {
  if (agent.match.credential) return "credential";
  if (agent.match.uid !== undefined && agent.match.comm && agent.match.comm.length > 0) return "uid+comm";
  if (agent.match.uid !== undefined) return "uid";
  if (agent.match.comm && agent.match.comm.length > 0) return "comm";
  return "none";
}

/**
 * Does the environment already tell the client to reach the canary without a proxy.
 *
 * Matching follows the common denominator of what clients actually do, which is the only
 * defensible rule when they disagree: comma separated entries, `*` matching everything, a
 * leading dot or a bare name matching by domain suffix, and an exact host matching itself.
 *
 * A `:port` on an entry is reported and never used to rule a match OUT. Measured across the
 * runtimes an agent is actually built on: curl matches the host and ignores the port entirely,
 * Go's httpproxy and Python's requests honour it, and Node's global fetch ignores NO_PROXY
 * altogether. Requiring the port to agree would let a `127.0.0.1:3000` entry look harmless
 * while curl treated it as all of loopback, which is the exact failure this function exists to
 * catch before it is reported as a bypass.
 */
export function proxyExemptionFor(host: string, port: number, env: NodeJS.ProcessEnv): ProxyExemption | null {
  const target = host.replace(/^\[|\]$/g, "").toLowerCase();

  // The WHOLE list, both variables, before answering. Returning on the first match would let a
  // narrow entry mask a broad one: `NO_PROXY=127.0.0.1:3000,127.0.0.1` would report `possible`
  // and leave a loud BYPASS standing, when the bare entry two characters later exempts the
  // canary for every client measured. An `exempted` match ends the walk because nothing beats
  // it; a `possible` one is only the answer if no `exempted` match exists anywhere.
  let possible: ProxyExemption | null = null;

  for (const name of ["NO_PROXY", "no_proxy"]) {
    const raw = env[name];
    if (!raw) continue;
    for (const piece of raw.split(",")) {
      const entry = piece.trim();
      if (!entry) continue;
      if (entry === "*") {
        return {
          entry,
          source: name,
          certainty: "exempted",
          detail: `${name} is "*", which exempts every destination from the proxy.`,
        };
      }
      const colon = entry.lastIndexOf(":");
      const bracket = entry.lastIndexOf("]");
      const hasPort = colon > bracket && /^\d+$/.test(entry.slice(colon + 1));
      const entryHost = (hasPort ? entry.slice(0, colon) : entry).replace(/^\[|\]$/g, "").toLowerCase();
      const entryPort = hasPort ? Number(entry.slice(colon + 1)) : null;
      const bare = entryHost.startsWith(".") ? entryHost.slice(1) : entryHost;
      if (!bare) continue;
      if (target !== bare && !target.endsWith(`.${bare}`)) continue;

      // An entry naming some other port is graded `possible`, not `exempted`. Measured: curl
      // 8.5.0, python requests 2.31.0, and node 24 under NODE_USE_ENV_PROXY all compare the
      // port, so "127.0.0.1:3000" exempts nothing in any of them. Three runtimes are not every
      // runtime, so it is reported; and because all three agree it is inert, it must not
      // suppress a bypass verdict.
      if (entryPort !== null && entryPort !== port) {
        possible ??= {
          entry,
          source: name,
          certainty: "possible",
          detail:
            `${name} contains "${entry}", whose host part covers the canary host ${target} but whose port ` +
            `${entryPort} is not the canary's ${port}. Measured on this host, curl 8.5.0, python requests ` +
            `2.31.0 and node 24 under NODE_USE_ENV_PROXY all compare the port, so for those three the entry ` +
            `exempts nothing and the verdict below stands. It is named here only because a client that ` +
            `compared the host alone would behave differently, and none of the three was yours.`,
        };
        continue;
      }
      return {
        entry,
        source: name,
        certainty: "exempted",
        detail:
          `${name} contains "${entry}", which covers the canary at ${target}:${port}.` +
          (entryPort === null ? "" : ` The entry names the canary's own port.`),
      };
    }
  }
  return possible;
}

/** Port of the proxy the agent is configured to use, for the peer-pid corroboration only. */
function proxyPortOf(proxyUrl: string | undefined): { port: number | null; local: boolean; source: string } {
  const raw =
    proxyUrl ??
    process.env["HTTPS_PROXY"] ??
    process.env["https_proxy"] ??
    process.env["HTTP_PROXY"] ??
    process.env["http_proxy"];
  if (!raw) return { port: null, local: false, source: "no proxy URL given and none in the environment" };
  let parsed: URL;
  try {
    parsed = new URL(raw.includes("://") ? raw : `http://${raw}`);
  } catch {
    return { port: null, local: false, source: `could not parse proxy URL ${JSON.stringify(raw)}` };
  }
  const port = Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80));
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  const local = host === "127.0.0.1" || host === "::1" || host === "localhost";
  return {
    port: Number.isInteger(port) && port > 0 ? port : null,
    local,
    source: raw,
  };
}

/**
 * Decide whether the process that reached the canary was AgentWall.
 *
 * Three-valued on purpose. A resolved pid that is not the proxy's is real evidence of a direct
 * connection and names the process that made it. A pid that could not be resolved is no
 * evidence at all, and the report says "unavailable" rather than contradicting a chain record
 * that may well be correct.
 */
function corroborate(hits: CanaryHit[], proxy: { port: number | null; local: boolean; source: string }): Corroboration {
  // Every request carrying the token, replays included. A replay is still a connection that
  // reached the canary, and in the case this command exists to catch (captured AND also going
  // around) the direct hit is the one that arrives second and gets refused 410. Excluding it
  // would throw away the only evidence of the bypass.
  const tokenHits = hits.filter((hit) => hit.token);
  if (tokenHits.length === 0) {
    return { status: "unavailable", detail: "nothing reached the canary, so there is no peer to attribute.", proxyPids: [] };
  }
  if (proxy.port === null) {
    return {
      status: "unavailable",
      detail: `the proxy's own pid is unknown (${proxy.source}), so the canary's peer cannot be compared against it. Pass --proxy to enable this check.`,
      proxyPids: [],
    };
  }
  if (!proxy.local) {
    return {
      status: "unavailable",
      detail: `the configured proxy ${proxy.source} is not on this host, so its pid is not visible in /proc here.`,
      proxyPids: [],
    };
  }
  const found = listenerPids(proxy.port);
  const proxyPids = [...found];
  if (found.size === 0) {
    return {
      status: "unavailable",
      detail: `no readable process holds a listening socket on port ${proxy.port}. /proc/<pid>/fd is only readable for your own uid, so this is expected when AgentWall runs as another user.`,
      proxyPids,
    };
  }
  const strangers = tokenHits.filter((hit) => hit.peer.pid !== null && !found.has(hit.peer.pid));
  if (strangers.length > 0) {
    return {
      status: "contradicted",
      detail:
        `${strangers.length} connection(s) to the canary came from a process that is not AgentWall: ` +
        `${strangers.map((hit) => `pid ${hit.peer.pid} (${describeOwner(hit.peer)})`).join(", ")}. ` +
        `The proxy on port ${proxy.port} is pid ${proxyPids.join(", ")}.`,
      proxyPids,
    };
  }
  if (tokenHits.some((hit) => hit.peer.pid === null)) {
    return {
      status: "unavailable",
      detail:
        "at least one process that reached the canary could not be resolved through /proc. Attribution is " +
        "best-effort, so this is not evidence either way.",
      proxyPids,
    };
  }
  // What was measured, and no more. This establishes that the hop came from THE PROCESS
  // LISTENING ON THE PORT YOU NAMED, which is not the same sentence as "it came from
  // AgentWall": nothing here reads that process's identity beyond its comm, and --proxy is
  // whatever the operator or the environment supplied. That the process is AgentWall is
  // established by the chain record existing, which is assertion 1's job, not this one's.
  const names = proxyPids.map((pid) => `${pid} (${processComm(pid) ?? "comm unknown"})`).join(", ");
  return {
    status: "confirmed",
    detail:
      `every connection to the canary came from the process listening on proxy port ${proxy.port}: ` +
      `pid ${names}. The hop was made by your proxy rather than by the agent.`,
    proxyPids,
  };
}

function describeOwner(owner: SocketOwner & { address?: string | null }): string {
  const parts = [`comm ${owner.comm ?? "unknown"}`, `uid ${owner.uid ?? "unknown"}`];
  return parts.join(", ");
}

/**
 * Turn what was observed into three separate verdicts.
 *
 * Split out from the orchestration so the decision table is one readable function and so a
 * test can hand it a synthetic observation. Nothing here does I/O.
 */
export function evaluate(input: {
  agentId: string;
  declaredTier: AgentMatchSignal | null;
  hits: CanaryHit[];
  records: MatchedRecord[];
  corroboration: Corroboration;
  /** NO_PROXY already told the client to reach the canary directly, when it did. */
  exemption?: ProxyExemption | null;
}): {
  assertions: CaptureAssertion[];
  observedTier: AgentMatchSignal | null;
  tierStrength: CaptureTierStrength;
  tierNote: string;
  tierShortfall: string | null;
  outcome: CaptureOutcome;
} {
  // A direct hit the environment ASKED for is not a measurement of anything. Where the exemption
  // is unambiguous, every branch below that would otherwise report a bypass degrades to unproven
  // and names the entry instead. Reporting "BYPASS" there would accuse an operator of a hole
  // their own NO_PROXY opened, on the default path of any onboarding profile that exempts
  // loopback.
  //
  // Only `certainty: "exempted"` downgrades anything. A `possible` match is reported and changes
  // no verdict: suppressing a bypass on a maybe would be the same unverified confidence in the
  // reassuring direction, and reassuring-and-wrong is the worse of the two failures here.
  //
  // Silence about the entry is not the alternative either. The full explanation goes on the
  // no-bypass assertion, which is the one it qualifies; the other two carry a pointer, because
  // three copies of the same paragraph is how an operator learns to skip all three.
  const declared = input.exemption ?? null;
  const exempt = declared?.certainty === "exempted" ? declared : null;
  const exemptionNote = exempt ? ` Caused by ${exempt.source}: see the no-bypass line below.` : "";
  const exemptionFix = declared
    ? ` ${declared.detail}` +
      (exempt
        ? ` This check cannot distinguish a direct hit from the one ${exempt.source} asked for, so it ` +
          `claims neither. Narrow ${exempt.source} so it does not cover the canary, or re-run with --host ` +
          `on an address it does not match. Note what the entry costs meanwhile: every address ` +
          `${exempt.source} covers is one this agent is told to reach without AgentWall.`
        : "")
    : "";
  const tokenHits = input.hits.filter((hit) => hit.token);
  const records = input.records;
  const bound = records.filter(
    // All three, because none of them is sufficient. `agentId` alone is not identity: the
    // registry falls back to the process comm for a connection no declared agent claims, so a
    // process that sets process.title to a declared agent's id produces a record carrying that
    // id with agentDeclared=false. Requiring the declaration and a real tier is what makes the
    // undeclared case fail the check for a named agent instead of satisfying it.
    (record) => record.declared && record.matchedOn !== "none" && record.agentId === input.agentId
  );

  const assertions: CaptureAssertion[] = [];

  // 1. Did anything reach the chain at all.
  if (records.length > 0) {
    const record = records[0];
    assertions.push({
      id: "chain-record",
      title: "recorded in the audit chain",
      status: "pass",
      detail:
        `${records.length} record(s) for this token. First: chain index ${record.chainIndex}, ` +
        `decision "${record.decision}", ${record.host}:${record.port} via the ${record.transportMode} ` +
        `transport in ${record.enforcementMode} mode.`,
    });
  } else if (tokenHits.length > 0) {
    assertions.push({
      id: "chain-record",
      title: "recorded in the audit chain",
      status: exempt ? "unproven" : "fail",
      detail:
        `the canary was reached ${tokenHits.length} time(s) and no record for this token exists in the chain.` +
        exemptionNote,
    });
  } else {
    assertions.push({
      id: "chain-record",
      title: "recorded in the audit chain",
      status: "unproven",
      detail: "nothing reached the canary and nothing reached the chain. The agent never fetched the URL.",
    });
  }

  // 2. Who the chain says made it, and on what evidence.
  let observedTier: AgentMatchSignal | null = null;
  if (bound.length > 0) {
    observedTier = bound.reduce<AgentMatchSignal>(
      (weakest, record) => (rank(record.matchedOn) < rank(weakest) ? record.matchedOn : weakest),
      bound[0].matchedOn
    );
    assertions.push({
      id: "agent-binding",
      title: "bound to the expected agent",
      status: "pass",
      detail: `bound to "${input.agentId}" at tier ${observedTier} (${TIER_STRENGTH[observedTier]}): ${TIER_NOTE[observedTier]}`,
    });
  } else if (records.length > 0) {
    const record = records[0];
    observedTier = record.matchedOn;
    const attribution = record.declared
      ? `bound to declared agent "${record.agentId}" at tier ${record.matchedOn}`
      : `recorded as unattributed: agentDeclared=false, agentMatchedOn=${record.matchedOn}, and the id "${record.agentId}" is the process comm rather than a declared agent`;
    assertions.push({
      id: "agent-binding",
      title: "bound to the expected agent",
      status: "fail",
      detail: `${attribution}. This does not satisfy a check for agent "${input.agentId}".`,
    });
  } else {
    assertions.push({
      id: "agent-binding",
      title: "bound to the expected agent",
      status: tokenHits.length > 0 && !exempt ? "fail" : "unproven",
      detail:
        tokenHits.length > 0
          ? `the request that reached the canary has no chain record, so nothing bound it to any agent.` +
            exemptionNote
          : "no request was recorded, so there is nothing to bind.",
    });
  }

  // 3. The one that matters: did anything reach the canary without going through AgentWall.
  const escapees = tokenHits.length - records.length;
  if (escapees > 0) {
    // Name the connections that were NOT AgentWall, when /proc could tell them apart. Where it
    // could not, every hit is listed: an operator hunting a leak needs the candidate set, and a
    // report that guessed which one escaped would send them after the wrong process.
    const proxyPids = new Set(input.corroboration.proxyPids);
    const suspects =
      proxyPids.size > 0 ? tokenHits.filter((hit) => hit.peer.pid === null || !proxyPids.has(hit.peer.pid)) : tokenHits;
    assertions.push({
      id: "no-bypass",
      title: "the canary was NOT reached directly",
      status: exempt ? "unproven" : "fail",
      detail: exempt
        ? `${escapees} of ${tokenHits.length} request(s) reached the canary with no matching chain record, ` +
          `and that is what ${exempt.source} asked for. ${namePeers(suspects.length > 0 ? suspects : tokenHits)}` +
          exemptionFix
        : `BYPASS. ${escapees} of ${tokenHits.length} request(s) reached the canary with no matching chain ` +
          `record. ${namePeers(suspects.length > 0 ? suspects : tokenHits)} That traffic left this host's control ` +
          `without passing through AgentWall.` +
          // A `possible` exemption reaches here: it did not earn a downgrade, and an operator
          // about to hunt this leak still needs to know the entry exists.
          exemptionFix,
    });
  } else if (input.corroboration.status === "contradicted") {
    assertions.push({
      id: "no-bypass",
      title: "the canary was NOT reached directly",
      status: exempt ? "unproven" : "fail",
      detail: exempt
        ? `the connection that reached the canary did not come from AgentWall, which is what ${exempt.source} ` +
          `asked for. ${input.corroboration.detail}` + exemptionFix
        : `BYPASS. ${input.corroboration.detail} A chain record exists, so something was proxied, but the connection that actually reached the canary was not it.`,
    });
  } else if (tokenHits.length === 0 && records.length === 0) {
    assertions.push({
      id: "no-bypass",
      title: "the canary was NOT reached directly",
      status: "unproven",
      detail: "nothing reached the canary, and nothing reached the chain either. This is silence, not proof.",
    });
  } else if (tokenHits.length === 0) {
    // Read from EVERY record, not records[0]. With a deny and an allow both on file, "the
    // destination never saw it" would be a confident claim drawn from whichever happened to be
    // written first, and the allow is the one that would matter.
    const decisions = [...new Set(records.map((record) => record.decision))];
    const allDenied = decisions.length === 1 && decisions[0] === "deny";
    assertions.push({
      id: "no-bypass",
      title: "the canary was NOT reached directly",
      status: "pass",
      detail:
        `nothing reached the canary. AgentWall recorded ${records.length} request(s) for this token and ` +
        `returned ${decisions.map((decision) => `"${decision}"`).join(", ")}` +
        (allDenied
          ? ". The destination never saw it: the proxy refuses before it opens an upstream socket, and " +
            "the canary confirms it heard nothing. A refusal at the proxy is capture and enforcement together."
          : ". Nothing arrived here regardless, so the request stopped between the proxy and the destination."),
    });
  } else {
    assertions.push({
      id: "no-bypass",
      title: "the canary was NOT reached directly",
      status: "pass",
      detail:
        `${tokenHits.length} request(s) reached the canary and each has a chain record. ` +
        (input.corroboration.status === "confirmed"
          ? `Independently confirmed: ${input.corroboration.detail}`
          : `Peer attribution unavailable (${input.corroboration.detail}), so this rests on the chain record.`),
    });
  }

  const tier = observedTier ?? "none";
  const shortfall =
    input.declaredTier && observedTier && rank(observedTier) < rank(input.declaredTier)
      ? `configured to bind at tier ${input.declaredTier}, actually bound at tier ${observedTier}. ` +
        (input.declaredTier === "credential"
          ? "The proxy credential is not being presented on this connection, so the strong binding the config promises is not in force."
          : "The stronger signal did not match.")
      : null;

  const failed = assertions.filter((assertion) => assertion.status === "fail");
  const bypassed = failed.some((assertion) => assertion.id === "no-bypass");
  const outcome: CaptureOutcome = bypassed
    ? "bypass"
    : failed.length > 0
      ? "not-captured"
      : assertions.some((assertion) => assertion.status === "unproven")
        ? "inconclusive"
        : "captured";

  return {
    assertions,
    observedTier,
    tierStrength: TIER_STRENGTH[tier],
    tierNote: TIER_NOTE[tier],
    tierShortfall: shortfall,
    outcome,
  };
}

const TIER_ORDER: AgentMatchSignal[] = ["none", "comm", "uid", "uid+comm", "credential"];
function rank(tier: AgentMatchSignal): number {
  return TIER_ORDER.indexOf(tier);
}

function namePeers(hits: CanaryHit[]): string {
  const named = hits
    .map((hit) =>
      hit.peer.pid === null
        ? `${hit.method} ${hit.path} from ${hit.peer.address ?? "unknown"}:${hit.peer.port ?? "?"} (process unresolved)`
        : `${hit.method} ${hit.path} from pid ${hit.peer.pid} (${describeOwner(hit.peer)})`
    )
    .join("; ");
  return named ? `Reached by: ${named}.` : "";
}

/**
 * Drive the fetch, wait for the evidence to settle, and judge it.
 *
 * The child's environment is INHERITED and never augmented with proxy variables. Injecting
 * HTTPS_PROXY here would measure this function's environment rather than the agent's real
 * configuration, and would report "captured" for an agent that is not configured at all.
 */
export async function runVerifyCapture(options: VerifyCaptureOptions): Promise<CaptureReport> {
  if (options.command !== undefined && options.commandArgv !== undefined) {
    throw new Error("verify-capture takes command or commandArgv, not both.");
  }
  const typedCommand = options.commandArgv === undefined
    ? undefined
    : validateCaptureCommandArgv(options.commandArgv);
  const log = options.log ?? (() => {});
  const configPath = resolveConfigSource(options.configPath);

  let declaredTier: AgentMatchSignal | null = null;
  let declared: FleetAgentConfig | undefined;
  try {
    const config = loadConfig(options.configPath);
    declared = config.fleet?.agents.find((agent) => agent.id === options.agentId);
    if (declared) declaredTier = declaredTierOf(declared);
  } catch (err) {
    // A config that will not load is worth saying out loud and is not fatal here: the chain is
    // the evidence, and the declaration only tells us what tier to EXPECT.
    log(`could not read the fleet declaration: ${(err as Error).message}`);
  }
  if (!declared) {
    log(
      `note: no agent "${options.agentId}" is declared in ${configPath ?? "any config file found"}. ` +
        `The check still runs against the chain, and the expected binding tier is unknown.`
    );
  }

  const token = mintCanaryToken();
  const canary = await startCanary(options.host, token);
  const proxy = proxyPortOf(options.proxyUrl);

  // The canary must not land on the forward proxy's own port. Two bound listeners cannot share
  // one, so this is belt and braces, and it costs one comparison.
  //
  // Note what this does NOT establish: that nothing else routes this port. A transparent
  // perimeter installed by `agentwall perimeter` redirects by uid, not by port, and could carry
  // a "direct" connection into the proxy anyway. That would make the capture real rather than
  // this check wrong, and docs/verify-capture.md says so under limits.
  if (proxy.port !== null && proxy.port === canary.port) {
    await canary.close();
    throw new Error(
      `the canary was given port ${canary.port}, which is the proxy's own port. Re-run; the ephemeral port will differ.`
    );
  }

  // Read the environment the CHILD will inherit, which is this process's, because the fetch is
  // never given an augmented one. Warned about up front rather than only in the verdict: an
  // operator watching an interactive run should know before they go and drive their agent.
  //
  // Branched on certainty, because the two cases lead to opposite verdicts and a single
  // reassuring sentence covering both would be a promise this code does not keep.
  const exemption = proxyExemptionFor(options.host, canary.port, process.env);
  if (exemption) {
    log(
      `warning: ${exemption.detail} ` +
        (exemption.certainty === "exempted"
          ? `A direct hit will be reported as unproven rather than as a bypass, because this check cannot ` +
            `tell the two apart. Narrow ${exemption.source} or pass --host.`
          : `The verdict below still stands, up to and including a bypass. This is named so you can rule ` +
            `the entry out yourself.`)
    );
  }

  const fetch: CaptureReport["fetch"] = typedCommand
    ? { mode: "command", commandArgv: [...typedCommand] }
    : options.command
      ? { mode: "command", command: options.command }
      : { mode: "interactive" };
  try {
    if (typedCommand) {
      const result = await runCommandArgv(typedCommand, canary.url, options.timeoutMs);
      fetch.exitCode = result.exitCode;
      fetch.stdout = result.stdout;
      fetch.stderr = result.stderr;
      if (result.exitCode !== 0) {
        log(`the fetch command exited ${result.exitCode ?? "on a signal"}.`);
        if (result.stderr.trim()) log(result.stderr.trim().split("\n").slice(-5).join("\n"));
      }
    } else if (options.command) {
      const result = await runCommand(options.command, canary.url, options.timeoutMs);
      fetch.exitCode = result.exitCode;
      fetch.stdout = result.stdout;
      fetch.stderr = result.stderr;
      if (result.exitCode !== 0) {
        log(`the fetch command exited ${result.exitCode ?? "on a signal"}.`);
        if (result.stderr.trim()) log(result.stderr.trim().split("\n").slice(-5).join("\n"));
      }
    } else {
      await waitInteractive(canary, options, log);
    }

    // Settle. The proxy writes its record when the connection closes, so a record can trail the
    // fetch by a few milliseconds. The loop waits for one record PER canary hit rather than for
    // the first record, because "more hits than records" is precisely how a bypass is detected
    // and a proxied second request whose record is still in flight looks exactly like one. The
    // full wait is only paid when a record never arrives, which is the case that must not be
    // rushed.
    const deadline = Date.now() + options.settleMs;
    let records = findChainRecords(options.auditPath, token);
    while (records.length < Math.max(1, canary.hits.filter((hit) => hit.token).length) && Date.now() < deadline) {
      await sleep(100);
      records = findChainRecords(options.auditPath, token);
    }

    const corroboration = corroborate(canary.hits, proxy);
    const verdict = evaluate({
      agentId: options.agentId,
      declaredTier,
      hits: canary.hits,
      records,
      corroboration,
      exemption,
    });

    return {
      agentId: options.agentId,
      canaryUrl: canary.url,
      token,
      auditPath: options.auditPath,
      configPath,
      declaredTier,
      observedTier: verdict.observedTier,
      tierStrength: verdict.tierStrength,
      tierNote: verdict.tierNote,
      tierShortfall: verdict.tierShortfall,
      assertions: verdict.assertions,
      corroboration,
      exemption,
      hits: [...canary.hits],
      records,
      fetch,
      outcome: verdict.outcome,
      captured: verdict.outcome === "captured",
      limits: [...LIMITS],
    };
  } finally {
    await canary.close();
  }
}
interface CommandResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

function runCaptureChild(executable: string, args: string[], url: string, timeoutMs: number): Promise<CommandResult> {
  const done = deferred<CommandResult>();
  const grouped = process.platform !== "win32";
  const child = spawn(executable, args, {
    env: { ...process.env, AGENTWALL_CANARY_URL: url },
    stdio: ["ignore", "pipe", "pipe"],
    detached: grouped,
  });
  let stdout = "";
  let stderr = "";
  let settled = false;
  let timer: NodeJS.Timeout;
  const finish = (result: CommandResult): void => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    done.resolve(result);
  };

  child.stdout?.on("data", (chunk) => {
    if (stdout.length < 64 * 1024) stdout += String(chunk);
  });
  child.stderr?.on("data", (chunk) => {
    if (stderr.length < 64 * 1024) stderr += String(chunk);
  });
  child.on("error", (error) => {
    const separator = stderr.length === 0 || stderr.endsWith("\n") ? "" : "\n";
    finish({ exitCode: null, stdout, stderr: `${stderr}${separator}${String(error)}` });
  });
  child.on("close", (code) => finish({ exitCode: code, stdout, stderr }));

  timer = setTimeout(() => {
    const timeoutMessage = `Capture command timed out after ${timeoutMs} ms.`;
    const separator = stderr.length === 0 || stderr.endsWith("\n") ? "" : "\n";
    try {
      if (grouped && child.pid !== undefined) {
        process.kill(-child.pid, "SIGKILL");
      } else {
        child.kill("SIGKILL");
      }
    } catch {
      child.kill("SIGKILL");
    }
    child.stdout?.destroy();
    child.stderr?.destroy();
    child.unref();
    finish({ exitCode: null, stdout, stderr: `${stderr}${separator}${timeoutMessage}` });
  }, timeoutMs);

  return done.promise;
}

/**
 * Run the operator's fetch command with the canary URL substituted.
 *
 * `{url}` is replaced wherever it appears; with no placeholder the URL is appended as the last
 * argument, which is what every HTTP client on a command line expects. The URL is single
 * quoted because it goes through a shell, and it is ours: hex and ASCII punctuation only, so
 * the quoting is correctness rather than a defence against content we do not control.
 */
function runCommand(command: string, url: string, timeoutMs: number): Promise<CommandResult> {
  const quoted = `'${url}'`;
  const line = command.includes("{url}") ? command.split("{url}").join(quoted) : `${command} ${quoted}`;
  return runCaptureChild("/bin/sh", ["-c", line], url, timeoutMs);
}

const CAPTURE_SHELL_SYNTAX = /[\0\r\n;&|`$<>]/;

export function validateCaptureCommandArgv(commandArgv: readonly string[]): string[] {
  if (commandArgv.length === 0) {
    throw new Error("verify-capture commandArgv is empty.");
  }
  let evalSource = false;
  for (const value of commandArgv) {
    if (value.length === 0) {
      throw new Error("verify-capture commandArgv contains an empty value.");
    }
    const normalized = value.replaceAll("{url}", "");
    if (normalized.includes("\0")) {
      throw new Error("verify-capture commandArgv contains shell syntax.");
    }
    if (evalSource) {
      evalSource = false;
      continue;
    }
    if (value === "-e" || value === "--eval") {
      evalSource = true;
      continue;
    }
    if (CAPTURE_SHELL_SYNTAX.test(normalized)) {
      throw new Error("verify-capture commandArgv contains shell syntax.");
    }
  }
  return [...commandArgv];
}

function runCommandArgv(commandArgv: readonly string[], url: string, timeoutMs: number): Promise<CommandResult> {
  const safe = validateCaptureCommandArgv(commandArgv);
  const executable = safe[0];
  let substituted = false;
  const args = safe.slice(1).map((value) => {
    if (!value.includes("{url}")) return value;
    substituted = true;
    return value.replaceAll("{url}", url);
  });
  if (!substituted) args.push(url);
  return runCaptureChild(executable, args, url, timeoutMs);
}

/**
 * Interactive mode: print the URL, then wait for whichever comes first.
 *
 * Three ways out, because all three happen. The canary being hit is the normal one. A line on
 * stdin covers the case where AgentWall refused the destination, so the canary is never reached
 * and waiting for it would hang until the timeout. The timeout covers an operator who walked
 * away.
 */
async function waitInteractive(
  canary: Canary,
  options: VerifyCaptureOptions,
  log: (line: string) => void
): Promise<void> {
  const stdin = options.stdin === undefined ? process.stdin : options.stdin;
  // Promise the Enter key only when something can actually deliver it. Under `< /dev/null`, in
  // a pipeline, or in CI, stdin never emits and "Press Enter" is an instruction that silently
  // does nothing until the timeout expires. Read from the stream rather than assumed.
  const readable = Boolean(stdin) && (stdin as NodeJS.ReadStream).readable !== false;

  log(`Have ${options.agentId} fetch this URL, then this check will continue:`);
  log("");
  log(`    ${canary.url}`);
  log("");
  log(
    `Waiting up to ${Math.round(options.timeoutMs / 1000)}s, or until the canary is reached.` +
      (readable
        ? ` Press Enter when the agent has tried, which is how you finish the check if AgentWall ` +
          `refused the destination and the canary was therefore never reached.`
        : ` Standard input is not readable here, so there is no way to finish early: if AgentWall ` +
          `refuses the destination the canary is never reached and this waits out the timeout. ` +
          `Use --timeout to shorten it.`)
  );

  const operatorDone = deferred<void>();
  const onLine = (): void => operatorDone.resolve();
  if (stdin) {
    stdin.on("data", onLine);
    if (typeof (stdin as NodeJS.ReadStream).resume === "function") (stdin as NodeJS.ReadStream).resume();
  }

  const timedOut = deferred<void>();
  const timer = setTimeout(timedOut.resolve, options.timeoutMs);

  try {
    await Promise.race([canary.firstTokenHit.then(() => undefined), operatorDone.promise, timedOut.promise]);
  } finally {
    clearTimeout(timer);
    if (stdin) {
      stdin.removeListener("data", onLine);
      if (typeof (stdin as NodeJS.ReadStream).pause === "function") (stdin as NodeJS.ReadStream).pause();
    }
  }
}

const STATUS_LABEL: Record<AssertionStatus, string> = {
  pass: "PASS",
  fail: "FAIL",
  unproven: "????",
};

const HEADLINE: Record<CaptureOutcome, string> = {
  captured: "CAPTURED",
  bypass: "BYPASS DETECTED",
  "not-captured": "NOT CAPTURED",
  inconclusive: "INCONCLUSIVE",
};

/** The human report. Every claim carries the evidence it rests on, in the same block. */
export function formatCaptureReport(report: CaptureReport): string {
  const lines: string[] = [];
  lines.push(`${HEADLINE[report.outcome]}  agent "${report.agentId}"`);
  lines.push(`  canary   ${report.canaryUrl}`);
  lines.push(`  chain    ${report.auditPath}`);
  if (report.exemption) {
    // Above the assertions, not buried under them. This one line changes how every line below
    // it should be read, and an operator who scrolls to the verdict and stops must still see it.
    lines.push(`  WARNING  ${report.exemption.detail}`);
    lines.push(
      `           Every address ${report.exemption.source} covers is one this agent is told to reach ` +
        `without AgentWall.` +
        (report.exemption.certainty === "exempted"
          ? ` Narrow it, or pass --host to put the canary somewhere it does not match.`
          : ` It did not change the verdict below.`)
    );
  }
  lines.push("");

  for (const assertion of report.assertions) {
    lines.push(`${STATUS_LABEL[assertion.status]}  ${assertion.title}`);
    lines.push(`      ${assertion.detail}`);
  }
  lines.push("");

  if (report.observedTier) {
    lines.push(`Binding tier: ${report.observedTier} (${report.tierStrength})`);
    lines.push(`  ${report.tierNote}`);
  } else {
    lines.push("Binding tier: none observed.");
  }
  if (report.declaredTier) {
    lines.push(`  Declared in ${report.configPath ?? "config"}: ${report.declaredTier}.`);
  }
  if (report.tierShortfall) {
    lines.push(`  WEAKER THAN CONFIGURED: ${report.tierShortfall}`);
  }

  if (report.outcome === "captured" && report.tierStrength === "weak") {
    lines.push("");
    lines.push(
      "Captured, and weakly bound. comm is self-declared, so this says the traffic is governed " +
        "and does not say the process is who it claims to be. Add a credential to the agent's " +
        "match rule for a binding no process can assert without reading the secret."
    );
  }

  if (report.hits.length > 0) {
    lines.push("");
    lines.push("Canary hits:");
    for (const hit of report.hits) {
      const who =
        hit.peer.pid === null
          ? `${hit.peer.address ?? "unknown"}:${hit.peer.port ?? "?"} (process unresolved)`
          : `pid ${hit.peer.pid} (${describeOwner(hit.peer)})`;
      const kind = !hit.token ? "unrelated" : hit.replay ? "REPLAY, refused 410" : "token, served once";
      lines.push(`  ${hit.at}  ${hit.method} ${hit.path}  ${kind}  from ${who}`);
    }
  }

  if (report.fetch.mode === "command" && report.fetch.exitCode !== 0 && report.fetch.exitCode !== undefined) {
    lines.push("");
    lines.push(`Fetch command exited ${report.fetch.exitCode ?? "on a signal"}.`);
  }

  lines.push("");
  lines.push("What this does NOT prove:");
  for (const limit of report.limits) lines.push(`  - ${limit}`);

  return lines.join("\n");
}

export function captureExitCode(report: CaptureReport): number {
  switch (report.outcome) {
    case "captured":
      return EXIT_CAPTURED;
    case "inconclusive":
      return EXIT_INCOMPLETE;
    default:
      return EXIT_NOT_CAPTURED;
  }
}

const USAGE = [
  "Usage: agentwall verify-capture --agent <id> [--command '<cmd>'] [options]",
  "",
  "Prove that one declared agent's traffic actually passes through AgentWall, by making the",
  "agent fetch a single-use canary URL and then asserting three things separately:",
  "  1. a record for that exact request is in the audit chain,",
  "  2. the record binds it to the named agent, and at which tier,",
  "  3. the canary was NOT reached directly, which is the one that catches a bypass.",
  "",
  "Options:",
  "  --agent <id>          Declared agent the traffic must bind to. Required.",
  "  --command '<cmd>'     Shell command that makes the agent fetch. '{url}' is substituted;",
  "                        with no placeholder the URL is appended as the last argument.",
  "                        Omit this for interactive mode, which prints the URL and waits.",
  "  --audit <path>        Audit chain file. Defaults to $AGENTWALL_AUDIT_FILE.",
  "  --config <path>       Config file naming the fleet. Defaults to the usual discovery.",
  "  --proxy <url>         Proxy the agent is configured to use. Enables the independent",
  "                        peer-pid check on top of the chain correlation.",
  "  --host <addr>         Interface the canary binds. Default 127.0.0.1.",
  "  --timeout <ms>        How long to wait for the fetch. Default 120000.",
  "  --settle-ms <ms>      How long to wait for the chain to catch up. Default 3000.",
  "  --json                Machine-readable report.",
  "",
  "Exit codes: 0 captured, 1 not captured or bypassed, 2 the check could not be completed.",
  "",
  "The fetch inherits your environment and this command never injects proxy variables into it.",
  "Injecting them would test this command's environment rather than the agent's configuration.",
].join("\n");

interface ParsedCaptureArgs {
  agent?: string;
  command?: string;
  audit?: string;
  config?: string;
  proxy?: string;
  host: string;
  timeoutMs: number;
  settleMs: number;
  json: boolean;
  help: boolean;
}

class UsageError extends Error {}

function parseCaptureArgs(argv: string[]): ParsedCaptureArgs {
  const parsed: ParsedCaptureArgs = {
    host: "127.0.0.1",
    timeoutMs: 120_000,
    settleMs: 3_000,
    json: false,
    help: false,
  };

  const value = (flag: string, index: number): string => {
    const next = argv[index + 1];
    if (next === undefined || next.startsWith("--")) throw new UsageError(`${flag} needs a value.`);
    return next;
  };
  const positiveInt = (flag: string, raw: string): number => {
    const n = Number(raw);
    if (!Number.isInteger(n) || n <= 0) throw new UsageError(`${flag} needs a positive whole number of milliseconds.`);
    return n;
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--agent":
        parsed.agent = value(arg, i++);
        break;
      case "--command":
        parsed.command = value(arg, i++);
        break;
      case "--audit":
        parsed.audit = value(arg, i++);
        break;
      case "--config":
        parsed.config = value(arg, i++);
        break;
      case "--proxy":
        parsed.proxy = value(arg, i++);
        break;
      case "--host":
        parsed.host = value(arg, i++);
        break;
      case "--timeout":
        parsed.timeoutMs = positiveInt(arg, value(arg, i++));
        break;
      case "--settle-ms":
        parsed.settleMs = positiveInt(arg, value(arg, i++));
        break;
      case "--json":
        parsed.json = true;
        break;
      case "--help":
      case "-h":
      case "help":
        parsed.help = true;
        break;
      default:
        throw new UsageError(`unknown option "${arg}".`);
    }
  }
  return parsed;
}

/**
 * `agentwall verify-capture` entry point. Returns the exit code rather than calling exit, so
 * the CLI keeps one place where the process ends and a test can call this directly.
 */
export async function runVerifyCaptureCommand(argv: string[]): Promise<number> {
  let args: ParsedCaptureArgs;
  try {
    args = parseCaptureArgs(argv);
  } catch (err) {
    console.error(`agentwall verify-capture: ${(err as Error).message}\n\n${USAGE}`);
    return EXIT_INCOMPLETE;
  }

  if (args.help || argv.length === 0) {
    console.log(USAGE);
    return args.help ? EXIT_CAPTURED : EXIT_INCOMPLETE;
  }
  if (!args.agent) {
    console.error(`agentwall verify-capture: --agent <id> is required.\n\n${USAGE}`);
    return EXIT_INCOMPLETE;
  }

  const auditPath = args.audit ?? process.env["AGENTWALL_AUDIT_FILE"];
  if (!auditPath) {
    console.error(
      "agentwall verify-capture: no audit file configured. Set AGENTWALL_AUDIT_FILE or pass --audit <path>.\n" +
        "This is the file the proxy appends decisions to, and it is the evidence this check reads."
    );
    return EXIT_INCOMPLETE;
  }

  let report: CaptureReport;
  try {
    report = await runVerifyCapture({
      agentId: args.agent,
      auditPath,
      configPath: args.config,
      command: args.command,
      host: args.host,
      proxyUrl: args.proxy,
      timeoutMs: args.timeoutMs,
      settleMs: args.settleMs,
      // Progress and prompts go to stderr so `--json` on stdout stays a single parseable
      // document even in interactive mode, where the URL has to be printed before the answer.
      log: (line) => console.error(line),
    });
  } catch (err) {
    console.error(`agentwall verify-capture: ${(err as Error).message}`);
    return EXIT_INCOMPLETE;
  }

  console.log(args.json ? JSON.stringify(report, null, 2) : formatCaptureReport(report));
  return captureExitCode(report);
}
