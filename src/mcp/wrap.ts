import { accessSync, closeSync, constants, fstatSync, openSync, readSync } from "fs";
import { basename, delimiter, join, resolve as resolvePath } from "path";
import { createHash, randomUUID } from "crypto";

import { emit, registerAuditSink, seedAuditChain } from "../audit/logger";
import { createFileSink, resumeChainState } from "../audit/file-sink";
import { DetectionMapping, detectionCatalog } from "../policy/detections";
import { PolicyEngine } from "../policy/engine";
import { AgentContext, DetectionMatch, PolicyResult, ProvenanceTag } from "../types";
import { GateContext, evaluateFrame, recordToolInventory } from "./gates";
import { McpHttpHandle, startMcpHttpListener } from "./http";
import { runStdioWrapper } from "./stdio";
import {
  FrameAction,
  FrameDirection,
  JsonRpcFrame,
  MCP_BLOCKED_ERROR_CODE,
  McpEvaluation,
  McpGateName,
  McpServerIdentity,
  McpToolDescriptor,
} from "./types";

/**
 * `agentwall mcp wrap`: the composition layer of the MCP plane.
 *
 * Nothing here decides anything. The transport in ./stdio owns the pipes, the gates in
 * ./gates own the verdict, the PolicyEngine owns the rules, and the audit logger owns the
 * hash chain. This file holds those four in the right order and makes sure no verdict escapes
 * without a record, because a call that was blocked but never recorded is indistinguishable,
 * a week later, from a call that was never made.
 *
 * Deliberately thin. Judgement added here would be a second policy system arguing with the
 * first, and the one property an operator needs from this layer is that the decision they read
 * in the audit file is the decision the client actually experienced.
 */

/** Chunk size for hashing the launched binary, so a large executable is never held whole in memory. */
const HASH_CHUNK_BYTES = 64 * 1024;

/**
 * Upper bound on outstanding request-id to method mappings.
 *
 * A client that issues requests and never reads the responses would otherwise grow this map for
 * the life of the session. Evicting the oldest costs one metadata field on one record; it can
 * never change a decision, because attribution is not an input to any gate.
 */
const MAX_TRACKED_REQUESTS = 512;

/**
 * What we call the agent when the caller did not say.
 *
 * Matching the forward proxy: where attribution is unavailable the record says so rather than
 * inventing a plausible name. An audit file that guesses is worse than one that admits.
 */
const DEFAULT_AGENT_ID = "unattributed";

/** Recorded method for a frame whose method could not be established. */
const UNKNOWN_METHOD = "unknown";

/** Catalogued detections by id, so a policy-gate finding keeps the MITRE mapping it already has. */
const detectionById = new Map<string, DetectionMapping>(
  detectionCatalog.map((entry) => [entry.id, entry])
);

export interface WrapOptions {
  /** The MCP server to launch, argv style: `command[0]` is the executable, the rest are its arguments. */
  command: string[];
  /** Name recorded for this server. Defaults to the basename of the executable. */
  serverName?: string;
  /** Agent the wrapped traffic is attributed to in the audit chain. */
  agentId?: string;
  /** Session the wrapped traffic is grouped under. One wrap invocation is one session by default. */
  sessionId?: string;
  /** Called with every audit event this wrap produced, after it joined the chain. */
  onAuditEvent?: (event: unknown) => void;
  /**
   * Stdio overrides, defaulting to this process's own streams.
   *
   * They exist so the wrapper can be driven over streams that are not a terminal's - a test,
   * or a host process that already owns its stdio and wants the gates on a stream it manages.
   * The CLI passes nothing and gets the process streams.
   */
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
}

/** A request we have seen, kept so the response that answers it can be named. */
interface PendingCall {
  method: string;
  toolName?: string;
}

/**
 * Hash the bytes of a file, or return undefined when it cannot be read.
 *
 * Read in chunks rather than with readFileSync: an interpreter or a bundled server binary can be
 * hundreds of megabytes, and a startup fingerprint has no reason to hold all of it at once.
 */
function hashFileBytes(file: string): string | undefined {
  let fd: number | undefined;
  try {
    fd = openSync(file, "r");
    if (!fstatSync(fd).isFile()) return undefined;
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
    for (;;) {
      const read = readSync(fd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      hash.update(buffer.subarray(0, read));
    }
    return hash.digest("hex");
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* the descriptor goes away with the process regardless */
      }
    }
  }
}

/**
 * Find the file a command will actually execute.
 *
 * A command containing a separator is a path and is used as given. A bare name is looked up
 * along PATH the way a shell would, so `node` and `/usr/bin/node` produce the same fingerprint
 * instead of one of them silently producing none.
 */
function resolveExecutable(command: string): string | undefined {
  if (command.length === 0) return undefined;
  if (command.includes("/") || command.includes("\\")) return resolvePath(command);

  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (dir.length === 0) continue;
    const candidate = join(dir, command);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      /* not here; keep looking, exactly as a shell would */
    }
  }
  return undefined;
}

/**
 * Identify the server about to be launched.
 *
 * The hash pins the file handed to the kernel. It is absent whenever that file cannot be read -
 * a bare name PATH does not resolve, a permission the operator does not hold, a command that is
 * a shell builtin. Deliberately not fatal: an unhashable server is a weaker guarantee, not a
 * reason to refuse to gate its traffic. Failing closed on a missing fingerprint would mean the
 * operator runs the server unwrapped instead, trading one absent metadata field for no
 * enforcement at all.
 *
 * The hash also says nothing about what the launched file loads at runtime. A launcher that
 * fetches a package on start is pinned only as a launcher: its hash will not change when the
 * code it fetches does.
 */
export function buildServerIdentity(command: string[], serverName?: string): McpServerIdentity {
  const executable = command[0];
  if (typeof executable !== "string" || executable.length === 0) {
    throw new Error("MCP server command is empty: there is nothing to wrap.");
  }

  const resolved = resolveExecutable(executable);
  const commandHash = resolved === undefined ? undefined : hashFileBytes(resolved);
  const named = serverName === undefined ? "" : serverName.trim();

  return {
    serverName: named.length > 0 ? named : basename(executable),
    command: [...command],
    ...(commandHash === undefined ? {} : { commandHash }),
  };
}

/**
 * Correlation key for a JSON-RPC id.
 *
 * Numeric 1 and string "1" are different ids in JSON-RPC, so the type is part of the key. A
 * notification, or a frame with a null id, is not correlatable and gets no key.
 */
function requestKey(id: JsonRpcFrame["id"]): string | null {
  if (typeof id === "number") return `n:${id}`;
  if (typeof id === "string") return `s:${id}`;
  return null;
}

/**
 * Name the frame: its own method when it has one, otherwise the method of the request it answers.
 *
 * Responses carry no method, so without this a result would be recorded as an anonymous event
 * and a reader could not tell which call produced the content that was scanned. A response
 * consumes its entry, so a well-behaved session keeps the map near empty.
 */
function classifyFrame(frame: JsonRpcFrame, inFlight: Map<string, PendingCall>): PendingCall {
  const key = requestKey(frame.id);

  if (typeof frame.method === "string" && frame.method.length > 0) {
    const call: PendingCall = { method: frame.method };
    if (frame.method === "tools/call" && frame.params !== null && typeof frame.params === "object" && "name" in frame.params) {
      const name = frame.params.name;
      if (typeof name === "string" && name.length > 0) call.toolName = name;
    }
    if (key !== null) {
      if (inFlight.size >= MAX_TRACKED_REQUESTS) {
        const oldest = inFlight.keys().next();
        if (!oldest.done) inFlight.delete(oldest.value);
      }
      inFlight.set(key, call);
    }
    return call;
  }

  if (key === null) return { method: UNKNOWN_METHOD };
  const remembered = inFlight.get(key);
  if (remembered === undefined) return { method: UNKNOWN_METHOD };
  inFlight.delete(key);
  return remembered;
}

/**
 * Read the tool list out of a `tools/list` result.
 *
 * Sniffed by shape rather than by the method of the request it answers, because a response
 * carries no method and the correlation map is bounded: an evicted mapping must not cost us the
 * inventory baseline. A malformed entry is skipped rather than defaulted, so it cannot enter the
 * baseline as a tool named "undefined" that a later comparison then treats as approved.
 */
function parseToolDescriptors(result: unknown): McpToolDescriptor[] {
  if (result === null || typeof result !== "object" || !("tools" in result)) return [];
  if (!Array.isArray(result.tools)) return [];
  const listed: readonly unknown[] = result.tools;

  const tools: McpToolDescriptor[] = [];
  for (const entry of listed) {
    if (entry === null || typeof entry !== "object") continue;
    if (!("name" in entry) || typeof entry.name !== "string" || entry.name.length === 0) continue;

    const tool: McpToolDescriptor = { name: entry.name };
    if ("description" in entry && typeof entry.description === "string") tool.description = entry.description;
    if ("inputSchema" in entry) tool.inputSchema = entry.inputSchema;
    tools.push(tool);
  }
  return tools;
}

/**
 * Project a gate evaluation onto the audit record's detection list.
 *
 * A detection the policy gate raised is already in the catalogue, MITRE mapping included, and
 * preserving that mapping is the only reason to look ids up at all. Injection and inventory
 * findings are not catalogued: for those the id is the evidence and the surrounding prose is
 * derived from the gate that raised it. That is less than a curated entry carries, and writing a
 * description that reads like one would misrepresent how much is actually known.
 */
function resolveDetections(evaluation: McpEvaluation): DetectionMatch[] {
  const resolved = new Map<string, DetectionMatch>();
  for (const outcome of evaluation.outcomes) {
    for (const id of outcome.detectionIds) {
      if (resolved.has(id)) continue;
      const known = detectionById.get(id);
      resolved.set(
        id,
        known ?? {
          id,
          ruleId: `mcp:${outcome.gate}`,
          name: id,
          description: `Raised by the MCP ${outcome.gate.replace(/_/g, " ")} gate.`,
          severity: outcome.riskLevel,
        }
      );
    }
  }
  return [...resolved.values()];
}

/**
 * Turn a gate evaluation into the PolicyResult the chain records.
 *
 * `matchedRules` answers "what fired". On this plane the deciding units are gates, so the gates
 * that returned anything other than allow go there, namespaced `mcp:` so a gate name can never
 * be read as a policy rule id. `highRiskFlow` follows the gates' risk level, which is the only
 * flow signal available for a frame whose content is deliberately kept out of the record.
 */
function toPolicyResult(evaluation: McpEvaluation): PolicyResult {
  return {
    decision: evaluation.decision,
    riskLevel: evaluation.riskLevel,
    matchedRules: evaluation.outcomes
      .filter((outcome) => outcome.decision !== "allow")
      .map((outcome) => `mcp:${outcome.gate}`),
    reasons: evaluation.reasons,
    requiresApproval: evaluation.decision === "approve",
    highRiskFlow: evaluation.riskLevel === "high" || evaluation.riskLevel === "critical",
    detections: resolveDetections(evaluation),
  };
}

/**
 * The reason a frame was refused, taken from the gate that refused it.
 *
 * Not `reasons[0]`: every gate that ran contributes its reasoning, including the ones that
 * passed, so the first entry is normally an allow reason from an earlier gate. Reporting that
 * to the client produces a refusal whose message asserts the frame was fine, which is worse
 * than no message - it sends the operator looking in the wrong place. Prefer the blocking
 * gate's own reason, fall back to any non-allow outcome, and only then to a generic line.
 */
function blockReason(evaluation: McpEvaluation, fallback: string): string {
  const blocking = evaluation.blockingGate
    ? evaluation.outcomes.find((o) => o.gate === evaluation.blockingGate)
    : undefined;
  const restrictive = blocking ?? evaluation.outcomes.find((o) => o.decision !== "allow");
  return restrictive?.reasons[0] ?? fallback;
}

/**
 * The JSON-RPC error a blocked frame becomes.
 *
 * The detection ids and the deciding gate travel in `data` so a client, or a human reading the
 * client's log, can tell a policy block from a transport failure without access to the audit
 * file. It is the same identifier that appears in the chain, which is what makes the two
 * records joinable after the fact.
 */
function blockAction(evaluation: McpEvaluation, message: string): FrameAction {
  return {
    kind: "block",
    error: {
      code: MCP_BLOCKED_ERROR_CODE,
      message,
      data: {
        detections: evaluation.detectionIds,
        gate: evaluation.blockingGate,
      },
    },
  };
}

/**
 * Which transport carried a frame.
 *
 * Recorded on every audit event because the two transports fail in different places: a stdio
 * decision belongs to a child process this host launched, an HTTP decision belongs to a listener
 * a remote server answered. An operator reading a chain that mixes both needs to know which one
 * they are looking at before any of the other metadata means what they think it means.
 */
export type McpTransport = "stdio" | "http";

/** The per-frame work both transports share. */
interface FrameHandling {
  /** Gate one frame and record the verdict. Returns what the transport should do with it. */
  handleFrame(frame: JsonRpcFrame, direction: FrameDirection): Promise<FrameAction>;
  /** Record a payload that never became a frame, so a transport-level refusal is still evidence. */
  recordMalformed(raw: string, direction: FrameDirection): void;
}

/**
 * Build the gate-and-record pipeline for one wrapped session.
 *
 * Both transports call this and neither adds to it. That is the property worth protecting: if the
 * HTTP path had its own copy of the gate call or its own audit metadata, the two would drift, and
 * the first sign of it would be a frame that stdio refuses and HTTP forwards. A decision has to be
 * a property of the frame, not of the socket it arrived on.
 */
function createFrameHandling(args: {
  server: McpServerIdentity;
  transport: McpTransport;
  agentId?: string;
  sessionId?: string;
  onAuditEvent?: (event: unknown) => void;
  /** Extra metadata stamped on every record, for facts that are true of the whole session. */
  baseMetadata?: Record<string, string>;
}): FrameHandling {
  const { server, transport } = args;
  const agentId = args.agentId ?? DEFAULT_AGENT_ID;
  // One wrap invocation is one session. Every frame it evaluates shares this id, which is how a
  // reader groups one server's traffic in the chain instead of inferring it from timestamps.
  const sessionId = args.sessionId ?? randomUUID();

  // The chain has to be wired up here, not inherited.
  //
  // The HTTP API server registers the durable file sink during its own boot, and `mcp wrap` never
  // boots it: the wrapper is a standalone process whose only job is the transport. Without this
  // block `emit()` still chains every decision, and every one of them goes nowhere - the gates
  // would report blocks the audit file has no record of, which is the precise failure a
  // tamper-evident log exists to prevent.
  //
  // Deliberately no stdout sink. On the stdio path stdout IS the MCP protocol channel, so writing
  // audit JSON to it would interleave records into the client's JSON-RPC stream and corrupt the
  // session. The file is the record; unset means this wrap produces no durable evidence, and that
  // is the operator's choice to make explicitly.
  const auditPath = process.env.AGENTWALL_AUDIT_FILE;
  if (auditPath) {
    const resumed = resumeChainState(auditPath);
    seedAuditChain(resumed.state);
    registerAuditSink(createFileSink(auditPath), { durable: true });
  }

  // One context for the whole session, because the tool-inventory baseline lives on it.
  // Rebuilding it per frame would reset the baseline before every comparison, making drift
  // permanently undetectable while still looking like it was being checked.
  const ctx: GateContext = {
    agentId,
    sessionId,
    server,
    engine: new PolicyEngine(),
  };

  const inFlight = new Map<string, PendingCall>();
  // Accumulated across pages: tools/list is cursor-paginated, so page two must not erase page
  // one. Merging by name also means a tool that stops being advertised stays in the baseline.
  // Forgetting it would hand a re-introduced tool a clean first appearance, which is exactly the
  // sequence a poisoned tool would use to walk past a drift check.
  const advertised = new Map<string, McpToolDescriptor>();

  const record = (recordArgs: {
    /** Audit action, `mcp:<method>` for an evaluated frame. */
    action: string;
    /** Recorded as `mcpMethod`; the method of the frame, or "unknown" when it could not be established. */
    method: string;
    direction: FrameDirection;
    result: PolicyResult;
    toolName?: string;
    gate?: McpGateName;
    extraMetadata?: Record<string, string>;
  }): void => {
    try {
      const metadata: Record<string, string> = {
        mcpServer: server.serverName,
        mcpMethod: recordArgs.method,
        mcpTransport: transport,
        direction: recordArgs.direction,
        ...args.baseMetadata,
        ...recordArgs.extraMetadata,
      };
      if (recordArgs.toolName !== undefined) metadata.mcpTool = recordArgs.toolName;
      if (server.commandHash !== undefined) metadata.commandHash = server.commandHash;
      if (recordArgs.gate !== undefined) metadata.mcpGate = recordArgs.gate;

      // Untrusted tool output is the label that makes the rest of the system treat an MCP result
      // correctly. A file the server read, or text it fetched, is content an attacker may
      // control, and it reaches the agent with the same standing as anything else it reads
      // unless the record says otherwise.
      const provenance: ProvenanceTag[] | undefined =
        recordArgs.direction === "server_to_client"
          ? [{ source: "tool_output", trustLabel: "untrusted" }]
          : undefined;

      const context: AgentContext = {
        agentId,
        sessionId,
        // Client frames are tool intent; server frames are content the agent will act on.
        plane: recordArgs.direction === "client_to_server" ? "tool" : "content",
        action: recordArgs.action,
        // The frame stays out of the record. emit() does not persist payload today, and the
        // metadata above is what actually lands in the chain; putting params and results here
        // would leave the audit file one refactor away from quoting the file contents and tokens
        // that MCP traffic routinely carries.
        payload: {},
        metadata,
        ...(provenance === undefined ? {} : { provenance }),
      };

      const event = emit(context, recordArgs.result);
      args.onAuditEvent?.(event);
    } catch {
      // Neither the chain nor an observer may break the session, matching the forward proxy's
      // posture: the decision was already made and enforced, and losing its record must not
      // also lose the enforcement.
    }
  };

  return {
    async handleFrame(frame: JsonRpcFrame, direction: FrameDirection): Promise<FrameAction> {
      const call = classifyFrame(frame, inFlight);
      const evaluation = evaluateFrame(frame, direction, ctx);
      record({
        action: `mcp:${call.method}`,
        method: call.method,
        direction,
        result: toPolicyResult(evaluation),
        toolName: call.toolName,
        gate: evaluation.blockingGate,
      });

      if (evaluation.decision === "deny") {
        return blockAction(evaluation, blockReason(evaluation, `MCP ${call.method} blocked by AgentWall.`));
      }

      // An `approve` verdict blocks.
      //
      // Interactive approval is not implemented on either transport. Neither has a side channel to
      // ask a human anything, and holding the frame open until an operator answers would stall the
      // client for as long as the operator is away. The approval queue is reachable over the HTTP
      // API; until an approval channel exists on the MCP transports, refusing is the honest answer.
      // Forwarding the call, or telling the client it was approved, would be a claim the client
      // then acts on.
      if (evaluation.decision === "approve") {
        const reason = blockReason(evaluation, "policy holds this call for a human.");
        return blockAction(evaluation, `MCP ${call.method} requires operator approval: ${reason}`);
      }

      const forwarded =
        evaluation.decision === "redact" && evaluation.redactedFrame !== undefined
          ? evaluation.redactedFrame
          : frame;

      if (direction === "server_to_client") {
        // Baselined only from a frame we are actually forwarding, and only after the gates have
        // judged it. Recording a denied or held inventory would launder it: the next tools/list
        // would be compared against the poisoned list and come back clean.
        const tools = parseToolDescriptors(forwarded.result);
        if (tools.length > 0) {
          for (const tool of tools) advertised.set(tool.name, tool);
          recordToolInventory(ctx, [...advertised.values()]);
        }
      }

      return { kind: "forward", frame: forwarded };
    },

    recordMalformed(raw: string, direction: FrameDirection): void {
      // A payload that does not parse cannot be evaluated, so the transport does not forward it and
      // the record says deny rather than leaving a silent hole where a frame went missing. Only the
      // byte count is kept: the bytes themselves are unvalidated input that may carry exactly the
      // material the rest of this file keeps out of the audit file.
      record({
        action: "mcp:malformed",
        method: UNKNOWN_METHOD,
        direction,
        gate: "frame_integrity",
        extraMetadata: { mcpFrameBytes: String(Buffer.byteLength(raw, "utf8")) },
        result: {
          decision: "deny",
          riskLevel: "high",
          matchedRules: ["mcp:frame_integrity"],
          reasons: [`Unparseable JSON-RPC frame on the ${direction} stream; it was not forwarded.`],
          requiresApproval: false,
          highRiskFlow: true,
          detections: [],
        },
      });
    },
  };
}

/**
 * Wrap a local MCP server: launch it, gate every frame, record every decision.
 *
 * Resolves with the server's exit code once it has exited, so a wrapped server is a drop-in
 * replacement for the server in a client's configuration - the client sees the status it would
 * have seen without the wrapper.
 */
export async function runMcpWrap(opts: WrapOptions): Promise<number> {
  const server = buildServerIdentity(opts.command, opts.serverName);
  const handling = createFrameHandling({
    server,
    transport: "stdio",
    agentId: opts.agentId,
    sessionId: opts.sessionId,
    onAuditEvent: opts.onAuditEvent,
  });

  return runStdioWrapper({
    command: opts.command,
    onClientFrame: (frame) => handling.handleFrame(frame, "client_to_server"),
    onServerFrame: (frame) => handling.handleFrame(frame, "server_to_client"),
    onMalformed: (raw, direction) => handling.recordMalformed(raw, direction),
    stdin: opts.stdin,
    stdout: opts.stdout,
    stderr: opts.stderr,
  });
}

export interface HttpWrapOptions {
  /** Absolute `http:` or `https:` URL of the MCP server to wrap. */
  upstreamUrl: string;
  /** Port for the local listener clients are pointed at. 0 takes an ephemeral port. */
  listenPort: number;
  /** Interface for the local listener. Defaults to loopback; anything else requires `authToken`. */
  listenHost?: string;
  /** Bearer token clients must present. Required unless the listener is on loopback. */
  authToken?: string;
  /** Request-body ceiling in bytes. Defaults to 8 MiB. */
  maxBodyBytes?: number;
  /** Name recorded for this server. Defaults to the upstream host. */
  serverName?: string;
  /** Agent the wrapped traffic is attributed to in the audit chain. */
  agentId?: string;
  /** Session the wrapped traffic is grouped under. One listener is one session by default. */
  sessionId?: string;
  /** Called with every audit event this wrap produced, after it joined the chain. */
  onAuditEvent?: (event: unknown) => void;
}

/**
 * Wrap a remote MCP server: listen locally, gate every frame, record every decision.
 *
 * A separate entry point from runMcpWrap rather than a flag on it, because the two have different
 * lifecycles and pretending otherwise would produce a function whose return value means two things.
 * A stdio wrap owns a child process and is finished when that child exits, which is why it resolves
 * with an exit code; an HTTP wrap owns a socket that stays up until someone closes it, and has no
 * exit code to report. What the two do share - the gates, the audit metadata, the session state -
 * is shared for real, through createFrameHandling, which is the part that had to be identical.
 *
 * There is no command to hash here. `commandHash` exists to pin a binary this host launched, and
 * nothing about a remote server is pinned by anything on this side of the connection: the operator
 * is trusting a URL and whatever authenticates it. The record says so by carrying `mcpUpstream`
 * and no hash, rather than by leaving a field that looks like a supply-chain guarantee it is not.
 */
export async function runMcpHttpWrap(opts: HttpWrapOptions): Promise<McpHttpHandle> {
  let upstream: URL;
  try {
    upstream = new URL(opts.upstreamUrl);
  } catch {
    throw new Error(`MCP HTTP wrap: --http-upstream "${opts.upstreamUrl}" is not an absolute URL.`);
  }
  if (upstream.protocol !== "http:" && upstream.protocol !== "https:") {
    throw new Error(`MCP HTTP wrap: --http-upstream must be http: or https:, got "${upstream.protocol}".`);
  }

  const named = opts.serverName === undefined ? "" : opts.serverName.trim();
  const server: McpServerIdentity = {
    serverName: named.length > 0 ? named : upstream.host,
    // Nothing was launched, and an argv that was never executed would be a fabrication. Empty is
    // the accurate answer, and `mcpUpstream` below is where the identifying detail actually lives.
    command: [],
  };

  const handling = createFrameHandling({
    server,
    transport: "http",
    agentId: opts.agentId,
    sessionId: opts.sessionId,
    onAuditEvent: opts.onAuditEvent,
    // Origin and path only. A URL's userinfo and query string are exactly where a deployment hides
    // a credential, and the audit file is the last place one should reappear.
    baseMetadata: { mcpUpstream: `${upstream.protocol}//${upstream.host}${upstream.pathname}` },
  });

  return startMcpHttpListener({
    listenPort: opts.listenPort,
    listenHost: opts.listenHost,
    upstreamUrl: opts.upstreamUrl,
    authToken: opts.authToken,
    maxBodyBytes: opts.maxBodyBytes,
    onClientFrame: (frame) => handling.handleFrame(frame, "client_to_server"),
    onServerFrame: (frame) => handling.handleFrame(frame, "server_to_client"),
    onMalformed: (raw, direction) => handling.recordMalformed(raw, direction),
  });
}
