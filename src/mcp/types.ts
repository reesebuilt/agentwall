import { Decision, RiskLevel } from "../types";

/**
 * Shared contract for the MCP plane.
 *
 * Why MCP gets its own transport but not its own policy system: a tool call
 * arriving over MCP is the same kind of event as a tool call arriving over
 * /evaluate, and an operator who has written a rule for one should not discover
 * it silently does not apply to the other. So this module defines framing and
 * gate vocabulary only. Decisions come from the existing PolicyEngine, and every
 * MCP decision joins the same hash chain as every other decision.
 *
 * Transport scope is stdio. MCP's stdio transport is newline-delimited JSON-RPC
 * 2.0 over the child's stdin/stdout, which is the transport every local MCP
 * server supports. HTTP and SSE transports are deliberately absent rather than
 * half-present: a partially-wrapped transport would report "protected" while
 * leaving a live path unscanned, which is worse than an honest gap.
 */

/**
 * A JSON-RPC 2.0 message. MCP constrains JSON-RPC but does not replace it, so
 * this stays faithful to the base protocol: a frame is a request (method + id),
 * a notification (method, no id), or a response (result xor error, with id).
 */
export interface JsonRpcFrame {
  jsonrpc: "2.0";
  id?: string | number | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

/**
 * Which way a frame is travelling. Direction decides trust: a frame from the
 * client carries operator intent, a frame from the server carries content the
 * agent will act on and is therefore untrusted input.
 */
export type FrameDirection = "client_to_server" | "server_to_client";

/**
 * Normalization passes applied before injection matching.
 *
 * Injection text is adversarial, so matching raw bytes only catches the naive
 * case. Each pass rewrites the text into a canonical form and re-runs the
 * pattern set; a finding records which pass surfaced it, because "matched only
 * after base64 decoding" is a materially different signal from "matched
 * literally" and an operator triaging a false positive needs to know which.
 */
export type NormalizationPass =
  | "raw"
  | "zero_width"
  | "homoglyph"
  | "leetspeak"
  | "whitespace"
  | "base64"
  | "hex";

/** What an injection attempt is trying to accomplish. */
export type InjectionCategory =
  | "instruction_override"
  | "exfiltration_directive"
  | "role_manipulation"
  | "tool_coercion"
  | "state_poisoning";

export interface InjectionFinding {
  /** Stable id, e.g. "inj.instruction_override.ignore_previous". */
  patternId: string;
  category: InjectionCategory;
  severity: RiskLevel;
  /** Which normalization pass surfaced this match. */
  pass: NormalizationPass;
  /**
   * Bounded, DLP-redacted excerpt of the matching region. Bounded because an
   * audit record must not become an exfiltration channel for the payload it is
   * reporting, and redacted because injection text frequently carries the
   * secret it is trying to move.
   */
  excerpt: string;
}

export interface InjectionScanResult {
  findings: InjectionFinding[];
  containsInjection: boolean;
  /** Present only when the caller asked for stripping. */
  strippedText?: string;
}

/**
 * The ordered inbound gates. Order is a contract, not an implementation
 * detail: inventory must run before input scanning so a poisoned tool
 * description is caught before its arguments are trusted, and policy runs last
 * so it sees every prior gate's findings.
 */
export type McpGateName =
  | "frame_integrity"
  | "tool_inventory"
  | "input_scan"
  | "policy"
  | "response_scan";

export interface McpGateOutcome {
  gate: McpGateName;
  decision: Decision;
  riskLevel: RiskLevel;
  reasons: string[];
  /** Detection catalog ids, e.g. "det.mcp.tool.poisoned". */
  detectionIds: string[];
}

/**
 * Aggregate result for one frame.
 *
 * blockingGate names the first gate that returned a block-level decision and
 * short-circuited the rest. An absent blockingGate does not mean "clean": a
 * frame can run every gate and still carry warnings or a redact decision.
 */
export interface McpEvaluation {
  decision: Decision;
  riskLevel: RiskLevel;
  reasons: string[];
  detectionIds: string[];
  blockingGate?: McpGateName;
  outcomes: McpGateOutcome[];
  /**
   * Set when a gate rewrote the frame, e.g. secrets replaced with typed
   * placeholders in tool arguments. Callers forward this instead of the
   * original when present.
   */
  redactedFrame?: JsonRpcFrame;
}

/**
 * Identity of the wrapped server. The command hash pins what was launched:
 * a server whose binary changes between runs is a supply-chain event, and the
 * existing manifest-drift machinery is what consumes this.
 */
export interface McpServerIdentity {
  /** Operator-supplied stable name, or the argv basename when unset. */
  serverName: string;
  /** argv as launched. */
  command: string[];
  /** SHA-256 over the resolved executable, when it could be read. */
  commandHash?: string;
}

/** A tool as advertised by the server in a tools/list response. */
export interface McpToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

/**
 * What a transport does with a frame after the gates have run.
 *
 * Blocking is expressed as a JSON-RPC error returned to the client rather than
 * a dropped frame. A dropped frame leaves the client waiting on an id that will
 * never be answered, which reads as a hang; an error is a refusal the client can
 * surface. Silence is not a security posture.
 */
export type FrameAction =
  | { kind: "forward"; frame: JsonRpcFrame }
  | { kind: "block"; error: { code: number; message: string; data?: unknown } };

/** JSON-RPC error codes used when a gate blocks a call. */
export const MCP_BLOCKED_ERROR_CODE = -32001;
