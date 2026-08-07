import { z } from "zod";
import { isDeepStrictEqual } from "util";
import { AgentContext, Decision, RiskLevel } from "../types";
import { PolicyEngine } from "../policy/engine";
import { scanText } from "../planes/identity/dlp";
import { scanInjection } from "../policy/injection";
import {
  FrameDirection,
  JsonRpcFrame,
  McpBaselineDecision,
  McpBaselineKey,
  McpBaselineMode,
  McpEvaluation,
  McpGateName,
  McpGateOutcome,
  McpServerIdentity,
  McpToolDescriptor,
} from "./types";
import { parseMcpToolInventoryPage } from "./inventory";
import type { McpBaselineStore } from "./baseline";

/**
 * The MCP gate pipeline: one frame in, one decision out.
 *
 * Gate order is a contract, not an implementation detail. Inventory runs before
 * input scanning because a poisoned tool description is what talks the model into
 * building malicious arguments in the first place; scanning arguments first would
 * catch the symptom and wave the cause through, leaving the operator reviewing an
 * argument list instead of the tool that produced it. Policy runs last because it
 * is the only gate that needs to see what the earlier gates found: the scanners
 * flatten their findings into context metadata and the operator's rules decide
 * what those findings are worth. Response scanning sits at the end because it
 * applies to the opposite direction of travel and has nothing to say about an
 * outbound call.
 *
 * Every gate runs inside a try/catch and a gate that throws contributes a deny.
 * A security control that fails open is worse than no control at all, because it
 * reports "inspected" while inspecting nothing and the operator stops looking.
 * The price is that a bug in a scanner breaks the wrapped server instead of
 * quietly degrading it. That is the correct price for a component whose entire
 * value is that its verdicts can be believed.
 *
 * Two limits worth knowing. First, JSON-RPC responses carry an id and no method,
 * and this function is stateless by design, so it cannot correlate a response
 * back to the request that produced it; server frames are classified by shape
 * instead, which errs toward scanning more rather than less. Second, the policy
 * context uses the JSON-RPC method as its action, so the MCP tool name travels in
 * metadata (`mcpTool`) rather than in the action string: a rule that keys off
 * action fragments sees `mcp:tools/call`, not the tool being called.
 */

/**
 * The wire shapes the gates read.
 *
 * Frames arrive from a subprocess over a pipe, so nothing inside them is typed
 * until it has been parsed. These schemas are that boundary: below them the code
 * consumes named output types instead of re-interrogating `unknown` at each use.
 * They are loose about keys they do not name because MCP servers legitimately
 * carry extra fields such as progress tokens, and a gate that rejected an
 * unfamiliar key would break interoperability without catching a single attack.
 */
const JsonObjectSchema = z.record(z.string(), z.unknown());

const ToolCallParamsSchema = z.looseObject({
  name: z.string().optional(),
  arguments: JsonObjectSchema.optional(),
});


const JsonRpcErrorSchema = z.object({
  code: z.number(),
  message: z.string(),
  data: z.unknown().optional(),
});

/**
 * Decision and risk precedence. These mirror the tables inside the policy engine
 * rather than importing them, because the engine's copies are private. The
 * duplication is deliberate but it is also a coupling: a pipeline that disagreed
 * with the engine about whether deny outranks approve would emit evaluations no
 * operator could reconcile with the rule that produced them. If the engine's
 * precedence changes, this changes with it.
 */
const DECISION_PRECEDENCE: Record<Decision, number> = {
  allow: 0,
  redact: 1,
  approve: 2,
  deny: 3,
};

const RISK_PRECEDENCE: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/** The gates, in the order they run. See the module comment for why this order. */
const GATE_ORDER: readonly McpGateName[] = [
  "frame_integrity",
  "tool_inventory",
  "input_scan",
  "policy",
  "response_scan",
];

export interface GateContext {
  agentId: string;
  sessionId?: string;
  server: McpServerIdentity;
  engine: PolicyEngine;
  /**
   * The tool inventory this session has already accepted. Undefined means no
   * session baseline exists yet. This remains the complete behavior in off mode.
   */
  approvedTools?: McpToolDescriptor[];
  /** Persistent inventory behavior. Undefined preserves off-mode compatibility. */
  baselineMode?: McpBaselineMode;
  /** Persistent store used by learn and lock mode. */
  baselineStore?: McpBaselineStore;
  /** Agent, server, and command identity used to select the persistent inventory. */
  baselineKey?: McpBaselineKey;
  /** Most recent inventory comparison, used by the audit composition layer. */
  baselineDecision?: McpBaselineDecision;
  /** Complete candidate built across a paginated tools/list response. */
  inventoryCandidate?: McpToolDescriptor[];
  /** False until the server returns the final tools/list page. */
  inventoryComplete?: boolean;
}

interface GateRun {
  markers: Record<string, string>;
  redactedFrame?: JsonRpcFrame;
}

/**
 * Presence, not definedness. A JSON-RPC result is legitimately `null`, and
 * `undefined` never survives JSON.parse, so an own-property check is the only
 * test that distinguishes "the server answered null" from "the server did not
 * answer".
 */
function hasKey(frame: JsonRpcFrame, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(frame, key);
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

function maxDecision(current: Decision, candidate: Decision): Decision {
  return DECISION_PRECEDENCE[candidate] > DECISION_PRECEDENCE[current] ? candidate : current;
}

function maxRisk(current: RiskLevel, candidate: RiskLevel): RiskLevel {
  return RISK_PRECEDENCE[candidate] > RISK_PRECEDENCE[current] ? candidate : current;
}


/**
 * Gate 1: structural validity.
 *
 * Everything checked here is a property of the JSON-RPC envelope rather than of
 * the payload, so it can be established without trusting anything inside the
 * frame. Server error objects are deliberately not shape-checked: a malformed
 * error is a sloppy server rather than an attack, and denying it would break
 * interoperability while blocking nothing an attacker wanted through.
 */
function gateFrameIntegrity(frame: JsonRpcFrame): McpGateOutcome {
  const reasons: string[] = [];

  if (frame.jsonrpc !== "2.0") {
    reasons.push(`Frame declares jsonrpc "${String(frame.jsonrpc)}"; only "2.0" is valid`);
  }

  const carriesMethod = hasKey(frame, "method");
  const carriesId = hasKey(frame, "id");
  const carriesResult = hasKey(frame, "result");
  const carriesError = hasKey(frame, "error");

  if (carriesResult && carriesError) {
    reasons.push("Frame carries both result and error; a response is one or the other");
  }
  if (!carriesMethod && carriesId && !carriesResult && !carriesError) {
    reasons.push("Response frame carries neither result nor error");
  }
  if (carriesMethod && typeof frame.method !== "string") {
    reasons.push("Frame declares a method that is not a string");
  }
  if (!carriesMethod && !carriesId) {
    reasons.push("Frame is neither a request nor a response: it has no method and no id");
  }

  if (reasons.length > 0) {
    return {
      gate: "frame_integrity",
      decision: "deny",
      riskLevel: "medium",
      reasons,
      detectionIds: [],
    };
  }

  return {
    gate: "frame_integrity",
    decision: "allow",
    riskLevel: "low",
    reasons: ["Frame is a well-formed JSON-RPC 2.0 message"],
    detectionIds: [],
  };
}

/**
 * Gate 2: what the server says its tools are.
 *
 * A tool description is read by the model as guidance, which makes it executable
 * text in everything but name. Instruction content in a description is therefore
 * treated as a compromise of the server itself rather than as a content warning,
 * and it denies outright.
 *
 * Drift is separate and softer. A changed inventory is not evidence of an attack
 * on its own, but it is precisely what an attack looks like afterwards, so it
 * goes to a human instead of being reconciled automatically.
 */
function inventoryDrift(
  baseline: McpToolDescriptor[],
  advertised: McpToolDescriptor[],
  compareFullDescriptor: boolean,
): string[] {
  const approvedByName = new Map(baseline.map((tool) => [tool.name, tool]));
  const advertisedNames = new Set<string>();
  const drift: string[] = [];

  for (const tool of advertised) {
    advertisedNames.add(tool.name);
    const approved = approvedByName.get(tool.name);
    if (!approved) {
      drift.push(`"${tool.name}" is new since approval`);
      continue;
    }
    const changed = compareFullDescriptor
      ? !isDeepStrictEqual(approved, tool)
      : (approved.description ?? "") !== (tool.description ?? "");
    if (changed) {
      drift.push(
        compareFullDescriptor
          ? `"${tool.name}" changed since approval`
          : `"${tool.name}" changed its description since approval`,
      );
    }
  }
  for (const approved of baseline) {
    if (!advertisedNames.has(approved.name)) {
      drift.push(`"${approved.name}" was withdrawn since approval`);
    }
  }
  return drift;
}

function gateToolInventory(
  frame: JsonRpcFrame,
  direction: FrameDirection,
  ctx: GateContext,
  run: GateRun
): McpGateOutcome | null {
  if (direction !== "server_to_client") return null;
  const page = parseMcpToolInventoryPage(frame.result);
  if (page === null) return null;
  const tools = ctx.inventoryCandidate ?? page.tools;

  const reasons: string[] = [];
  const detectionIds: string[] = [];
  let decision: Decision = "allow";
  let riskLevel: RiskLevel = "low";
  for (const tool of page.tools) {
    const scanned = scanInjection(`${tool.name}\n${tool.description ?? ""}`);
    if (!scanned.containsInjection) continue;

    decision = maxDecision(decision, "deny");
    riskLevel = maxRisk(riskLevel, "critical");
    detectionIds.push("det.mcp.tool.poisoned");
    run.markers["mcpToolPoisoned"] = "true";
    reasons.push(
      `Tool "${tool.name}" advertises instructions to the model rather than a description ` +
        `(${dedupe(scanned.findings.map((finding) => finding.patternId)).join(", ")})`
    );
  }

  if (ctx.inventoryComplete === false) {
    if (reasons.length === 0) {
      reasons.push(`Received ${page.tools.length} tool(s); waiting for the final tools/list page`);
    }
    return {
      gate: "tool_inventory",
      decision,
      riskLevel,
      reasons,
      detectionIds: dedupe(detectionIds),
    };
  }

  const baselineMode = ctx.baselineMode ?? "off";
  if (baselineMode === "off") {
    const sessionBaseline = ctx.approvedTools;
    const drift = sessionBaseline === undefined
      ? []
      : inventoryDrift(sessionBaseline, tools, false);
    ctx.baselineDecision = sessionBaseline === undefined
      ? { state: "missing", drift: [] }
      : drift.length === 0
        ? { state: "matched", drift: [] }
        : { state: "drift", drift };
    if (drift.length > 0) {
      decision = maxDecision(decision, "approve");
      riskLevel = maxRisk(riskLevel, "high");
      detectionIds.push("det.mcp.tool.drift");
      run.markers["mcpToolDrift"] = "true";
      reasons.push(`Advertised tool inventory drifted from the approved set: ${drift.join("; ")}`);
    }
  } else {
    if (ctx.baselineStore === undefined || ctx.baselineKey === undefined) {
      throw new Error(`${baselineMode} mode needs a baseline store and baseline key`);
    }

    let baseline: McpToolDescriptor[] | undefined;
    try {
      baseline = ctx.baselineStore.read(ctx.baselineKey);
    } catch (error) {
      const warning = error instanceof Error ? error.message : String(error);
      ctx.baselineDecision = { state: "missing", drift: [warning] };
      if (baselineMode === "lock") throw error;
      reasons.push(`${warning}; learn mode left the file unchanged`);
      return {
        gate: "tool_inventory",
        decision,
        riskLevel,
        reasons,
        detectionIds: dedupe(detectionIds),
      };
    }

    if (baseline === undefined) {
      if (decision === "deny") {
        ctx.baselineDecision = { state: "missing", drift: [] };
      } else if (baselineMode === "learn") {
        try {
          ctx.baselineStore.write(ctx.baselineKey, tools);
          ctx.baselineDecision = { state: "learned", drift: [] };
          reasons.push(`Learned the first clean inventory with ${tools.length} tool(s)`);
        } catch (error) {
          const warning = error instanceof Error ? error.message : String(error);
          ctx.baselineDecision = { state: "missing", drift: [warning] };
          reasons.push(`The clean inventory was not learned: ${warning}`);
        }
      } else {
        const drift = tools.map((tool) => `"${tool.name}" is new because no baseline exists`);
        if (drift.length === 0) drift.push("No accepted baseline exists for this server");
        ctx.baselineDecision = { state: "missing", drift };
        decision = maxDecision(decision, "approve");
        riskLevel = maxRisk(riskLevel, "high");
        detectionIds.push("det.mcp.tool.drift");
        run.markers["mcpToolDrift"] = "true";
        reasons.push(`No locked tool inventory exists: ${drift.join("; ")}`);
      }
    } else {
      const drift = inventoryDrift(baseline, tools, true);
      ctx.baselineDecision = drift.length === 0
        ? { state: "matched", drift: [] }
        : { state: "drift", drift };
      if (drift.length > 0) {
        decision = maxDecision(decision, "approve");
        riskLevel = maxRisk(riskLevel, "high");
        detectionIds.push("det.mcp.tool.drift");
        run.markers["mcpToolDrift"] = "true";
        reasons.push(`Advertised tool inventory drifted from the locked set: ${drift.join("; ")}`);
      }
    }
  }

  if (reasons.length === 0) {
    reasons.push(`Server advertised ${tools.length} tool(s); none carry injected instructions`);
  }

  return { gate: "tool_inventory", decision, riskLevel, reasons, detectionIds: dedupe(detectionIds) };
}

/**
 * Rewrite tool arguments with the DLP's redacted serialization.
 *
 * Returns null when the redacted text cannot be turned back into an object. The
 * caller treats that as a hard failure rather than falling back to the original,
 * because the one thing this must never do is forward the unredacted frame
 * because the redacted one would not parse.
 *
 * Note that the DLP redacts PII alongside secrets, so a frame rewritten because
 * it carried a credential also loses any personal data travelling with it. That
 * is intended: both are leaks, and the frame is already being rewritten.
 */
function rewriteToolArguments(frame: JsonRpcFrame, redactedText: string | undefined): JsonRpcFrame | null {
  if (redactedText === undefined) return null;

  const params = ToolCallParamsSchema.safeParse(frame.params);
  if (!params.success) return null;

  let reparsed: unknown;
  try {
    reparsed = JSON.parse(redactedText);
  } catch {
    return null;
  }

  const args = JsonObjectSchema.safeParse(reparsed);
  if (!args.success) return null;

  return { ...frame, params: { ...params.data, arguments: args.data } };
}

/**
 * Gate 3: what the agent is about to hand the server.
 *
 * Arguments are serialized before scanning so nested structures get the same pass
 * as top-level strings. Secrets redact rather than deny because the call itself is
 * usually legitimate and only the credential is not; injection denies because an
 * argument carrying instructions is aimed at whatever the server feeds it to next,
 * and there is no redacted version of that intent worth forwarding.
 */
function gateInputScan(frame: JsonRpcFrame, direction: FrameDirection, run: GateRun): McpGateOutcome | null {
  if (direction !== "client_to_server") return null;
  if (frame.method !== "tools/call") return null;

  // A tool that takes no input is legitimately called with no argument object, so
  // absent or unparseable params are an empty argument set here. Structural
  // complaints about the frame belong to the integrity gate, not this one.
  const params = ToolCallParamsSchema.safeParse(frame.params);
  const serialized = JSON.stringify(params.success ? params.data.arguments ?? {} : {});

  const dlp = scanText(serialized, true);
  const injection = scanInjection(serialized);

  const reasons: string[] = [];
  const detectionIds: string[] = [];
  let decision: Decision = "allow";
  let riskLevel: RiskLevel = "low";

  if (dlp.containsSecrets) {
    decision = maxDecision(decision, "redact");
    riskLevel = maxRisk(riskLevel, "high");
    detectionIds.push("det.mcp.input.secret");
    run.markers["mcpInputSecret"] = "true";
    run.markers["mcpSecretTypes"] = dlp.secretTypes.join(",");
    reasons.push(
      `Tool arguments carry credential material (${dlp.secretTypes.join(", ")}); ` +
        "forwarding the raw values would hand them to the server"
    );

    const rewritten = rewriteToolArguments(frame, dlp.redactedText);
    if (rewritten) {
      run.redactedFrame = rewritten;
    } else {
      decision = maxDecision(decision, "deny");
      riskLevel = maxRisk(riskLevel, "critical");
      reasons.push("Redacted arguments could not be reserialized; denying rather than forwarding them intact");
    }
  }

  if (injection.containsInjection) {
    decision = maxDecision(decision, "deny");
    riskLevel = maxRisk(riskLevel, "high");
    detectionIds.push("det.mcp.input.injection");
    run.markers["mcpInputInjection"] = "true";
    reasons.push(
      "Tool arguments carry injected instructions " +
        `(${dedupe(injection.findings.map((finding) => finding.patternId)).join(", ")})`
    );
  }

  if (reasons.length === 0) {
    reasons.push("Tool arguments carry no credential material or injected instructions");
  }

  return { gate: "input_scan", decision, riskLevel, reasons, detectionIds };
}

/**
 * Turn a PolicyResult into a gate outcome.
 *
 * The engine's default decision is deliberately not honoured here. `new
 * PolicyEngine()` defaults to deny for actions no rule models, which is right for
 * an open-ended evaluation API where an unrecognised action means a gap in
 * coverage. On the MCP path it would mean every initialize, every notification
 * and every benign tool call is refused until somebody writes a rule for it, and
 * a control that has to be switched off before the server works is not a control
 * at all. So an evaluation that matched nothing contributes an allow outcome that
 * records the miss. The deny authority on this path is the gates; an operator who
 * wants default-deny for MCP writes it as a rule, where it is visible in the rule
 * catalog and named in the audit trail, rather than inheriting it from an engine
 * default that no decision record could ever point at.
 */
function policyOutcome(gate: McpGateName, engine: PolicyEngine, agentCtx: AgentContext): McpGateOutcome {
  const result = engine.evaluate(agentCtx);

  if (result.matchedRules.length === 0) {
    return {
      gate,
      decision: "allow",
      riskLevel: result.riskLevel,
      reasons: [`No policy rule matched ${agentCtx.action}`],
      detectionIds: [],
    };
  }

  return {
    gate,
    decision: result.decision,
    riskLevel: result.riskLevel,
    reasons: [...result.reasons, `Matched policy rules: ${result.matchedRules.join(", ")}`],
    detectionIds: result.detections.map((detection) => detection.id),
  };
}

/**
 * Gate 4: the operator's rules, applied to outbound requests.
 *
 * This is the point of the whole plane. A tool call arriving over MCP is the same
 * event as a tool call arriving over the evaluation API, so it goes through the
 * same engine and lands in the same hash chain instead of through a second policy
 * system that would drift out of agreement with the first.
 */
function gatePolicy(
  frame: JsonRpcFrame,
  direction: FrameDirection,
  ctx: GateContext,
  run: GateRun
): McpGateOutcome | null {
  if (direction !== "client_to_server") return null;
  if (typeof frame.method !== "string") return null;

  const method = frame.method;
  const isToolCall = method === "tools/call";
  const params = ToolCallParamsSchema.safeParse(frame.params);

  const metadata: Record<string, string> = {
    mcpServer: ctx.server.serverName,
    mcpMethod: method,
    mcpDirection: direction,
    ...run.markers,
  };
  if (isToolCall && params.success && params.data.name) {
    metadata["mcpTool"] = params.data.name;
  }
  if (ctx.server.commandHash) {
    metadata["mcpServerHash"] = ctx.server.commandHash;
  }

  const payload = params.success
    ? isToolCall
      ? params.data.arguments ?? {}
      : params.data
    : {};

  const agentCtx: AgentContext = {
    agentId: ctx.agentId,
    sessionId: ctx.sessionId,
    plane: "tool",
    action: isToolCall ? "mcp:tools/call" : `mcp:${method}`,
    payload,
    metadata,
  };

  return policyOutcome("policy", ctx.engine, agentCtx);
}

/**
 * Rewrite a response with the DLP's redacted serialization. Same failure contract
 * as the request-side rewrite: null means the caller must deny rather than
 * forward. The error branch revalidates the reparsed object because an error the
 * client cannot read as an error is worse than no response at all.
 */
function rewriteResponse(
  frame: JsonRpcFrame,
  redactedText: string | undefined,
  carriesResult: boolean
): JsonRpcFrame | null {
  if (redactedText === undefined) return null;

  let reparsed: unknown;
  try {
    reparsed = JSON.parse(redactedText);
  } catch {
    return null;
  }

  if (carriesResult) {
    return { ...frame, result: reparsed };
  }

  const error = JsonRpcErrorSchema.safeParse(reparsed);
  if (!error.success) return null;
  return { ...frame, error: error.data };
}

/**
 * Gate 5: what comes back.
 *
 * Tool output is untrusted content that the agent will read as fact and act on,
 * so injection here denies at critical: the payload has reached the point where
 * the model would consume it and there is no gate left downstream. Secrets redact
 * instead, because a server returning a credential is usually doing its job badly
 * rather than maliciously and the rest of the response is still useful.
 *
 * Scope note: this covers error frames as well as result frames. An error message
 * is server-controlled text that the agent reads and reasons about exactly like a
 * result, and leaving that path unscanned would mean calling the transport
 * protected while a live channel into the model went uninspected.
 */
function gateResponseScan(
  frame: JsonRpcFrame,
  direction: FrameDirection,
  ctx: GateContext,
  run: GateRun
): McpGateOutcome | null {
  if (direction !== "server_to_client") return null;

  const carriesResult = hasKey(frame, "result");
  const carriesError = hasKey(frame, "error");
  if (!carriesResult && !carriesError) return null;
  // Inventory frames belong to gate 2; scanning them here as well would report
  // the same finding twice under two different gate names.
  if (carriesResult && parseMcpToolInventoryPage(frame.result) !== null) return null;

  const serialized = JSON.stringify(carriesResult ? frame.result : frame.error) ?? "null";
  const injection = scanInjection(serialized);
  const dlp = scanText(serialized, true);

  const reasons: string[] = [];
  const detectionIds: string[] = [];
  let decision: Decision = "allow";
  let riskLevel: RiskLevel = "low";

  if (injection.containsInjection) {
    decision = maxDecision(decision, "deny");
    riskLevel = maxRisk(riskLevel, "critical");
    detectionIds.push("det.mcp.response.injection");
    run.markers["mcpResponseInjection"] = "true";
    reasons.push(
      "Tool output carries instructions aimed at the agent " +
        `(${dedupe(injection.findings.map((finding) => finding.patternId)).join(", ")})`
    );
  }

  if (dlp.containsSecrets) {
    decision = maxDecision(decision, "redact");
    riskLevel = maxRisk(riskLevel, "high");
    detectionIds.push("det.mcp.response.secret");
    run.markers["mcpResponseSecret"] = "true";
    run.markers["mcpSecretTypes"] = dlp.secretTypes.join(",");
    reasons.push(`Tool output contains credential material (${dlp.secretTypes.join(", ")})`);

    const rewritten = rewriteResponse(frame, dlp.redactedText, carriesResult);
    if (rewritten) {
      run.redactedFrame = rewritten;
    } else {
      decision = maxDecision(decision, "deny");
      riskLevel = maxRisk(riskLevel, "critical");
      reasons.push("Redacted response could not be reserialized; denying rather than returning it intact");
    }
  }

  const agentCtx: AgentContext = {
    agentId: ctx.agentId,
    sessionId: ctx.sessionId,
    plane: "content",
    action: "mcp:tool_result",
    payload: carriesResult ? { result: frame.result } : { error: frame.error },
    metadata: {
      mcpServer: ctx.server.serverName,
      mcpDirection: direction,
      mcpFrameKind: carriesResult ? "result" : "error",
      ...run.markers,
    },
    provenance: [{ source: "tool_output", trustLabel: "untrusted" }],
    flow: { direction: "ingress" },
  };

  const policy = policyOutcome("response_scan", ctx.engine, agentCtx);
  decision = maxDecision(decision, policy.decision);
  riskLevel = maxRisk(riskLevel, policy.riskLevel);
  reasons.push(...policy.reasons);
  detectionIds.push(...policy.detectionIds);

  return { gate: "response_scan", decision, riskLevel, reasons, detectionIds: dedupe(detectionIds) };
}

function runGate(
  gate: McpGateName,
  frame: JsonRpcFrame,
  direction: FrameDirection,
  ctx: GateContext,
  run: GateRun
): McpGateOutcome | null {
  switch (gate) {
    case "frame_integrity":
      return gateFrameIntegrity(frame);
    case "tool_inventory":
      return gateToolInventory(frame, direction, ctx, run);
    case "input_scan":
      return gateInputScan(frame, direction, run);
    case "policy":
      return gatePolicy(frame, direction, ctx, run);
    case "response_scan":
      return gateResponseScan(frame, direction, ctx, run);
  }
}

/**
 * Run one frame through the gates.
 *
 * Synchronous on purpose. This sits inline on a stdio pipe where every awaited
 * tick is latency a user feels on a tool call, and an asynchronous signature
 * would invite a scanner that reaches the network, which is the last thing a
 * frame inspector should be permitted to do.
 *
 * The function does not throw. Each gate is isolated and a gate that fails
 * contributes a deny naming itself, so a crash inside a scanner becomes a refused
 * frame with a diagnosable reason rather than an unscanned frame that was let
 * through while the pipeline was on fire.
 */
export function evaluateFrame(
  frame: JsonRpcFrame,
  direction: FrameDirection,
  ctx: GateContext
): McpEvaluation {
  const run: GateRun = { markers: {} };
  const outcomes: McpGateOutcome[] = [];
  let blockingGate: McpGateName | undefined;

  for (const gate of GATE_ORDER) {
    let outcome: McpGateOutcome | null;
    try {
      outcome = runGate(gate, frame, direction, ctx, run);
    } catch (err) {
      outcome = {
        gate,
        decision: "deny",
        riskLevel: "high",
        reasons: [
          `Gate ${gate} failed internally and the frame was denied: ${err instanceof Error ? err.message : String(err)}`,
        ],
        detectionIds: [],
      };
    }

    if (outcome === null) continue;
    outcomes.push(outcome);

    // First deny stops the pipeline. Later gates could only make an already
    // refused frame more refused, and running a scanner across a payload that is
    // never going to be forwarded spends time to learn nothing.
    if (outcome.decision === "deny") {
      blockingGate = gate;
      break;
    }
  }

  let decision: Decision = "allow";
  let riskLevel: RiskLevel = "low";
  const reasons: string[] = [];
  const detectionIds: string[] = [];

  for (const outcome of outcomes) {
    decision = maxDecision(decision, outcome.decision);
    riskLevel = maxRisk(riskLevel, outcome.riskLevel);
    reasons.push(...outcome.reasons);
    detectionIds.push(...outcome.detectionIds);
  }

  const evaluation: McpEvaluation = {
    decision,
    riskLevel,
    reasons: dedupe(reasons),
    detectionIds: dedupe(detectionIds),
    outcomes,
  };

  if (blockingGate) {
    evaluation.blockingGate = blockingGate;
  }
  // A denied frame is never forwarded, so it must not carry a rewritten copy that
  // a caller could reach for with `redactedFrame ?? frame`. Withholding it makes
  // the wrong call impossible rather than merely discouraged.
  if (run.redactedFrame && decision !== "deny") {
    evaluation.redactedFrame = run.redactedFrame;
  }

  return evaluation;
}

/**
 * Accept the current inventory as this session's baseline.
 *
 * The descriptors are copied rather than referenced. The baseline has to mean
 * "what was approved at that moment": if it aliased the caller's array, a later
 * mutation there would silently move the line drift is measured against, and the
 * next poisoned description would compare clean.
 */
export function recordToolInventory(ctx: GateContext, tools: McpToolDescriptor[]): void {
  ctx.approvedTools = tools.map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema === undefined ? undefined : structuredClone(tool.inputSchema),
  }));
}
