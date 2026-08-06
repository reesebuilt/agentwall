import { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import { emit } from "../audit/logger";
import { RuntimeState } from "../dashboard/state";
import { InjectionFinding } from "../mcp/types";
import { scanText } from "../planes/identity/dlp";
import { inspectNetworkRequest } from "../planes/network/ssrf";
import { PolicyEngine } from "../policy/engine";
import { INJECTION_PATTERN_COUNT, scanInjection } from "../policy/injection";
import { AgentContext, Decision, NetworkInspection, Plane, PolicyResult, RiskLevel } from "../types";

/**
 * The Probe API: ask AgentWall for a verdict on content you already hold.
 *
 * Every detector behind these routes already runs inline on the proxy and MCP paths. This
 * surface exists because the inline paths only see traffic that goes through them, and a CI
 * job, a pre-commit hook, or a sibling service has content it wants judged without routing
 * it through a proxy first. Nothing here is a new detector; it is the missing door.
 *
 * The limit that matters, stated once here and again in docs/probe-api.md: a probe is a
 * point-in-time verdict on bytes the caller chose to hand over. It proves nothing about what
 * an agent actually did, because the caller decides what to submit and can submit nothing.
 * Treat a clean verdict as "no loaded rule or pattern objected to this input", never as
 * "this agent is behaving".
 */

/**
 * Per-field ceiling, in bytes of UTF-8.
 *
 * Matched to the injection scanner's own work cap (256 KiB) rather than picked round: a
 * larger field would be silently truncated by that scanner, and returning a verdict over
 * a prefix while implying it covered the whole input is exactly the kind of quiet
 * over-claim this codebase treats as a defect. Above the ceiling the caller gets 413 and
 * decides how to chunk, which keeps the "what was probed" question answerable.
 */
const MAX_FIELD_BYTES = 256 * 1024;

/**
 * Batch ceiling.
 *
 * Rejected rather than truncated: a caller who sends 150 items and receives 100 results has
 * 50 unprobed inputs it believes are clean, and that failure is silent at exactly the wrong
 * layer. Note that Fastify's own 1 MiB body limit binds first for large items, so the
 * practical batch is bounded by total bytes, not just by count.
 */
const MAX_BATCH_ITEMS = 100;

const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export type ProbeVerdict = "clean" | "flagged";

/**
 * One thing a detector objected to.
 *
 * `detail` is written by AgentWall, never echoed from the caller's input, with one deliberate
 * exception documented at `urlFindings`. Injection findings do not use this shape: they carry
 * the richer per-pattern record the scanner already produces.
 */
export interface ProbeFinding {
  /** Stable identifier, e.g. "network.cloud_metadata" or "dlp.secret.aws-access-key". */
  id: string;
  severity: RiskLevel;
  detail: string;
}

interface ProbeCore {
  verdict: ProbeVerdict;
  decision: Decision;
  riskLevel: RiskLevel;
  reasons: string[];
}

export interface UrlProbeResult extends ProbeCore {
  findings: ProbeFinding[];
}

export interface DlpProbeResult extends ProbeCore {
  findings: ProbeFinding[];
  containsSecrets: boolean;
  secretTypes: string[];
  containsPII: boolean;
  piiTypes: string[];
  /** Bytes of UTF-8 submitted. Reported so a caller can confirm what was actually probed. */
  inputBytes: number;
  /** Present only when the caller passed `redact: true`. */
  redactedText?: string;
}

export interface InjectionProbeResult extends ProbeCore {
  findings: InjectionFinding[];
  /** How many patterns were consulted, so a verdict can be tied to a detector version. */
  patternsEvaluated: number;
  inputBytes: number;
  /** Present only when the caller passed `strip: true`. */
  strippedText?: string;
}

export type ProbeBatchEntry =
  | ({ id: string; kind: "url"; auditEventId: string } & UrlProbeResult)
  | ({ id: string; kind: "dlp"; auditEventId: string } & DlpProbeResult)
  | ({ id: string; kind: "injection"; auditEventId: string } & InjectionProbeResult);

const ProbeUrlBodySchema = z.object({
  url: z.string(),
});

const ProbeDlpBodySchema = z.object({
  text: z.string(),
  redact: z.boolean().optional(),
});

const ProbeInjectionBodySchema = z.object({
  text: z.string(),
  strip: z.boolean().optional(),
});

const ProbeToolCallBodySchema = z.object({
  agentId: z.string(),
  tool: z.string(),
  // Key schema explicit for the same reason as AgentContext.payload: tool arguments are
  // keyed by whatever the tool author chose, and nothing here constrains that.
  arguments: z.record(z.string(), z.unknown()),
});

const ProbeBatchBodySchema = z.object({
  items: z.array(
    z.object({
      id: z.string(),
      kind: z.enum(["url", "dlp", "injection"]),
      value: z.string(),
    })
  ),
});

function tooLarge(reply: FastifyReply, field: string, bytes: number): FastifyReply {
  return reply.status(413).send({
    error: "Payload too large",
    detail: `Field '${field}' is ${bytes} bytes; the per-field ceiling is ${MAX_FIELD_BYTES} bytes. Split the input and probe it in parts.`,
  });
}

function maxSeverity(severities: RiskLevel[]): RiskLevel {
  let worst: RiskLevel = "low";
  for (const severity of severities) {
    if (RISK_ORDER[severity] > RISK_ORDER[worst]) worst = severity;
  }
  return worst;
}

/**
 * Turn a network inspection into findings.
 *
 * The one place a caller-supplied string reaches a finding: `blockedCategory` details carry
 * the inspector's own reason, which names the target hostname. That is deliberate — a network
 * verdict without its target is unactionable — and it is bounded to the hostname the URL
 * parser produced. The full URL never appears anywhere, here or in the audit record, because
 * query strings routinely carry tokens and an endpoint that probes for secrets must not be a
 * place secrets accumulate.
 */
function urlFindings(result: NetworkInspection): ProbeFinding[] {
  const findings: ProbeFinding[] = [];
  if (result.blockedCategory) {
    findings.push({
      id: `network.${result.blockedCategory.replace(/-/g, "_")}`,
      severity: result.riskLevel,
      detail: result.reason,
    });
  }
  if (result.ssrf) {
    findings.push({
      id: "network.ssrf_target",
      severity: result.riskLevel,
      detail: "Target is a server-side request forgery destination rather than an ordinary internet host",
    });
  }
  if (result.privateRange) {
    findings.push({
      id: "network.private_range",
      severity: result.riskLevel,
      detail: "Target is a private, link-local, or loopback address",
    });
  }
  return findings;
}

/**
 * Probe a URL for intrinsic target risk.
 *
 * `defaultDeny` is turned OFF for this path and only this path. The proxy's egress allowlist
 * answers "may this process reach that host", which is a question about the operator's
 * configuration; a probe answers "is this target dangerous", which is a question about the
 * target. Leaving default-deny on would flag every ordinary documentation link as an egress
 * violation and make the endpoint useless to the CI job that is the reason it exists. The
 * scheme and port defaults (https/443) are kept, because plaintext and odd ports are
 * properties of the target rather than of anyone's allowlist.
 */
function probeUrl(url: string): UrlProbeResult {
  const inspection = inspectNetworkRequest({ url }, { defaultDeny: false });
  const findings = urlFindings(inspection);
  return {
    verdict: inspection.allowed ? "clean" : "flagged",
    decision: inspection.allowed ? "allow" : "deny",
    riskLevel: inspection.riskLevel,
    findings,
    reasons: [inspection.reason],
  };
}

/**
 * Probe text for secret and personal data.
 *
 * Risk mapping mirrors classifyContent: secret material is critical, personal data is high.
 * The decision is `redact` rather than `deny` for both, because masking is the remediation
 * that actually exists for content the caller already holds; whether to escalate past that is
 * the caller's call, not this endpoint's.
 */
function probeDlp(text: string, redact: boolean): DlpProbeResult {
  const scan = scanText(text, redact);
  const findings: ProbeFinding[] = [
    ...scan.secretTypes.map((type) => ({
      id: `dlp.secret.${type}`,
      severity: "critical" as RiskLevel,
      detail: `Secret material matched the ${type} pattern`,
    })),
    ...scan.piiTypes.map((type) => ({
      id: `dlp.pii.${type}`,
      severity: "high" as RiskLevel,
      detail: `Personal data matched the ${type} pattern`,
    })),
  ];

  const reasons: string[] = [];
  if (scan.containsSecrets) reasons.push(`Secret material detected: ${scan.secretTypes.join(", ")}`);
  if (scan.containsPII) reasons.push(`Personal data detected: ${scan.piiTypes.join(", ")}`);
  if (reasons.length === 0) reasons.push("No known secret or personal-data pattern matched");

  const riskLevel: RiskLevel = scan.containsSecrets ? "critical" : scan.containsPII ? "high" : "low";
  const flagged = scan.containsSecrets || scan.containsPII;

  return {
    verdict: flagged ? "flagged" : "clean",
    decision: flagged ? "redact" : "allow",
    riskLevel,
    findings,
    // Type names only. The matched values are never repeated back: the caller already has
    // its own input, and a response body carrying the key it just asked about turns every
    // proxy log, error tracker, and CI artefact along the return path into a secret store.
    reasons,
    containsSecrets: scan.containsSecrets,
    secretTypes: scan.secretTypes,
    containsPII: scan.containsPII,
    piiTypes: scan.piiTypes,
    inputBytes: Buffer.byteLength(text, "utf8"),
    redactedText: scan.redactedText,
  };
}

/**
 * Probe text for prompt injection.
 *
 * Findings pass through as the scanner produced them, including the excerpt, which is already
 * bounded to a short window and run through DLP redaction before it leaves the scanner. That
 * is the one caller-derived string in the response, and it is here because a pattern id
 * without any sight of what matched is not triageable.
 *
 * The decision is advisory, not a policy outcome: no rule was consulted. It splits at
 * high/critical to mirror the severity rationale in the injection pattern pack — a directive
 * that moves credentials or executes a command has no recovery from a successful one, while
 * a medium finding is a real precursor that on its own changes tone, not state.
 */
function probeInjectionText(text: string, strip: boolean): InjectionProbeResult {
  const scan = scanInjection(text, { strip });
  const riskLevel = maxSeverity(scan.findings.map((finding) => finding.severity));
  const severe = riskLevel === "critical" || riskLevel === "high";
  return {
    verdict: scan.containsInjection ? "flagged" : "clean",
    decision: scan.containsInjection ? (severe ? "deny" : "approve") : "allow",
    riskLevel: scan.containsInjection ? riskLevel : "low",
    findings: scan.findings,
    // Pattern ids and passes only. The excerpts stay in `findings`, which is the response the
    // caller asked for; they must not leak into the audit reasons, which are written to the
    // evidence chain and to stdout.
    reasons: scan.containsInjection
      ? scan.findings.map((finding) => `${finding.patternId} matched on the ${finding.pass} pass`)
      : ["No known injection pattern matched"],
    patternsEvaluated: INJECTION_PATTERN_COUNT,
    inputBytes: Buffer.byteLength(text, "utf8"),
    strippedText: scan.strippedText,
  };
}

/**
 * Write a probe verdict to the audit chain.
 *
 * Probes are themselves accountable: somebody with a token can ask this service to judge
 * arbitrary content, and that activity should be visible in the same evidence stream as
 * everything else. What goes in is the verdict, the plane, and the input SIZE. What never
 * goes in is the input, because the whole point of /probe/dlp is that callers send it their
 * secrets, and an audit chain is durable, hash-linked, and frequently shipped off-box.
 *
 * `matchedRules` is empty and `detections` is empty on purpose for the detector routes. No
 * policy rule was consulted, and attaching rule ids the probe never evaluated would put a
 * false claim into a record whose only value is being true.
 */
function recordProbe(
  runtime: RuntimeState,
  probe: {
    plane: Plane;
    action: string;
    kind: string;
    core: ProbeCore;
    inputBytes: number;
    findingCount: number;
  }
): string {
  const ctx: AgentContext = {
    agentId: "probe-api",
    sessionId: `probe:${probe.kind}`,
    plane: probe.plane,
    action: probe.action,
    // Empty by construction, not stripped after the fact: there is no code path on which
    // caller text can reach the audit record through this context.
    payload: {},
    metadata: {
      probeKind: probe.kind,
      probeVerdict: probe.core.verdict,
      probeInputBytes: String(probe.inputBytes),
      probeFindingCount: String(probe.findingCount),
    },
  };
  const result: PolicyResult = {
    decision: probe.core.decision,
    riskLevel: probe.core.riskLevel,
    matchedRules: [],
    reasons: probe.core.reasons,
    requiresApproval: probe.core.decision === "approve",
    highRiskFlow: false,
    detections: [],
  };
  const event = emit(ctx, result);
  runtime.recordAuditEvent(event);
  return event.id;
}

export async function probeRoutes(
  app: FastifyInstance,
  engine: PolicyEngine,
  runtime: RuntimeState
): Promise<void> {
  app.post("/probe/url", async (req, reply) => {
    const parsed = ProbeUrlBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid request body", details: parsed.error.flatten() });
    }

    const bytes = Buffer.byteLength(parsed.data.url, "utf8");
    if (bytes > MAX_FIELD_BYTES) {
      return tooLarge(reply, "url", bytes);
    }

    const result = probeUrl(parsed.data.url);
    const auditEventId = recordProbe(runtime, {
      plane: "network",
      action: "probe_url",
      kind: "url",
      core: result,
      inputBytes: bytes,
      findingCount: result.findings.length,
    });

    return reply.send({ ...result, auditEventId });
  });

  app.post("/probe/dlp", async (req, reply) => {
    const parsed = ProbeDlpBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid request body", details: parsed.error.flatten() });
    }

    const bytes = Buffer.byteLength(parsed.data.text, "utf8");
    if (bytes > MAX_FIELD_BYTES) {
      return tooLarge(reply, "text", bytes);
    }

    const result = probeDlp(parsed.data.text, parsed.data.redact === true);
    const auditEventId = recordProbe(runtime, {
      plane: "content",
      action: "probe_dlp",
      kind: "dlp",
      core: result,
      inputBytes: bytes,
      findingCount: result.findings.length,
    });

    // The response carries types, counts, and — only when explicitly requested — the
    // caller's own text with matches masked. The raw input is never echoed and never
    // logged: an endpoint you send secrets to must not become a place secrets accumulate,
    // and every copy of a secret is another thing that has to be rotated later.
    return reply.send({ ...result, auditEventId });
  });

  app.post("/probe/injection", async (req, reply) => {
    const parsed = ProbeInjectionBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid request body", details: parsed.error.flatten() });
    }

    const bytes = Buffer.byteLength(parsed.data.text, "utf8");
    if (bytes > MAX_FIELD_BYTES) {
      return tooLarge(reply, "text", bytes);
    }

    const result = probeInjectionText(parsed.data.text, parsed.data.strip === true);
    const auditEventId = recordProbe(runtime, {
      plane: "content",
      action: "probe_injection",
      kind: "injection",
      core: result,
      inputBytes: bytes,
      findingCount: result.findings.length,
    });

    return reply.send({ ...result, auditEventId });
  });

  app.post("/probe/tool-call", async (req, reply) => {
    const parsed = ProbeToolCallBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid request body", details: parsed.error.flatten() });
    }

    // Arguments are an object, so the ceiling applies to their serialized form. Without this
    // the per-field limit would be trivially bypassed by nesting the payload.
    const serialized = JSON.stringify(parsed.data.arguments);
    const bytes = Buffer.byteLength(serialized, "utf8");
    if (bytes > MAX_FIELD_BYTES) {
      return tooLarge(reply, "arguments", bytes);
    }

    // This route DOES consult the policy engine, so unlike the detector routes its context
    // carries the real payload: the rules match on argument content and an evaluation over
    // an emptied payload would be a different, weaker evaluation. The audit event still
    // records no payload — emit() writes decision, rules, and metadata, never the context
    // body — so arguments are visible to the rules and invisible to the evidence stream.
    const ctx: AgentContext = {
      agentId: parsed.data.agentId,
      sessionId: "probe:tool-call",
      plane: "tool",
      // The tool name IS the action: builtin rules match shell, delete, and write verbs
      // against it, so passing it through unchanged is what makes the evaluation real.
      action: parsed.data.tool,
      payload: parsed.data.arguments,
      metadata: {
        probeKind: "tool-call",
        probeInputBytes: String(bytes),
      },
    };
    const result = engine.evaluate(ctx);
    const event = emit(ctx, result);
    runtime.recordAuditEvent(event);

    return reply.send({
      verdict: result.decision === "allow" ? "clean" : "flagged",
      decision: result.decision,
      riskLevel: result.riskLevel,
      matchedRules: result.matchedRules,
      reasons: result.reasons,
      detections: result.detections,
      requiresApproval: result.requiresApproval,
      highRiskFlow: result.highRiskFlow,
      auditEventId: event.id,
    });
  });

  app.post("/probe/batch", async (req, reply) => {
    const parsed = ProbeBatchBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid request body", details: parsed.error.flatten() });
    }

    const { items } = parsed.data;
    if (items.length > MAX_BATCH_ITEMS) {
      return reply.status(413).send({
        error: "Batch too large",
        detail: `Received ${items.length} items; the ceiling is ${MAX_BATCH_ITEMS}. The batch was rejected rather than truncated, so no item is reported clean without having been probed.`,
      });
    }

    // One pass for both preconditions. A full batch can carry 25 MiB of text, and measuring
    // it once for the ceiling and again for the audit record is 25 MiB of pointless work
    // before any probing starts.
    const sizes: number[] = new Array(items.length);
    const seen = new Set<string>();
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const bytes = Buffer.byteLength(item.value, "utf8");
      if (bytes > MAX_FIELD_BYTES) {
        return tooLarge(reply, `items[${item.id}].value`, bytes);
      }
      // Duplicate ids would silently collapse in the keyed response, and the caller would
      // read one item's verdict as another's. Rejecting is the only answer that cannot
      // mislead, and it happens before anything is probed or recorded.
      if (seen.has(item.id)) {
        return reply.status(400).send({
          error: "Invalid request body",
          detail: `Duplicate item id '${item.id}'. Results are keyed by id, so ids must be unique within a batch.`,
        });
      }
      seen.add(item.id);
      sizes[i] = bytes;
    }

    // One audit event per item, not one per batch: a batch is a transport convenience, and
    // collapsing 100 verdicts into a single record would make the evidence stream depend on
    // how the caller chose to group its requests.
    const results: Record<string, ProbeBatchEntry> = {};
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const inputBytes = sizes[i];
      if (item.kind === "url") {
        const result = probeUrl(item.value);
        const auditEventId = recordProbe(runtime, {
          plane: "network",
          action: "probe_url",
          kind: "url",
          core: result,
          inputBytes,
          findingCount: result.findings.length,
        });
        results[item.id] = { id: item.id, kind: "url", auditEventId, ...result };
      } else if (item.kind === "dlp") {
        // No redaction in batch mode: the request has no per-item redact flag, and returning
        // transformed copies of a hundred inputs is the opposite of what this endpoint is for.
        const result = probeDlp(item.value, false);
        const auditEventId = recordProbe(runtime, {
          plane: "content",
          action: "probe_dlp",
          kind: "dlp",
          core: result,
          inputBytes,
          findingCount: result.findings.length,
        });
        results[item.id] = { id: item.id, kind: "dlp", auditEventId, ...result };
      } else {
        const result = probeInjectionText(item.value, false);
        const auditEventId = recordProbe(runtime, {
          plane: "content",
          action: "probe_injection",
          kind: "injection",
          core: result,
          inputBytes,
          findingCount: result.findings.length,
        });
        results[item.id] = { id: item.id, kind: "injection", auditEventId, ...result };
      }
    }

    const flagged = Object.values(results).filter((entry) => entry.verdict === "flagged").length;
    return reply.send({
      probed: items.length,
      flagged,
      results,
    });
  });
}
