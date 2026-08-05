import { FastifyInstance } from "fastify";
import { inspectNetworkRequest } from "../planes/network/ssrf";
import { classifyContent } from "../planes/identity/dlp";
import {
  ManifestFingerprintSchema,
  ManifestSubjectTypeSchema,
  NetworkRequestSchema,
  ProvenanceSourceSchema,
  TrustLabelSchema,
} from "../types";
import { z } from "zod";
import { AgentwallConfig } from "../config";
import { RuntimeState } from "../dashboard/state";
import { detectManifestDrift } from "../integrity/manifest";
import { DecisionTraceExporter } from "../telemetry/otel";

const ContentInspectBodySchema = z.object({
  text: z.string(),
  source: ProvenanceSourceSchema.optional(),
  trustLabel: TrustLabelSchema.optional(),
  redact: z.boolean().optional(),
});

const ManifestInspectBodySchema = z.object({
  subjectId: z.string(),
  subjectType: ManifestSubjectTypeSchema,
  manifest: z.unknown(),
  approvedFingerprint: ManifestFingerprintSchema.optional(),
  source: z.string().optional(),
});

export async function inspectRoutes(
  app: FastifyInstance,
  config: AgentwallConfig,
  runtime: RuntimeState,
  telemetry: DecisionTraceExporter
): Promise<void> {
  app.post("/inspect/network", async (req, reply) => {
    const startedAtMs = Date.now();
    const startedAtHrTime = process.hrtime.bigint();
    const parsed = NetworkRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid request body", details: parsed.error.flatten() });
    }

    const result = inspectNetworkRequest(parsed.data, config.egress);
    runtime.recordNetworkInspection(parsed.data, result);

    await telemetry.export({
      routeName: "inspect.network",
      routePath: "/inspect/network",
      plane: "network",
      action: "inspect_network",
      decision: result.allowed ? "allow" : "deny",
      riskLevel: result.riskLevel,
      resultStatus: result.allowed ? "allowed" : "blocked",
      startedAtMs,
      durationNs: process.hrtime.bigint() - startedAtHrTime,
      httpMethod: req.method,
      httpStatusCode: 200,
      attributes: {
        "agentwall.target_url": parsed.data.url,
        "agentwall.network_allowed": result.allowed,
        "agentwall.network_ssrf": result.ssrf,
        "agentwall.network_private_range": result.privateRange,
        "agentwall.network_egress_denied": result.egressDenied,
        "agentwall.network_blocked_category": result.blockedCategory,
      },
    });

    return reply.send(result);
  });

  app.post("/inspect/content", async (req, reply) => {
    const startedAtMs = Date.now();
    const startedAtHrTime = process.hrtime.bigint();
    const parsed = ContentInspectBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid request body", details: parsed.error.flatten() });
    }

    const { text, source = "user", trustLabel, redact = config.dlp.redactSecrets } = parsed.data;
    const result = classifyContent(text, trustLabel, redact, source);
    runtime.recordContentInspection(text, result);

    await telemetry.export({
      routeName: "inspect.content",
      routePath: "/inspect/content",
      plane: "content",
      action: "inspect_content",
      decision: result.redacted ? "redact" : "allow",
      riskLevel: result.riskLevel,
      resultStatus: result.containsSecrets || result.containsPII ? "sensitive_content_detected" : "clear",
      startedAtMs,
      durationNs: process.hrtime.bigint() - startedAtHrTime,
      httpMethod: req.method,
      httpStatusCode: 200,
      attributes: {
        "agentwall.content_source": result.source,
        "agentwall.content_trust_label": result.trustLabel,
        "agentwall.content_contains_secrets": result.containsSecrets,
        "agentwall.content_contains_pii": result.containsPII,
        "agentwall.content_redacted": result.redacted,
        "agentwall.content_label_count": result.labels.length,
        "agentwall.content_secret_type_count": result.secretTypes.length,
        "agentwall.content_pii_type_count": result.piiTypes.length,
      },
    });

    return reply.send(result);
  });

  app.post("/inspect/manifest", async (req, reply) => {
    const startedAtMs = Date.now();
    const startedAtHrTime = process.hrtime.bigint();
    const parsed = ManifestInspectBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid request body", details: parsed.error.flatten() });
    }

    const inspection: {
      subjectId: string;
      subjectType: z.infer<typeof ManifestSubjectTypeSchema>;
      manifest: unknown;
      approvedFingerprint?: z.infer<typeof ManifestFingerprintSchema>;
      source?: string;
    } = {
      subjectId: parsed.data.subjectId as string,
      subjectType: parsed.data.subjectType as z.infer<typeof ManifestSubjectTypeSchema>,
      manifest: parsed.data.manifest,
      approvedFingerprint: parsed.data.approvedFingerprint,
      source: parsed.data.source,
    };
    const result = detectManifestDrift(inspection);
    runtime.recordManifestInspection(inspection, result);

    await telemetry.export({
      routeName: "inspect.manifest",
      routePath: "/inspect/manifest",
      plane: "governance",
      action: "inspect_manifest",
      decision: manifestTrustDecision(result.trustState),
      riskLevel: manifestRiskLevel(result.trustState, result.status),
      resultStatus: result.status,
      startedAtMs,
      durationNs: process.hrtime.bigint() - startedAtHrTime,
      httpMethod: req.method,
      httpStatusCode: 200,
      attributes: {
        "agentwall.subject_id": result.subjectId,
        "agentwall.subject_type": result.subjectType,
        "agentwall.manifest_trust_state": result.trustState,
        "agentwall.manifest_changed": result.changed,
        "agentwall.manifest_requires_reapproval": result.requiresReapproval,
        "agentwall.manifest_attestation_status": result.attestation.status,
      },
    });

    return reply.send(result);
  });
}

function manifestTrustDecision(trustState: "trusted" | "review_required" | "untrusted"): "allow" | "approve" | "deny" {
  if (trustState === "trusted") {
    return "allow";
  }

  if (trustState === "review_required") {
    return "approve";
  }

  return "deny";
}

function manifestRiskLevel(
  trustState: "trusted" | "review_required" | "untrusted",
  status: "approved" | "drifted" | "missing" | "untracked"
): "low" | "medium" | "high" | "critical" {
  if (trustState === "untrusted") {
    return "critical";
  }

  if (trustState === "review_required") {
    return status === "untracked" ? "medium" : "high";
  }

  return "low";
}
