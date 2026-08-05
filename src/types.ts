import { z } from "zod";

// --- Decision types ---

export const DecisionSchema = z.enum(["allow", "deny", "approve", "redact"]);
export type Decision = z.infer<typeof DecisionSchema>;

export const RiskLevelSchema = z.enum(["low", "medium", "high", "critical"]);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const PlaneSchema = z.enum([
  "network",
  "tool",
  "content",
  "browser",
  "identity",
  "governance",
]);
export type Plane = z.infer<typeof PlaneSchema>;

// --- Provenance / flow ---

export const ProvenanceSourceSchema = z.enum([
  "user",
  "system",
  "web",
  "email",
  "tool_metadata",
  "tool_output",
  "memory",
]);
export type ProvenanceSource = z.infer<typeof ProvenanceSourceSchema>;

export const TrustLabelSchema = z.enum(["trusted", "untrusted", "derived"]);
export type TrustLabel = z.infer<typeof TrustLabelSchema>;

export const FlowDirectionSchema = z.enum(["ingress", "internal", "egress"]);
export type FlowDirection = z.infer<typeof FlowDirectionSchema>;

export const FlowLabelSchema = z.enum([
  "external_egress",
  "cross_boundary",
  "high_risk",
  "secret_material",
  "pii",
  "credential_access",
  "destructive_action",
  "payment",
  "private_network_target",
  "manifest_drift",
  "watchdog_timeout",
]);
export type FlowLabel = z.infer<typeof FlowLabelSchema>;

export const ProvenanceTagSchema = z.object({
  source: ProvenanceSourceSchema,
  trustLabel: TrustLabelSchema,
  labels: z.array(FlowLabelSchema).optional(),
  derivedFrom: z.array(ProvenanceSourceSchema).optional(),
  justification: z.string().optional(),
});
export type ProvenanceTag = z.infer<typeof ProvenanceTagSchema>;

export const FlowDescriptorSchema = z.object({
  direction: FlowDirectionSchema,
  channel: z.string().optional(),
  target: z.string().optional(),
  labels: z.array(FlowLabelSchema).optional(),
  crossesBoundary: z.boolean().optional(),
  highRisk: z.boolean().optional(),
});
export type FlowDescriptor = z.infer<typeof FlowDescriptorSchema>;

export const ActorScopeSchema = z.object({
  channelId: z.string().optional(),
  userId: z.string().optional(),
  roleIds: z.array(z.string()).optional(),
});
export type ActorScope = z.infer<typeof ActorScopeSchema>;

export const ExecutionModeSchema = z.enum(["normal", "read_only", "answer_only"]);
export type ExecutionMode = z.infer<typeof ExecutionModeSchema>;

export const ControlPlaneStateSchema = z.object({
  executionMode: ExecutionModeSchema.default("normal"),
  reason: z.string().optional(),
  enforcedBy: z.string().optional(),
});
export type ControlPlaneState = z.infer<typeof ControlPlaneStateSchema>;

// --- Request / context ---

export const AgentContextSchema = z.object({
  agentId: z.string(),
  sessionId: z.string().optional(),
  plane: PlaneSchema,
  action: z.string(),
  // Key schemas are explicit: both records are keyed by arbitrary caller-supplied
  // strings, so nothing here constrains which keys may appear.
  payload: z.record(z.string(), z.unknown()),
  metadata: z.record(z.string(), z.string()).optional(),
  actor: ActorScopeSchema.optional(),
  control: ControlPlaneStateSchema.optional(),
  provenance: z.array(ProvenanceTagSchema).optional(),
  flow: FlowDescriptorSchema.optional(),
});
export type AgentContext = z.infer<typeof AgentContextSchema>;

// --- Policy ---

export interface PolicyRuleScope {
  actor?: {
    channelIds?: string[];
    userIds?: string[];
    roleIds?: string[];
  };
  subject?: {
    agentIds?: string[];
    sessionIds?: string[];
  };
  control?: {
    executionModes?: ExecutionMode[];
  };
}

export interface PolicyRule {
  id: string;
  description: string;
  plane: Plane | "all";
  match: (ctx: AgentContext) => boolean;
  decision: Decision;
  riskLevel: RiskLevel;
  reason: string;
  scope?: PolicyRuleScope;
}

export interface DetectionMatch {
  id: string;
  ruleId: string;
  name: string;
  description: string;
  severity: RiskLevel;
  mitreAttack?: {
    tactic: string;
    technique: string;
    techniqueId: string;
  };
}

export interface PolicyResult {
  decision: Decision;
  riskLevel: RiskLevel;
  matchedRules: string[];
  reasons: string[];
  requiresApproval: boolean;
  highRiskFlow: boolean;
  detections: DetectionMatch[];
}

export interface CapabilityTicketFlowConstraints {
  direction: FlowDirection;
  labels?: FlowLabel[];
  target?: string;
  highRisk?: boolean;
  crossesBoundary?: boolean;
}

export interface CapabilityTicketConstraints {
  payloadKeys: string[];
  flow?: CapabilityTicketFlowConstraints;
}

export interface CapabilityTicket {
  id: string;
  issuedAt: string;
  expiresAt: string;
  decision: Decision;
  riskLevel: RiskLevel;
  agentId: string;
  sessionId?: string;
  plane: Plane;
  action: string;
  actor?: ActorScope;
  constraints: CapabilityTicketConstraints;
  signature: string;
}

export interface PolicyEvaluationResponse {
  decision: Decision;
  riskLevel: RiskLevel;
  matchedRules: string[];
  reasons: string[];
  requiresApproval: boolean;
  highRiskFlow: boolean;
  detections: DetectionMatch[];
  auditEventId: string;
  capabilityTicket?: CapabilityTicket;
}

// --- Audit ---

export interface AuditIntegrity {
  chainIndex: number;
  hash: string;
  previousHash: string | null;
  algorithm: "sha256";
  /**
   * What the writer attests at write time, NOT a verification result.
   * "chained-local": hash-linked into the local chain when written. It says nothing
   * about whether the chain has since been verified, signed, or anchored off-box —
   * the previous label ("verified-local") implied all three and delivered none.
   */
  status: "chained-local";
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  agentId: string;
  sessionId?: string;
  plane: Plane;
  action: string;
  decision: Decision;
  riskLevel: RiskLevel;
  matchedRules: string[];
  reasons: string[];
  requiresApproval: boolean;
  highRiskFlow: boolean;
  detections?: DetectionMatch[];
  metadata?: Record<string, string>;
  actor?: ActorScope;
  provenance?: ProvenanceTag[];
  flow?: FlowDescriptor;
  integrity: AuditIntegrity;
}

// --- Approval ---

export const ApprovalRequestSchema = z.object({
  context: AgentContextSchema,
  policyResult: z.object({
    decision: DecisionSchema,
    riskLevel: RiskLevelSchema,
    matchedRules: z.array(z.string()),
    reasons: z.array(z.string()),
    requiresApproval: z.boolean(),
    highRiskFlow: z.boolean().optional(),
    detections: z.array(z.object({
      id: z.string(),
      ruleId: z.string(),
      name: z.string(),
      description: z.string(),
      severity: RiskLevelSchema,
      mitreAttack: z.object({
        tactic: z.string(),
        technique: z.string(),
        techniqueId: z.string(),
      }).optional(),
    })).optional(),
  }),
  timeoutMs: z.number().optional(),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;

export const ApprovalResponseSchema = z.object({
  requestId: z.string(),
  decision: z.enum(["approved", "denied", "timeout"]),
  approvedBy: z.string().optional(),
  note: z.string().optional(),
  timestamp: z.string(),
});
export type ApprovalResponse = z.infer<typeof ApprovalResponseSchema>;

// --- Content ---

export const ContentClassificationSchema = z.object({
  source: ProvenanceSourceSchema,
  trustLabel: TrustLabelSchema,
  labels: z.array(FlowLabelSchema),
  containsSecrets: z.boolean(),
  secretTypes: z.array(z.string()),
  containsPII: z.boolean(),
  piiTypes: z.array(z.string()),
  riskLevel: RiskLevelSchema,
  redacted: z.boolean(),
});
export type ContentClassification = z.infer<typeof ContentClassificationSchema>;

// --- Network ---

export const NetworkRequestSchema = z.object({
  url: z.string(),
  method: z.string().optional(),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.string().optional(),
});
export type NetworkRequest = z.infer<typeof NetworkRequestSchema>;

export const NetworkInspectionSchema = z.object({
  allowed: z.boolean(),
  reason: z.string(),
  riskLevel: RiskLevelSchema,
  ssrf: z.boolean(),
  privateRange: z.boolean(),
  blockedCategory: z.string().optional(),
  egressDenied: z.boolean(),
});
export type NetworkInspection = z.infer<typeof NetworkInspectionSchema>;

export const EgressPolicySchema = z.object({
  enabled: z.boolean(),
  defaultDeny: z.boolean(),
  allowPrivateRanges: z.boolean(),
  allowedHosts: z.array(z.string()),
  allowedSchemes: z.array(z.string()),
  allowedPorts: z.array(z.number()),
});
export type EgressPolicy = z.infer<typeof EgressPolicySchema>;

// --- Manifest integrity ---

export const ManifestSubjectTypeSchema = z.enum(["tool", "mcp_server"]);
export type ManifestSubjectType = z.infer<typeof ManifestSubjectTypeSchema>;

export const ManifestAttestationEnvelopeSchema = z.object({
  version: z.literal(1),
  algorithm: z.literal("hmac-sha256"),
  subjectId: z.string(),
  subjectType: ManifestSubjectTypeSchema,
  fingerprintHash: z.string(),
  fingerprintAlgorithm: z.literal("sha256"),
  issuedAt: z.string(),
  signer: z.string(),
  signature: z.string(),
});
export type ManifestAttestationEnvelope = z.infer<typeof ManifestAttestationEnvelopeSchema>;

export const ManifestFingerprintSchema = z.object({
  algorithm: z.literal("sha256"),
  hash: z.string(),
  manifestSize: z.number(),
  source: z.string().optional(),
  approvedAt: z.string().optional(),
  attestation: ManifestAttestationEnvelopeSchema.optional(),
});
export type ManifestFingerprint = z.infer<typeof ManifestFingerprintSchema>;

export const ManifestIntegrityStatusSchema = z.enum(["approved", "drifted", "missing", "untracked"]);
export type ManifestIntegrityStatus = z.infer<typeof ManifestIntegrityStatusSchema>;

export const ManifestTrustStateSchema = z.enum(["trusted", "review_required", "untrusted"]);
export type ManifestTrustState = z.infer<typeof ManifestTrustStateSchema>;

export const ManifestAttestationStatusSchema = z.enum(["valid", "missing", "invalid", "not_applicable"]);
export type ManifestAttestationStatus = z.infer<typeof ManifestAttestationStatusSchema>;

export const ManifestAttestationAssessmentSchema = z.object({
  status: ManifestAttestationStatusSchema,
  signer: z.string().optional(),
  issuedAt: z.string().optional(),
});
export type ManifestAttestationAssessment = z.infer<typeof ManifestAttestationAssessmentSchema>;

export const ManifestDriftSchema = z.object({
  subjectId: z.string(),
  subjectType: ManifestSubjectTypeSchema,
  status: ManifestIntegrityStatusSchema,
  trustState: ManifestTrustStateSchema,
  changed: z.boolean(),
  requiresReapproval: z.boolean(),
  reason: z.string(),
  attestation: ManifestAttestationAssessmentSchema,
  currentFingerprint: ManifestFingerprintSchema,
  approvedFingerprint: ManifestFingerprintSchema.optional(),
});
export type ManifestDrift = z.infer<typeof ManifestDriftSchema>;

// --- Watchdog / kill switch ---

export const HeartbeatStatusSchema = z.enum(["healthy", "stale", "expired", "disabled"]);
export type HeartbeatStatus = z.infer<typeof HeartbeatStatusSchema>;

export const KillSwitchModeSchema = z.enum(["monitor", "deny_all", "approve_only"]);
export type KillSwitchMode = z.infer<typeof KillSwitchModeSchema>;

export const HeartbeatConfigSchema = z.object({
  enabled: z.boolean(),
  staleAfterMs: z.number(),
  timeoutMs: z.number(),
  killSwitchMode: KillSwitchModeSchema,
});
export type HeartbeatConfig = z.infer<typeof HeartbeatConfigSchema>;

export const WatchdogStateSchema = z.object({
  agentId: z.string(),
  status: HeartbeatStatusSchema,
  lastHeartbeatAt: z.string().optional(),
  killSwitchEngaged: z.boolean(),
  reason: z.string(),
});
export type WatchdogState = z.infer<typeof WatchdogStateSchema>;
