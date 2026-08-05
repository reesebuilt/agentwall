import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import { z } from "zod";
import {
  AgentContext,
  DecisionSchema,
  ExecutionMode,
  FlowLabelSchema,
  PlaneSchema,
  PolicyRule,
  PolicyRuleScope,
  ProvenanceSourceSchema,
  RiskLevelSchema,
  TrustLabelSchema,
} from "../types";
import { extractHostname, isPrivateHostname, isPrivateIp } from "../planes/network/ssrf";

export const MatchSchema = z.object({
  type: z.enum(["hostname-equals"]).optional(),
  values: z.array(z.string()).optional(),
  action: z.object({
    equals: z.array(z.string()).optional(),
    includes: z.array(z.string()).optional(),
  }).optional(),
  payload: z.object({
    includes: z.array(z.string()).optional(),
    hasKeys: z.array(z.string()).optional(),
  }).optional(),
  flow: z.object({
    direction: z.enum(["ingress", "internal", "egress"]).optional(),
    labels: z.array(FlowLabelSchema).optional(),
    highRisk: z.boolean().optional(),
    crossesBoundary: z.boolean().optional(),
  }).optional(),
  provenance: z.object({
    source: z.array(ProvenanceSourceSchema).optional(),
    trustLabel: z.array(TrustLabelSchema).optional(),
  }).optional(),
  actor: z.object({
    channelId: z.array(z.string()).optional(),
    userId: z.array(z.string()).optional(),
    roleId: z.array(z.string()).optional(),
  }).optional(),
  subject: z.object({
    agentId: z.array(z.string()).optional(),
    sessionId: z.array(z.string()).optional(),
  }).optional(),
  control: z.object({
    executionMode: z.array(z.enum(["normal", "read_only", "answer_only"])).optional(),
  }).optional(),
}).refine((value) => {
  return Boolean(
    value.type || value.action || value.payload || value.flow || value.provenance || value.actor || value.subject || value.control
  );
}, "Custom rule match must include at least one matcher");

export const DeclarativePolicyRuleSchema = z.object({
  id: z.string(),
  description: z.string(),
  plane: PlaneSchema.or(z.literal("all")),
  match: MatchSchema,
  decision: DecisionSchema,
  riskLevel: RiskLevelSchema,
  reason: z.string(),
  enabled: z.boolean().optional(),
});

export const PolicyFileSchema = z.object({
  version: z.string().optional(),
  rules: z.array(DeclarativePolicyRuleSchema).default([]),
});

export type DeclarativePolicyRule = z.infer<typeof DeclarativePolicyRuleSchema>;
export type DeclarativePolicyFile = z.infer<typeof PolicyFileSchema>;

function payloadText(payload: Record<string, unknown>): string {
  return JSON.stringify(payload).toLowerCase();
}

function payloadHasKeys(payload: Record<string, unknown>, keys: string[]): boolean {
  const payloadKeys = new Set(Object.keys(payload));
  return keys.some((key) => payloadKeys.has(key));
}

function extractHostFromPayload(payload: Record<string, unknown>): string | null {
  const url = payload["url"] ?? payload["target"] ?? payload["href"];
  return typeof url === "string" ? extractHostname(url) : null;
}

function hostnameMatches(ctx: AgentContext, values: string[]): boolean {
  const host = extractHostFromPayload(ctx.payload);
  if (!host) return false;
  const normalized = host.toLowerCase();
  return values.some((value) => normalized === value.toLowerCase());
}

function buildMatch(rule: DeclarativePolicyRule): (ctx: AgentContext) => boolean {
  const expectedActionEquals = rule.match.action?.equals?.map((value) => value.toLowerCase());
  const expectedActionIncludes = rule.match.action?.includes?.map((value) => value.toLowerCase());
  const expectedPayloadIncludes = rule.match.payload?.includes?.map((value) => value.toLowerCase());
  const expectedPayloadKeys = rule.match.payload?.hasKeys;
  const expectedFlowLabels = rule.match.flow?.labels;
  const expectedSources = rule.match.provenance?.source;
  const expectedTrustLabels = rule.match.provenance?.trustLabel;
  const expectedHostValues = rule.match.values;
  const expectedChannelIds = rule.match.actor?.channelId;
  const expectedUserIds = rule.match.actor?.userId;
  const expectedRoleIds = rule.match.actor?.roleId;
  const expectedAgentIds = rule.match.subject?.agentId;
  const expectedSessionIds = rule.match.subject?.sessionId;
  const expectedExecutionModes = rule.match.control?.executionMode;

  return (ctx: AgentContext) => {
    if (rule.plane !== "all" && ctx.plane !== rule.plane) return false;

    if (rule.match.type === "hostname-equals") {
      if (!expectedHostValues?.length || !hostnameMatches(ctx, expectedHostValues)) return false;
    }

    if (expectedActionEquals?.length && !expectedActionEquals.includes(ctx.action.toLowerCase())) {
      return false;
    }

    if (expectedActionIncludes?.length) {
      const action = ctx.action.toLowerCase();
      if (!expectedActionIncludes.some((value) => action.includes(value))) return false;
    }

    if (expectedPayloadIncludes?.length) {
      const serialized = payloadText(ctx.payload);
      if (!expectedPayloadIncludes.some((value) => serialized.includes(value))) return false;
    }

    if (expectedPayloadKeys?.length && !payloadHasKeys(ctx.payload, expectedPayloadKeys)) {
      return false;
    }

    if (rule.match.flow?.direction && ctx.flow?.direction !== rule.match.flow.direction) {
      return false;
    }

    if (expectedFlowLabels?.length) {
      const labels = ctx.flow?.labels ?? [];
      if (!expectedFlowLabels.every((label) => labels.includes(label))) return false;
    }

    if (rule.match.flow?.highRisk !== undefined && ctx.flow?.highRisk !== rule.match.flow.highRisk) {
      return false;
    }

    if (rule.match.flow?.crossesBoundary !== undefined && ctx.flow?.crossesBoundary !== rule.match.flow.crossesBoundary) {
      return false;
    }

    if (expectedSources?.length) {
      const sources = ctx.provenance?.map((entry) => entry.source) ?? [];
      if (!expectedSources.some((source) => sources.includes(source))) return false;
    }

    if (expectedTrustLabels?.length) {
      const trustLabels = ctx.provenance?.map((entry) => entry.trustLabel) ?? [];
      if (!expectedTrustLabels.some((label) => trustLabels.includes(label))) return false;
    }

    if (expectedChannelIds?.length) {
      const channelId = ctx.actor?.channelId;
      if (!channelId || !expectedChannelIds.includes(channelId)) return false;
    }

    if (expectedUserIds?.length) {
      const userId = ctx.actor?.userId;
      if (!userId || !expectedUserIds.includes(userId)) return false;
    }

    if (expectedRoleIds?.length) {
      const roleIds = ctx.actor?.roleIds ?? [];
      if (!expectedRoleIds.some((roleId) => roleIds.includes(roleId))) return false;
    }

    if (expectedAgentIds?.length) {
      if (!expectedAgentIds.includes(ctx.agentId)) return false;
    }

    if (expectedSessionIds?.length) {
      const sessionId = ctx.sessionId;
      if (!sessionId || !expectedSessionIds.includes(sessionId)) return false;
    }

    if (expectedExecutionModes?.length) {
      const executionMode = ctx.control?.executionMode ?? "normal";
      if (!expectedExecutionModes.includes(executionMode)) return false;
    }

    return true;
  };
}

function validateDeclarativeRuleShape(rule: DeclarativePolicyRule): void {
  if (rule.match.type === "hostname-equals") {
    if (!rule.match.values?.length) {
      throw new Error(`Custom rule ${rule.id} uses hostname-equals but has no values`);
    }

    const invalidValues = rule.match.values.filter((value) => {
      const normalized = value.toLowerCase();
      return isPrivateHostname(normalized) || isPrivateIp(normalized);
    });

    if (invalidValues.length > 0) {
      throw new Error(`Custom rule ${rule.id} cannot allow private or local hosts via hostname-equals: ${invalidValues.join(", ")}`);
    }
  }
}

export function buildRuleScope(rule: DeclarativePolicyRule): PolicyRuleScope | undefined {
  const actor = {
    channelIds: rule.match.actor?.channelId,
    userIds: rule.match.actor?.userId,
    roleIds: rule.match.actor?.roleId,
  };
  const subject = {
    agentIds: rule.match.subject?.agentId,
    sessionIds: rule.match.subject?.sessionId,
  };
  const control = {
    executionModes: rule.match.control?.executionMode as ExecutionMode[] | undefined,
  };

  const scope: PolicyRuleScope = {};

  if (actor.channelIds?.length || actor.userIds?.length || actor.roleIds?.length) {
    scope.actor = actor;
  }

  if (subject.agentIds?.length || subject.sessionIds?.length) {
    scope.subject = subject;
  }

  if (control.executionModes?.length) {
    scope.control = control;
  }

  return scope.actor || scope.subject || scope.control ? scope : undefined;
}

export function loadDeclarativePolicyFile(policyPath: string): DeclarativePolicyFile {
  const resolved = path.resolve(policyPath);
  const raw = fs.readFileSync(resolved, "utf-8");
  const parsed = PolicyFileSchema.parse(yaml.load(raw));
  parsed.rules.forEach(validateDeclarativeRuleShape);
  return parsed;
}

export function writeDeclarativePolicyFile(policyPath: string, policyFile: DeclarativePolicyFile): void {
  const resolved = path.resolve(policyPath);
  const parsed = PolicyFileSchema.parse(policyFile);
  parsed.rules.forEach(validateDeclarativeRuleShape);
  fs.writeFileSync(resolved, yaml.dump(parsed, { noRefs: true }));
}

export function compileDeclarativePolicyRules(policyFile: DeclarativePolicyFile): PolicyRule[] {
  return policyFile.rules
    .filter((rule) => rule.enabled !== false)
    .map((rule) => {
      validateDeclarativeRuleShape(rule);
      return {
        id: rule.id,
        description: rule.description,
        plane: rule.plane,
        match: buildMatch(rule),
        decision: rule.decision,
        riskLevel: rule.riskLevel,
        reason: rule.reason,
        scope: buildRuleScope(rule),
      } satisfies PolicyRule;
    });
}

export function loadDeclarativePolicyRules(policyPath: string): PolicyRule[] {
  return compileDeclarativePolicyRules(loadDeclarativePolicyFile(policyPath));
}
