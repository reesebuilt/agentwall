import { DeclarativePolicyRule, buildRuleScope } from "./loader";

export interface ScopedRuleCatalogItem {
  id: string;
  description: string;
  plane: DeclarativePolicyRule["plane"];
  decision: DeclarativePolicyRule["decision"];
  riskLevel: DeclarativePolicyRule["riskLevel"];
  reason: string;
  enabled: boolean;
  editable: true;
  scopeSummary: string;
  actionSummary: string;
  actorChannelIds: string[];
  actorUserIds: string[];
  actorRoleIds: string[];
  subjectAgentIds: string[];
  subjectSessionIds: string[];
  executionModes: string[];
  actionIncludes: string[];
  actionEquals: string[];
}

function listOrEmpty(values?: string[]): string[] {
  return Array.isArray(values) ? values.filter(Boolean) : [];
}

function summarizeScope(rule: DeclarativePolicyRule): string {
  const scope = buildRuleScope(rule);
  const segments: string[] = [];
  if (scope?.subject?.agentIds?.length) {
    segments.push(scope.subject.agentIds.join(", "));
  }
  if (scope?.actor?.channelIds?.length) {
    segments.push(`in ${scope.actor.channelIds.join(", ")}`);
  }
  if (scope?.actor?.roleIds?.length) {
    segments.push(`roles ${scope.actor.roleIds.join(", ")}`);
  }
  if (scope?.control?.executionModes?.length) {
    segments.push(`mode ${scope.control.executionModes.join(", ")}`);
  }
  if (scope?.subject?.sessionIds?.length) {
    segments.push(`sessions ${scope.subject.sessionIds.join(", ")}`);
  }
  if (scope?.actor?.userIds?.length) {
    segments.push(`users ${scope.actor.userIds.join(", ")}`);
  }
  return segments.length > 0 ? segments.join(" · ") : "Scoped guardrail";
}

function summarizeActions(rule: DeclarativePolicyRule): string {
  const includes = listOrEmpty(rule.match.action?.includes);
  if (includes.length) {
    return `Action contains ${includes.join(", ")}`;
  }
  const equals = listOrEmpty(rule.match.action?.equals);
  if (equals.length) {
    return `Action equals ${equals.join(", ")}`;
  }
  return `${rule.plane} plane scoped rule`;
}

export function isScopedDeclarativeRule(rule: DeclarativePolicyRule): boolean {
  return Boolean(rule.match.actor || rule.match.subject || rule.match.control);
}

export function buildScopedRuleCatalogItem(rule: DeclarativePolicyRule): ScopedRuleCatalogItem {
  return {
    id: rule.id,
    description: rule.description,
    plane: rule.plane,
    decision: rule.decision,
    riskLevel: rule.riskLevel,
    reason: rule.reason,
    enabled: rule.enabled !== false,
    editable: true,
    scopeSummary: summarizeScope(rule),
    actionSummary: summarizeActions(rule),
    actorChannelIds: listOrEmpty(rule.match.actor?.channelId),
    actorUserIds: listOrEmpty(rule.match.actor?.userId),
    actorRoleIds: listOrEmpty(rule.match.actor?.roleId),
    subjectAgentIds: listOrEmpty(rule.match.subject?.agentId),
    subjectSessionIds: listOrEmpty(rule.match.subject?.sessionId),
    executionModes: listOrEmpty(rule.match.control?.executionMode),
    actionIncludes: listOrEmpty(rule.match.action?.includes),
    actionEquals: listOrEmpty(rule.match.action?.equals),
  };
}
