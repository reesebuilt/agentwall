import { AgentContext, Decision, PolicyResult, PolicyRule, RiskLevel } from "../types";
import { builtinRules } from "./rules";
import { detectionsForRules } from "./detections";

const RISK_ORDER: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

const DECISION_ORDER: Record<Decision, number> = {
  allow: 0,
  redact: 1,
  approve: 2,
  deny: 3,
};

function isHighRiskFlow(ctx: AgentContext): boolean {
  return Boolean(
    ctx.flow?.highRisk ||
    ctx.flow?.crossesBoundary ||
    ctx.flow?.direction === "egress" ||
    (ctx.flow?.labels?.length ?? 0) > 0 ||
    ctx.provenance?.some((entry) =>
      entry.trustLabel !== "trusted" && (entry.labels?.length ?? 0) > 0
    )
  );
}

export class PolicyEngine {
  private rules: PolicyRule[];
  private defaultDecision: Decision;

  constructor(rules: PolicyRule[] = builtinRules, defaultDecision: Decision = "deny") {
    this.rules = rules;
    this.defaultDecision = defaultDecision;
  }

  evaluate(ctx: AgentContext): PolicyResult {
    const matched: PolicyRule[] = [];

    for (const rule of this.rules) {
      try {
        if (rule.match(ctx)) {
          matched.push(rule);
        }
      } catch {
        // rule evaluation failure is non-fatal; skip
      }
    }

    const highRiskFlow = isHighRiskFlow(ctx);

    if (matched.length === 0) {
      return {
        decision: this.defaultDecision,
        riskLevel: highRiskFlow ? "high" : "low",
        matchedRules: [],
        reasons: [`Default decision: ${this.defaultDecision}`],
        requiresApproval: false,
        highRiskFlow,
        detections: [],
      };
    }

    const decision: Decision = matched.reduce((best, rule) =>
      DECISION_ORDER[rule.decision] > DECISION_ORDER[best.decision] ? rule : best
    ).decision;

    const riskLevel: RiskLevel = matched.reduce((best, rule) =>
      RISK_ORDER[rule.riskLevel] > RISK_ORDER[best.riskLevel] ? rule : best
    ).riskLevel;

    const matchedRules = matched.map((rule) => rule.id);

    return {
      decision,
      riskLevel: highRiskFlow && riskLevel === "low" ? "medium" : riskLevel,
      matchedRules,
      reasons: matched.map((rule) => rule.reason),
      requiresApproval: decision === "approve",
      highRiskFlow,
      detections: detectionsForRules(matchedRules),
    };
  }

  addRule(rule: PolicyRule): void {
    this.rules.push(rule);
  }

  replaceRules(rules: PolicyRule[]): void {
    this.rules = [...rules];
  }

  getRules(): PolicyRule[] {
    return [...this.rules];
  }
}
