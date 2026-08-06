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

/**
 * An immutable, versioned view of the ruleset.
 *
 * Reload swaps the engine's pointer to a NEW snapshot; it never mutates an existing one. A
 * caller that captures a snapshot therefore keeps the policy it captured for as long as it
 * holds the reference. That is what makes the in-flight guarantee a property of the design
 * rather than an accident of `evaluate` happening to be synchronous: a request that spans an
 * await, or that evaluates twice, sees one ruleset either way.
 *
 * `version` starts at 1 and increments on every swap, so 0 is never a policy that was in
 * force and an audit record can name the exact ruleset that decided a request.
 */
export interface PolicySnapshot {
  readonly version: number;
  readonly defaultDecision: Decision;
  getRules(): PolicyRule[];
  evaluate(ctx: AgentContext): PolicyResult;
}

function evaluateAgainst(
  rules: readonly PolicyRule[],
  defaultDecision: Decision,
  ctx: AgentContext
): PolicyResult {
  const matched: PolicyRule[] = [];

  for (const rule of rules) {
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
      decision: defaultDecision,
      riskLevel: highRiskFlow ? "high" : "low",
      matchedRules: [],
      reasons: [`Default decision: ${defaultDecision}`],
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

function createSnapshot(
  version: number,
  rules: readonly PolicyRule[],
  defaultDecision: Decision
): PolicySnapshot {
  // Copied, then frozen. The old constructor stored the caller's array by reference, so a
  // caller who kept it could edit the live ruleset from outside the engine with nothing
  // recording that a change happened.
  const own = Object.freeze([...rules]);
  return Object.freeze({
    version,
    defaultDecision,
    getRules: () => [...own],
    evaluate: (ctx: AgentContext) => evaluateAgainst(own, defaultDecision, ctx),
  });
}

export class PolicyEngine {
  private current: PolicySnapshot;

  constructor(rules: PolicyRule[] = builtinRules, defaultDecision: Decision = "deny") {
    this.current = createSnapshot(1, rules, defaultDecision);
  }

  /**
   * The ruleset in force right now. Capture this once per request and evaluate against the
   * capture; do not re-read it mid-request.
   */
  snapshot(): PolicySnapshot {
    return this.current;
  }

  evaluate(ctx: AgentContext): PolicyResult {
    return this.current.evaluate(ctx);
  }

  addRule(rule: PolicyRule): void {
    this.current = createSnapshot(
      this.current.version + 1,
      [...this.current.getRules(), rule],
      this.current.defaultDecision
    );
  }

  replaceRules(rules: PolicyRule[]): void {
    this.current = createSnapshot(this.current.version + 1, rules, this.current.defaultDecision);
  }

  /**
   * Swap the fallback decision. Separate from `replaceRules` because config reload can
   * change this without the rule file changing at all, and the version has to move either
   * way: the same request evaluated before and after gets a different answer.
   */
  setDefaultDecision(defaultDecision: Decision): void {
    if (defaultDecision === this.current.defaultDecision) {
      return;
    }

    this.current = createSnapshot(
      this.current.version + 1,
      this.current.getRules(),
      defaultDecision
    );
  }

  getDefaultDecision(): Decision {
    return this.current.defaultDecision;
  }

  getRules(): PolicyRule[] {
    return this.current.getRules();
  }
}
