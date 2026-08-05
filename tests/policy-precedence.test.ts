import { describe, expect, it } from "@jest/globals";
import { PolicyEngine } from "../src/policy/engine";
import { AgentContext, Decision, PolicyRule, RiskLevel } from "../src/types";

/**
 * What happens when rules of different decisions match the same action.
 *
 * The engine reduces every match down to one decision by taking the most restrictive, and
 * that reduction is the whole safety property: a deny rule an operator wrote is worthless if
 * a broader allow rule that also matches can outvote it. Nothing covered the conflict, so a
 * reordered DECISION_ORDER table or a reduce that kept the first match instead of the
 * strictest would have shipped with every existing test green.
 */

const ORDER: Decision[] = ["allow", "redact", "approve", "deny"];

function rule(decision: Decision, riskLevel: RiskLevel = "low"): PolicyRule {
  return {
    id: `conflict:${decision}`,
    description: `matches everything and votes ${decision}`,
    plane: "all",
    match: () => true,
    decision,
    riskLevel,
    reason: `${decision} rule matched`,
  };
}

const ctx: AgentContext = {
  agentId: "precedence-agent",
  sessionId: "precedence-session",
  plane: "tool",
  action: "write_file",
  payload: {},
} as AgentContext;

/** Evaluate with both orderings, so a result cannot come from rule order. */
function decide(rules: PolicyRule[]): Decision[] {
  return [
    new PolicyEngine(rules, "allow").evaluate(ctx).decision,
    new PolicyEngine([...rules].reverse(), "allow").evaluate(ctx).decision,
  ];
}

describe("decision precedence when rules conflict", () => {
  it("lets deny beat allow", () => {
    expect(decide([rule("allow"), rule("deny")])).toEqual(["deny", "deny"]);
  });

  it("lets approve beat redact", () => {
    expect(decide([rule("redact"), rule("approve")])).toEqual(["approve", "approve"]);
  });

  it("lets redact beat allow", () => {
    expect(decide([rule("allow"), rule("redact")])).toEqual(["redact", "redact"]);
  });

  it("lets deny beat approve", () => {
    expect(decide([rule("approve"), rule("deny")])).toEqual(["deny", "deny"]);
  });

  it("takes the strictest decision when every kind matches at once", () => {
    expect(decide(ORDER.map((decision) => rule(decision)))).toEqual(["deny", "deny"]);
  });

  it("holds the whole ordering pairwise", () => {
    for (let i = 0; i < ORDER.length; i++) {
      for (let j = i + 1; j < ORDER.length; j++) {
        expect(decide([rule(ORDER[i]), rule(ORDER[j])])).toEqual([ORDER[j], ORDER[j]]);
      }
    }
  });

  it("reports every matched rule, not just the one that won", () => {
    const result = new PolicyEngine([rule("allow"), rule("deny")], "allow").evaluate(ctx);
    expect(result.matchedRules).toEqual(["conflict:allow", "conflict:deny"]);
    expect(result.reasons).toEqual(["allow rule matched", "deny rule matched"]);
  });

  it("requires approval only when approve is the decision that survived", () => {
    expect(new PolicyEngine([rule("redact"), rule("approve")], "allow").evaluate(ctx).requiresApproval).toBe(true);
    // A deny outranks the approve rule, so the request is refused rather than queued for a
    // human: routing it to an approver would offer someone a button that grants a denied action.
    expect(new PolicyEngine([rule("approve"), rule("deny")], "allow").evaluate(ctx).requiresApproval).toBe(false);
  });

  it("takes the highest risk level independently of the winning decision", () => {
    // Risk and decision reduce separately: a low-risk deny must not drag the reported risk
    // down from a critical allow that also matched, or an operator triaging by severity
    // never sees the finding.
    const result = new PolicyEngine([rule("allow", "critical"), rule("deny", "low")], "allow").evaluate(ctx);
    expect(result.decision).toBe("deny");
    expect(result.riskLevel).toBe("critical");
  });
});
