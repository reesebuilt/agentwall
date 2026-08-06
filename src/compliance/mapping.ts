import { detectionCatalog, DetectionMapping } from "../policy/detections";
import { builtinRules } from "../policy/rules";

/**
 * Control mappings: which recognised risks this codebase actually addresses.
 *
 * Why this file exists at all: nobody adopts a security control inside an
 * organisation on the strength of a feature list. They need to hand someone a
 * table that says which named risks are covered, which are not, and what backs
 * each claim. Written badly, that table is the most dangerous artefact a security
 * project ships, because it converts "we wrote some regexes" into "we are
 * compliant" and the reader stops looking. So the rule here is inverted from the
 * usual marketing instinct: an entry is only allowed to claim coverage it can
 * name evidence for, and when the honest answer is uncomfortable the entry says
 * the uncomfortable thing.
 *
 * The evidence strings are load-bearing, not decoration. Every one is a real
 * identifier in this repository — a detection id from the catalog, a rule id from
 * the built-in rule set, an injection pattern id, or a module path — and
 * tests/compliance.test.ts resolves each of them against the actual source. A
 * mapping that cites something which does not exist fails the build. That is the
 * only mechanism that keeps a document like this honest over time, because prose
 * disclaimers do not survive contact with a roadmap.
 *
 * WHAT THE THREE COVERAGE LEVELS MEAN, precisely, because a rating with fuzzy
 * semantics is worse than no rating:
 *
 *   strong  — an inline control ships enabled by default, it can DENY the risk's
 *             primary action, and it addresses the risk category rather than one
 *             corner of it. Detector recall limits are still recorded in `gap`.
 *   partial — a control exists, but it only observes, or the operator must turn
 *             it on or configure it, or it addresses a named subset of the risk.
 *   none    — nothing in this codebase addresses it. Stated rather than omitted,
 *             because a table with gaps silently missing reads as full coverage.
 *
 * THE SCOPE CAVEAT THAT APPLIES TO EVERY ROW, stated once here instead of being
 * repeated into meaninglessness in twenty `gap` fields: every rating is scoped to
 * flows AgentWall mediates — an MCP frame crossing the wrap, a request through the
 * forward proxy, a call to the evaluation API. An agent action that never reaches
 * one of those surfaces is not covered by anything below, whatever its rating
 * says. The insertion surface, not the rule set, is the real limit of this tool.
 *
 * AND WHAT A MAPPING IS NOT: it is a claim about which controls exist in the code,
 * not evidence that they are correctly configured in your deployment, nor that
 * they are effective against an adversary who has read them. These ratings are
 * this project's own assessment of its own code. They are not an audit, not a
 * certification, and not independent. Use src/compliance/score.ts to ask the
 * separate question of whether a particular configuration switches the controls on.
 */

export type Framework = "owasp-llm" | "owasp-agentic" | "mitre-attack";

export interface ControlMapping {
  framework: Framework;
  controlId: string;
  controlName: string;
  coverage: "strong" | "partial" | "none";
  /** Detection ids, rule ids, injection pattern ids, or module paths that back the claim. */
  evidence: string[];
  /** What is NOT covered. Required whenever coverage is not "strong". */
  gap?: string;
}

/**
 * OWASP Top 10 for LLM Applications (2025).
 *
 * Two ratings in here will look pessimistic and both are deliberate.
 *
 * LLM01 is `partial`, not `strong`, even though prompt injection is the risk this
 * project talks about most. Detection is a deterministic pattern set over
 * normalized text, and src/policy/injection.ts says in its own header that
 * paraphrase defeats it and a clean scan means "no known pattern" rather than
 * "safe". Rating the hardest open problem in the field as strongly covered on the
 * strength of a regex table is precisely the failure this file exists to avoid.
 *
 * LLM04, LLM08, and LLM09 are `none`. They are training-time, retrieval-layer,
 * and output-truthfulness concerns respectively, and a runtime boundary that sees
 * frames and requests cannot reach any of them. Inventing a partial claim for
 * each — "provenance labels help with poisoning!" — would be the compliance
 * theatre this table is supposed to make impossible.
 */
const OWASP_LLM: readonly ControlMapping[] = [
  {
    framework: "owasp-llm",
    controlId: "LLM01",
    controlName: "Prompt Injection",
    coverage: "partial",
    evidence: [
      "src/policy/injection.ts",
      "src/mcp/gates.ts",
      "inj.instruction_override.ignore_previous",
      "inj.tool_coercion.run_shell_command",
      "det.mcp.input.injection",
      "det.mcp.response.injection",
      "det.mcp.tool.poisoned",
      "mcp:deny-input-injection",
      "mcp:deny-response-injection",
      "mcp:deny-tool-poisoning",
      "content:approve-untrusted-derived-egress",
    ],
    gap:
      "Detection is deterministic pattern matching over normalized text, so paraphrase " +
      "defeats it: an instruction override written in words no pattern anticipates scans " +
      "clean. It raises the cost of the copy-pasted attack and produces an explainable " +
      "audit record; it is not a proof of absence. Nothing here inspects the model's " +
      "reasoning, so an injection that survives the scan is uncontested from that point on.",
  },
  {
    framework: "owasp-llm",
    controlId: "LLM02",
    controlName: "Sensitive Information Disclosure",
    coverage: "strong",
    evidence: [
      "src/planes/identity/dlp.ts",
      "src/canary/index.ts",
      "src/sentinel/filesystem.ts",
      "det.content.secret.exfil",
      "det.mcp.input.secret",
      "det.mcp.response.secret",
      "det.net.metadata.access",
      "det.identity.canary.triggered",
      "det.content.fs.secret_written",
      "content:block-secret-exfil",
      "content:redact-pii",
      "mcp:redact-input-secret",
      "mcp:redact-response-secret",
      "channel:deny-sensitive-content-egress",
      "channel:redact-pii-content-egress",
      "net:block-metadata-endpoint",
      "identity:deny-canary-triggered",
      "content:deny-fs-secret-write",
    ],
    gap:
      "The scanner is a pattern table, so a secret in a format it does not know — an " +
      "internal token scheme, a bare high-entropy string — passes. Canary values close part " +
      "of that hole by being synthetic and therefore unmistakable, but only for credentials " +
      "someone planted on purpose. The harder limit is what the scanner is handed: https " +
      "bodies through the forward proxy are opaque because that proxy does not terminate " +
      "TLS, so egress of a secret over https is visible as a destination and a byte count, " +
      "not as content.",
  },
  {
    framework: "owasp-llm",
    controlId: "LLM03",
    controlName: "Supply Chain Vulnerabilities",
    coverage: "partial",
    evidence: [
      "src/integrity/manifest.ts",
      "src/mcp/gates.ts",
      "det.tool.manifest.drift",
      "det.mcp.tool.poisoned",
      "det.mcp.tool.drift",
      "tool:approve-manifest-drift",
      "mcp:deny-tool-poisoning",
      "mcp:approve-tool-drift",
    ],
    gap:
      "Covers one layer of the supply chain: the tool and MCP-server surface an agent " +
      "talks to at runtime, where a changed manifest or a poisoned tool description is " +
      "caught by hash comparison and inspection. Model weights, training data, base " +
      "images, and package provenance are upstream of anything a runtime boundary can " +
      "observe, and this codebase makes no claim about them.",
  },
  {
    framework: "owasp-llm",
    controlId: "LLM04",
    controlName: "Data and Model Poisoning",
    coverage: "none",
    evidence: [],
    gap:
      "Nothing here touches training data, fine-tuning pipelines, or model artefacts. " +
      "AgentWall sits at runtime between a running agent and the things it acts on, which " +
      "is the wrong side of the lifecycle for this risk entirely. Poisoning that arrives " +
      "in-context through tool output is a different risk and is mapped at LLM01 and ASI06.",
  },
  {
    framework: "owasp-llm",
    controlId: "LLM05",
    controlName: "Improper Output Handling",
    coverage: "partial",
    evidence: [
      "src/integrations/damage-control/command-firewall.ts",
      "src/mcp/gates.ts",
      "det.mcp.response.injection",
      "det.mcp.response.secret",
      "mcp:deny-response-injection",
      "mcp:redact-response-secret",
      "tool:require-approval-shell",
    ],
    gap:
      "Two consumers of model output are inspected: shell command strings submitted to " +
      "the command firewall, and MCP frames crossing the wrap. Every other downstream " +
      "sink is out of reach — model output rendered into HTML, interpolated into SQL, or " +
      "written to a template in the host application never crosses an AgentWall boundary, " +
      "so nothing here can encode or escape it.",
  },
  {
    framework: "owasp-llm",
    controlId: "LLM06",
    controlName: "Excessive Agency",
    coverage: "strong",
    evidence: [
      "src/policy/engine.ts",
      "src/approval/gate.ts",
      "src/planes/network/ssrf.ts",
      "src/proxy/forward-proxy.ts",
      "src/runtime/enforcement.ts",
      "det.identity.credential.access",
      "det.browser.oauth.approval",
      "det.net.ssrf.private",
      "det.net.egress.blocked",
      "control:deny-external-actions-answer-only",
      "control:deny-mutations-read-only",
      "tool:require-approval-shell",
      "tool:require-approval-file-delete",
      "identity:flag-credential-access",
      "browser:require-approval-oauth",
      "browser:block-form-submit-payment",
      "net:block-ssrf-private",
      "net:deny-egress-not-allowlisted",
      "channel:deny-filesystem-mutation",
      "channel:deny-sensitive-data-access",
    ],
    gap:
      "This is the risk the whole design is shaped around, and the limit is structural " +
      "rather than partial: the controls are complete over the actions that reach them and " +
      "absent over the actions that do not. An agent with a tool that calls a cloud API " +
      "directly, in-process, over https, is exercising exactly the excessive agency " +
      "described here and AgentWall sees a destination host at best.",
  },
  {
    framework: "owasp-llm",
    controlId: "LLM07",
    controlName: "System Prompt Leakage",
    coverage: "partial",
    evidence: [
      "src/policy/injection.ts",
      "inj.exfiltration_directive.reveal_system_prompt",
      "inj.exfiltration_directive.reveal_instructions",
      "inj.exfiltration_directive.share_conversation",
      "det.mcp.response.injection",
      "mcp:deny-response-injection",
    ],
    gap:
      "Catches the request, not the disclosure. Patterns fire on text asking an agent to " +
      "reveal its instructions, which is the common shape of this attack arriving through " +
      "tool output. AgentWall is never told what the system prompt contains, so it cannot " +
      "recognise that prompt on the way out; a leak phrased as ordinary prose in a " +
      "response is indistinguishable from any other response.",
  },
  {
    framework: "owasp-llm",
    controlId: "LLM08",
    controlName: "Vector and Embedding Weaknesses",
    coverage: "none",
    evidence: [],
    gap:
      "There is no vector store, no embedding model, and no retrieval component in this " +
      "codebase, so there is nothing here to attack in the way this control describes and " +
      "nothing here that inspects a retrieval layer belonging to someone else.",
  },
  {
    framework: "owasp-llm",
    controlId: "LLM09",
    controlName: "Misinformation",
    coverage: "none",
    evidence: [],
    gap:
      "AgentWall makes no assessment of whether anything an agent says is true. It decides " +
      "whether actions are permitted. Those are unrelated questions and conflating them " +
      "would be the least defensible claim in this table.",
  },
  {
    framework: "owasp-llm",
    controlId: "LLM10",
    controlName: "Unbounded Consumption",
    coverage: "strong",
    evidence: [
      "src/runtime/floodguard.ts",
      "src/watchdog/heartbeat.ts",
      "src/runtime/kill-switch.ts",
      "governance:deny-watchdog-timeout",
    ],
    gap:
      "The budget is denominated in AgentWall's own weighted cost units and request counts, " +
      "not in provider tokens or currency, because AgentWall never sees a billing signal. " +
      "It bounds how fast an agent can act through this boundary, which correlates with " +
      "spend but does not measure it. An agent burning tokens in a loop that makes no " +
      "gated call is not throttled by anything here.",
  },
];

/**
 * OWASP Top 10 for Agentic Applications (2026), the ASI series.
 *
 * Nine of ten are `partial` and that is the honest shape of this codebase rather
 * than false modesty. The agentic taxonomy is largely about properties of the
 * agent's own internals — its plan, its memory, its identity, its peers — and a
 * boundary that mediates actions gets a real but incomplete grip on each of them.
 * The one `strong` entry, ASI02, is the risk this design is actually built for:
 * an agent invoking a tool it should not, in a way it should not.
 */
const OWASP_AGENTIC: readonly ControlMapping[] = [
  {
    framework: "owasp-agentic",
    controlId: "ASI01",
    controlName: "Agent Goal Hijack",
    coverage: "partial",
    evidence: [
      "src/policy/injection.ts",
      "src/mcp/gates.ts",
      "det.mcp.response.injection",
      "det.mcp.tool.poisoned",
      "mcp:deny-response-injection",
      "mcp:deny-tool-poisoning",
      "net:approve-untrusted-egress",
      "content:approve-untrusted-derived-egress",
    ],
    gap:
      "AgentWall sees actions, never goals. It has no representation of what the agent was " +
      "asked to do, so it cannot compare the current plan against the original one. What it " +
      "can do is catch the injected text that commonly performs the hijack, and require " +
      "approval when untrusted provenance is what is driving egress. A hijack expressed " +
      "entirely through individually-permitted actions is invisible to it.",
  },
  {
    framework: "owasp-agentic",
    controlId: "ASI02",
    controlName: "Tool Misuse and Exploitation",
    coverage: "strong",
    evidence: [
      "src/policy/engine.ts",
      "src/mcp/gates.ts",
      "src/integrations/damage-control/command-firewall.ts",
      "src/planes/network/ssrf.ts",
      "src/runtime/enforcement.ts",
      "det.mcp.tool.poisoned",
      "det.mcp.input.injection",
      "det.mcp.input.secret",
      "det.net.ssrf.private",
      "det.net.egress.blocked",
      "mcp:deny-tool-poisoning",
      "mcp:deny-input-injection",
      "mcp:redact-input-secret",
      "tool:require-approval-shell",
      "tool:require-approval-file-delete",
      "tool:flag-write-operations",
      "net:block-ssrf-private",
      "net:block-metadata-endpoint",
      "net:deny-egress-not-allowlisted",
    ],
    gap:
      "The engine reasons about action strings and payload shapes, not tool semantics. It " +
      "does not know what a given tool does, so a destructive operation named in a way no " +
      "rule fragment matches — a tool called `sync` that deletes — is evaluated as an " +
      "ordinary call. Coverage here is a function of how well the operator's rules describe " +
      "their own tools, which is why the built-in set is a floor and not a finished policy.",
  },
  {
    framework: "owasp-agentic",
    controlId: "ASI03",
    controlName: "Identity and Privilege Abuse",
    coverage: "partial",
    evidence: [
      "src/auth/operator.ts",
      "src/canary/index.ts",
      "det.identity.credential.access",
      "det.net.metadata.access",
      "det.browser.oauth.approval",
      "det.identity.canary.triggered",
      "det.content.fs.secret_written",
      "identity:flag-credential-access",
      "browser:require-approval-oauth",
      "net:block-metadata-endpoint",
      "channel:deny-sensitive-data-access",
      "identity:deny-canary-triggered",
      "content:deny-fs-secret-write",
    ],
    gap:
      "Credential acquisition is gated: reads of secret stores need approval, cloud metadata " +
      "is blocked outright, and OAuth grants stop for a human. Identity itself is thin. " +
      "Operator authentication is a single shared bearer token with no roles and no scopes, " +
      "agents are identified by a self-asserted id in the request, and there is no delegation " +
      "chain, so AgentWall cannot tell you on whose authority an action was taken.",
  },
  {
    framework: "owasp-agentic",
    controlId: "ASI04",
    controlName: "Agentic Supply Chain Vulnerabilities",
    coverage: "partial",
    evidence: [
      "src/integrity/manifest.ts",
      "src/mcp/gates.ts",
      "det.tool.manifest.drift",
      "det.mcp.tool.drift",
      "det.mcp.tool.poisoned",
      "tool:approve-manifest-drift",
      "mcp:approve-tool-drift",
      "mcp:deny-tool-poisoning",
    ],
    gap:
      "Detects change, not badness. A manifest is hashed and compared against what the " +
      "operator approved, so a server that silently grows a new tool trips re-approval; a " +
      "tool description carrying instructions to the model is denied. Nothing verifies who " +
      "published the server, checks a signature, or evaluates a registry's trustworthiness, " +
      "so a component that was malicious on the day it was first approved stays approved.",
  },
  {
    framework: "owasp-agentic",
    controlId: "ASI05",
    controlName: "Unexpected Code Execution (RCE)",
    coverage: "partial",
    evidence: [
      "src/integrations/damage-control/command-firewall.ts",
      "src/integrations/agent-harness/preflight.ts",
      "inj.tool_coercion.run_shell_command",
      "inj.tool_coercion.curl_pipe_shell",
      "inj.tool_coercion.destructive_command",
      "tool:require-approval-shell",
      "control:deny-mutations-read-only",
      "control:deny-external-actions-answer-only",
      "channel:deny-filesystem-mutation",
    ],
    gap:
      "The command firewall analyses command strings a harness submits to it, with a " +
      "whitelist default and a five-level ladder the operator chooses from. That makes it a " +
      "review step, not a sandbox: it depends on the harness asking before executing, and a " +
      "process that spawns a shell without asking is unaffected. Real containment of code " +
      "execution belongs to the operating system, and this codebase does not provide it.",
  },
  {
    framework: "owasp-agentic",
    controlId: "ASI06",
    controlName: "Memory and Context Poisoning",
    coverage: "partial",
    evidence: [
      "src/policy/injection.ts",
      "src/mcp/gates.ts",
      "inj.state_poisoning.write_to_memory",
      "inj.state_poisoning.all_future_responses",
      "inj.state_poisoning.remember_for_later",
      "det.mcp.response.injection",
      "mcp:deny-response-injection",
      "content:approve-untrusted-derived-egress",
    ],
    gap:
      "Inspection happens on the way in, once: tool output carrying text that tries to " +
      "install a durable instruction is denied before the agent reads it, and provenance " +
      "labels mark what came from an untrusted source. AgentWall holds no memory of its own " +
      "and cannot read the agent's, so anything already written to a memory or conversation " +
      "store is beyond reach — there is no retroactive revocation of a poisoned entry.",
  },
  {
    framework: "owasp-agentic",
    controlId: "ASI07",
    controlName: "Insecure Inter-Agent Communication",
    coverage: "partial",
    evidence: [
      "src/mcp/framing.ts",
      "src/mcp/gates.ts",
      "src/org/federation.ts",
      "det.mcp.input.injection",
      "det.mcp.response.injection",
      "mcp:deny-input-injection",
      "mcp:deny-response-injection",
    ],
    gap:
      "One hop is mediated properly: the agent-to-MCP-server channel is parsed frame by " +
      "frame, gated in both directions, and audited, and federated peer summaries are schema- " +
      "validated before they are merged. Agent-to-agent protocols are not covered — there is " +
      "no inspection of a message bus, a task-delegation protocol, or a peer agent's " +
      "requests, and transport authenticity is left to the transport.",
  },
  {
    framework: "owasp-agentic",
    controlId: "ASI08",
    controlName: "Cascading Failures",
    coverage: "partial",
    evidence: [
      "src/runtime/floodguard.ts",
      "src/watchdog/heartbeat.ts",
      "src/runtime/kill-switch.ts",
      "det.governance.killswitch.active",
      "governance:deny-watchdog-timeout",
      "governance:kill-switch",
      "governance:log-all",
    ],
    gap:
      "Blast radius is bounded locally: per-session rate and cost caps, a ceiling on pending " +
      "approvals, shield mode to tighten every limit at once, a watchdog that stops " +
      "governance changes when it fires, and a kill switch that refuses everything at once. " +
      "None of that constitutes an understanding of the system a failure is cascading " +
      "through. AgentWall has no dependency graph, no circuit breaker between agents, and no " +
      "view of an agent whose calls do not pass through it, so it can stop its own agents " +
      "and cannot stop a failure travelling between someone else's.",
  },
  {
    framework: "owasp-agentic",
    controlId: "ASI09",
    controlName: "Human-Agent Trust Exploitation",
    coverage: "partial",
    evidence: [
      "src/approval/gate.ts",
      "src/runtime/floodguard.ts",
      "det.browser.oauth.approval",
      "browser:require-approval-oauth",
      "browser:block-form-submit-payment",
      "channel:deny-filesystem-mutation",
      "channel:deny-sensitive-data-access",
      "channel:deny-sensitive-content-egress",
      "channel:redact-pii-content-egress",
    ],
    gap:
      "Structural defences exist where the human is being used as a lever: payment " +
      "submission is blocked rather than queued, requests arriving from a chat channel " +
      "cannot mutate the filesystem or read secrets whatever the requester claims, and " +
      "approval volume is rate-limited so an operator cannot be flooded into clicking. The " +
      "residual risk is unaddressed and unaddressable here: an operator who approves without " +
      "reading defeats every one of these, and AgentWall records that a decision was made, " +
      "not that it was understood.",
  },
  {
    framework: "owasp-agentic",
    controlId: "ASI10",
    controlName: "Rogue Agents",
    coverage: "partial",
    evidence: [
      "src/watchdog/heartbeat.ts",
      "src/runtime/kill-switch.ts",
      "src/audit/logger.ts",
      "src/audit/chain.ts",
      "src/proxy/forward-proxy.ts",
      "det.governance.killswitch.active",
      "det.net.egress.blocked",
      "governance:deny-watchdog-timeout",
      "governance:kill-switch",
      "governance:log-all",
      "control:deny-external-actions-answer-only",
      "net:deny-egress-not-allowlisted",
    ],
    gap:
      "An agent that stops heart-beating, trips rules, or reaches an unlisted destination is " +
      "detectable, the audit chain makes the sequence reconstructible afterwards because " +
      "records cannot be edited without breaking the hash links, and the kill switch refuses " +
      "every action that reaches it. That is containment of the agent's ACTIONS, not of the " +
      "agent: AgentWall cannot terminate a process, revoke a credential it did not issue, or " +
      "see an agent that was never pointed at it. An operator holding the emergency stop " +
      "still needs the operating system and the identity provider to finish the job.",
  },
];

/**
 * Rule id to decision, built from the live rule set rather than restated here.
 *
 * A Map because the keys come from an array that other work appends to; the whole
 * point is that a rule added tomorrow is in this lookup without anyone editing
 * this file.
 */
const ruleDecisions = new Map<string, string>(builtinRules.map((rule) => [rule.id, rule.decision]));

interface MitreGroup {
  technique: string;
  detections: DetectionMapping[];
}

/**
 * The MITRE ATT&CK view is computed, never written down.
 *
 * A hand-maintained ATT&CK table is a drift machine: detections get added in one
 * commit and the compliance doc is updated in a different one, or never. So this
 * reads detectionCatalog directly and every technique in the table is there
 * because a detection names it. The coverage rating is derived too — from the
 * DECISION of each backing rule, which is the only defensible source for "do we
 * block this or merely notice it".
 *
 * The derivation takes the WEAKEST decision behind a technique, not the strongest.
 * T1195 is mapped by one detection whose rule denies and one whose rule routes to
 * approval; taking the strongest would advertise the technique as blocked when
 * half of it is a prompt an operator can click through. Downgrading is the only
 * direction that cannot mislead.
 *
 * It is recomputed per call rather than memoized at module load. The catalog is a
 * mutable exported array and the cost is a loop over a couple of dozen entries;
 * a cache here would be a correctness bug bought with an unmeasurable saving.
 *
 * One thing this view does NOT mean: absence from it is not "not applicable". It
 * means no detection in this codebase names that technique. ATT&CK has hundreds.
 */
function deriveMitre(): ControlMapping[] {
  const order: string[] = [];
  const groups = new Map<string, MitreGroup>();

  for (const detection of detectionCatalog) {
    const attack = detection.mitreAttack;
    if (!attack) continue;
    const existing = groups.get(attack.techniqueId);
    if (existing) {
      existing.detections.push(detection);
      continue;
    }
    groups.set(attack.techniqueId, { technique: attack.technique, detections: [detection] });
    order.push(attack.techniqueId);
  }

  return order.map((techniqueId) => {
    const group = groups.get(techniqueId) as MitreGroup;
    const evidence: string[] = [];
    const ruleIds: string[] = [];

    for (const detection of group.detections) {
      if (!evidence.includes(detection.id)) evidence.push(detection.id);
      if (!ruleIds.includes(detection.ruleId)) ruleIds.push(detection.ruleId);
    }
    for (const ruleId of ruleIds) {
      if (ruleDecisions.has(ruleId)) evidence.push(ruleId);
    }

    const gated = ruleIds.filter((id) => ruleDecisions.get(id) === "approve");
    const degraded = ruleIds.filter((id) => ruleDecisions.get(id) === "redact");
    const recorded = ruleIds.filter((id) => ruleDecisions.get(id) === "allow");
    const external = ruleIds.filter((id) => !ruleDecisions.has(id));

    const clauses: string[] = [];
    if (gated.length > 0) {
      clauses.push(
        `gated rather than blocked (${gated.join(", ")}): the action proceeds if an operator approves it`
      );
    }
    if (degraded.length > 0) {
      clauses.push(
        `payload degraded rather than action stopped (${degraded.join(", ")}): the call still happens with the sensitive material removed`
      );
    }
    if (recorded.length > 0) {
      clauses.push(`recorded only (${recorded.join(", ")}): the action is permitted and audited`);
    }
    if (external.length > 0) {
      clauses.push(
        `backed by ${external.join(", ")}, which is not in the built-in rule set, so coverage depends on the operator's own policy file`
      );
    }

    const mapping: ControlMapping = {
      framework: "mitre-attack",
      controlId: techniqueId,
      controlName: group.technique,
      coverage: clauses.length === 0 ? "strong" : "partial",
      evidence,
    };
    if (clauses.length > 0) mapping.gap = `Partially addressed: ${clauses.join("; ")}.`;
    return mapping;
  });
}

/** Fresh objects on every call, so a caller cannot edit the tables through the result. */
function copyOf(rows: readonly ControlMapping[]): ControlMapping[] {
  return rows.map((row) => ({ ...row, evidence: [...row.evidence] }));
}

export function mappingsFor(framework: Framework): ControlMapping[] {
  switch (framework) {
    case "owasp-llm":
      return copyOf(OWASP_LLM);
    case "owasp-agentic":
      return copyOf(OWASP_AGENTIC);
    case "mitre-attack":
      return deriveMitre();
  }
}

export function coverageSummary(framework: Framework): {
  strong: number;
  partial: number;
  none: number;
  total: number;
} {
  const rows = mappingsFor(framework);
  return {
    strong: rows.filter((row) => row.coverage === "strong").length,
    partial: rows.filter((row) => row.coverage === "partial").length,
    none: rows.filter((row) => row.coverage === "none").length,
    total: rows.length,
  };
}

/**
 * Detections that no hand-authored framework row cites — the reverse drift signal.
 *
 * The forward direction is guarded by tests: a mapping cannot cite a detection
 * that does not exist. This is the other direction, which is the one that fails
 * quietly. Someone adds a detection for a new class of attack and nobody revisits
 * the OWASP tables, so the tool grows a capability its own compliance document
 * denies having, and the next person to read the table underestimates it.
 *
 * Deliberately computed over the OWASP tables only, NOT the derived ATT&CK view.
 * Including the derived view would make this function inert: the derivation cites
 * every detection carrying a MITRE mapping, so nothing would ever be reported and
 * the check would pass forever while meaning nothing.
 */
export function unmappedDetections(): string[] {
  const cited = new Set<string>();
  for (const row of [...OWASP_LLM, ...OWASP_AGENTIC]) {
    for (const item of row.evidence) {
      if (item.startsWith("det.")) cited.add(item);
    }
  }

  const unmapped: string[] = [];
  for (const detection of detectionCatalog) {
    if (cited.has(detection.id) || unmapped.includes(detection.id)) continue;
    unmapped.push(detection.id);
  }
  return unmapped;
}
