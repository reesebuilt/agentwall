import { AgentContext, FlowLabel, PolicyRule, ProvenanceTag, TrustLabel } from "../types";
import { scanText } from "../planes/identity/dlp";
import { extractHostname, isPrivateHostname, isPrivateIp } from "../planes/network/ssrf";

function payloadContains(payload: Record<string, unknown>, keys: string[]): boolean {
  const serialized = JSON.stringify(payload).toLowerCase();
  return keys.some((key) => serialized.includes(key.toLowerCase()));
}

function payloadText(payload: Record<string, unknown>): string {
  const values: string[] = [];
  const collect = (value: unknown) => {
    if (typeof value === "string") {
      values.push(value);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach(collect);
      return;
    }
    if (value && typeof value === "object") {
      Object.values(value as Record<string, unknown>).forEach(collect);
    }
  };
  collect(payload);
  return values.join("\n");
}

function contentDlpScan(ctx: AgentContext) {
  return scanText(payloadText(ctx.payload), false);
}

function provenanceHasTrust(ctx: AgentContext, trustLabel: TrustLabel): boolean {
  return ctx.provenance?.some((entry) => entry.trustLabel === trustLabel) ?? false;
}

function provenanceHasSource(ctx: AgentContext, source: ProvenanceTag["source"]): boolean {
  return ctx.provenance?.some((entry) => entry.source === source) ?? false;
}

function hasFlowLabel(ctx: AgentContext, label: FlowLabel): boolean {
  return (
    ctx.flow?.labels?.includes(label) ||
    ctx.provenance?.some((entry) => entry.labels?.includes(label))
  ) ?? false;
}

function extractHostFromPayload(payload: Record<string, unknown>): string | null {
  const url = payload["url"] ?? payload["target"] ?? payload["href"];
  return typeof url === "string" ? extractHostname(url) : null;
}

function actionIncludes(ctx: AgentContext, fragments: string[]): boolean {
  const action = ctx.action.toLowerCase();
  return fragments.some((fragment) => action.includes(fragment));
}

function isCommunicationChannelRequest(ctx: AgentContext): boolean {
  return Boolean(ctx.actor?.channelId);
}

function isCommunicationChannelContentEgress(ctx: AgentContext): boolean {
  return isCommunicationChannelRequest(ctx) && ctx.plane === "content" && ctx.flow?.direction === "egress";
}

function channelContentContainsSecret(ctx: AgentContext): boolean {
  return hasFlowLabel(ctx, "secret_material") || contentDlpScan(ctx).containsSecrets;
}

function channelContentContainsPII(ctx: AgentContext): boolean {
  return hasFlowLabel(ctx, "pii") || contentDlpScan(ctx).containsPII;
}

function isFilesystemMutationAction(ctx: AgentContext): boolean {
  if (ctx.plane !== "tool") return false;
  return actionIncludes(ctx, [
    "write_file",
    "write",
    "create",
    "update",
    "patch",
    "delete",
    "remove",
    "unlink",
    "mkdir",
    "move",
    "rename",
    "chmod",
    "chown",
    "install",
  ]);
}

function isSensitiveDataAccessAction(ctx: AgentContext): boolean {
  const sensitiveFragments = [
    "secret",
    "credential",
    "password",
    "token",
    "api_key",
    "apikey",
    "private key",
    "private_key",
    ".env",
    "id_rsa",
    "ssh",
    "vault",
    "keychain",
  ];

  if (ctx.plane === "identity") {
    return actionIncludes(ctx, sensitiveFragments) || payloadContains(ctx.payload, sensitiveFragments);
  }

  if (ctx.plane === "tool") {
    return actionIncludes(ctx, ["read_file", "cat", "open", "get", "read"]) && payloadContains(ctx.payload, sensitiveFragments);
  }

  return ctx.plane !== "content" && (hasFlowLabel(ctx, "credential_access") || hasFlowLabel(ctx, "secret_material"));
}

function isMutatingToolAction(ctx: AgentContext): boolean {
  if (ctx.plane !== "tool") return false;
  return actionIncludes(ctx, [
    "shell",
    "bash",
    "exec",
    "run_command",
    "terminal",
    "write",
    "create",
    "update",
    "post",
    "put",
    "delete",
    "remove",
    "unlink",
    "upload",
    "install",
    "deploy",
  ]);
}

function isExternalActionPlane(ctx: AgentContext): boolean {
  return ["network", "tool", "browser", "identity", "governance"].includes(ctx.plane);
}

function executionModeIs(ctx: AgentContext, mode: "normal" | "read_only" | "answer_only"): boolean {
  return (ctx.control?.executionMode ?? "normal") === mode;
}

/**
 * MCP frames reach the engine with their action namespaced by `mcp:` and with the
 * gate pipeline's findings flattened into metadata markers. The markers are the
 * only coupling between the MCP gates and these rules: no gate names a rule id
 * and no rule imports a gate, the two meet on these string keys. They are strings
 * because AgentContext.metadata is a string map, and the key names are mirrored
 * in src/mcp/gates.ts.
 */
function isMcpAction(ctx: AgentContext): boolean {
  return ctx.action.startsWith("mcp:");
}

function mcpMarker(ctx: AgentContext, marker: string): boolean {
  return ctx.metadata?.[marker] === "true";
}

export const builtinRules: PolicyRule[] = [
  {
    id: "channel:deny-filesystem-mutation",
    description: "Deny filesystem mutation requested from a human communication channel",
    plane: "tool",
    match: (ctx: AgentContext) => isCommunicationChannelRequest(ctx) && isFilesystemMutationAction(ctx),
    decision: "deny",
    riskLevel: "critical",
    reason: "Communication-channel users cannot mutate the agent filesystem",
  },
  {
    id: "channel:deny-sensitive-data-access",
    description: "Deny sensitive data access requested from a human communication channel",
    plane: "all",
    match: (ctx: AgentContext) => isCommunicationChannelRequest(ctx) && isSensitiveDataAccessAction(ctx),
    decision: "deny",
    riskLevel: "critical",
    reason: "Communication-channel users cannot access secrets or credentials through the agent",
  },
  {
    id: "channel:deny-sensitive-content-egress",
    description: "Deny outbound communication-channel replies containing secrets or credential material",
    plane: "content",
    match: (ctx: AgentContext) => isCommunicationChannelContentEgress(ctx) && channelContentContainsSecret(ctx),
    decision: "deny",
    riskLevel: "critical",
    reason: "Communication-channel replies cannot contain secrets or credential material",
  },
  {
    id: "channel:redact-pii-content-egress",
    description: "Redact outbound communication-channel replies containing PII",
    plane: "content",
    match: (ctx: AgentContext) => isCommunicationChannelContentEgress(ctx) && channelContentContainsPII(ctx),
    decision: "redact",
    riskLevel: "high",
    reason: "Communication-channel replies containing PII must be redacted before delivery",
  },
  {
    id: "control:deny-external-actions-answer-only",
    description: "Deny external or privileged actions when the control plane is in answer-only mode",
    plane: "all",
    match: (ctx: AgentContext) => executionModeIs(ctx, "answer_only") && isExternalActionPlane(ctx),
    decision: "deny",
    riskLevel: "critical",
    reason: "Control plane is in answer-only mode; external execution is disabled",
  },
  {
    id: "control:deny-mutations-read-only",
    description: "Deny mutating tool actions when the control plane is in read-only mode",
    plane: "tool",
    match: (ctx: AgentContext) => executionModeIs(ctx, "read_only") && isMutatingToolAction(ctx),
    decision: "deny",
    riskLevel: "high",
    reason: "Control plane is in read-only mode; mutating tool execution is disabled",
  },
  {
    id: "net:block-ssrf-private",
    description: "Block requests targeting private, local, or loopback ranges",
    plane: "network",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "network") return false;
      const host = extractHostFromPayload(ctx.payload);
      return host ? isPrivateHostname(host) || isPrivateIp(host) : false;
    },
    decision: "deny",
    riskLevel: "critical",
    reason: "Request targets a private or local network address",
  },
  {
    id: "net:block-metadata-endpoint",
    description: "Block access to cloud metadata endpoints",
    plane: "network",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "network") return false;
      const host = extractHostFromPayload(ctx.payload);
      return host === "169.254.169.254" || host === "metadata.google.internal" || host === "metadata.google.com";
    },
    decision: "deny",
    riskLevel: "critical",
    reason: "Request targets a cloud metadata endpoint",
  },
  {
    id: "net:approve-untrusted-egress",
    description: "Require approval for egress initiated from untrusted content",
    plane: "network",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "network") return false;
      return ctx.flow?.direction === "egress" && provenanceHasTrust(ctx, "untrusted");
    },
    decision: "approve",
    riskLevel: "high",
    reason: "Untrusted provenance is attempting network egress",
  },

  {
    id: "tool:require-approval-shell",
    description: "Require human approval before executing shell or terminal commands",
    plane: "tool",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "tool") return false;
      return actionIncludes(ctx, ["shell", "bash", "exec", "run_command", "terminal"]);
    },
    decision: "approve",
    riskLevel: "high",
    reason: "Shell execution requires human approval",
  },
  {
    id: "tool:require-approval-file-delete",
    description: "Require approval before deleting files",
    plane: "tool",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "tool") return false;
      return actionIncludes(ctx, ["delete", "remove", "unlink"]);
    },
    decision: "approve",
    riskLevel: "high",
    reason: "File deletion requires human approval",
  },
  {
    id: "tool:approve-manifest-drift",
    description: "Require re-approval when a tool or MCP manifest drifts",
    plane: "tool",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "tool") return false;
      return hasFlowLabel(ctx, "manifest_drift") || payloadContains(ctx.payload, ["requiresReapproval", "manifest drift"]);
    },
    decision: "approve",
    riskLevel: "critical",
    reason: "Tool or MCP manifest changed from approved state",
  },
  {
    id: "tool:flag-write-operations",
    description: "Flag write or mutating tool operations as medium risk",
    plane: "tool",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "tool") return false;
      return actionIncludes(ctx, ["write", "create", "update", "post", "put"]);
    },
    decision: "allow",
    riskLevel: "medium",
    reason: "Write operation flagged for audit",
  },

  {
    id: "content:block-secret-exfil",
    description: "Block content containing detected secrets from reaching external channels",
    plane: "content",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "content") return false;
      return payloadContains(ctx.payload, [
        "PRIVATE KEY",
        "BEGIN RSA",
        "AKIA",
        "ghp_",
        "sk-",
        "xoxb-",
      ]) && (ctx.flow?.direction === "egress" || hasFlowLabel(ctx, "secret_material"));
    },
    decision: "deny",
    riskLevel: "critical",
    reason: "Content contains potential secrets and is attempting a risky flow",
  },
  {
    id: "content:redact-pii",
    description: "Redact PII patterns from content on high-risk flows",
    plane: "content",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "content") return false;
      return payloadContains(ctx.payload, ["ssn", "social security", "credit card", "passport"]) &&
        (ctx.flow?.direction === "egress" || hasFlowLabel(ctx, "pii"));
    },
    decision: "redact",
    riskLevel: "high",
    reason: "Content contains potential PII on a risky flow",
  },
  {
    id: "content:approve-untrusted-derived-egress",
    description: "Require approval when untrusted web/email/tool output content drives external egress",
    plane: "content",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "content") return false;
      return (
        ctx.flow?.direction === "egress" &&
        (provenanceHasSource(ctx, "web") || provenanceHasSource(ctx, "email") || provenanceHasSource(ctx, "tool_output")) &&
        (provenanceHasTrust(ctx, "untrusted") || provenanceHasTrust(ctx, "derived"))
      );
    },
    decision: "approve",
    riskLevel: "high",
    reason: "Untrusted or derived external content is driving outbound content flow",
  },

  {
    id: "identity:flag-credential-access",
    description: "Flag any action accessing credential stores",
    plane: "identity",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "identity") return false;
      return (
        payloadContains(ctx.payload, ["keychain", "vault", "secret", "credential", "password", "token"]) ||
        ctx.action.toLowerCase().includes("credential") ||
        ctx.action.toLowerCase().includes("secret") ||
        hasFlowLabel(ctx, "credential_access")
      );
    },
    decision: "approve",
    riskLevel: "critical",
    reason: "Credential or secret access requires human approval",
  },

  {
    id: "browser:block-form-submit-payment",
    description: "Block browser actions that submit payment forms",
    plane: "browser",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "browser") return false;
      return payloadContains(ctx.payload, ["payment", "checkout", "credit card", "billing"]) &&
        (ctx.action.toLowerCase().includes("submit") || hasFlowLabel(ctx, "payment"));
    },
    decision: "deny",
    riskLevel: "critical",
    reason: "Payment form submission blocked and requires explicit human action",
  },
  {
    id: "browser:require-approval-oauth",
    description: "Require approval before completing OAuth authorization flows",
    plane: "browser",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "browser") return false;
      return payloadContains(ctx.payload, ["oauth", "authorize", "grant_access", "allow_access"]);
    },
    decision: "approve",
    riskLevel: "high",
    reason: "OAuth authorization requires human approval",
  },

  {
    id: "governance:deny-watchdog-timeout",
    description: "Deny governance actions when the watchdog kill switch is engaged",
    plane: "governance",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "governance") return false;
      return hasFlowLabel(ctx, "watchdog_timeout") || payloadContains(ctx.payload, ["killSwitchEngaged"]);
    },
    decision: "deny",
    riskLevel: "critical",
    reason: "Watchdog kill switch engaged; governance changes are blocked",
  },
  {
    id: "governance:log-all",
    description: "Emit audit signal for all governance-plane actions",
    plane: "governance",
    match: (ctx: AgentContext) => ctx.plane === "governance",
    decision: "allow",
    riskLevel: "low",
    reason: "Governance action logged",
  },

  {
    id: "mcp:deny-tool-poisoning",
    description: "Deny MCP frames whose advertised tool metadata carries injected instructions",
    plane: "tool",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "tool") return false;
      return isMcpAction(ctx) && mcpMarker(ctx, "mcpToolPoisoned");
    },
    decision: "deny",
    riskLevel: "critical",
    reason: "MCP tool metadata carries instructions to the model rather than a description",
  },
  {
    id: "mcp:approve-tool-drift",
    description: "Require re-approval when an MCP server's advertised tool inventory changes",
    plane: "tool",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "tool") return false;
      return isMcpAction(ctx) && (mcpMarker(ctx, "mcpToolDrift") || hasFlowLabel(ctx, "manifest_drift"));
    },
    decision: "approve",
    riskLevel: "high",
    reason: "MCP server advertised a tool inventory that differs from the approved set",
  },
  {
    id: "mcp:redact-input-secret",
    description: "Redact credential material found in outbound MCP tool arguments",
    plane: "tool",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "tool") return false;
      // The DLP scan is a second, marker-independent path on purpose: if the
      // input gate ever stops setting its marker, the credential still does not
      // reach the server.
      return isMcpAction(ctx) && (mcpMarker(ctx, "mcpInputSecret") || contentDlpScan(ctx).containsSecrets);
    },
    decision: "redact",
    riskLevel: "high",
    reason: "MCP tool arguments contain credential material that must not reach the server",
  },
  {
    id: "mcp:deny-input-injection",
    description: "Deny MCP tool calls whose arguments carry injected instructions",
    plane: "tool",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "tool") return false;
      return isMcpAction(ctx) && mcpMarker(ctx, "mcpInputInjection");
    },
    decision: "deny",
    riskLevel: "high",
    reason: "MCP tool arguments carry injected instructions aimed at the server",
  },
  {
    id: "mcp:deny-response-injection",
    description: "Deny MCP tool output that carries injected instructions back to the agent",
    plane: "content",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "content") return false;
      return isMcpAction(ctx) && mcpMarker(ctx, "mcpResponseInjection") && provenanceHasSource(ctx, "tool_output");
    },
    decision: "deny",
    riskLevel: "critical",
    reason: "MCP tool output carries instructions aimed at the agent",
  },
  {
    id: "mcp:redact-response-secret",
    description: "Redact credential material returned by an MCP server",
    plane: "content",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "content") return false;
      return isMcpAction(ctx) && (mcpMarker(ctx, "mcpResponseSecret") || contentDlpScan(ctx).containsSecrets);
    },
    decision: "redact",
    riskLevel: "high",
    reason: "MCP tool output contains credential material and must be redacted before the agent reads it",
  },
  /**
   * Strict-mode egress gate.
   *
   * The allowlist question is answered by the enforcement runtime and handed here as a
   * marker, the same way the MCP gates hand over their scan results. The rule cannot ask it
   * directly: the allowlist is process configuration, and a rule set that reached into the
   * runtime that calls it would close an import cycle for no gain.
   *
   * Gated on `enforcementMode === "strict"` rather than firing whenever a host is off the
   * allowlist, because guarded mode's whole contract is that an unmatched destination is
   * allowed. A rule that ignored the mode would silently promote every guarded deployment
   * to allowlist-only on the first restart after an upgrade.
   *
   * A caller could forge these markers on a hand-built context, and that is safe in the only
   * direction that matters: forging them produces a denial, never an allow. The enforcement
   * runtime re-checks the allowlist itself and does not consult this rule for permission.
   */
  {
    id: "net:deny-egress-not-allowlisted",
    description: "Deny proxied egress to a host outside the configured allowlist in strict enforcement mode",
    plane: "network",
    match: (ctx: AgentContext) =>
      ctx.plane === "network" &&
      ctx.metadata?.["enforcementMode"] === "strict" &&
      ctx.metadata?.["egressAllowlisted"] === "false",
    decision: "deny",
    riskLevel: "high",
    reason: "Destination host is not in the configured egress allowlist",
  },
  /**
   * The port half of the strict-mode allowlist, separate from the host half so a denial
   * names which of the two was wrong. Same marker contract and the same safe direction:
   * forging the marker produces a denial, never an allow, and the enforcement runtime
   * re-checks the port list itself rather than trusting this rule to be present.
   */
  {
    id: "net:deny-egress-port-not-allowlisted",
    description: "Deny proxied egress to a port outside the configured allowlist in strict enforcement mode",
    plane: "network",
    match: (ctx: AgentContext) =>
      ctx.plane === "network" &&
      ctx.metadata?.["enforcementMode"] === "strict" &&
      ctx.metadata?.["egressPortAllowlisted"] === "false",
    decision: "deny",
    riskLevel: "high",
    reason: "Destination port is not in the configured egress port allowlist",
  },
  /**
   * The fleet's identity gate, for a deployment that declared its agents and said that
   * anything else is a finding.
   *
   * Same marker contract as the two above: the registry answers "did any declared agent
   * claim this connection" and hands the answer over, because identity resolution reads
   * /proc and process configuration and a rule set that reached into either would close an
   * import cycle for no gain. Forging the markers produces a denial and never an allow, and
   * the enforcement runtime re-checks both itself rather than trusting this rule to exist.
   *
   * Gated on the operator having chosen `fleet.unmatched: "deny"`. Without that the default
   * is that an unattributed connection is judged by the process-wide allowlist exactly as it
   * was before agents existed, and a rule that ignored the setting would turn every upgrade
   * into an outage for whatever on the host is not in the agent list yet.
   */
  {
    id: "fleet:deny-undeclared-agent",
    description: "Deny proxied egress that no declared fleet agent claims, when the fleet is closed",
    plane: "network",
    match: (ctx: AgentContext) =>
      ctx.plane === "network" &&
      ctx.metadata?.["fleetUnmatched"] === "deny" &&
      ctx.metadata?.["agentDeclared"] === "false",
    decision: "deny",
    riskLevel: "high",
    reason: "No declared fleet agent claims this connection and the fleet is configured to refuse those",
  },
  /**
   * The per-agent egress budget, expressed as a rule for the same reason the lockdown is:
   * a refusal that costs an agent its remaining allowance should land in the ledger with a
   * rule id, a detection, and an ATT&CK mapping, not as a bare string.
   *
   * The counter itself lives in src/fleet/budget.ts and is the authority. This rule reads
   * the marker the runtime sets after measuring the window, so evaluating policy stays a
   * pure function of its context and a replayed context decides the way it did live.
   */
  {
    id: "fleet:deny-agent-budget-exhausted",
    description: "Deny proxied egress from an agent that has spent its configured request or byte budget",
    plane: "network",
    match: (ctx: AgentContext) =>
      ctx.plane === "network" &&
      ctx.metadata?.["enforcementMode"] !== "monitor" &&
      ctx.metadata?.["agentBudgetExhausted"] === "true",
    decision: "deny",
    riskLevel: "medium",
    reason: "Agent has spent its configured egress budget for the current window",
  },
  /**
   * The emergency stop, expressed as a rule so that a halted action is recorded with the
   * same shape as any other denial: a rule id, a detection, and an ATT&CK mapping an
   * analyst can pivot on. It matches on the marker rather than reading the lockdown state
   * itself, so evaluating policy stays a pure function of the context handed to it and a
   * replayed context decides the same way it did live.
   *
   * Same trust direction as the gate above: a forged marker can only stop something. The
   * runtime reads the state directly, so clearing the marker cannot restart gated activity.
   */
  {
    id: "governance:lockdown",
    description: "Deny any action attempted while the operator lockdown is engaged",
    plane: "governance",
    match: (ctx: AgentContext) => ctx.metadata?.["lockdownActive"] === "true",
    decision: "deny",
    riskLevel: "critical",
    reason: "Operator lockdown is engaged; all gated activity is stopped",
  },
  /**
   * The decoy rule, expressed as a marker match for the same reason the lockdown rule is: the
   * engine must stay a pure function of the context it is handed, so a replayed context reaches
   * the same verdict it did live. Nothing here searches for the decoy value - it is not in the
   * context and must never be put there, because the context is what the audit record is built
   * from. The detection has already happened by the time policy sees this; the rule exists so a
   * decoy hit lands with a rule id, a detection, and an ATT&CK mapping like every other denial.
   */
  {
    id: "identity:deny-decoy-triggered",
    description: "Deny any flow in which a planted decoy token was observed",
    plane: "identity",
    match: (ctx: AgentContext) =>
      ctx.plane === "identity" &&
      (ctx.action === "decoy:triggered" || ctx.metadata?.["decoyTriggered"] === "true"),
    decision: "deny",
    riskLevel: "critical",
    reason: "A decoy token that is never legitimately used appeared in inspected content",
  },
  /**
   * Credential material observed in a file under a path the spill watch observes.
   *
   * The decision is a verdict on something already done rather than an intervention: the
   * watch sees the write after the bytes have landed, so nothing here prevents anything.
   * Recording it as an allow would tell an analyst reading the chain that staging a
   * credential on disk was considered acceptable, which is the opposite of the finding.
   *
   * It matches on the spill watch's own action and on the presence of type names in metadata,
   * never on file contents - the contents are deliberately absent from the context, so a
   * rule that tried to re-derive the match here would find nothing to read.
   */
  {
    id: "content:deny-spill-file-write",
    description: "Deny credential material written to a filesystem path under spill watch",
    plane: "content",
    match: (ctx: AgentContext) => {
      if (ctx.plane !== "content") return false;
      return ctx.action === "spill:file-write" && (ctx.metadata?.["secretTypes"] ?? "") !== "";
    },
    decision: "deny",
    riskLevel: "high",
    reason: "Credential material was written to a watched filesystem path",
  },
  /**
   * Content findings from the forward proxy's plaintext HTTP path.
   *
   * Marker matches, like the egress allowlist and lockdown rules above and for the same
   * reason: the scan is expensive, it runs once per decision in the enforcement runtime, and
   * the engine must stay a pure function of the context it is handed so a replayed context
   * decides the same way it did live. Nothing here re-scans anything, and the matched value
   * is deliberately not in the context to be re-scanned - the context is what the audit
   * record is built from, and a DLP record carrying the secret it detected is worse than no
   * record. What the markers carry is the class and the position; that is all a rule needs.
   *
   * These four are the heuristic half of content inspection and are meant to be editable. An
   * operator who deletes them has turned off pattern-based content gating on the proxy, which
   * is a legitimate choice for a detector with a real false-positive rate. The decoy check is
   * the exception and is enforced by the runtime whether or not its rule survives, because a
   * planted synthetic value appearing in traffic has no false-positive rate to trade against.
   *
   * Direction is part of every match. A secret going out and a secret coming back are
   * different events with different responses, and one rule covering both would force the
   * stricter answer onto the case that does not deserve it.
   */
  {
    id: "net:deny-proxy-request-secret",
    description: "Deny a proxied plaintext HTTP request whose path, headers, or body carry credential material",
    plane: "network",
    match: (ctx: AgentContext) =>
      ctx.plane === "network" &&
      ctx.metadata?.["contentDirection"] === "request" &&
      (ctx.metadata?.["contentSecretTypes"] ?? "") !== "",
    decision: "deny",
    riskLevel: "critical",
    reason: "Proxied request carries credential material out to the destination",
  },
  {
    id: "net:deny-proxy-request-injection",
    description: "Deny a proxied plaintext HTTP request carrying prompt-injection patterns",
    plane: "network",
    match: (ctx: AgentContext) =>
      ctx.plane === "network" &&
      ctx.metadata?.["contentDirection"] === "request" &&
      (ctx.metadata?.["contentInjectionPatterns"] ?? "") !== "",
    decision: "deny",
    riskLevel: "high",
    reason: "Proxied request carries injected instructions",
  },
  /**
   * The response half, and the one worth having most.
   *
   * A poisoned tool result is the dominant real-world shape of this attack: the agent asks a
   * server for data and the answer contains instructions aimed at the agent that reads it.
   * Inspecting only what leaves misses it completely, which is what inspecting only egress
   * had been doing.
   */
  {
    id: "net:deny-proxy-response-injection",
    description: "Deny a proxied plaintext HTTP response carrying prompt-injection patterns",
    plane: "network",
    match: (ctx: AgentContext) =>
      ctx.plane === "network" &&
      ctx.metadata?.["contentDirection"] === "response" &&
      (ctx.metadata?.["contentInjectionPatterns"] ?? "") !== "",
    decision: "deny",
    riskLevel: "high",
    reason: "Proxied response carries injected instructions back to the agent",
  },
  /**
   * Recorded, not blocked, and the asymmetry with the request rule is deliberate.
   *
   * A response carrying a credential is usually the agent reading a secret it is entitled to:
   * its own config endpoint, a token refresh, a vault fetch. Denying that would break the
   * legitimate case far more often than it would catch anything, and there is no redaction
   * available as a middle path - rewriting a body in flight means recomputing Content-Length
   * and re-encoding whatever content encoding it arrived under. So the finding is filed with
   * its class and position and the bytes are forwarded. An operator who wants it denied has
   * one field to change, right here, and can see exactly what they are trading.
   */
  {
    id: "net:flag-proxy-response-secret",
    description: "Record credential material observed in a proxied plaintext HTTP response body",
    plane: "network",
    match: (ctx: AgentContext) =>
      ctx.plane === "network" &&
      ctx.metadata?.["contentDirection"] === "response" &&
      (ctx.metadata?.["contentSecretTypes"] ?? "") !== "",
    decision: "allow",
    riskLevel: "high",
    reason: "Proxied response carries credential material into the agent's context",
  },
];
