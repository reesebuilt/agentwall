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
];
