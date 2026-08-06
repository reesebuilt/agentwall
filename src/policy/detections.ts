export interface DetectionMapping {
  id: string;
  ruleId: string;
  name: string;
  description: string;
  mitreAttack?: {
    tactic: string;
    technique: string;
    techniqueId: string;
  };
  severity: "low" | "medium" | "high" | "critical";
}

export const detectionCatalog: DetectionMapping[] = [
  {
    id: "det.net.ssrf.private",
    ruleId: "net:block-ssrf-private",
    name: "Private-range SSRF attempt",
    description: "Outbound request targeted loopback, private, or link-local infrastructure.",
    mitreAttack: {
      tactic: "Initial Access",
      technique: "Exploit Public-Facing Application",
      techniqueId: "T1190",
    },
    severity: "critical",
  },
  {
    id: "det.net.metadata.access",
    ruleId: "net:block-metadata-endpoint",
    name: "Cloud metadata access",
    description: "Request attempted to access cloud instance metadata endpoints.",
    mitreAttack: {
      tactic: "Credential Access",
      technique: "Cloud Instance Metadata API",
      techniqueId: "T1552.005",
    },
    severity: "critical",
  },
  {
    id: "det.net.sni.connect-mismatch",
    ruleId: "net:sni-connect-mismatch",
    name: "CONNECT host and TLS SNI disagree",
    description:
      "A tunnelled connection named one host on its CONNECT line and negotiated a different one in its ClientHello. The proxy re-evaluated policy against the negotiated name. This is a client contradicting itself to the proxy, NOT domain fronting: fronting hides its real destination in the HTTP Host header inside the TLS session, which a proxy that does not terminate TLS cannot read.",
    // Deliberately unmapped. The nearest-looking technique is T1090.004 (Domain Fronting),
    // and it is the wrong one: ATT&CK defines that as SNI disagreeing with the inner Host
    // header, which is invisible here. Claiming it would publish an ATT&CK coverage row for
    // traffic this cannot see. `unmappedDetections()` is the honest home for a real detection
    // with no accurate framework row, and the compliance suite reports it as such.
    severity: "high",
  },
  {
    id: "det.content.secret.exfil",
    ruleId: "content:block-secret-exfil",
    name: "Potential secret exfiltration",
    description: "Detected credential material in outbound content flow.",
    mitreAttack: {
      tactic: "Exfiltration",
      technique: "Exfiltration Over C2 Channel",
      techniqueId: "T1041",
    },
    severity: "critical",
  },
  {
    id: "det.identity.credential.access",
    ruleId: "identity:flag-credential-access",
    name: "Credential store access",
    description: "Action requested access to secrets, passwords, tokens, or credential vaults.",
    mitreAttack: {
      tactic: "Credential Access",
      technique: "Credentials from Password Stores",
      techniqueId: "T1555",
    },
    severity: "critical",
  },
  {
    id: "det.browser.oauth.approval",
    ruleId: "browser:require-approval-oauth",
    name: "OAuth grant attempt",
    description: "Browser flow indicates third-party authorization grant request.",
    mitreAttack: {
      tactic: "Persistence",
      technique: "Additional Cloud Credentials",
      techniqueId: "T1098.001",
    },
    severity: "high",
  },
  {
    id: "det.tool.manifest.drift",
    ruleId: "tool:approve-manifest-drift",
    name: "Tool manifest drift",
    description: "Tool or MCP manifest changed after prior approval.",
    mitreAttack: {
      tactic: "Defense Evasion",
      technique: "Impair Defenses",
      techniqueId: "T1562",
    },
    severity: "high",
  },
  {
    id: "det.mcp.tool.poisoned",
    ruleId: "mcp:deny-tool-poisoning",
    name: "Poisoned MCP tool description",
    description: "An MCP server advertised a tool whose name or description carries instructions aimed at the model.",
    mitreAttack: {
      tactic: "Initial Access",
      technique: "Supply Chain Compromise",
      techniqueId: "T1195",
    },
    severity: "critical",
  },
  {
    id: "det.mcp.tool.drift",
    ruleId: "mcp:approve-tool-drift",
    name: "MCP tool inventory drift",
    description: "An MCP server advertised a tool set that differs from the inventory approved for this session.",
    mitreAttack: {
      tactic: "Initial Access",
      technique: "Supply Chain Compromise",
      techniqueId: "T1195",
    },
    severity: "high",
  },
  {
    id: "det.mcp.input.secret",
    ruleId: "mcp:redact-input-secret",
    name: "Credential material in MCP tool arguments",
    description: "Outbound MCP tool arguments carried credential material and were redacted before reaching the server.",
    mitreAttack: {
      tactic: "Credential Access",
      technique: "Unsecured Credentials",
      techniqueId: "T1552",
    },
    severity: "high",
  },
  {
    id: "det.mcp.input.injection",
    ruleId: "mcp:deny-input-injection",
    name: "Injected instructions in MCP tool arguments",
    description: "Outbound MCP tool arguments carried instruction-injection text aimed at the receiving server.",
    mitreAttack: {
      tactic: "Execution",
      technique: "Command and Scripting Interpreter",
      techniqueId: "T1059",
    },
    severity: "high",
  },
  {
    id: "det.mcp.response.injection",
    ruleId: "mcp:deny-response-injection",
    name: "Injected instructions in MCP tool output",
    description: "An MCP server returned tool output carrying instruction-injection text aimed at the agent.",
    mitreAttack: {
      tactic: "Execution",
      technique: "Command and Scripting Interpreter",
      techniqueId: "T1059",
    },
    severity: "critical",
  },
  {
    id: "det.mcp.response.secret",
    ruleId: "mcp:redact-response-secret",
    name: "Credential material in MCP tool output",
    description: "An MCP server returned credential material, which was redacted before it reached the agent.",
    mitreAttack: {
      tactic: "Credential Access",
      technique: "Unsecured Credentials",
      techniqueId: "T1552",
    },
    severity: "high",
  },
  {
    id: "det.net.egress.blocked",
    ruleId: "net:deny-egress-not-allowlisted",
    name: "Blocked egress to a non-allowlisted destination",
    description:
      "A proxied agent tried to reach a host outside the configured egress allowlist while strict enforcement was active, and the connection was refused.",
    mitreAttack: {
      tactic: "Command and Control",
      technique: "Application Layer Protocol",
      techniqueId: "T1071",
    },
    severity: "high",
  },
  {
    id: "det.net.egress.port_blocked",
    ruleId: "net:deny-egress-port-not-allowlisted",
    name: "Blocked egress to a non-allowlisted port",
    description:
      "A proxied agent tried to reach a port outside the configured egress port allowlist while strict enforcement was active, and the connection was refused. Reaching an unexpected port on an otherwise permitted host is how an agent turns a web allowlist into shell, database, or admin access.",
    mitreAttack: {
      tactic: "Command and Control",
      technique: "Non-Standard Port",
      techniqueId: "T1571",
    },
    severity: "high",
  },
  {
    id: "det.governance.lockdown.active",
    ruleId: "governance:lockdown",
    name: "Action refused by the operator lockdown",
    description:
      "An action was attempted while the emergency stop was engaged and was refused. Expected during an intentional halt; unexpected outside one, which is why it is recorded rather than suppressed.",
    mitreAttack: {
      tactic: "Impact",
      technique: "Service Stop",
      techniqueId: "T1489",
    },
    severity: "critical",
  },
  {
    id: "det.identity.decoy.triggered",
    ruleId: "identity:deny-decoy-triggered",
    name: "Decoy token triggered",
    description:
      "A planted decoy credential appeared in inspected content. The value is synthetic and is never legitimately used, so its presence demonstrates exfiltration rather than inferring it.",
    mitreAttack: {
      tactic: "Credential Access",
      technique: "Unsecured Credentials",
      techniqueId: "T1552",
    },
    severity: "critical",
  },
  {
    id: "det.content.spill.file_write",
    ruleId: "content:deny-spill-file-write",
    name: "Credential written to a watched path",
    description:
      "The spill watch observed credential material appear in a file under a watched path. The write itself is the finding: staging a harvested credential on disk precedes the commit or upload that would make it egress, and nothing in the network plane sees that step.",
    mitreAttack: {
      tactic: "Credential Access",
      technique: "Credentials In Files",
      techniqueId: "T1552.001",
    },
    severity: "high",
  },
  {
    id: "det.net.proxy.request_secret",
    ruleId: "net:deny-proxy-request-secret",
    name: "Credential material in a proxied request",
    description:
      "A plaintext HTTP request through the forward proxy carried credential material in its path, headers, or body, and was refused. This is the first control in the product that sees a proxied body at all; the same request over https is invisible to it, because that body is never decrypted.",
    mitreAttack: {
      tactic: "Exfiltration",
      technique: "Exfiltration Over C2 Channel",
      techniqueId: "T1041",
    },
    severity: "critical",
  },
  {
    id: "det.net.proxy.request_injection",
    ruleId: "net:deny-proxy-request-injection",
    name: "Injected instructions in a proxied request",
    description:
      "A plaintext HTTP request through the forward proxy carried prompt-injection patterns in its path, headers, or body. An agent relaying an instruction override to a downstream service is aiming it at whatever consumes the request next.",
    mitreAttack: {
      tactic: "Execution",
      technique: "Command and Scripting Interpreter",
      techniqueId: "T1059",
    },
    severity: "high",
  },
  {
    id: "det.net.proxy.response_injection",
    ruleId: "net:deny-proxy-response-injection",
    name: "Injected instructions in a proxied response",
    description:
      "A plaintext HTTP response through the forward proxy carried prompt-injection patterns back to the agent. A poisoned tool result is the dominant real-world shape of this attack, and a control that inspects only egress never sees it.",
    mitreAttack: {
      tactic: "Execution",
      technique: "Command and Scripting Interpreter",
      techniqueId: "T1059",
    },
    severity: "high",
  },
  {
    id: "det.net.proxy.response_secret",
    ruleId: "net:flag-proxy-response-secret",
    name: "Credential material in a proxied response",
    description:
      "A plaintext HTTP response through the forward proxy carried credential material into the agent's context. Recorded rather than refused: a response carrying a secret is usually the agent reading one it is entitled to, and blocking that breaks the legitimate case far more often than it catches anything.",
    mitreAttack: {
      tactic: "Credential Access",
      technique: "Unsecured Credentials",
      techniqueId: "T1552",
    },
    severity: "high",
  },
  {
    id: "det.fleet.budget.exhausted",
    ruleId: "fleet:deny-agent-budget-exhausted",
    name: "Agent egress budget exhausted",
    description:
      "A declared agent reached the request or byte ceiling configured for its window and the connection was refused. Expected when a budget is doing its job; worth reading when an agent that has never approached its ceiling suddenly does, which is what a runaway loop or an exfiltration attempt looks like from the outside.",
    mitreAttack: {
      tactic: "Exfiltration",
      technique: "Exfiltration Over C2 Channel",
      techniqueId: "T1041",
    },
    severity: "medium",
  },
  {
    id: "det.fleet.agent.undeclared",
    ruleId: "fleet:deny-undeclared-agent",
    name: "Egress from an agent no declaration claims",
    description:
      "A proxied connection could not be bound to any declared agent and the fleet is configured to refuse those. Either an agent was deployed without being declared, or something on the host is using the proxy that the operator did not put there. Both are worth knowing; only the second is an incident.",
    mitreAttack: {
      tactic: "Defense Evasion",
      technique: "Masquerading",
      techniqueId: "T1036",
    },
    severity: "high",
  },
];

const detectionByRule = new Map<string, DetectionMapping[]>(
  detectionCatalog.reduce<Array<[string, DetectionMapping[]]>>((acc, item) => {
    const existing = acc.find(([ruleId]) => ruleId === item.ruleId);
    if (existing) {
      existing[1].push(item);
    } else {
      acc.push([item.ruleId, [item]]);
    }
    return acc;
  }, [])
);

const inspectionDetections: Record<string, DetectionMapping> = {
  "embedded-credentials": {
    id: "det.net.embedded.credentials",
    ruleId: "inspection:embedded-credentials",
    name: "Embedded credentials in URL",
    description: "Outbound request included a username or password in the URL.",
    mitreAttack: {
      tactic: "Credential Access",
      technique: "Exposed Credentials",
      techniqueId: "T1552",
    },
    severity: "high",
  },
  "cloud-metadata": {
    id: "det.net.metadata.access",
    ruleId: "inspection:cloud-metadata",
    name: "Cloud metadata access",
    description: "Request attempted to access cloud instance metadata endpoints.",
    mitreAttack: {
      tactic: "Credential Access",
      technique: "Cloud Instance Metadata API",
      techniqueId: "T1552.005",
    },
    severity: "critical",
  },
  "private-target": {
    id: "det.net.ssrf.private",
    ruleId: "inspection:private-target",
    name: "Private-range SSRF attempt",
    description: "Outbound request targeted loopback, private, or link-local infrastructure.",
    mitreAttack: {
      tactic: "Initial Access",
      technique: "Exploit Public-Facing Application",
      techniqueId: "T1190",
    },
    severity: "critical",
  },
  "default-deny-egress": {
    id: "det.net.egress.default-deny",
    ruleId: "inspection:default-deny-egress",
    name: "Default-deny egress block",
    description: "Outbound request was blocked by the default-deny egress posture.",
    severity: "high",
  },
  "blocked-scheme": {
    id: "det.net.egress.scheme",
    ruleId: "inspection:blocked-scheme",
    name: "Blocked egress scheme",
    description: "Outbound request used a disallowed URL scheme.",
    severity: "high",
  },
  "blocked-port": {
    id: "det.net.egress.port",
    ruleId: "inspection:blocked-port",
    name: "Blocked egress port",
    description: "Outbound request used a disallowed destination port.",
    severity: "high",
  },
  "invalid-url": {
    id: "det.net.egress.invalid-url",
    ruleId: "inspection:invalid-url",
    name: "Malformed outbound URL",
    description: "Outbound request URL could not be parsed.",
    severity: "high",
  },
};

export function detectionForBlockedCategory(category: string | undefined): DetectionMapping | null {
  if (!category) return null;
  return inspectionDetections[category] ?? null;
}

export function detectionsForRules(ruleIds: string[]): DetectionMapping[] {
  const results: DetectionMapping[] = [];
  const seen = new Set<string>();

  for (const ruleId of ruleIds) {
    const mapped = detectionByRule.get(ruleId) ?? [];
    for (const entry of mapped) {
      if (!seen.has(entry.id)) {
        seen.add(entry.id);
        results.push(entry);
      }
    }
  }

  return results;
}
