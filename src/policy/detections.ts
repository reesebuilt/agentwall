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
