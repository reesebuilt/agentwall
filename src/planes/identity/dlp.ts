import { ContentClassification, FlowLabel, ProvenanceSource, TrustLabel } from "../../types";

interface DlpMatch {
  type: string;
  pattern: RegExp;
  riskLabel: "secret" | "pii";
  redactReplacement: string;
}

const DLP_PATTERNS: DlpMatch[] = [
  { type: "aws-access-key", pattern: /\bAKIA[0-9A-Z]{16}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:AWS-KEY]" },
  { type: "aws-secret-key", pattern: /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/, riskLabel: "secret", redactReplacement: "[REDACTED:AWS-SECRET]" },
  { type: "github-pat", pattern: /\bghp_[A-Za-z0-9]{36,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GH-PAT]" },
  { type: "github-oauth", pattern: /\bgho_[A-Za-z0-9]{36,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:GH-OAUTH]" },
  { type: "openai-key", pattern: /\bsk-[A-Za-z0-9]{32,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:OPENAI-KEY]" },
  { type: "slack-bot-token", pattern: /\bxoxb-[A-Za-z0-9-]{50,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:SLACK-TOKEN]" },
  { type: "slack-user-token", pattern: /\bxoxp-[A-Za-z0-9-]{50,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:SLACK-TOKEN]" },
  { type: "private-key", pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, riskLabel: "secret", redactReplacement: "[REDACTED:PRIVATE-KEY]" },
  { type: "jwt", pattern: /\bey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/, riskLabel: "secret", redactReplacement: "[REDACTED:JWT]" },
  { type: "generic-api-key", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?/i, riskLabel: "secret", redactReplacement: "[REDACTED:API-KEY]" },
  { type: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:SSN]" },
  { type: "credit-card", pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/, riskLabel: "pii", redactReplacement: "[REDACTED:CC]" },
  { type: "email", pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:EMAIL]" },
  { type: "phone-us", pattern: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, riskLabel: "pii", redactReplacement: "[REDACTED:PHONE]" },
];

export interface DlpScanResult {
  secretTypes: string[];
  piiTypes: string[];
  containsSecrets: boolean;
  containsPII: boolean;
  redactedText?: string;
}

export function defaultTrustForSource(source: ProvenanceSource): TrustLabel {
  if (source === "system") return "trusted";
  if (source === "memory" || source === "tool_metadata") return "derived";
  return "untrusted";
}

export function scanText(text: string, redact = false): DlpScanResult {
  const secretTypes: string[] = [];
  const piiTypes: string[] = [];
  let redactedText = text;

  for (const entry of DLP_PATTERNS) {
    if (entry.pattern.test(text)) {
      if (entry.riskLabel === "secret") {
        if (!secretTypes.includes(entry.type)) secretTypes.push(entry.type);
      } else if (!piiTypes.includes(entry.type)) {
        piiTypes.push(entry.type);
      }

      if (redact) {
        redactedText = redactedText.replace(new RegExp(entry.pattern.source, "g"), entry.redactReplacement);
      }
    }
  }

  return {
    secretTypes,
    piiTypes,
    containsSecrets: secretTypes.length > 0,
    containsPII: piiTypes.length > 0,
    redactedText: redact ? redactedText : undefined,
  };
}

export function classifyContent(
  text: string,
  trustLabel?: TrustLabel,
  redact = true,
  source: ProvenanceSource = "user"
): ContentClassification {
  const scan = scanText(text, redact);
  const resolvedTrust = trustLabel ?? defaultTrustForSource(source);
  const labels: FlowLabel[] = [];

  let riskLevel: ContentClassification["riskLevel"] = "low";
  if (scan.containsSecrets) {
    riskLevel = "critical";
    labels.push("secret_material", "high_risk");
  } else if (scan.containsPII) {
    riskLevel = "high";
    labels.push("pii", "high_risk");
  }

  if (resolvedTrust !== "trusted") {
    labels.push("cross_boundary");
  }

  return {
    source,
    trustLabel: resolvedTrust,
    labels,
    containsSecrets: scan.containsSecrets,
    secretTypes: scan.secretTypes,
    containsPII: scan.containsPII,
    piiTypes: scan.piiTypes,
    riskLevel,
    redacted: redact && (scan.containsSecrets || scan.containsPII),
  };
}
