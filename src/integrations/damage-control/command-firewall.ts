import { z } from "zod";
import { Decision, RiskLevel } from "../../types";

export const DamageControlModeSchema = z.enum(["monitor", "blacklist", "whitelist", "no_bash"]);
export type DamageControlMode = z.infer<typeof DamageControlModeSchema>;

export const DamageControlLevelSchema = z.enum(["L1", "L2", "L3", "L4", "L5"]);
export type DamageControlLevel = z.infer<typeof DamageControlLevelSchema>;

export const CommandPreflightRequestSchema = z.object({
  agentId: z.string().trim().min(1),
  command: z.string().min(1),
  channelId: z.string().trim().min(1).optional(),
  threadId: z.string().trim().min(1).optional(),
  userId: z.string().trim().min(1).optional(),
  cwd: z.string().trim().min(1).optional(),
  mode: DamageControlModeSchema.optional(),
  allowedCommands: z.array(z.string().trim().min(1)).optional(),
});
export type CommandPreflightRequest = z.infer<typeof CommandPreflightRequestSchema>;

export interface CommandAnalysis {
  decision: Decision;
  riskLevel: RiskLevel;
  mode: DamageControlMode;
  reasons: string[];
  matchedSignals: string[];
  recommendedLevel: DamageControlLevel;
  bypassNotes: string[];
  normalizedCommand: string;
  source: "damage-control-analyzer";
}

export const DAMAGE_CONTROL_LADDER: Array<{
  level: DamageControlLevel;
  title: string;
  summary: string;
  enforcement: "advisory" | "soft" | "real";
}> = [
  {
    level: "L1",
    title: "Prompt-only safety",
    summary: "System prompt asks the agent to be careful. No enforcement.",
    enforcement: "advisory",
  },
  {
    level: "L2",
    title: "Skill / playbook guidance",
    summary: "Skill files document risky commands. Still advisory.",
    enforcement: "advisory",
  },
  {
    level: "L3",
    title: "Blacklist",
    summary: "Reject obvious destructive commands. Reactive and bypassable.",
    enforcement: "soft",
  },
  {
    level: "L4",
    title: "Whitelist",
    summary: "Allow only enumerated safe commands. No compound operators, no broad interpreters.",
    enforcement: "real",
  },
  {
    level: "L5",
    title: "No bash",
    summary: "Remove bash entirely. Expose only purpose-built safe tools.",
    enforcement: "real",
  },
];

export const DEFAULT_DAMAGE_CONTROL_MODE: DamageControlMode = "whitelist";
export const RECOMMENDED_DEFAULT_LEVEL: DamageControlLevel = "L4";

const DEFAULT_WHITELIST = [
  "git status",
  "git diff",
  "git log --oneline -5",
  "pwd",
  "npm test",
  "npm run lint",
  "npm run build",
];

export function defaultWhitelistCommands(): string[] {
  return [...DEFAULT_WHITELIST];
}

const COMPOUND_OPERATOR_SIGNALS: Array<{ pattern: RegExp; signal: string; reason: string }> = [
  { pattern: /&&/, signal: "compound:and", reason: "Compound shell operator '&&' allows chaining commands and bypasses single-command audit." },
  { pattern: /\|\|/, signal: "compound:or", reason: "Compound shell operator '||' allows chaining commands." },
  { pattern: /;/, signal: "compound:semicolon", reason: "Shell separator ';' allows running multiple commands in one call." },
  { pattern: /\|(?!\|)/, signal: "compound:pipe", reason: "Shell pipe '|' can route data through unaudited interpreters (curl|sh)." },
  { pattern: />/, signal: "redirect:write", reason: "Output redirection '>' can overwrite files outside the audited surface." },
  { pattern: /</, signal: "redirect:read", reason: "Input redirection '<' can read arbitrary files into interpreters." },
  { pattern: /\$\(/, signal: "subshell:dollar-paren", reason: "Subshell substitution '$( ... )' executes a hidden inner command." },
  { pattern: /`/, signal: "subshell:backtick", reason: "Backtick subshell executes a hidden inner command." },
];

const INTERPRETER_PATTERNS: Array<{ pattern: RegExp; signal: string; reason: string }> = [
  { pattern: /\beval\b/, signal: "interpreter:eval", reason: "'eval' executes arbitrary strings as shell commands." },
  { pattern: /\bbash\b\s+-c\b/, signal: "interpreter:bash-c", reason: "'bash -c' executes an arbitrary inline script." },
  { pattern: /\bsh\b\s+-c\b/, signal: "interpreter:sh-c", reason: "'sh -c' executes an arbitrary inline script." },
  { pattern: /^\s*(python3?|node|ruby|perl|deno|bun|php)\b/, signal: "interpreter:script", reason: "Running an interpreter on a script enables write-code-then-execute bypass." },
  { pattern: /^\s*bash\b\s+\S+\.sh\b/, signal: "interpreter:bash-script", reason: "Running a shell script enables write-code-then-execute bypass." },
  { pattern: /^\s*sh\b\s+\S+\.sh\b/, signal: "interpreter:sh-script", reason: "Running a shell script enables write-code-then-execute bypass." },
  { pattern: /\bchmod\s+\+x\b/, signal: "interpreter:chmod-x", reason: "Making a file executable is usually a step in write-code-then-execute." },
  { pattern: /(^|\s)\.\/\S+/, signal: "interpreter:dot-slash", reason: "Direct './script' execution runs an unaudited binary or script." },
];

interface DestructiveSignal {
  pattern: RegExp;
  signal: string;
  reason: string;
  risk: RiskLevel;
}

const DESTRUCTIVE_SIGNALS: DestructiveSignal[] = [
  { pattern: /\brm\b(?=[^|;&]*\s(?:-[a-z]*r[a-z]*|--recursive)\b)(?=[^|;&]*\s(?:-[a-z]*f[a-z]*|--force)\b)/, signal: "destructive:rm-rf", reason: "'rm -rf' recursively deletes files without prompt.", risk: "critical" },
  { pattern: /\bfind\b[^|;&]*-delete\b/, signal: "destructive:find-delete", reason: "'find ... -delete' silently removes matched files.", risk: "critical" },
  { pattern: /\bgit\s+clean\s+-[a-z]*f[a-z]*d[a-z]*x[a-z]*\b|\bgit\s+clean\s+-[a-z]*x[a-z]*d[a-z]*f[a-z]*\b|\bgit\s+clean\s+-fdx\b/, signal: "destructive:git-clean-fdx", reason: "'git clean -fdx' deletes ignored files and untracked work.", risk: "high" },
  { pattern: /\bdd\b\s+if=/, signal: "destructive:dd", reason: "'dd' can overwrite disks or devices.", risk: "critical" },
  { pattern: /\bmkfs(\.|\b)/, signal: "destructive:mkfs", reason: "'mkfs' formats a filesystem.", risk: "critical" },
  { pattern: /\bshred\b/, signal: "destructive:shred", reason: "'shred' destructively overwrites files.", risk: "critical" },
  { pattern: /\bdrop\s+database\b/i, signal: "destructive:drop-database", reason: "SQL 'DROP DATABASE' destroys all data in the database.", risk: "critical" },
  { pattern: /\bdrop\s+table\b/i, signal: "destructive:drop-table", reason: "SQL 'DROP TABLE' destroys all data in the table.", risk: "high" },
  { pattern: /\bterraform\s+destroy\b/, signal: "destructive:terraform-destroy", reason: "'terraform destroy' tears down infrastructure.", risk: "critical" },
  { pattern: /\bkubectl\s+delete\b/, signal: "destructive:kubectl-delete", reason: "'kubectl delete' removes live cluster resources.", risk: "high" },
  { pattern: /\bdocker\s+rm\s+-f\b/, signal: "destructive:docker-rm", reason: "'docker rm -f' force-removes a container.", risk: "high" },
  { pattern: /\baws\s+\S+\s+delete\b/, signal: "destructive:aws-delete", reason: "'aws ... delete' removes a cloud resource.", risk: "high" },
  { pattern: /\bgcloud\s+\S+\s+delete\b/, signal: "destructive:gcloud-delete", reason: "'gcloud ... delete' removes a cloud resource.", risk: "high" },
  { pattern: /\bvercel\s+(rm|remove|delete)\b/, signal: "destructive:vercel-remove", reason: "'vercel rm' deletes deployments.", risk: "high" },
  { pattern: /\bwrangler\s+(delete|kv:bulk\s+delete)\b/, signal: "destructive:wrangler-delete", reason: "'wrangler delete' destroys Cloudflare resources.", risk: "high" },
  { pattern: /\bcurl\b[^|;&]*\|\s*(bash|sh|zsh)\b/, signal: "destructive:curl-pipe-shell", reason: "'curl | sh' executes remote code with no audit.", risk: "critical" },
  { pattern: /\bwget\b[^|;&]*\|\s*(bash|sh|zsh)\b/, signal: "destructive:wget-pipe-shell", reason: "'wget | sh' executes remote code with no audit.", risk: "critical" },
  { pattern: /\bnc\b\s+.*-e\b/, signal: "destructive:nc-reverse-shell", reason: "'nc -e' patterns are commonly used as reverse shells.", risk: "critical" },
  { pattern: /\bbase64\b[^|;&]*-d[^|;&]*\|\s*(bash|sh|zsh)\b/, signal: "destructive:base64-pipe-shell", reason: "Decoding base64 and piping to a shell hides the real payload.", risk: "critical" },
  { pattern: /\bchmod\b\s+-R\s+777\b/, signal: "destructive:chmod-777", reason: "'chmod -R 777' makes everything world-writable.", risk: "high" },
  { pattern: /\bchown\b\s+-R\b/, signal: "destructive:chown-recursive", reason: "'chown -R' rewrites ownership of entire trees.", risk: "high" },
];

function normalizeWhitespace(command: string): string {
  return command.replace(/\s+/g, " ").trim();
}

function normalizeAllowed(command: string): string {
  return normalizeWhitespace(command).toLowerCase();
}

function detectCompoundSignals(command: string): { signals: string[]; reasons: string[] } {
  const signals: string[] = [];
  const reasons: string[] = [];
  for (const entry of COMPOUND_OPERATOR_SIGNALS) {
    if (entry.pattern.test(command)) {
      signals.push(entry.signal);
      reasons.push(entry.reason);
    }
  }
  return { signals, reasons };
}

function detectInterpreterSignals(command: string): { signals: string[]; reasons: string[] } {
  const signals: string[] = [];
  const reasons: string[] = [];
  for (const entry of INTERPRETER_PATTERNS) {
    if (entry.pattern.test(command)) {
      signals.push(entry.signal);
      reasons.push(entry.reason);
    }
  }
  return { signals, reasons };
}

function detectDestructiveSignals(command: string): { signals: string[]; reasons: string[]; risk: RiskLevel } {
  const signals: string[] = [];
  const reasons: string[] = [];
  let risk: RiskLevel = "low";
  const riskOrder: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };
  for (const entry of DESTRUCTIVE_SIGNALS) {
    if (entry.pattern.test(command)) {
      signals.push(entry.signal);
      reasons.push(entry.reason);
      if (riskOrder[entry.risk] > riskOrder[risk]) {
        risk = entry.risk;
      }
    }
  }
  return { signals, reasons, risk };
}

function escalateRisk(current: RiskLevel, next: RiskLevel): RiskLevel {
  const order: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };
  return order[next] > order[current] ? next : current;
}

function analyzeNoBash(normalized: string): CommandAnalysis {
  return {
    decision: "deny",
    riskLevel: "critical",
    mode: "no_bash",
    reasons: ["Bash is disabled. All command execution is denied. Use a purpose-built safe tool."],
    matchedSignals: ["mode:no-bash"],
    recommendedLevel: "L5",
    bypassNotes: [
      "L5 (no bash) is the strongest posture. Replace destructive funnels with narrow safe tools (read_file, list_dir, etc).",
    ],
    normalizedCommand: normalized,
    source: "damage-control-analyzer",
  };
}

function analyzeWhitelist(normalized: string, allowed: string[] | undefined): CommandAnalysis {
  const effectiveAllowed = (allowed && allowed.length > 0 ? allowed : DEFAULT_WHITELIST).map(normalizeAllowed);
  const normalizedLower = normalizeAllowed(normalized);
  const compound = detectCompoundSignals(normalized);
  const interpreter = detectInterpreterSignals(normalized);
  const destructive = detectDestructiveSignals(normalized);

  const matchedSignals: string[] = [];
  const reasons: string[] = [];
  const bypassNotes: string[] = [];
  let riskLevel: RiskLevel = "low";

  if (compound.signals.length > 0) {
    matchedSignals.push(...compound.signals);
    reasons.push(...compound.reasons);
    riskLevel = escalateRisk(riskLevel, "high");
    bypassNotes.push("Whitelist rejects compound shell operators. They are the most common way to smuggle a second command past audits.");
  }
  if (interpreter.signals.length > 0) {
    matchedSignals.push(...interpreter.signals);
    reasons.push(...interpreter.reasons);
    riskLevel = escalateRisk(riskLevel, "high");
    bypassNotes.push("Whitelist rejects broad interpreters. Write-code-then-execute is the canonical L3 bypass.");
  }
  if (destructive.signals.length > 0) {
    matchedSignals.push(...destructive.signals);
    reasons.push(...destructive.reasons);
    riskLevel = escalateRisk(riskLevel, destructive.risk);
  }

  if (matchedSignals.length > 0) {
    return {
      decision: "deny",
      riskLevel,
      mode: "whitelist",
      reasons,
      matchedSignals,
      recommendedLevel: "L4",
      bypassNotes,
      normalizedCommand: normalized,
      source: "damage-control-analyzer",
    };
  }

  if (effectiveAllowed.includes(normalizedLower)) {
    return {
      decision: "allow",
      riskLevel: "low",
      mode: "whitelist",
      reasons: ["Command matches a whitelist entry."],
      matchedSignals: ["whitelist:exact-match"],
      recommendedLevel: "L4",
      bypassNotes: [],
      normalizedCommand: normalized,
      source: "damage-control-analyzer",
    };
  }

  return {
    decision: "deny",
    riskLevel: "medium",
    mode: "whitelist",
    reasons: [`Command is not on the whitelist. Whitelist allows only enumerated commands; everything else is denied by default.`],
    matchedSignals: ["whitelist:no-match"],
    recommendedLevel: "L4",
    bypassNotes: [
      "Add the command to allowedCommands only if it is read-only and side-effect free, or move that workflow to a purpose-built safe tool (L5).",
    ],
    normalizedCommand: normalized,
    source: "damage-control-analyzer",
  };
}

function analyzeBlacklist(normalized: string): CommandAnalysis {
  const destructive = detectDestructiveSignals(normalized);
  const interpreter = detectInterpreterSignals(normalized);
  const compound = detectCompoundSignals(normalized);

  const bypassNotes: string[] = [
    "Blacklists are reactive and bypassable. Encoded payloads, alternate spellings, or 'write code then run it' all defeat L3.",
    "Recommend moving to L4 (whitelist) or L5 (no bash) for real enforcement.",
  ];

  if (destructive.signals.length > 0) {
    return {
      decision: "deny",
      riskLevel: destructive.risk,
      mode: "blacklist",
      reasons: destructive.reasons,
      matchedSignals: destructive.signals,
      recommendedLevel: "L4",
      bypassNotes,
      normalizedCommand: normalized,
      source: "damage-control-analyzer",
    };
  }

  if (interpreter.signals.length > 0 || compound.signals.length > 0) {
    return {
      decision: "approve",
      riskLevel: "high",
      mode: "blacklist",
      reasons: [
        ...interpreter.reasons,
        ...compound.reasons,
        "Command is not directly destructive but routes through an interpreter or compound operator. Requires approval.",
      ],
      matchedSignals: [...interpreter.signals, ...compound.signals],
      recommendedLevel: "L4",
      bypassNotes,
      normalizedCommand: normalized,
      source: "damage-control-analyzer",
    };
  }

  return {
    decision: "allow",
    riskLevel: "low",
    mode: "blacklist",
    reasons: ["Command did not match any blacklisted destructive signal."],
    matchedSignals: ["blacklist:no-match"],
    recommendedLevel: "L4",
    bypassNotes,
    normalizedCommand: normalized,
    source: "damage-control-analyzer",
  };
}

function analyzeMonitor(normalized: string, allowed: string[] | undefined): CommandAnalysis {
  const shadow = analyzeWhitelist(normalized, allowed);
  const wouldHaveBeen = shadow.decision;
  return {
    decision: "allow",
    riskLevel: shadow.riskLevel,
    mode: "monitor",
    reasons: [
      `Monitor mode: command observed, no enforcement. Whitelist mode would have returned '${wouldHaveBeen}'.`,
      ...shadow.reasons,
    ],
    matchedSignals: ["monitor:shadow", ...shadow.matchedSignals],
    recommendedLevel: shadow.decision === "allow" ? "L4" : "L4",
    bypassNotes: [
      "Monitor mode never blocks. Use it only to baseline traffic before turning on L4.",
      ...shadow.bypassNotes,
    ],
    normalizedCommand: normalized,
    source: "damage-control-analyzer",
  };
}

export function analyzeCommand(input: CommandPreflightRequest): CommandAnalysis {
  const mode: DamageControlMode = input.mode ?? DEFAULT_DAMAGE_CONTROL_MODE;
  const normalized = normalizeWhitespace(input.command);

  if (!normalized) {
    return {
      decision: "deny",
      riskLevel: "medium",
      mode,
      reasons: ["Empty command after normalization."],
      matchedSignals: ["input:empty"],
      recommendedLevel: "L4",
      bypassNotes: [],
      normalizedCommand: "",
      source: "damage-control-analyzer",
    };
  }

  if (mode === "no_bash") return analyzeNoBash(normalized);
  if (mode === "blacklist") return analyzeBlacklist(normalized);
  if (mode === "monitor") return analyzeMonitor(normalized, input.allowedCommands);
  return analyzeWhitelist(normalized, input.allowedCommands);
}

export function combineDecision(a: Decision, b: Decision): Decision {
  const order: Record<Decision, number> = { allow: 0, redact: 1, approve: 2, deny: 3 };
  return order[a] >= order[b] ? a : b;
}

export function combineRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  const order: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };
  return order[a] >= order[b] ? a : b;
}
