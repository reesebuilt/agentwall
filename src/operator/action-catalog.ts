export const MUTATING_OPERATOR_ACTIONS = [
  "approval-mode",
  "shield",
  "normal",
  "session-boost",
  "session-reset",
  "pause",
  "resume",
  "terminate",
  "fleet-issue",
  "fleet-rotate",
  "fleet-revoke",
  "anchor",
  "verify-capture",
  "mcp-wrap",
  "mcp-http-wrap",
  "mcp-http-stop",
  "perimeter-install",
  "perimeter-rollback",
  "perimeter-run",
  "sandbox-build",
  "sandbox-run",
  "intercept-init",
  "intercept-trust",
  "decoy-generate",
] as const;

export const READ_ONLY_OPERATOR_ACTIONS = [
  "doctor",
  "status",
  "verify",
  "fleet-list",
  "mcp-http-list",
  "perimeter-plan",
  "perimeter-status",
  "perimeter-verify",
  "sandbox-probe",
  "sandbox-plan",
  "intercept-status",
  "decoy-list",
  "why",
  "version",
  "help",
] as const;

export type MutatingOperatorAction = (typeof MUTATING_OPERATOR_ACTIONS)[number];
export type ReadOnlyOperatorAction = (typeof READ_ONLY_OPERATOR_ACTIONS)[number];
export type OperatorActionId = MutatingOperatorAction | ReadOnlyOperatorAction;

export interface OperatorActionField {
  name: string;
  label: string;
  type: "text" | "number" | "select" | "textarea" | "path" | "boolean";
  required: boolean;
  options?: string[];
  placeholder?: string;
}

export interface OperatorActionCatalogEntry {
  id: OperatorActionId;
  label: string;
  group: string;
  mutating: boolean;
  confirmation: boolean;
  description: string;
  cli: string;
  fields: OperatorActionField[];
}

export const operatorActionCatalog: readonly OperatorActionCatalogEntry[] = [
  {
    id: "approval-mode", label: "Set approval mode", group: "Runtime", mutating: true, confirmation: true,
    description: "Set how AgentWall handles approval requests.", cli: "agentwall approval-mode <auto|always|never>",
    fields: [{ name: "mode", label: "Mode", type: "select", required: true, options: ["auto", "always", "never"] }],
  },
  {
    id: "shield", label: "Enable shield", group: "Runtime", mutating: true, confirmation: true,
    description: "Apply stricter FloodGuard limits for a fixed time.", cli: "agentwall shield --duration <time>",
    fields: [{ name: "durationMs", label: "Duration in milliseconds", type: "number", required: false, placeholder: "600000" }],
  },
  {
    id: "normal", label: "Use normal limits", group: "Runtime", mutating: true, confirmation: true,
    description: "Return FloodGuard to its normal limits.", cli: "agentwall normal", fields: [],
  },
  {
    id: "session-boost", label: "Boost session", group: "Sessions", mutating: true, confirmation: true,
    description: "Raise FloodGuard limits for one session and a fixed time.", cli: "agentwall session-boost --session <id>",
    fields: [
      { name: "sessionId", label: "Session ID", type: "text", required: true },
      { name: "multiplier", label: "Limit multiplier", type: "number", required: false, placeholder: "1.5" },
      { name: "durationMs", label: "Duration in milliseconds", type: "number", required: false, placeholder: "600000" },
    ],
  },
  {
    id: "session-reset", label: "Reset session limits", group: "Sessions", mutating: true, confirmation: true,
    description: "Remove the FloodGuard override from one session.", cli: "agentwall session-reset --session <id>",
    fields: [{ name: "sessionId", label: "Session ID", type: "text", required: true }],
  },
  {
    id: "pause", label: "Pause session", group: "Sessions", mutating: true, confirmation: true,
    description: "Pause one runtime session.", cli: "agentwall pause --session <id>",
    fields: [
      { name: "sessionId", label: "Session ID", type: "text", required: true },
      { name: "note", label: "Operator note", type: "textarea", required: false },
    ],
  },
  {
    id: "resume", label: "Resume session", group: "Sessions", mutating: true, confirmation: true,
    description: "Resume one paused runtime session.", cli: "agentwall resume --session <id>",
    fields: [
      { name: "sessionId", label: "Session ID", type: "text", required: true },
      { name: "note", label: "Operator note", type: "textarea", required: false },
    ],
  },
  {
    id: "terminate", label: "Terminate session", group: "Sessions", mutating: true, confirmation: true,
    description: "Terminate one runtime session.", cli: "agentwall terminate --session <id> --confirm",
    fields: [
      { name: "sessionId", label: "Session ID", type: "text", required: true },
      { name: "note", label: "Operator note", type: "textarea", required: false },
    ],
  },
  {
    id: "fleet-issue", label: "Issue fleet credential", group: "Fleet", mutating: true, confirmation: true,
    description: "Issue one credential for a declared agent.", cli: "agentwall fleet issue --agent <id>",
    fields: [{ name: "agentId", label: "Agent ID", type: "text", required: true }],
  },
  {
    id: "fleet-rotate", label: "Rotate fleet credential", group: "Fleet", mutating: true, confirmation: true,
    description: "Rotate one agent credential with a controlled overlap.", cli: "agentwall fleet rotate --agent <id>",
    fields: [
      { name: "agentId", label: "Agent ID", type: "text", required: true },
      { name: "overlapSeconds", label: "Overlap seconds", type: "number", required: false, placeholder: "900" },
    ],
  },
  {
    id: "fleet-revoke", label: "Revoke fleet credential", group: "Fleet", mutating: true, confirmation: true,
    description: "Revoke one credential or all credentials for one agent.", cli: "agentwall fleet revoke --credential <id>",
    fields: [
      { name: "credentialId", label: "Credential ID", type: "text", required: false },
      { name: "agentId", label: "Agent ID", type: "text", required: false },
      { name: "reason", label: "Reason", type: "textarea", required: false },
    ],
  },
  { id: "anchor", label: "Anchor audit evidence", group: "Evidence", mutating: true, confirmation: true, description: "Create and submit an audit checkpoint.", cli: "agentwall anchor", fields: [] },
  {
    id: "verify-capture", label: "Verify capture", group: "Evidence", mutating: true, confirmation: true,
    description: "Run a typed fetch and check its AgentWall audit evidence.", cli: "agentwall verify-capture --agent <id> --command <command>",
    fields: [
      { name: "agentId", label: "Agent ID", type: "text", required: true },
      { name: "command", label: "Declared executable", type: "text", required: true },
      { name: "args", label: "Arguments", type: "textarea", required: false, placeholder: "One argument per line" },
      { name: "workingDirectory", label: "Working directory", type: "path", required: false },
    ],
  },
  {
    id: "mcp-wrap", label: "Prepare MCP stdio wrapper", group: "MCP", mutating: true, confirmation: true,
    description: "Prepare a safe command for a client-owned local MCP stdio process.", cli: "agentwall mcp wrap -- <command>",
    fields: [
      { name: "command", label: "Declared executable", type: "text", required: true },
      { name: "args", label: "Arguments", type: "textarea", required: false, placeholder: "One argument per line" },
      { name: "workingDirectory", label: "Working directory", type: "path", required: false },
      { name: "serverName", label: "Server name", type: "text", required: false },
      { name: "agentId", label: "Agent ID", type: "text", required: false },
    ],
  },
  {
    id: "mcp-http-wrap", label: "Start MCP HTTP wrapper", group: "MCP", mutating: true, confirmation: true,
    description: "Start a local loopback wrapper for a remote MCP HTTP server.", cli: "agentwall mcp wrap --http-upstream <url> --http-port 0",
    fields: [
      { name: "upstreamUrl", label: "MCP HTTP URL", type: "text", required: true, placeholder: "https://mcp.example.com/mcp" },
      { name: "listenPort", label: "Local port", type: "number", required: false, placeholder: "0 for an available port" },
      { name: "serverName", label: "Server name", type: "text", required: false },
      { name: "agentId", label: "Agent ID", type: "text", required: false },
      { name: "baselineMode", label: "Tool inventory mode", type: "select", required: false, options: ["off", "learn", "lock"] },
      { name: "baselineFile", label: "Inventory file", type: "path", required: false, placeholder: ".agentwall/mcp-baselines.json" },
    ],
  },
  {
    id: "mcp-http-stop", label: "Stop MCP HTTP wrapper", group: "MCP", mutating: true, confirmation: true,
    description: "Stop one managed local MCP HTTP wrapper.", cli: "agentwall mcp stop <wrapper-id>", fields: [{ name: "wrapId", label: "Wrapper ID", type: "text", required: true }],
  },
  {
    id: "perimeter-install", label: "Install perimeter", group: "Perimeter", mutating: true, confirmation: true,
    description: "Install the planned host network perimeter.", cli: "agentwall perimeter install",
    fields: [
      { name: "agentUid", label: "Agent UID", type: "number", required: false },
      { name: "proxyUid", label: "Proxy UID", type: "number", required: false },
      { name: "proxyPort", label: "Proxy port", type: "number", required: false },
      { name: "dnsResolver", label: "DNS resolver", type: "text", required: false },
      { name: "agentGid", label: "Agent GID", type: "number", required: false },
      { name: "allowLoopback", label: "Allow other loopback services", type: "boolean", required: false },
    ],
  },
  { id: "perimeter-rollback", label: "Roll back perimeter", group: "Perimeter", mutating: true, confirmation: true, description: "Remove the AgentWall host network perimeter.", cli: "agentwall perimeter rollback", fields: [] },
  {
    id: "perimeter-run", label: "Run inside perimeter", group: "Perimeter", mutating: true, confirmation: true,
    description: "Run a declared executable inside the installed perimeter.", cli: "agentwall perimeter run -- <command>",
    fields: [
      { name: "command", label: "Declared executable", type: "text", required: true },
      { name: "args", label: "Arguments", type: "textarea", required: false, placeholder: "One argument per line" },
      { name: "workingDirectory", label: "Working directory", type: "path", required: false },
      { name: "agentUid", label: "Agent UID", type: "number", required: false },
      { name: "proxyUid", label: "Proxy UID", type: "number", required: false },
      { name: "proxyPort", label: "Proxy port", type: "number", required: false },
      { name: "dnsResolver", label: "DNS resolver", type: "text", required: false },
      { name: "agentGid", label: "Agent GID", type: "number", required: false },
      { name: "allowLoopback", label: "Allow other loopback services", type: "boolean", required: false },
    ],
  },
  { id: "sandbox-build", label: "Build sandbox launcher", group: "Sandbox", mutating: true, confirmation: true, description: "Build the local sandbox launcher.", cli: "agentwall sandbox build", fields: [] },
  {
    id: "sandbox-run", label: "Run in sandbox", group: "Sandbox", mutating: true, confirmation: true,
    description: "Run a declared executable with the selected sandbox profile.", cli: "agentwall sandbox run -- <command>",
    fields: [
      { name: "command", label: "Declared executable", type: "text", required: true },
      { name: "args", label: "Arguments", type: "textarea", required: false, placeholder: "One argument per line" },
      { name: "workingDirectory", label: "Working directory", type: "path", required: false },
    ],
  },
  {
    id: "intercept-init", label: "Create interception CA", group: "Interception", mutating: true, confirmation: true,
    description: "Create the local interception certificate authority.", cli: "agentwall intercept init",
    fields: [
      { name: "caDir", label: "CA directory", type: "path", required: false },
      { name: "days", label: "Validity days", type: "number", required: false },
    ],
  },
  {
    id: "intercept-trust", label: "Plan CA trust", group: "Interception", mutating: true, confirmation: true,
    description: "Show the trust steps for the local certificate authority.", cli: "agentwall intercept trust",
    fields: [{ name: "caDir", label: "CA directory", type: "path", required: false }],
  },
  {
    id: "decoy-generate", label: "Generate decoy", group: "Decoys", mutating: true, confirmation: true,
    description: "Generate and store one decoy credential.", cli: "agentwall decoy generate --kind <kind>",
    fields: [
      { name: "kind", label: "Kind", type: "select", required: true, options: ["aws-access-key", "github-pat", "openai-key", "generic-secret", "url"] },
      { name: "label", label: "Label", type: "text", required: false },
      { name: "out", label: "Decoy file", type: "path", required: false, placeholder: ".agentwall/decoys.json" },
    ],
  },
  { id: "doctor", label: "Run doctor", group: "Status", mutating: false, confirmation: false, description: "Check the local AgentWall configuration and fleet state.", cli: "agentwall doctor", fields: [] },
  { id: "status", label: "Show status", group: "Status", mutating: false, confirmation: false, description: "Show the current runtime status.", cli: "agentwall status", fields: [] },
  { id: "verify", label: "Verify audit evidence", group: "Evidence", mutating: false, confirmation: false, description: "Check each audit integrity layer.", cli: "agentwall verify", fields: [] },
  { id: "fleet-list", label: "List fleet credentials", group: "Fleet", mutating: false, confirmation: false, description: "List credential identifiers and states without secrets.", cli: "agentwall fleet list", fields: [] },
  { id: "mcp-http-list", label: "List MCP HTTP wrappers", group: "MCP", mutating: false, confirmation: false, description: "Show managed MCP HTTP wrappers and their local endpoints.", cli: "agentwall mcp status", fields: [] },
  { id: "perimeter-plan", label: "Plan perimeter", group: "Perimeter", mutating: false, confirmation: false, description: "Show the host network perimeter plan.", cli: "agentwall perimeter plan", fields: [
    { name: "agentUid", label: "Agent UID", type: "number", required: false },
    { name: "proxyUid", label: "Proxy UID", type: "number", required: false },
    { name: "proxyPort", label: "Proxy port", type: "number", required: false },
    { name: "dnsResolver", label: "DNS resolver", type: "text", required: false },
    { name: "agentGid", label: "Agent GID", type: "number", required: false },
    { name: "allowLoopback", label: "Allow other loopback services", type: "boolean", required: false },
  ] },
  { id: "perimeter-status", label: "Show perimeter status", group: "Perimeter", mutating: false, confirmation: false, description: "Read the installed host network perimeter status.", cli: "agentwall perimeter status", fields: [
    { name: "agentUid", label: "Agent UID", type: "number", required: false },
    { name: "proxyUid", label: "Proxy UID", type: "number", required: false },
    { name: "proxyPort", label: "Proxy port", type: "number", required: false },
    { name: "dnsResolver", label: "DNS resolver", type: "text", required: false },
    { name: "agentGid", label: "Agent GID", type: "number", required: false },
    { name: "allowLoopback", label: "Allow other loopback services", type: "boolean", required: false },
  ] },
  { id: "perimeter-verify", label: "Verify perimeter", group: "Perimeter", mutating: false, confirmation: false, description: "Check the installed host network perimeter.", cli: "agentwall perimeter verify", fields: [
    { name: "agentUid", label: "Agent UID", type: "number", required: false },
    { name: "proxyUid", label: "Proxy UID", type: "number", required: false },
    { name: "proxyPort", label: "Proxy port", type: "number", required: false },
    { name: "dnsResolver", label: "DNS resolver", type: "text", required: false },
    { name: "agentGid", label: "Agent GID", type: "number", required: false },
    { name: "allowLoopback", label: "Allow other loopback services", type: "boolean", required: false },
  ] },
  { id: "sandbox-probe", label: "Probe sandbox", group: "Sandbox", mutating: false, confirmation: false, description: "Measure local kernel sandbox support.", cli: "agentwall sandbox probe", fields: [] },
  { id: "sandbox-plan", label: "Plan sandbox", group: "Sandbox", mutating: false, confirmation: false, description: "Show the sandbox profile and its limits.", cli: "agentwall sandbox plan", fields: [] },
  { id: "intercept-status", label: "Show interception status", group: "Interception", mutating: false, confirmation: false, description: "Read the local interception certificate status.", cli: "agentwall intercept status", fields: [] },
  { id: "decoy-list", label: "List decoys", group: "Decoys", mutating: false, confirmation: false, description: "List stored decoy identifiers without credential values.", cli: "agentwall decoy list --file <path>", fields: [{ name: "file", label: "Decoy file", type: "path", required: true }] },
  {
    id: "why", label: "Explain a decision", group: "Policy", mutating: false, confirmation: false,
    description: "Explain which checks match one subject.", cli: "agentwall why <subject>",
    fields: [
      { name: "subject", label: "Subject", type: "textarea", required: true },
      { name: "kind", label: "Subject kind", type: "select", required: false, options: ["url", "text", "tool"] },
      { name: "tool", label: "Tool name", type: "text", required: false },
      { name: "toolArgs", label: "Tool arguments as JSON", type: "textarea", required: false },
    ],
  },
  { id: "version", label: "Show version", group: "Status", mutating: false, confirmation: false, description: "Show the running AgentWall version.", cli: "agentwall version", fields: [] },
  { id: "help", label: "Show commands", group: "Status", mutating: false, confirmation: false, description: "Show the supported operator commands.", cli: "agentwall help", fields: [] },
];

export const mutatingOperatorActionSet: Readonly<Record<MutatingOperatorAction, true>> = {
  "approval-mode": true,
  shield: true,
  normal: true,
  "session-boost": true,
  "session-reset": true,
  pause: true,
  resume: true,
  terminate: true,
  "fleet-issue": true,
  "fleet-rotate": true,
  "fleet-revoke": true,
  anchor: true,
  "verify-capture": true,
  "mcp-wrap": true,
  "mcp-http-wrap": true,
  "mcp-http-stop": true,
  "perimeter-install": true,
  "perimeter-rollback": true,
  "perimeter-run": true,
  "sandbox-build": true,
  "sandbox-run": true,
  "intercept-init": true,
  "intercept-trust": true,
  "decoy-generate": true,
};
