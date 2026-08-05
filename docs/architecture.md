# Agentwall Technical Architecture

## System shape
Agentwall is a stateless HTTP decision service with small local persistence for approvals.

Execution flow:
1. Caller sends `AgentContext` to `/evaluate`
2. Policy engine evaluates built-in + declarative runtime rules
3. Engine returns decision bundle (`decision`, `riskLevel`, `matchedRules`, `reasons`, `detections`)
4. Audit event emitted and runtime state updated
5. Optional approval loop gates execution

## Core modules
- `src/policy/*` — rule model, matching engine, runtime policy loader, detection catalog
- `src/planes/network/*` — SSRF/private-range/egress inspection
- `src/planes/identity/*` — content and DLP classification
- `src/approval/*` — approval queue, persistence, response handling
- `src/audit/*` — structured event emission
- `src/dashboard/*` + `src/routes/*` — operator state APIs

## Canonical data model
### AgentContext (input)
- identity: `agentId`, optional `sessionId`
- action: `plane`, `action`, `payload`
- causality: `provenance[]`, `flow`
- authority: `actor`, `control.executionMode`

### PolicyResult (decision output)
- `decision`: allow | deny | approve | redact
- `riskLevel`: low | medium | high | critical
- `matchedRules[]`, `reasons[]`
- `highRiskFlow`
- `detections[]` (security finding metadata, ATT&CK-mapped when useful)

### AuditEvent (forensics output)
- decision metadata + context snapshot + detection mapping references

## Decision precedence
- Highest-impact decision wins (deny > approve > redact > allow)
- Highest risk among matches sets `riskLevel`
- High-risk flow can elevate low risk results

## Detection mapping model
`src/policy/detections.ts` maps stable `ruleId` values to detection metadata:
- detection id/name/description/severity
- optional MITRE ATT&CK tactic + technique + technique ID

This keeps policy logic and analyst-facing context loosely coupled.

## Integration contract (caller side)
Callers are expected to:
- invoke `/evaluate` before executing high-risk actions
- enforce returned decisions (including approval workflows)
- attach provenance and flow context whenever available
- consume audit stream for observability and response workflows
