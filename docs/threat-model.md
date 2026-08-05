# Agentwall Threat Model

## Primary threats

### SSRF and unsafe egress

Agents should not have ambient outbound access. Agentwall now treats egress as deny-by-default and blocks:

- private and loopback targets
- link-local and cloud metadata endpoints
- non-allowlisted hosts
- non-HTTPS schemes by default
- URLs with embedded credentials

### Prompt injection from external content

Web pages, emails, tool output, and retrieved memory can contain adversarial instructions. Agentwall models that content explicitly with provenance and trust labels, then escalates when untrusted or derived content drives egress or sensitive actions.

### Secret and PII exfiltration

Content inspection detects common secrets and PII. Policy can deny secret-bearing egress and redact PII on risky flows.

### Tool and MCP manifest drift

A changed manifest can silently expand an agent's authority. Agentwall adds manifest fingerprinting and drift detection so changed tools require re-approval.

### Agent liveness failure

If the controller cannot establish that an agent is still healthy, high-risk autonomy should stop. The watchdog design introduces a heartbeat-driven kill-switch model for that case.

## Trust assumptions

Agentwall trusts:

- protected local configuration
- explicit allowlists and approved manifest fingerprints
- human approvals

Agentwall does not trust:

- user input
- web content
- email content
- tool output
- tool metadata from unapproved or drifted manifests
- any outbound target that is not explicitly allowlisted

## Out of scope

- model-internal prompt defenses
- data already present in model context
- post-approval operator mistakes
- full distributed watchdog orchestration
