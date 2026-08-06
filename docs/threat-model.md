# Agentwall Threat Model

## Primary threats

### SSRF and unsafe egress

Agents should not have ambient outbound access. Agentwall now treats egress as deny-by-default and blocks:

- private and loopback targets
- link-local and cloud metadata endpoints
- non-allowlisted hosts
- non-HTTPS schemes by default
- URLs with embedded credentials

Those blocks apply to traffic Agentwall sees. By default that is traffic from a client that honours `HTTP_PROXY` / `HTTPS_PROXY`, so a process that ignores them is neither observed nor blocked — it never reaches the proxy at all. Capture is cooperative, and that is still the default posture behind every claim above.

It is no longer unavoidable. Running the agent as a dedicated unprivileged UID and redirecting that UID's outbound TCP with nftables makes capture a property of the kernel rather than of the client's configuration, and drops whatever it does not redirect. That is opt-in, needs root and Linux, and leaves holes of its own — DNS in particular. See [the perimeter](perimeter.md).

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
- the agent's client to honour proxy configuration, unless a perimeter is installed

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
