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

On the forward proxy, a plaintext HTTP response is scanned for injected instructions before any byte of it reaches the client, and a hit is refused with a 403. That covers the dominant real-world shape of this attack, where the answer to a tool call is the attack, and it covers it only on that scheme: an https response is never decrypted and never scanned, and an event-stream body is passed through uninspected because buffering one to scan it would hang it. Detection is a deterministic pattern table, so a clean scan means "no known pattern in the bytes we read", never "safe".

### Secret and PII exfiltration

Content inspection detects common secrets and PII. Policy can deny secret-bearing egress and redact PII on risky flows.

Read that with its scope attached. Inspection runs on content Agentwall is handed directly - the `/inspect/*` and `/evaluate` payloads, the MCP frames it wraps, channel messages, watched file writes - and on plaintext HTTP through the forward proxy, where the request path, headers, and body are scanned before anything is opened upstream and a credential in any of them is refused. It does not run on https through the proxy, because that body is encrypted, so a secret leaving inside a TLS session is visible as a destination, a negotiated SNI, and a byte count and never as content; the egress allowlist is what stands between it and the network. The plaintext scan is bounded at 256 KiB per body and the bound is evadable by padding, which makes it a control against accident and unsophisticated theft rather than against an adversary who is choosing their transport.

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
