# Control mapping

Which named risks AgentWall addresses, what backs each claim, and what each claim leaves
out. Three frameworks: the OWASP Top 10 for LLM Applications (2025), the OWASP Top 10 for
Agentic Applications (2026), and the MITRE ATT&CK techniques named by the detection catalog.

This page is a rendering of [`src/compliance/mapping.ts`](../src/compliance/mapping.ts).
Call `mappingsFor(framework)` for the machine-readable version. Where this page and that
function disagree, the function is right and this page is stale — `tests/compliance.test.ts`
checks the ATT&CK table below against it, so that should not happen quietly.

Read the [Limits](#limits) section before using any of this in a review. It is short and it
changes what the ratings mean.

## What the ratings mean

| Rating | Meaning |
| --- | --- |
| `strong` | An inline control ships enabled by default, it can **deny** the risk's primary action, and it addresses the risk category rather than one corner of it. Detector recall limits are still recorded under known limits. |
| `partial` | A control exists, but it observes only, or the operator must turn it on or configure it, or it addresses a named subset of the risk. |
| `none` | Nothing in this codebase addresses it. Listed rather than omitted, because a table with gaps silently missing reads as full coverage. |

**One caveat applies to every row and is not repeated in each one:** every rating is scoped
to flows AgentWall mediates — an MCP frame crossing the wrap, a request through the forward
proxy, a call to the evaluation API. An agent action that never reaches one of those
surfaces is not covered by anything below, whatever its rating says. The insertion surface,
not the rule set, is the real limit of this tool.

Every evidence identifier below is a real thing in this repository: a detection id from
[`src/policy/detections.ts`](../src/policy/detections.ts), a rule id from
[`src/policy/rules.ts`](../src/policy/rules.ts), an injection pattern id from
[`src/policy/injection.ts`](../src/policy/injection.ts), or a module path.
`tests/compliance.test.ts` resolves all of them against the source, so a citation cannot
survive the thing it cites being renamed or deleted.

## OWASP Top 10 for LLM Applications (2025)

3 strong, 4 partial, 3 none.

| Control | Coverage |
| --- | --- |
| LLM01 Prompt Injection | `partial` |
| LLM02 Sensitive Information Disclosure | `strong` |
| LLM03 Supply Chain Vulnerabilities | `partial` |
| LLM04 Data and Model Poisoning | `none` |
| LLM05 Improper Output Handling | `partial` |
| LLM06 Excessive Agency | `strong` |
| LLM07 System Prompt Leakage | `partial` |
| LLM08 Vector and Embedding Weaknesses | `none` |
| LLM09 Misinformation | `none` |
| LLM10 Unbounded Consumption | `strong` |

### LLM01 Prompt Injection — `partial`

Evidence: `src/policy/injection.ts`, `src/mcp/gates.ts`,
`inj.instruction_override.ignore_previous`, `inj.tool_coercion.run_shell_command`,
`det.mcp.input.injection`, `det.mcp.response.injection`, `det.mcp.tool.poisoned`,
`mcp:deny-input-injection`, `mcp:deny-response-injection`, `mcp:deny-tool-poisoning`,
`content:approve-untrusted-derived-egress`.

Known limits: detection is deterministic pattern matching over normalized text, so
paraphrase defeats it — an instruction override written in words no pattern anticipates
scans clean. It raises the cost of the copy-pasted attack and produces an explainable audit
record; it is not a proof of absence. Nothing here inspects the model's reasoning, so an
injection that survives the scan is uncontested from that point on.

This is deliberately not rated `strong`. Prompt injection is the risk this project talks
about most, and rating the hardest open problem in the field as strongly covered on the
strength of a pattern table would be the exact failure this page exists to avoid.

### LLM02 Sensitive Information Disclosure — `strong`

Evidence: `src/planes/identity/dlp.ts`, `src/canary/index.ts`,
`src/sentinel/filesystem.ts`, `det.content.secret.exfil`, `det.mcp.input.secret`,
`det.mcp.response.secret`, `det.net.metadata.access`, `det.identity.canary.triggered`,
`det.content.fs.secret_written`, `content:block-secret-exfil`, `content:redact-pii`,
`mcp:redact-input-secret`, `mcp:redact-response-secret`,
`channel:deny-sensitive-content-egress`, `channel:redact-pii-content-egress`,
`net:block-metadata-endpoint`, `identity:deny-canary-triggered`,
`content:deny-fs-secret-write`.

Known limits: the scanner is a pattern table, so a secret in a format it does not know — an
internal token scheme, a bare high-entropy string — passes. Canary values close part of
that hole by being synthetic and therefore unmistakable, but only for credentials someone
planted on purpose. The harder limit is what the scanner is handed: https bodies through the
forward proxy are opaque because that proxy does not terminate TLS, so egress of a secret
over https is visible as a destination and a byte count, not as content.

### LLM03 Supply Chain Vulnerabilities — `partial`

Evidence: `src/integrity/manifest.ts`, `src/mcp/gates.ts`, `det.tool.manifest.drift`,
`det.mcp.tool.poisoned`, `det.mcp.tool.drift`, `tool:approve-manifest-drift`,
`mcp:deny-tool-poisoning`, `mcp:approve-tool-drift`.

Known limits: covers one layer of the supply chain, the tool and MCP-server surface an agent
talks to at runtime, where a changed manifest or a poisoned tool description is caught by
hash comparison and inspection. Model weights, training data, base images, and package
provenance are upstream of anything a runtime boundary can observe, and this codebase makes
no claim about them.

### LLM04 Data and Model Poisoning — `none`

Nothing here touches training data, fine-tuning pipelines, or model artefacts. AgentWall
sits at runtime between a running agent and the things it acts on, which is the wrong side
of the lifecycle for this risk entirely. Poisoning that arrives in-context through tool
output is a different risk and is mapped at LLM01 and ASI06.

### LLM05 Improper Output Handling — `partial`

Evidence: `src/integrations/damage-control/command-firewall.ts`, `src/mcp/gates.ts`,
`det.mcp.response.injection`, `det.mcp.response.secret`, `mcp:deny-response-injection`,
`mcp:redact-response-secret`, `tool:require-approval-shell`.

Known limits: two consumers of model output are inspected — shell command strings submitted
to the command firewall, and MCP frames crossing the wrap. Every other downstream sink is
out of reach: model output rendered into HTML, interpolated into SQL, or written to a
template in the host application never crosses an AgentWall boundary, so nothing here can
encode or escape it.

### LLM06 Excessive Agency — `strong`

Evidence: `src/policy/engine.ts`, `src/approval/gate.ts`, `src/planes/network/ssrf.ts`,
`src/proxy/forward-proxy.ts`, `src/runtime/enforcement.ts`,
`det.identity.credential.access`, `det.browser.oauth.approval`, `det.net.ssrf.private`,
`det.net.egress.blocked`, `control:deny-external-actions-answer-only`,
`control:deny-mutations-read-only`, `tool:require-approval-shell`,
`tool:require-approval-file-delete`, `identity:flag-credential-access`,
`browser:require-approval-oauth`, `browser:block-form-submit-payment`,
`net:block-ssrf-private`, `net:deny-egress-not-allowlisted`,
`channel:deny-filesystem-mutation`, `channel:deny-sensitive-data-access`.

Known limits: this is the risk the whole design is shaped around, and the limit is
structural rather than partial — the controls are complete over the actions that reach them
and absent over the actions that do not. An agent with a tool that calls a cloud API
directly, in-process, over https is exercising exactly the excessive agency described here,
and AgentWall sees a destination host at best.

### LLM07 System Prompt Leakage — `partial`

Evidence: `src/policy/injection.ts`, `inj.exfiltration_directive.reveal_system_prompt`,
`inj.exfiltration_directive.reveal_instructions`,
`inj.exfiltration_directive.share_conversation`, `det.mcp.response.injection`,
`mcp:deny-response-injection`.

Known limits: catches the request, not the disclosure. Patterns fire on text asking an agent
to reveal its instructions, which is the common shape of this attack arriving through tool
output. AgentWall is never told what the system prompt contains, so it cannot recognise that
prompt on the way out; a leak phrased as ordinary prose in a response is indistinguishable
from any other response.

### LLM08 Vector and Embedding Weaknesses — `none`

There is no vector store, no embedding model, and no retrieval component in this codebase,
so there is nothing here to attack in the way this control describes and nothing here that
inspects a retrieval layer belonging to someone else.

### LLM09 Misinformation — `none`

AgentWall makes no assessment of whether anything an agent says is true. It decides whether
actions are permitted. Those are unrelated questions, and conflating them would be the least
defensible claim on this page.

### LLM10 Unbounded Consumption — `strong`

Evidence: `src/runtime/floodguard.ts`, `src/watchdog/heartbeat.ts`,
`src/runtime/kill-switch.ts`, `governance:deny-watchdog-timeout`.

Known limits: the budget is denominated in AgentWall's own weighted cost units and request
counts, not in provider tokens or currency, because AgentWall never sees a billing signal.
It bounds how fast an agent can act through this boundary, which correlates with spend but
does not measure it. An agent burning tokens in a loop that makes no gated call is not
throttled by anything here.

## OWASP Top 10 for Agentic Applications (2026)

1 strong, 9 partial, 0 none.

Nine of ten `partial` is the honest shape of this codebase rather than false modesty. The
agentic taxonomy is largely about properties of the agent's own internals — its plan, its
memory, its identity, its peers — and a boundary that mediates actions gets a real but
incomplete grip on each of them. The one `strong` entry is the risk this design is actually
built for: an agent invoking a tool it should not, in a way it should not.

| Control | Coverage |
| --- | --- |
| ASI01 Agent Goal Hijack | `partial` |
| ASI02 Tool Misuse and Exploitation | `strong` |
| ASI03 Identity and Privilege Abuse | `partial` |
| ASI04 Agentic Supply Chain Vulnerabilities | `partial` |
| ASI05 Unexpected Code Execution (RCE) | `partial` |
| ASI06 Memory and Context Poisoning | `partial` |
| ASI07 Insecure Inter-Agent Communication | `partial` |
| ASI08 Cascading Failures | `partial` |
| ASI09 Human-Agent Trust Exploitation | `partial` |
| ASI10 Rogue Agents | `partial` |

### ASI01 Agent Goal Hijack — `partial`

Evidence: `src/policy/injection.ts`, `src/mcp/gates.ts`, `det.mcp.response.injection`,
`det.mcp.tool.poisoned`, `mcp:deny-response-injection`, `mcp:deny-tool-poisoning`,
`net:approve-untrusted-egress`, `content:approve-untrusted-derived-egress`.

Known limits: AgentWall sees actions, never goals. It has no representation of what the
agent was asked to do, so it cannot compare the current plan against the original one. What
it can do is catch the injected text that commonly performs the hijack, and require approval
when untrusted provenance is what is driving egress. A hijack expressed entirely through
individually-permitted actions is invisible to it.

### ASI02 Tool Misuse and Exploitation — `strong`

Evidence: `src/policy/engine.ts`, `src/mcp/gates.ts`,
`src/integrations/damage-control/command-firewall.ts`, `src/planes/network/ssrf.ts`,
`src/runtime/enforcement.ts`, `det.mcp.tool.poisoned`, `det.mcp.input.injection`,
`det.mcp.input.secret`, `det.net.ssrf.private`, `det.net.egress.blocked`,
`mcp:deny-tool-poisoning`, `mcp:deny-input-injection`, `mcp:redact-input-secret`,
`tool:require-approval-shell`, `tool:require-approval-file-delete`,
`tool:flag-write-operations`, `net:block-ssrf-private`, `net:block-metadata-endpoint`,
`net:deny-egress-not-allowlisted`.

Known limits: the engine reasons about action strings and payload shapes, not tool
semantics. It does not know what a given tool does, so a destructive operation named in a
way no rule fragment matches — a tool called `sync` that deletes — is evaluated as an
ordinary call. Coverage here is a function of how well the operator's rules describe their
own tools, which is why the built-in set is a floor and not a finished policy.

### ASI03 Identity and Privilege Abuse — `partial`

Evidence: `src/auth/operator.ts`, `src/canary/index.ts`, `det.identity.credential.access`,
`det.net.metadata.access`, `det.browser.oauth.approval`, `det.identity.canary.triggered`,
`det.content.fs.secret_written`, `identity:flag-credential-access`,
`browser:require-approval-oauth`, `net:block-metadata-endpoint`,
`channel:deny-sensitive-data-access`, `identity:deny-canary-triggered`,
`content:deny-fs-secret-write`.

Known limits: credential acquisition is gated — reads of secret stores need approval, cloud
metadata is blocked outright, and OAuth grants stop for a human. Identity itself is thin.
Operator authentication is a single shared bearer token with no roles and no scopes, agents
are identified by a self-asserted id in the request, and there is no delegation chain, so
AgentWall cannot tell you on whose authority an action was taken.

### ASI04 Agentic Supply Chain Vulnerabilities — `partial`

Evidence: `src/integrity/manifest.ts`, `src/mcp/gates.ts`, `det.tool.manifest.drift`,
`det.mcp.tool.drift`, `det.mcp.tool.poisoned`, `tool:approve-manifest-drift`,
`mcp:approve-tool-drift`, `mcp:deny-tool-poisoning`.

Known limits: detects change, not badness. A manifest is hashed and compared against what
the operator approved, so a server that silently grows a new tool trips re-approval, and a
tool description carrying instructions to the model is denied. Nothing verifies who
published the server, checks a signature, or evaluates a registry's trustworthiness, so a
component that was malicious on the day it was first approved stays approved.

### ASI05 Unexpected Code Execution (RCE) — `partial`

Evidence: `src/integrations/damage-control/command-firewall.ts`,
`src/integrations/agent-harness/preflight.ts`, `inj.tool_coercion.run_shell_command`,
`inj.tool_coercion.curl_pipe_shell`, `inj.tool_coercion.destructive_command`,
`tool:require-approval-shell`, `control:deny-mutations-read-only`,
`control:deny-external-actions-answer-only`, `channel:deny-filesystem-mutation`.

Known limits: the command firewall analyses command strings a harness submits to it, with a
whitelist default and a five-level ladder the operator chooses from. That makes it a review
step, not a sandbox: it depends on the harness asking before executing, and a process that
spawns a shell without asking is unaffected. Real containment of code execution belongs to
the operating system, and this codebase does not provide it.

### ASI06 Memory and Context Poisoning — `partial`

Evidence: `src/policy/injection.ts`, `src/mcp/gates.ts`,
`inj.state_poisoning.write_to_memory`, `inj.state_poisoning.all_future_responses`,
`inj.state_poisoning.remember_for_later`, `det.mcp.response.injection`,
`mcp:deny-response-injection`, `content:approve-untrusted-derived-egress`.

Known limits: inspection happens on the way in, once. Tool output carrying text that tries
to install a durable instruction is denied before the agent reads it, and provenance labels
mark what came from an untrusted source. AgentWall holds no memory of its own and cannot
read the agent's, so anything already written to a memory or conversation store is beyond
reach — there is no retroactive revocation of a poisoned entry.

### ASI07 Insecure Inter-Agent Communication — `partial`

Evidence: `src/mcp/framing.ts`, `src/mcp/gates.ts`, `src/org/federation.ts`,
`det.mcp.input.injection`, `det.mcp.response.injection`, `mcp:deny-input-injection`,
`mcp:deny-response-injection`.

Known limits: one hop is mediated properly. The agent-to-MCP-server channel is parsed frame
by frame, gated in both directions, and audited, and federated peer summaries are
schema-validated before they are merged. Agent-to-agent protocols are not covered — there
is no inspection of a message bus, a task-delegation protocol, or a peer agent's requests,
and transport authenticity is left to the transport.

### ASI08 Cascading Failures — `partial`

Evidence: `src/runtime/floodguard.ts`, `src/watchdog/heartbeat.ts`,
`src/runtime/kill-switch.ts`, `det.governance.killswitch.active`,
`governance:deny-watchdog-timeout`, `governance:kill-switch`, `governance:log-all`.

Known limits: blast radius is bounded locally — per-session rate and cost caps, a ceiling on
pending approvals, shield mode to tighten every limit at once, a watchdog that stops
governance changes when it fires, and a kill switch that refuses everything at once. None of
that constitutes an understanding of the system a failure is cascading through. AgentWall
has no dependency graph, no circuit breaker between agents, and no view of an agent whose
calls do not pass through it, so it can stop its own agents and cannot stop a failure
travelling between someone else's.

### ASI09 Human-Agent Trust Exploitation — `partial`

Evidence: `src/approval/gate.ts`, `src/runtime/floodguard.ts`, `det.browser.oauth.approval`,
`browser:require-approval-oauth`, `browser:block-form-submit-payment`,
`channel:deny-filesystem-mutation`, `channel:deny-sensitive-data-access`,
`channel:deny-sensitive-content-egress`, `channel:redact-pii-content-egress`.

Known limits: structural defences exist where the human is being used as a lever — payment
submission is blocked rather than queued, requests arriving from a chat channel cannot mutate
the filesystem or read secrets whatever the requester claims, and approval volume is
rate-limited so an operator cannot be flooded into clicking. The residual risk is unaddressed
and unaddressable here: an operator who approves without reading defeats every one of these,
and AgentWall records that a decision was made, not that it was understood.

### ASI10 Rogue Agents — `partial`

Evidence: `src/watchdog/heartbeat.ts`, `src/runtime/kill-switch.ts`, `src/audit/logger.ts`,
`src/audit/chain.ts`, `src/proxy/forward-proxy.ts`, `det.governance.killswitch.active`,
`det.net.egress.blocked`, `governance:deny-watchdog-timeout`, `governance:kill-switch`,
`governance:log-all`, `control:deny-external-actions-answer-only`,
`net:deny-egress-not-allowlisted`.

Known limits: an agent that stops heart-beating, trips rules, or reaches an unlisted
destination is detectable, the audit chain makes the sequence reconstructible afterwards
because records cannot be edited without breaking the hash links, and the kill switch
refuses every action that reaches it. That is containment of the agent's *actions*, not of
the agent: AgentWall cannot terminate a process, revoke a credential it did not issue, or
see an agent that was never pointed at it. An operator holding the emergency stop still
needs the operating system and the identity provider to finish the job.

## MITRE ATT&CK

7 strong, 5 partial, 12 techniques.

This view is **computed**, not written down. It is derived from the `mitreAttack` field on
every entry in [`src/policy/detections.ts`](../src/policy/detections.ts), so a detection
added to the catalog appears here without anyone editing a document, and a technique cannot
appear here unless a detection names it.

The coverage rating is derived too, from the **decision of each backing rule**, because that
is the only defensible source for "do we block this or merely notice it". The derivation
takes the *weakest* decision behind a technique, not the strongest: `T1195` is mapped by one
detection whose rule denies and one whose rule routes to approval, and taking the strongest
would advertise the technique as blocked when half of it is a prompt an operator can click
through. Downgrading is the only direction that cannot mislead.

| Technique | Name | Coverage | Backing rules |
| --- | --- | --- | --- |
| `T1190` | Exploit Public-Facing Application | `strong` | `net:block-ssrf-private` (deny) |
| `T1552.005` | Cloud Instance Metadata API | `strong` | `net:block-metadata-endpoint` (deny) |
| `T1041` | Exfiltration Over C2 Channel | `strong` | `content:block-secret-exfil` (deny) |
| `T1555` | Credentials from Password Stores | `partial` | `identity:flag-credential-access` (approve) |
| `T1098.001` | Additional Cloud Credentials | `partial` | `browser:require-approval-oauth` (approve) |
| `T1562` | Impair Defenses | `partial` | `tool:approve-manifest-drift` (approve) |
| `T1195` | Supply Chain Compromise | `partial` | `mcp:deny-tool-poisoning` (deny), `mcp:approve-tool-drift` (approve) |
| `T1552` | Unsecured Credentials | `partial` | `mcp:redact-input-secret` (redact), `mcp:redact-response-secret` (redact), `identity:deny-canary-triggered` (deny) |
| `T1059` | Command and Scripting Interpreter | `strong` | `mcp:deny-input-injection` (deny), `mcp:deny-response-injection` (deny) |
| `T1071` | Application Layer Protocol | `strong` | `net:deny-egress-not-allowlisted` (deny) |
| `T1489` | Service Stop | `strong` | `governance:kill-switch` (deny) |
| `T1552.001` | Credentials In Files | `strong` | `content:deny-fs-secret-write` (deny) |

Two things this table does not mean. **Absence is not "not applicable":** a technique missing
from this list means no detection in this codebase names it, and ATT&CK has hundreds. And the
technique chosen for each detection is the catalog author's judgement about which ATT&CK entry
best describes the behaviour, not an independent classification — read the detection's own
description before relying on the mapping.

## Drift in the other direction

`unmappedDetections()` returns every detection in the catalog that no hand-authored OWASP row
above cites. It is the check for the failure that happens quietly: someone adds a detection
for a new class of attack, nobody revisits these tables, and the tool grows a capability its
own mapping denies having. A non-empty result means this page is behind the code.

## Limits

- **A mapping is a claim about which controls exist, not evidence that they work.** Every
  rating on this page describes code that is present in the repository. It says nothing
  about whether that code is enabled in your deployment, configured correctly, or effective
  against an adversary who has read it. For the configuration question, which is a different
  question, see [Configuration score](compliance.md).
- **These ratings are this project's own assessment of its own code.** They are not an audit,
  not a certification, not independent, and not endorsed by OWASP or MITRE. The evidence
  citations are machine-checked; the judgement calls behind `strong` versus `partial` are
  ours, and a reviewer who disagrees with one is not wrong.
- **Coverage of a control is not protection from the risk.** A `strong` rating means an
  inline control can deny the action. It does not mean the control catches every variant:
  the detectors are deterministic pattern tables and their recall limits are stated in each
  entry, not hidden in this footer.
- **The scope caveat is the big one.** Everything above is scoped to flows AgentWall
  mediates. Coverage of an action AgentWall never sees is zero regardless of what any row
  says, so the honest first question about any of these ratings is not "how good is the
  rule" but "does the action reach the boundary at all".
- **Framework versions move.** This page maps the 2025 LLM list and the 2026 agentic list.
  A later revision of either will renumber and re-scope controls, and nothing here updates
  itself when that happens.
