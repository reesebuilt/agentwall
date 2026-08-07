# Integration and fleet plan

Status: plan, not shipped behaviour. Written 2026-08-06 against `integration/train-v2`
(fifteen branches, 1055 tests). Everything in "What exists" was verified in the tree.
Everything under "Proposed" is not built yet and must not be described as if it were.

Two problems, and they are different problems.

1. **One operator, several agents, one host.** Someone runs Claude Code, Codex, OpenClaw,
   Hermes-Agent and a Pi Agent on a workstation and wants them governed without a project
   rewrite.
2. **A business with a fleet.** Many agents, many hosts, people who need to answer an auditor
   and cannot answer with "we read the JSONL".

---

## The real problem in both cases

Configuration is not the hard part. **Proof of capture is the hard part.**

Every integration reduces to three questions, and only the third one is dangerous:

1. How does this agent reach the network?
2. How do I bind that traffic to an identity?
3. **Am I actually protected, or does it only look that way?**

Question 3 is where security tools die, and this repo has hard evidence for that claim from a
single day of work:

- `agentwall perimeter install` never installed a perimeter on any host. `spawnSync` handed
  `nft` a socket, `nft` stat'd `/dev/stdin`, refused the transaction, exited 1. The operator
  ran the documented command and `status` truthfully said "not installed".
- The bundled gitleaks config inherited no rules and reported a clean tree by scanning nothing.
- Content inspection ran on **zero** proxied traffic. The DLP engine, the injection scanner and
  the decoy tripwires all existed, all had tests, and never saw a proxied byte, because
  `EgressAttempt` structurally could not carry a body.

Three controls, all green, none working. So the integration story cannot be "here is the config".
It has to be **"here is the config, and here is the proof it took effect"**, or we ship the same
failure to every user who installs it.

---

## What exists today, verified

- **Capture.** Cooperative via proxy environment variables, or enforced via the nftables
  perimeter (Linux, root). Containment measured with 29 bypass probes and two independent
  oracles agreeing on all 29.
- **Identity, four tiers, strongest first:** `credential` (a secret presented on
  `Proxy-Authorization`), `uid+comm`, `uid`, `comm`, then `none`. Unbindable traffic is recorded
  as `unattributed` rather than given a plausible name.
- **Per-agent governance on one host:** host and port allowlists, request and byte budgets over
  a sliding window, all recorded in the chain.
- **MCP plane:** `agentwall mcp wrap` gates JSON-RPC over stdio, Streamable HTTP and SSE.
- **Content inspection:** plaintext HTTP request and response, 256 KiB cap, evadable by padding
  and documented as such. HTTPS bodies require opt-in interception.
- **Evidence:** SHA-256 hash chain, Ed25519 checkpoints, OpenTimestamps anchoring, four
  independent verifiers (TypeScript, Go, Rust, Python) agreeing on 27 conformance cases.
- **Sandbox:** Landlock ABI 4 filesystem and TCP port scoping, seccomp denylist.

### The fact that reshapes the fleet story

`docs/fleet.md` lists "identity that survives the host boundary" as the hard multi-host blocker,
and says uid and comm are local kernel facts. That is true of the weaker tiers and **not true of
the credential tier**. A credential is presented on the proxy connection. It works identically
whether the agent is on this host or another continent.

Multi-host identity is therefore mostly **solved already**. What is missing is policy
distribution and evidence aggregation, which are far smaller problems than issuing and revoking
identity.

---

## Part A: single-operator integration

### A1. Agent profiles

A profile encodes what is different about each runtime, so the operator does not rediscover it:

| Profile | Egress shape | Notes that bite |
|---|---|---|
| `claude-code` | Node `fetch`, plus MCP servers | MCP servers egress independently of the parent |
| `codex` | CLI, own HTTP stack | |
| `openclaw` | Node/Bun fork | |
| `hermes-agent` | Python | `REQUESTS_CA_BUNDLE` differs from `NODE_EXTRA_CA_CERTS` |
| `pi-agent` | Bun | Bun reads proxy vars but not always the same set as Node |
| `generic` | Ask, then probe | |

Each profile answers: which environment variables the runtime honours, where its CA trust store
is (needed for interception), what its MCP surface is, and which of its subprocesses egress on
their own.

**Do not guess these.** A profile that names the wrong variable produces an agent that looks
configured and is not, which is failure mode 3 again. Every profile must be verified against the
real runtime before it ships, and profiles we have not verified must say so.

### A2. `agentwall onboard <profile>`

One command that:

1. Generates a credential, stores its digest in config, prints the secret **once**.
2. Emits the exact environment or config the runtime needs.
3. Registers the agent with a starter allowlist and budget.
4. **Runs the capture proof and refuses to report success without it.**

### A3. The capture proof, the load-bearing feature

`agentwall verify-capture --agent <id>`

1. Bind a single-use canary listener on a port AgentWall is not proxying.
2. Have the agent fetch the canary URL.
3. Assert three things:
   - the request appears in the audit chain,
   - it is bound to the expected agent at the expected tier,
   - **the canary was not reached directly.**

The third assertion is the whole point. Traffic arriving at the canary without a matching chain
record is a **bypass**, and the command must fail loudly, name the escape, and refuse to call the
agent onboarded. A capture check that only looks for a chain record would pass while half the
agent's traffic went around the proxy.

Report the binding tier explicitly. An agent bound by `comm` alone is weakly bound, because comm
is self-declared by the process, and the operator should be told that in the same breath as
"onboarded".

### A4. Reduce the blast radius of getting it wrong

- `agentwall doctor` gains a **capture section**: for each declared agent, when it was last seen,
  at which binding tier, and whether any `unattributed` egress was recorded since.
  Rising `unattributed` traffic is the signal that an agent is escaping.
- Ship starter policies per profile that begin in `monitor`, because a firewall that breaks
  tooling on day one gets switched off.

---

## Part B: fleet and business deployment

### B1. Architecture: federate on evidence, do not build a control plane

A central control plane on the egress path is a single point of failure that converts a
management outage into an agent outage. Instead:

- **Each host keeps its own AgentWall, its own policy and its own chain.** Unchanged from today.
- **Policy is distributed as signed bundles, pulled on an interval.** A host that cannot reach
  the distribution point keeps enforcing the last good bundle. Pull, not push, so no inbound
  listener on agent hosts.
- **Evidence is aggregated read-only.** The aggregator verifies each host's chain independently.
  It is a reader, never an authority.
- **Stated failure semantics, non-negotiable:** if the aggregator or the bundle source is down,
  agents keep running governed. You lose visibility, not enforcement. Document this so nobody
  discovers it during an incident.

This preserves the property that makes AgentWall credible in the first place: evidence that is
independently verifiable per host, with no central thing to trust. Four independent verifiers are
worth much more in a fleet than on one laptop, because the aggregator's verdict can be
reproduced by an auditor who does not trust the aggregator.

### B2. Fleet identity

Credential identity already crosses hosts. What is needed around it:

- **Issuance and revocation.** Today a credential is a digest in a config file. A fleet needs to
  mint per-agent credentials, distribute them, and revoke one without editing config on every
  host.
- **Rotation without an egress outage.** Accept the previous credential during an overlap window.
- **Binding tier as a fleet-wide policy.** An organisation should be able to say "credential
  tier or refuse", so that no agent anywhere is governed by a self-declared process name.

### B3. What an auditor actually asks

These questions should be answerable from the aggregator, and each maps to evidence that already
exists:

- Which agents ran, on which hosts, in which window.
- What each was permitted to reach, and what it attempted and was refused.
- Was any credential material seen in flight, and was it redacted.
- Can this be verified without trusting your dashboard. **Yes, and here are four independent
  verifiers, one of which you can build from source.**
- What was NOT covered. HTTPS bodies without interception, anything past the 256 KiB cap, DNS to
  a named resolver, and the padding evasion. An audit answer that omits its own gaps is the
  overclaim pattern in a suit.

### B4. Deployment shapes to support, in order

1. **One host, several agents.** Works today.
2. **Several hosts, central evidence.** Needs the aggregator and bundle distribution.
3. **Containerised agents.** The perimeter is uid-based and nftables tables are per-netns, so a
   container needs its own approach. `docs/sandbox.md` already records why a network namespace
   fights the perimeter rather than composing with it. Do not paper over this: state that
   containers need the sidecar shape, and build that deliberately.
4. **Kubernetes.** Only after 3, and only if someone actually asks.

---

## Implementation order

Sequenced by what unblocks the most, not by what demos best.

**Phase 1, integration UX.** Agent profiles, `onboard`, and `verify-capture` including the
bypass assertion. Highest value per unit of work: it turns every later integration into a
verified one, and it is the difference between a tool people try and a tool people keep.

**Phase 2, fleet identity.** Credential issuance, rotation with an overlap window, revocation,
and a fleet-wide minimum binding tier.

**Phase 3, evidence aggregation.** Read-only multi-host viewer over independently verified
chains. Explicit and documented failure semantics.

**Phase 4, policy bundles.** Signed, pulled, last-good retained. Rollback faster than the mistake,
because a bad fleet-wide allowlist takes every agent offline at once.

**Phase 5, containers.** Sidecar shape, honestly scoped.

---

## What we will not build, and why

- **A control plane on the egress hot path.** Its outage becomes an egress outage. Rejected.
- **A distributed budget counter with strong consistency.** Coordination on the egress path for a
  rate limit is a bad trade. Per-instance sub-budgets, with the consistency model stated plainly.
- **Agent-specific forks or patches.** If a runtime needs patching to be governed, the profile
  says so and we support it as an external tool rather than pretending it is seamless.
- **A merged fleet-wide chain.** N hosts produce N independently anchored chains. Merging needs a
  total order across hosts, which is a distributed systems problem we do not need to solve.
  Aggregate the verdicts, keep the chains separate, and say so.

---

## The standing rule for everything above

Every feature here ships with the proof that it works, executed, not rendered. This project has
already shipped an nft ruleset that never loaded, a secret scanner that scanned nothing, and a
content inspector that inspected nothing. All three passed their checks. The integration story is
worth building only if it does not become the fourth.
