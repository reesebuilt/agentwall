# AgentWall documentation

Everything needed to install, understand, and operate AgentWall. If you are looking for
something that is not here, it probably belongs in the code or the issue tracker rather
than a narrative document.

## Getting started

- [Install](install.md): requirements, install, first run, and how to point an agent at
  the proxy.
- [Tutorials](tutorials/): short, task-shaped walkthroughs. Each states how long it
  takes and what you should see when it works.
- [Onboarding an agent](onboarding.md): `agentwall onboard <profile>` mints an identity for one
  agent runtime, writes it into your config, prints the environment that runtime needs, and says
  plainly why configuration is not capture.

## Understanding the system

- [Architecture](architecture.md): the components, how a request flows through them, and
  where decisions are made.
- [Threat model](threat-model.md): what AgentWall defends against, what it explicitly
  does not, and the assumptions behind both. Read this before relying on it for anything.
- [Limits](limits.md): every documented limit in one table, from monitor-by-default to
  single-host scope. Load-bearing, not marketing hedges; read alongside the threat model.
- [Audit evidence format](audit-format.md): the normative on-disk spec. Record hashing,
  canonicalization, rotation manifest, checkpoints, and OpenTimestamps proofs, with worked
  examples and a statement of what the format does not prove.
- [Evidence viewer](evidence-viewer.md): the read-only console at `/evidence`, the per-session
  scorecard, the three verification layers shown inline, why a pending anchor is never rendered
  as verified, and the offline command the page prints so it is not the root of trust.
- [Fleet evidence](fleet-evidence.md): the read-only aggregator at `/evidence/fleet` over
  several hosts' chains, each verified independently on its own bytes; why the chains are not
  merged, what an unreachable host renders as and why that is not a clean one, and the coverage
  gaps shown as content rather than as a footnote.
- [FloodGuard](runtime-floodguard.md): runtime rate and burst control, including how
  shield mode changes behaviour.
- [Wrapping an MCP server](mcp.md): running a local MCP server behind the gates, what each gate
  checks, what the client sees when a call is blocked, and where those decisions land.
- [Emergency stop](lockdown.md): the four independent ways to put AgentWall into lockdown and
  halt the egress it decides, why releasing is per-source, and what the stop does not reach.
- [Decoy tokens](decoy.md): planting synthetic credentials that are never legitimately
  used, why a hit is proof rather than a guess, and the narrow band of theft it covers.
- [Probe API](probe-api.md): asking AgentWall for a verdict on content you already hold, the
  size and batch limits, and why a probe proves less than routing traffic through the proxy.
- [Spill watch](spill-watch.md): watching named directories for credentials
  written to disk, the platform caveat and its fallback, and what a finding deliberately
  omits.
- [Why a check fired](why.md): re-running the scanners against a subject to see which
  check fires, the narrowest knob that silences that one finding, and why a clean result is
  evidence rather than silence.
- [Proving capture](verify-capture.md): making an agent fetch a single-use canary to prove its
  traffic really passes through AgentWall, which binding tier actually held, and how a request
  that reached the network without passing through is caught and named.
- [Control mapping](owasp-mapping.md): which OWASP LLM, OWASP agentic, and ATT&CK controls
  this codebase addresses, the machine-checked evidence behind each rating, and the gaps
  stated rather than omitted.
- [Configuration score](compliance.md): grading a deployment description across fifteen
  categories, the critical exposures that force an F whatever the total, and why a
  configuration score is not a claim about a running system.
- [Egress enforcement](enforcement.md): the three enforcement modes, how to move from
  recording to blocking without breaking a working agent, what a blocked request looks like,
  and the traffic enforcement cannot reach.
- [The perimeter](perimeter.md): closing cooperative capture with a dedicated agent UID and
  nftables redirection, how a destination is named when there are no proxy headers to read,
  and the holes the model leaves open.
- [The sandbox](sandbox.md): confining the agent PROCESS with Landlock and seccomp rather than
  its packets, which kernel versions buy which rights, how to measure that the kernel really
  refused something, and why there is deliberately no network namespace.
- [Fleet governance](fleet.md): several agents on one host with their own identities,
  allowlists, and budgets, what each identity signal is actually worth, what stays global,
  and what multi-host would take that this does not do.
- [TLS interception](tls-interception.md): reading https request and response bodies for the
  hosts you choose, what installing a local CA costs your threat model, and everything that
  stays opaque anyway.
- [Detection benchmark](benchmark.md): re-measuring the detection numbers yourself, why
  precision and recall are never combined into one score, and what a corpus of 190 cases
  cannot tell you.
- [Verification](verification.md): running the four verifier implementations against a chain,
  the conformance corpus they are checked on, and what a passing verdict does not prove.
- [API and configuration](reference.md): the routes, environment variables, and configuration
  schema, worked end to end from a single policy decision outward.
- [Config and policy reload](reload.md): re-reading policy and config without a restart and
  without dropping a connection, validated before anything is applied and recorded on the chain.

## Elsewhere in the repository

- [README](../README.md): what AgentWall is, its limits, and a quick start.
- [SECURITY](../SECURITY.md): how to report a vulnerability.
- [CONTRIBUTING](../CONTRIBUTING.md): how to propose a change.
- [CHANGELOG](../CHANGELOG.md): what changed and when.

## What this tree is for

Documentation that helps someone run AgentWall on their own systems. Anything that only
describes how this project is planned, positioned, or built internally does not belong
here, because it is not useful to a reader who just wants the tool to work.
