# AgentWall documentation

Everything needed to install, understand, and operate AgentWall. If you are looking for
something that is not here, it probably belongs in the code or the issue tracker rather
than a narrative document.

## Getting started

- [Install](install.md): requirements, install, first run, and how to point an agent at
  the proxy.
- [Tutorials](tutorials/): short, task-shaped walkthroughs. Each states how long it
  takes and what you should see when it works.

## Understanding the system

- [Architecture](architecture.md): the components, how a request flows through them, and
  where decisions are made.
- [Threat model](threat-model.md): what AgentWall defends against, what it explicitly
  does not, and the assumptions behind both. Read this before relying on it for anything.
- [Audit evidence format](audit-format.md): the normative on-disk spec. Record hashing,
  canonicalization, rotation manifest, checkpoints, and OpenTimestamps proofs, with worked
  examples and a statement of what the format does not prove.
- [FloodGuard](runtime-floodguard.md): runtime rate and burst control, including how
  shield mode changes behaviour.
- [Wrapping an MCP server](mcp.md): running a local MCP server behind the gates, what each gate
  checks, what the client sees when a call is blocked, and where those decisions land.
- [Emergency stop](kill-switch.md): the four independent ways to halt AgentWall-decided
  egress, why releasing is per-source, and what the stop does not reach.
- [Canary tokens](canary.md): planting synthetic credentials that are never legitimately
  used, why a hit is proof rather than a guess, and the narrow band of theft it covers.
- [Scan API](scan-api.md): asking AgentWall for a verdict on content you already hold, the
  size and batch limits, and why a scan proves less than routing traffic through the proxy.
- [Filesystem sentinel](filesystem-sentinel.md): watching named directories for credentials
  written to disk, the platform caveat and its fallback, and what a finding deliberately
  omits.
- [Explaining a decision](explain.md): re-running the scanners against a subject to see which
  check fires, the narrowest knob that silences that one finding, and why a clean result is
  evidence rather than silence.
- [Control mapping](owasp-mapping.md): which OWASP LLM, OWASP agentic, and ATT&CK controls
  this codebase addresses, the machine-checked evidence behind each rating, and the gaps
  stated rather than omitted.
- [Configuration score](compliance.md): grading a deployment description across fifteen
  categories, the critical exposures that force an F whatever the total, and why a
  configuration score is not a claim about a running system.
- [Egress enforcement](enforcement.md): the three enforcement modes, how to move from
  recording to blocking without breaking a working agent, what a blocked request looks like,
  and the traffic enforcement cannot reach.
- [Detection benchmark](benchmark.md): re-measuring the detection numbers yourself, why
  precision and recall are never combined into one score, and what a corpus of 190 cases
  cannot tell you.

## Elsewhere in the repository

- [README](../README.md): what AgentWall is, its limits, and a quick start.
- [SECURITY](../SECURITY.md): how to report a vulnerability.
- [CONTRIBUTING](../CONTRIBUTING.md): how to propose a change.
- [CHANGELOG](../CHANGELOG.md): what changed and when.

## What this tree is for

Documentation that helps someone run AgentWall on their own systems. Anything that only
describes how this project is planned, positioned, or built internally does not belong
here, because it is not useful to a reader who just wants the tool to work.
