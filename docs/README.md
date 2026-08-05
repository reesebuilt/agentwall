# AgentWall documentation

Everything needed to install, understand, and operate AgentWall. If you are looking for
something that is not here, it probably belongs in the code or the issue tracker rather
than a narrative document.

## Getting started

- [Install](install.md) — requirements, install, first run, and how to point an agent at
  the proxy.
- [Tutorials](tutorials/) — short, task-shaped walkthroughs. Each states how long it
  takes and what you should see when it works.

## Understanding the system

- [Architecture](architecture.md) — the components, how a request flows through them, and
  where decisions are made.
- [Threat model](threat-model.md) — what AgentWall defends against, what it explicitly
  does not, and the assumptions behind both. Read this before relying on it for anything.
- [FloodGuard](runtime-floodguard.md) — runtime rate and burst control, including how
  shield mode changes behaviour.

## Elsewhere in the repository

- [README](../README.md) — what AgentWall is, its limits, and a quick start.
- [SECURITY](../SECURITY.md) — how to report a vulnerability.
- [CONTRIBUTING](../CONTRIBUTING.md) — how to propose a change.
- [CHANGELOG](../CHANGELOG.md) — what changed and when.

## What this tree is for

Documentation that helps someone run AgentWall on their own systems. Anything that only
describes how this project is planned, positioned, or built internally does not belong
here, because it is not useful to a reader who just wants the tool to work.
