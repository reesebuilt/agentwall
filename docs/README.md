# AgentWall documentation

Start with the [user guide](user-guide.md).
It uses `agentwall ui` as the first-run path.

## Start and operate

- [User guide](user-guide.md) covers install, setup, modes, approvals, verification, and common fixes.
- [Operator guide](operator-guide.md) maps every CLI action to a bootstrap or running UI workflow.
- [Feature reference](feature-reference.md) lists each capability and its limit.
- [Glossary](glossary.md) defines the public terms.
- [Install guide](install.md) covers package, source, container, and platform installation.
- [Onboarding guide](onboarding.md) creates one agent identity and proves capture.
- [Tutorials](tutorials/) give short procedures for common tasks.

## Control traffic and processes

- [Enforcement](enforcement.md) explains monitor, guarded, and strict modes.
- [Perimeter](perimeter.md) explains Linux UID network control and its DNS limit.
- [Sandbox](sandbox.md) explains Landlock, seccomp, kernel requirements, and degraded operation.
- [TLS interception](tls-interception.md) explains optional HTTPS inspection and CA risk.
- [MCP wrapper](mcp.md) explains stdio, Streamable HTTP, gates, and inventory checks.
- [Emergency stop](lockdown.md) explains each stop source and its scope.
- [FloodGuard](runtime-floodguard.md) explains runtime rate and burst controls.
- [Fleet governance](fleet.md) explains per-agent identity, credentials, allowlists, and budgets.

## Understand decisions

- [Architecture](architecture.md) shows request, decision, audit, and operator control paths.
- [Threat model](threat-model.md) states the protected paths, assumptions, and gaps.
- [Policy reference](reference.md) lists routes, settings, and environment variables.
- [Why a check fired](why.md) explains a decision for a supplied subject.
- [Probe API](probe-api.md) checks content that the caller already holds.
- [Configuration score](compliance.md) grades a deployment description and states its limits.
- [Control mapping](owasp-mapping.md) maps implemented controls to named risk frameworks.
- [Detection benchmark](benchmark.md) reports measured detector precision, recall, and known gaps.
- [Decoy credentials](decoy.md) explains synthetic secrets and their visibility limits.
- [Spill watch](spill-watch.md) explains watched file paths and platform limits.

## Verify evidence

- [Audit format](audit-format.md) defines record hashing, segment links, checkpoints, and proofs.
- [Verification](verification.md) defines each verification layer and conformance case.
- [Evidence viewer](evidence-viewer.md) explains the read-only view at `/evidence`.
- [Fleet evidence](fleet-evidence.md) explains independent host-chain checks at `/evidence/fleet`.
- [Proving capture](verify-capture.md) checks one agent route with a single-use canary.

## Project documents

- [Repository README](../README.md) gives a short product decision page.
- [Security policy](../SECURITY.md) gives the private report process.
- [Contribution guide](../CONTRIBUTING.md) gives change and test requirements.
- [Governance](../GOVERNANCE.md) defines project roles and decisions.
- [Changelog](../CHANGELOG.md) records released changes.
- [Enterprise roadmap](enterprise-roadmap.md) is a roadmap and does not describe shipped behavior.
- [Enterprise controls](enterprise-controls.md) states shipped limits, planned upgrades, outage behavior, and evidence gates.