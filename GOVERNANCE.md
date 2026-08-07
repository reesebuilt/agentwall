# Governance

AgentWall uses the Apache-2.0 license.
This document defines project roles and decisions.

## Current structure

AgentWall has one maintainer.
The maintainer makes final project decisions.

## Roles

### Maintainer

The maintainer:

- sets project scope and direction
- makes final architecture decisions
- manages releases
- manages security responses
- reviews and merges changes

### Contributor

A contributor opens an issue or pull request.
A contributor must use the DCO sign-off in [CONTRIBUTING.md](CONTRIBUTING.md).
The project requires no other contributor agreement.

## Decisions

The maintainer decides small changes in the pull request.
Small changes include defect fixes, tests, and documentation.

Open an issue before a change to any of these areas:

- the security model
- the policy decision path
- the audit chain format
- deployed enforcement behavior

The issue must state the threat and the verification method.
A security control must have a repeatable demonstration.

Document each incompatible change in `CHANGELOG.md`.
Add a migration note for changes to:

- the configuration schema
- the audit event format
- the capability-ticket format
- the HTTP API

## Security issues

Do not open a public issue for a vulnerability.
Use the private report channels in [SECURITY.md](SECURITY.md).

The changelog credits a demonstrated bypass unless the reporter declines credit.

## Public claims

Every capability claim must have a command that another person can run.
Do not document an unavailable feature as present.
State each limit beside the related capability.
State when traffic or an action can bypass AgentWall.

## Additional maintainers

The project has no fixed contribution threshold for a maintainer role.
A candidate must show sustained, high-quality contributions.
A candidate must also show sound judgment about security tradeoffs.

Update this document before the project adds a second maintainer.
Review the license and contribution terms with that maintainer.

## License

AgentWall uses Apache-2.0 for its express patent grant.
A license change requires agreement from every contributor whose work remains in the repository.
Treat the license as fixed unless an extraordinary reason requires a change.
