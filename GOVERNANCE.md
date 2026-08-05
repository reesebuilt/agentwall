# Governance

AgentWall is open source under Apache-2.0. This document says who decides what, so
contributors know where they stand before they invest time.

## Current state, stated plainly

AgentWall has a single maintainer. Calling that a "governance model" would be
overselling it. This document describes how decisions are made today and the conditions
under which that changes, rather than describing a committee that does not exist.

## Roles

**Maintainer.** Final call on scope, architecture, releases, and security response.
Merges changes and sets project direction.

**Contributor.** Anyone who opens an issue or pull request. No paperwork beyond the DCO
sign-off described in CONTRIBUTING.md.

## How decisions are made

Small changes (bug fixes, tests, docs) are decided in the pull request.

Changes to the security model, the policy decision path, the audit chain format, or
anything that alters what a deployed instance enforces get an issue first. Explain the
threat being addressed and how the change would be verified. A security control that
cannot be demonstrated is not a control.

Breaking changes to the config schema, the audit event or capability-ticket format, or
the HTTP API are called out in CHANGELOG.md with a migration note.

## Security issues

Do not open a public issue for a vulnerability. SECURITY.md has the reporting path.

Reports that demonstrate a bypass are the most valuable contribution to this project, and
they are treated that way: a working bypass is credited in the changelog unless the
reporter asks otherwise.

## The standard for claims

Every capability claim in the README or docs must be demonstrable by a command a stranger
can run on their own machine. If a feature cannot be shown working, it is not documented
as present.

This applies to security properties above all. Stating what a control does NOT cover is
part of documenting it, not an admission against interest.

## Adding maintainers

There is no fixed threshold. Sustained, high-quality contribution and demonstrated
judgment on security tradeoffs is the bar. When a second maintainer is added, this
document changes first, and the licensing and contribution terms are revisited with them
rather than around them.

## Licensing

Apache-2.0, chosen over MIT for its express patent grant, which enterprise adoption
commonly requires. Relicensing after outside contributions exist requires the agreement
of every contributor whose work remains in the tree, so the license is treated as fixed
absent an extraordinary reason.
