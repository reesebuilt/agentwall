# Enterprise controls

> This document separates current controls from planned enterprise controls. Planned controls do not describe shipped behavior.

The [enterprise roadmap](enterprise-roadmap.md) defines stage order, owner roles, failure behavior, and binary exit tests.

## Status definitions

- **Shipped:** The current repository implements the stated behavior.
- **Current limit:** The shipped behavior stops at the stated boundary.
- **Planned:** The required upgrade remains unavailable until its roadmap stage receives PASS.
- **Evidence:** The named result must exist for the planned control to receive PASS.

## Shipped control baseline

| Area | Current component | Shipped behavior | Current limit |
| --- | --- | --- | --- |
| Local policy | `src/runtime/reload.ts` and `src/routes/reload.ts` | AgentWall validates a local reload before it applies the policy. A rejected reload leaves the active policy in force. | Policy files have no distribution signature. No central service records host receipt or performs rollback. |
| Operator access | `src/auth/operator.ts` | A shared bearer token protects non-public operator routes. A development option can allow unauthenticated loopback access. | One token maps to one operator principal. AgentWall has no operator OIDC, mTLS, roles, or scopes. |
| Agent credentials | `src/fleet/credentials.ts` and `src/fleet/command.ts` | A local store can issue, rotate, and revoke agent credentials. Rotation has a bounded overlap. | The store has no built-in host distribution. A readable shared secret permits agent impersonation. |
| Local evidence | `src/audit/file-sink.ts`, `src/audit/rotation.ts`, and `src/audit/anchor-service.ts` | AgentWall can create a hash chain, seal rotated segments, sign checkpoints, and submit timestamp proofs. | The operator owns file custody, delivery, retention, backup, and trust-key pinning. |
| Fleet evidence | `src/evidence/fleet.ts` and `src/routes/fleet-evidence.ts` | A read-only view verifies host evidence files that the operator delivers to one location. | AgentWall has no managed receipt service, durable queue, retention rule, or fleet evidence SLO. |
| Release supply chain | `.github/workflows/release.yml` | The workflow creates checksums, an SBOM, SLSA provenance, reproducible verifier binaries, and a signed container image digest. | No single signed manifest covers every release asset. Some controls apply only to a specific release channel. |
| OIDC publication | `.github/workflows/release.yml` | The workflow uses OIDC for package publication, provenance, and keyless container image signing. | This identity protects the release process only. It does not authenticate an AgentWall operator or host. |
| Container build | `Dockerfile` and `.github/workflows/release.yml` | The workflow builds one Linux container image and records image provenance. | AgentWall has no supported sidecar contract, Kubernetes admission control, or tested Kubernetes rollback. |
| Service health | `src/routes/health.ts`, `src/routes/dashboard.ts`, and `src/telemetry/otel.ts` | AgentWall exposes local health data and optional telemetry. | The project states no managed service SLO, recovery objective, or enterprise support target. |
| Verification | `verifier`, `verifier-rs`, `verifier-py`, and the bundled verifier | Separate implementations use the same audit format and conformance corpus. | These implementations do not replace an independent external security or privacy review. |

## Planned enterprise control matrix

Every row below remains **Planned**. The current component column identifies the closest shipped component.

| Control | Current component | Current limit | Required enterprise upgrade | Required test evidence | Roadmap stage |
| --- | --- | --- | --- | --- | --- |
| Release signing | `.github/workflows/release.yml` | The workflow signs the container image digest. It creates signed provenance for release subjects. It does not sign one complete release manifest. | Sign one manifest that binds every release asset, checksum, SBOM, provenance record, source tag, and release identity. Publish the trust policy with the release. | A clean host accepts every unchanged asset. It rejects a changed asset, wrong source, wrong tag, or wrong release identity. | 1 |
| SBOM | `.github/workflows/release.yml` | The workflow creates one CycloneDX SBOM from production package data. Its coverage check detects a completely absent package name. | Create an applicable SBOM for each package and container layer. Bind each SBOM digest to the signed release manifest. | A release test matches each shipped component to an SBOM entry. It rejects an omitted component and a changed SBOM. | 1 |
| SLSA provenance | `.github/workflows/release.yml` | The workflow creates SLSA provenance for build subjects. Package and container channels also create provenance. | Require provenance for every release channel. Verify the source, tag, builder identity, parameters, and subject digest before publication. | A policy test accepts the approved build. It rejects a local build, wrong tag, wrong builder, or changed subject. | 1 |
| Reproducible verifier builds | `scripts/build-verifier.sh` and `.github/workflows/release.yml` | The release workflow rebuilds verifier binaries from a clean tree and compares checksums. | Run the clean rebuild on every supported release environment. Store the comparison result in the release evidence pack. | Two clean builds produce identical verifier digests for every supported target. One changed build input causes a mismatch. | 1 |
| OIDC operator identity | `src/auth/operator.ts` | The operator API uses one shared bearer token. Release OIDC does not protect this API. | Add OIDC login and API validation. Pin issuer and audience. Validate signatures, time claims, and required identity claims. | Route tests accept valid claims. They reject wrong issuer, wrong audience, expiry, missing claims, and identity service outage. | 4 |
| mTLS service identity | No shipped service identity component | TLS interception creates a local inspection authority. It does not provide mutual service authentication. | Require mTLS between hosts and enterprise services. Define trust roots, certificate profiles, expiry, renewal, revocation, and no-downgrade behavior. | Connection tests accept an approved certificate. They reject an expired, revoked, untrusted, or wrong-service certificate. | 4 |
| RBAC | `src/auth/operator.ts` | Every valid operator token receives the same principal and permissions. | Add viewer, operator, approver, auditor, and administrator roles. Apply least privilege to every route and action. | A route matrix proves every required allow and deny result. Audit records name the principal, role, action, and decision. | 4 |
| Separate approval | Current local approval routes and audit records | Current operator access does not establish separate enterprise identities or role separation. | Require a different authorized approver for declared high-impact actions. Bind approval to action parameters and expiry. | A high-impact action fails with no approval, self-approval, changed parameters, or expired approval. It passes with valid separate approval. | 4 |
| Agent credential authority | `src/fleet/credentials.ts` | One local file stores issued credential digests and lifecycle state. AgentWall does not distribute it. | Add one authenticated authority for issue, rotation, revocation, signed state, host delivery, and expiry. | Connected hosts reject a revoked credential within the stated target. An expired state rejects new credentials without restoring old credentials. | 2 |
| Trust-key rotation | Release OIDC, `src/fleet/credentials.ts`, and `src/audit/signing.ts` | Release OIDC avoids one long-lived publication key. Local credentials rotate. Local checkpoint keys have no coordinated enterprise lifecycle. | Define rotation and revocation for policy keys, service certificates, emergency credentials, and checkpoint trust keys. Use bounded overlap and custody records. | A forced rotation preserves valid access and verification. The prior key fails after overlap. The event appears in control evidence. | 1 and 6 |
| Signed policy distribution | `src/runtime/reload.ts` and `src/routes/reload.ts` | A host loads and validates local policy files. It does not verify a distribution signature. | Distribute signed, versioned policy bundles. Record requested, accepted, active, and last-good digests for every host. | Two hosts accept the approved bundle. Both reject a changed or unauthorized bundle and retain their prior active digest. | 2 |
| Policy rollback | `src/runtime/reload.ts` | A rejected reload leaves the current policy active. AgentWall has no durable signed rollback operation. | Retain approved last-good bundles. Add an authorized rollback to an exact signed digest. Record the reason and result. | A forced rollout fault stops distribution. A signed rollback restores the exact prior digest on every test host. | 2 |
| Fleet evidence | `src/evidence/fleet.ts` and `src/routes/fleet-evidence.ts` | The fleet view reads files from operator-managed paths. It does not receive evidence from hosts. | Add authenticated receipt, original-byte preservation, independent verification, host freshness, export, and explicit incomplete states. | Three hosts deliver evidence. A changed chain shows FAIL. A missing host shows INCOMPLETE. The service never reports either case as clean. | 3 |
| Container sidecar | `Dockerfile` | AgentWall can run in a container. The image does not define a supported sidecar control contract. | Define network path, storage, identity, health, resource, privilege, and failure requirements for a supported sidecar. | A workload uses the required sidecar path under normal load. A sidecar fault gives the declared safe behavior and a visible alert. | 5 |
| Kubernetes admission | No shipped admission component | A Kubernetes cluster can start a workload without AgentWall. | Add admission checks for protected namespaces and declared workloads. Verify image digests and the required AgentWall path. | A conforming workload starts. The same workload fails after removal of the required AgentWall path or approved image digest. | 5 |
| Deployment rollback | Release image digests and local policy reload | The repository has no tested Kubernetes upgrade or automatic deployment rollback. | Define supported upgrade order, schema compatibility, health gates, and rollback to prior image and policy digests. | A forced upgrade fault restores both prior digests. Active evidence records the fault, rollback decision, and restored state. | 5 |
| Evidence retention | Local audit files, segment manifests, checkpoint records, and fleet views | AgentWall does not enforce retention, legal hold, deletion, or managed storage durability. | Define retention by evidence class. Add immutable storage, legal hold, authorized expiry, deletion records, and export before deletion. | Time-based tests retain protected records, delete eligible records, preserve held records, and record every retention decision. | 3 |
| SLOs | `/health`, `/ready`, dashboard status, and optional telemetry | Health data has no enterprise objective, error budget, or service commitment. | Measure availability, policy delivery, revocation delivery, evidence delay, recovery, and severity-one support acknowledgment. | Thirty consecutive days meet every roadmap target. A forced breach creates the required alert and error-budget record. | 6 |
| Backup and restore | Operator-managed local files | AgentWall provides no managed backup service or scheduled restore test. | Back up control state, policy bundles, identity metadata, evidence metadata, and required evidence bytes. Encrypt backups and test isolated restore each quarter. | An isolated restore meets the 15-minute recovery point and four-hour recovery time objectives. Every restored evidence chain verifies. | 6 |
| Independent review | Conformance corpus and repository security checks | Project checks do not establish independent assurance. | Commission external security, penetration, and privacy reviews for the complete enterprise release scope. Track findings and retests. | The reviewer confirms closure of every critical and high finding. The release evidence pack contains the scope, result, limits, and remediation state. | 7 |

## Required outage behavior

These rules apply to the planned enterprise design. They do not describe current managed services.

| Outage | Required behavior | Prohibited behavior |
| --- | --- | --- |
| Control service | Hosts keep the last verified policy. Central mutations stop. Hosts report the outage and policy age. | A host must not accept an unsigned policy or report an unconfirmed change. |
| Policy state expiry | The host refuses new agent sessions and reports a critical state. Existing local enforcement remains active. | The host must not treat expired state as current without a visible exception. |
| Evidence service | Hosts keep local evidence. The fleet view marks data stale or incomplete. Delivery resumes after recovery. | The fleet view must not infer a clean result from missing evidence. |
| Identity service | New operator sessions fail closed. Existing sessions end at normal expiry. The shared token does not become a fallback. | AgentWall must not remove authentication or grant a broader role. |
| Admission service | New protected workloads fail admission. Existing protected workloads keep their current enforcement. | The cluster must not admit an unverified protected workload during the outage. |
| Backup service | Operations raise an alert and stop any process that depends on a current recovery point. | Operations must not report a recovery objective as met without a valid backup. |

## Control promotion rule

A control moves from Planned to Shipped only after its code, operator documentation, and required evidence exist for one supported release.

The applicable roadmap exit test must also receive PASS. A partial implementation remains Planned.
