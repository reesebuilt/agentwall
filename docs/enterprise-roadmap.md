# Enterprise roadmap

> This roadmap describes planned enterprise work. It does not describe shipped behavior.

AgentWall provides local operator controls today. Planned controls remain unavailable until the applicable stage receives a recorded PASS.

See [Enterprise controls](enterprise-controls.md) for the current component, current limit, required upgrade, and required test evidence.

## Status rules

- **Shipped** means the current repository implements the control.
- **Planned** means the control is not available as an enterprise capability.
- A stage receives PASS only after its complete exit test succeeds.
- One failed exit condition gives the stage FAIL.
- Public shipped lists change only after the applicable stage receives PASS.

## Shipped controls

These controls exist now. Their stated limits also apply now.

- **Local policy:** AgentWall validates local policy reloads. It keeps the active rules when a new local file fails validation.
- **Operator access:** One shared bearer token protects operator routes. AgentWall does not provide operator OIDC, mTLS, or RBAC.
- **Fleet credentials:** A local store supports issue, bounded-overlap rotation, and revocation. AgentWall does not distribute that store between hosts.
- **Local evidence:** AgentWall can write hash-chained audit files, seal segments, sign checkpoints, and verify the result locally.
- **Fleet evidence:** A read-only view checks operator-delivered host files. AgentWall does not provide a managed evidence service or retention policy.
- **Deployment:** The repository includes a container build and local package paths. It does not include supported Kubernetes admission control.
- **Release pipeline:** The workflow creates an SBOM and SLSA provenance. It uses OIDC for publication and signs the container image digest.
- **Release limits:** OIDC protects publication only. The workflow does not give every release asset a separate signature.
- **Assurance:** Several verifier implementations use one conformance corpus. This does not constitute an independent external security review.

## Planned stages

The stages follow dependency order. A later stage can start early, but it cannot receive PASS before its required earlier controls.

### Stage 1: Trust foundation

**Scope:** This stage covers release artifacts, build identities, dependency records, verifier builds, trust keys, and performance limits.

**Threat:** An attacker can replace an artifact, change its source, hide a dependency, misuse a key, or cause unsafe resource use.

**Planned work:**

- Sign one release manifest that identifies every published artifact by digest.
- Keep the current image signature and bind all artifact checks to the same release identity.
- Create a complete SBOM for each applicable artifact and container layer.
- Verify SLSA provenance for every release channel before publication.
- Reproduce each verifier binary from a clean source tree.
- Define trust-key rotation, revocation, overlap, and recovery procedures.
- Set measured CPU, memory, latency, and storage limits for supported deployment sizes.

**Evidence:** Keep the signed manifest, SBOM files, provenance, build logs, reproduction results, key events, and performance reports.

**Failure behavior:** The release workflow stops when required evidence is absent or invalid. The prior release remains the current release.

**Owner role:** The release engineering lead owns this stage. The security lead approves the trust policy.

**Binary exit test:**

- **PASS:** A clean host verifies every release asset and rejects one changed asset.
- **PASS:** A clean build reproduces every verifier binary byte for byte.
- **PASS:** A forced trust-key rotation keeps valid verification and rejects the revoked key.
- **PASS:** The supported load test stays within every published resource limit.
- **FAIL:** Any other result gives the stage FAIL.

### Stage 2: Fleet control

**Scope:** This stage covers signed policy distribution, host policy state, credential authority, rotation, revocation, and policy rollback.

**Threat:** An attacker can inject a policy, keep a revoked credential, cause policy drift, or force an unsafe partial rollout.

**Planned work:**

- Package policies as signed, versioned bundles with issue and expiry times.
- Bind each host group to an approved policy signer and release channel.
- Record the requested, accepted, active, and last-good policy digests for each host.
- Distribute credential issue, rotation, and revocation state from one authority.
- Support a signed rollback to a known policy digest.
- Use staged rollout gates and stop a rollout after a failed host check.

**Evidence:** Keep policy bundles, signatures, host receipts, active digests, rollout decisions, credential events, and rollback records.

**Failure behavior:** A host rejects an invalid bundle and keeps its last verified policy. The host never changes policy during a control service outage.

After policy expiry, the host refuses new agent sessions and reports a critical state. Existing local enforcement remains active.

A credential service outage does not restore revoked credentials. A host rejects new credentials when its signed credential state expires.

**Owner role:** The fleet security administrator owns this stage.

**Binary exit test:**

- **PASS:** Two hosts accept the same signed bundle and report the same active digest.
- **PASS:** Both hosts reject a changed bundle and keep the prior digest.
- **PASS:** A signed rollback restores the exact prior digest on both hosts.
- **PASS:** A revoked credential fails on every connected test host within the defined target.
- **FAIL:** Any other result gives the stage FAIL.

### Stage 3: Fleet evidence service

**Scope:** This stage covers read-only evidence receipt, validation, storage, search, export, and fleet status.

**Threat:** An attacker can delete evidence, alter a chain, hide a host, or make an incomplete fleet appear clean.

**Planned work:**

- Accept evidence through an authenticated, write-only host path.
- Preserve original evidence bytes before any index or summary process runs.
- Verify each chain with an implementation that does not share the evidence writer.
- Record host delivery time, chain state, active policy digest, and evidence age.
- Apply a declared retention rule and a legal hold process.
- Export original records, verification results, and retention metadata.

**Evidence:** Keep original chains, host receipts, verification results, retention events, export digests, and service health records.

**Failure behavior:** An evidence service outage does not change host enforcement. Hosts keep local evidence for later delivery.

The fleet view marks missing or stale evidence as incomplete. It never reports a clean result from absent evidence.

**Owner role:** The evidence service owner owns this stage.

**Binary exit test:**

- **PASS:** Three hosts deliver evidence, and an independent verifier gives the same result as the service.
- **PASS:** A changed chain receives FAIL, and a missing host receives INCOMPLETE.
- **PASS:** A service outage leaves host enforcement active and preserves queued local evidence.
- **PASS:** Service recovery accepts the queued evidence without a chain gap.
- **FAIL:** Any other result gives the stage FAIL.

### Stage 4: Identity and access

**Scope:** This stage covers human identity, service identity, transport identity, role permissions, approvals, and emergency access.

**Threat:** A shared token can leak. An attacker can impersonate a host, exceed assigned permission, or approve the attacker's own action.

**Planned work:**

- Add OIDC for human operator authentication.
- Validate issuer, audience, signature, time claims, and required identity claims.
- Add mTLS for host and service connections.
- Add RBAC for viewer, operator, approver, auditor, and administrator duties.
- Require a separate approver for declared high-impact actions.
- Record the principal, role, request, decision, reason, and result.
- Provide a local emergency credential with strict custody and complete audit records.

**Evidence:** Keep identity decisions, certificate identities, role checks, approval records, emergency access events, and denial records.

**Failure behavior:** Identity failure never falls back to the shared operator token. New sessions fail closed when the identity service is unavailable.

Current sessions end at their normal expiry. Emergency access uses only the separate local procedure and creates a critical audit event.

**Owner role:** The identity and access administrator owns this stage.

**Binary exit test:**

- **PASS:** The route matrix allows every required role action and denies every forbidden role action.
- **PASS:** Invalid OIDC claims and expired or untrusted client certificates receive denial.
- **PASS:** A high-impact action fails without a separate approver.
- **PASS:** An identity service outage creates no authentication downgrade.
- **FAIL:** Any other result gives the stage FAIL.

### Stage 5: Deployment

**Scope:** This stage covers supported container sidecars, Kubernetes admission checks, deployment policy, upgrades, and deployment rollback.

**Threat:** A workload can bypass AgentWall, run an unverified image, use unsafe privileges, or remain broken after an upgrade.

**Planned work:**

- Publish a supported sidecar deployment with explicit network and storage requirements.
- Pin every deployed image by verified digest.
- Add Kubernetes admission checks for protected namespaces and declared workload labels.
- Deny protected workloads that omit the required AgentWall control path.
- Define supported versions, upgrade order, schema compatibility, and rollback steps.
- Test upgrades with active sessions, policy changes, evidence delivery, and restart faults.

**Evidence:** Keep signed deployment manifests, image verification results, admission decisions, upgrade reports, rollback records, and compatibility results.

**Failure behavior:** Admission service failure denies new protected workloads. Existing workloads keep their current local enforcement.

A failed upgrade restores the prior signed image and policy. The deployment records the failure and the restored digests.

**Owner role:** The platform engineering lead owns this stage.

**Binary exit test:**

- **PASS:** A fresh Kubernetes cluster admits a conforming protected workload.
- **PASS:** The same cluster denies that workload after removal of the required AgentWall path.
- **PASS:** A forced upgrade fault restores the prior image and policy digests.
- **PASS:** Evidence shows every admission and rollback decision.
- **FAIL:** Any other result gives the stage FAIL.

### Stage 6: Operations and support

**Scope:** This stage covers SLOs, alerts, incident procedures, support, backups, restore tests, and routine key rotation.

**Threat:** A silent outage can delay control changes, lose evidence, exceed recovery limits, or leave an operator without a tested response.

**Planned work:**

- Measure control service availability with a monthly target of at least 99.9 percent.
- Deliver accepted policy to 99 percent of connected hosts within five minutes.
- Deliver revocation state to connected hosts within 60 seconds at the 95th percentile.
- Ingest host evidence within ten minutes at the 95th percentile.
- Set a recovery point objective of 15 minutes for managed control and evidence data.
- Set a recovery time objective of four hours for those services.
- Run quarterly restore tests in an isolated environment.
- Define incident severity, escalation, communication, and support ownership.
- Set a 30-minute acknowledgment target for a severity-one enterprise incident.

**Evidence:** Keep SLI reports, alert records, incident exercises, support records, backup manifests, restore results, and key-rotation records.

**Failure behavior:** A control service outage stops central mutations. Hosts keep the last verified policy and local enforcement.

An evidence service outage marks fleet data stale and keeps host evidence local. Operations follow the declared recovery procedure.

**Owner role:** The service operations lead owns this stage.

**Binary exit test:**

- **PASS:** All stated SLOs meet their targets for 30 consecutive days.
- **PASS:** One isolated restore test meets both recovery objectives and verifies every restored chain.
- **PASS:** One incident exercise meets the severity-one acknowledgment target.
- **PASS:** One routine key rotation completes without an authentication downgrade or evidence gap.
- **FAIL:** Any other result gives the stage FAIL.

### Stage 7: Assurance

**Scope:** This stage covers independent security review, penetration tests, privacy review, control evidence, and release approval.

**Threat:** Internal tests can miss design defects, unsafe defaults, privacy risks, or control claims that lack evidence.

**Planned work:**

- Commission an independent review of the defined enterprise release and deployment model.
- Include the policy path, identity path, evidence path, update path, and recovery path.
- Run penetration tests against the control service, host connection, operator API, and deployment path.
- Review personal data, retention, access, export, and deletion behavior.
- Publish the review scope, review date, material limits, and remediation state.
- Create a release evidence pack for every enterprise control.

**Evidence:** Keep the review report, test scope, findings, remediation records, retest results, privacy decision, and control evidence pack.

**Failure behavior:** An open critical or high finding blocks the enterprise release. Missing evidence keeps the related control in planned status.

**Owner role:** The assurance lead owns this stage. The product security lead owns remediation.

**Binary exit test:**

- **PASS:** An independent reviewer assesses the release candidate against the complete defined scope.
- **PASS:** The reviewer confirms closure of every critical and high finding.
- **PASS:** The privacy review approves the data flow and retention rules.
- **PASS:** Every enterprise control has current evidence in the release evidence pack.
- **FAIL:** Any other result gives the stage FAIL.

## Roadmap completion

The enterprise roadmap completes only when all seven stages receive PASS for the same supported release line.

A later failure can return an affected control to planned status. The owner must record the failure, scope, interim behavior, and new exit result.
