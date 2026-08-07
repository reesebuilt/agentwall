# AgentWall Simple Operator Design

**Date:** 2026-08-06
**Status:** Approved for implementation from the user request

## Objective

Make AgentWall simple for a first-time user while keeping its security evidence and operator controls.

## Users

1. A first-time user wants safe defaults and clear next steps.
2. An operator wants fast answers during an event.
3. An enterprise team wants repeatable controls and independent evidence.

## Design read

This is a security product repository and local operator console for non-specialist users.
The visual language uses calm graphite surfaces, one mint accent, short labels, and clear status actions.
The page uses a low-density layout with no decorative gradients.

The UI uses these values:

- Design variance: 4. A security console needs predictable placement.
- Motion intensity: 2. Motion shows state changes only.
- Visual density: 4. The first screen shows the current state and the next action.

## Public language

All user-facing prose uses ASD-STE100 rules.

- Use active voice.
- Use one instruction in one sentence.
- Use no more than 20 words in a procedure sentence.
- Use no more than 25 words in a descriptive sentence.
- Use no more than six sentences in a paragraph.
- Use the same term for the same concept.
- Define technical terms before use.
- State limits beside the feature that has the limit.
- Do not mention or link to another product in public files.

Code identifiers, shell commands, API paths, and exact error text stay unchanged where a contract requires them.

## Product flow

The first-run flow is:

1. Install the package.
2. Run `agentwall setup`.
3. Run `agentwall start`.
4. Open the local console.
5. Run `agentwall doctor`.
6. Move from monitor mode to guarded mode after the user reviews traffic.

`setup` creates local configuration, a local operator token, and a durable audit path.
It never enables LAN access without an explicit flag.
It never overwrites an existing configuration without `--force`.
The explicit environment remains the highest-priority configuration source.

## Architecture

### Guided setup

Add a setup module that owns safe local defaults and file permissions.
The module creates the starter files that the existing onboarding flow already defines.
It creates `.agentwall/operator.env` with mode `0600` when the platform supports file modes.
It adds local generated paths to `.gitignore` without changing existing user rules.

The CLI loads the generated environment only when the caller did not set the variable.
The loader never prints the operator token after setup creates it.

### Operator action API

Add a typed operator route group for every mutating CLI action that the running service can perform.
Each action has a Zod schema and an allowlisted operation name.
The route never evaluates a raw shell string.
Typed command actions accept a declared executable and an argument list.
The server rejects shell syntax, path traversal, and undeclared executable names.
The route returns structured status, a plain-language message, and the exact next action.

The complete mutating CLI inventory is:

- `approval-mode`, `shield`, and `normal`, which change runtime controls.
- `session-boost`, `session-reset`, `pause`, `resume`, and `terminate`, which change session controls.
- `fleet issue`, `fleet rotate`, and `fleet revoke`, which change credentials.
- `anchor` and `verify-capture`, which create or prove audit evidence.
- `mcp wrap`, which starts a typed MCP wrapper.
- `perimeter install`, `perimeter rollback`, and `perimeter run`, which change or use host network controls.
- `sandbox build` and `sandbox run`, which build or use process controls.
- `intercept init` and `intercept trust`, which change certificate trust.
- `decoy generate`, which creates a decoy credential.

Read-only CLI commands remain visible in the UI with status, output, and a copyable command.
The running UI performs every supported service-side mutation through a typed action workflow.
No supported mutating command stays host-only.
The API keeps an offline CLI command beside every action.

Host changes require a visible plan and confirmation before execution.
The browser never runs an arbitrary process.
The UI can run a declared command only through a server-side allowlist and an explicit confirmation.

### Bootstrap UI

Add a separately launchable `agentwall ui` command.
The bootstrap UI binds to loopback and starts before the AgentWall service.
It shows setup, service status, start, stop, and development start controls.
It performs `setup`, `init`, `onboard`, `start`, `dev`, and `stop` through typed server actions.
It starts only fixed AgentWall entry points and never accepts an arbitrary executable.
After startup, it links to the authenticated dashboard and the operator action API.
It uses a one-time local session token and origin checks for mutations.

The bootstrap UI keeps working when the AgentWall service is stopped.
The service dashboard does not claim to own setup or service start.

### Persistent MCP baseline

Add an optional baseline store for MCP tool inventories.
The baseline uses the existing descriptor shape and server command hash.
The store records the accepted inventory per server and agent.
The first inventory can enter learn mode without an approval prompt.
Lock mode requires approval for a new, removed, or changed tool.
A denied inventory never updates the baseline.
The baseline file uses atomic replacement and is not part of the audit root of trust.
The audit record stores the baseline state and the drift result.

### UI

Replace the current deep console split with five simple areas:

1. **Status.** Shows protection state, current mode, and the most important warning.
2. **Approvals.** Shows the next decision and safe actions.
3. **Policy.** Shows active rules and the policy editor.
4. **Agents.** Shows identity, credentials, budgets, and session controls.
5. **Evidence.** Shows audit state, verification, and export commands.

Containment and certificate tools appear under a secondary Operations view.
The UI keeps the existing API contracts for approvals, policy, session controls, and evidence.
New operator actions use the allowlisted operator route group.

The UI must support:

- keyboard-only operation
- a visible focus state
- a visible connection state
- loading, empty, error, and success states
- a small-screen layout below 600 pixels
- a confirmation step for destructive actions
- text labels that do not depend on color alone

The bootstrap UI must support the same states before service startup.


## Public documentation

Rewrite the README as a short decision page.
Add a simple user guide with install, setup, first run, safe mode changes, and common fixes.
Add a feature reference that lists each capability and its limit.
Add an operator guide that maps every CLI command to a UI action.
The guide states the bootstrap UI workflow for setup, initialization, onboarding, service start, and development start.
The guide states the running UI workflow for every other mutating command.
Rewrite public policy and security documents in the same language style.
Keep code blocks and API names exact.

## Enterprise roadmap

The repository will include a plan, not an unshipped enterprise claim.
The plan uses these stages:

1. **Trust foundation.** Signed releases, SBOM, reproducible verifier builds, key rotation, and measured performance.
2. **Fleet control.** Signed policy bundles, last-good rollback, credential authority, and revocation status.
3. **Evidence service.** Read-only aggregation with independent host verification and clear outage behavior.
4. **Identity and access.** OIDC, mTLS, role-based access, least privilege, and approval records.
5. **Deployment.** Container sidecars, Kubernetes admission checks, and tested upgrade paths.
6. **Operations.** SLOs, incident playbooks, support tools, backups, and recovery tests.
7. **Assurance.** External review, penetration tests, privacy review, and published control evidence.

Every stage has a binary exit test in the roadmap.

## Error handling

- Setup stops before overwriting user files.
- Invalid YAML keeps the last valid policy active.
- Operator actions return a named error and a safe next step.
- A failed host plan never reports an installed control.
- A missing audit record never reports a clean result.
- A stale connection shows the last update time and the fallback poll state.
- A destructive action requires explicit confirmation.

## Tests

Add behavior tests before each new production change.
Cover setup file creation, permission handling, environment precedence, operator action authorization, baseline learning, baseline drift, and UI action states.
Keep existing test contracts unless the new public design intentionally changes visible text.
Run `npm run lint` and `npm test` after each implementation phase.
Run a public-copy scan for banned competitor names and ASD-STE100 violations before release.
Run the local `gbrain advisor` command before the final report.

## Success criteria

- A new user can install and start AgentWall with two commands after package installation.
- Setup never overwrites existing configuration without `--force`.
- The UI exposes every supported mutable CLI action through a typed workflow.
- The UI lists every read-only CLI action with status, output, and a copyable command.
- MCP baseline learning and lock mode produce tested, auditable decisions.
- The public README and guide use short active sentences.
- Public repository files contain no competitor name or competitor link.
- The local console works at desktop and small-screen widths.
- `npm run lint` exits with code 0.
- `npm test` reports zero failed suites and zero failed tests.
- `gbrain advisor` reports its current findings before delivery.
