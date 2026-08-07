# User guide

Start with the local bootstrap UI.

```bash
agentwall ui
```

This guide gives a direct CLI command beside each UI procedure.

## Install AgentWall

**Goal:** Install the AgentWall command for the current machine.

```bash
npm install -g @repsecure/agentwall
```

**Expected result:** `agentwall version` prints the installed version.

**Common failure:** A permission error stops the global install.
Use a user-owned npm prefix, then run the command again.

## Open the first-run UI

**Goal:** Start the setup UI before the AgentWall service exists.

```bash
agentwall ui
```

**Expected result:** The terminal prints `http://127.0.0.1:3001` and the page shows setup status.

**Common failure:** Another process uses port `3001`.
Select another local port with `agentwall ui --port 3011`.

## Create the local setup

**Goal:** Create local configuration, policy, operator credentials, and an audit path.

Open **Setup** in the bootstrap UI.
Keep monitor mode and loopback access for the first run.
Review the paths, then confirm the action.

The direct CLI command is:

```bash
agentwall setup
```

**Expected result:** AgentWall creates the starter files and `.agentwall/operator.env`.
It does not print the operator token.

**Common failure:** Existing files stop setup.
Back up the files before you use `agentwall setup --force`.

Explicit environment variables have priority over `.agentwall/operator.env`.
The generated environment file uses mode `0600` when the platform supports file modes.

## Start the service

**Goal:** Start AgentWall with the generated local environment.

Select **Start service** in the bootstrap UI.
The direct CLI command is:

```bash
agentwall start
```

**Expected result:** The bootstrap status changes from `starting` to `running`.
The UI then shows a link to the authenticated dashboard.

**Common failure:** Invalid YAML stops startup.
Correct the named file, then start the service again.

Use `agentwall dev` only for work on a source checkout.
Use `agentwall stop` from the bootstrap UI or terminal to stop the managed service.

## Check the installation

**Goal:** Check files, runtime state, capture, fleet state, and audit evidence.

```bash
agentwall doctor
```

**Expected result:** Exit code `0` means the checks are clear.
Exit code `1` means a check failed.
Exit code `2` means AgentWall cannot prove a clear or failed result.

**Common failure:** The command reports an inconclusive capture result.
Apply the exact configuration fix in its output, then run the command again.

## Onboard one agent runtime

**Goal:** Create one declared identity and show its environment once.

Select **Onboard** in the bootstrap UI.
Choose a profile and enter a stable agent ID.
Then confirm the action.

The direct CLI form is:

```bash
agentwall onboard <profile> --agent-id <id>
```

**Expected result:** AgentWall updates the configuration and prints the runtime environment once.
The final output shows a `verify-capture` command.

**Common failure:** The agent ID contains an unsupported character.
Use only letters, numbers, `.`, `_`, or `-` in the ID.

Onboarding does not prove capture.
Run the printed `verify-capture` command before you rely on the identity.

## Use monitor mode

**Goal:** Record decisions before you enable blocking.

Create or update the local setup with this mode:

```bash
agentwall setup --mode monitor
```

If the configuration already exists, set this value and restart the service:

```yaml
enforcement:
  mode: monitor
```

**Expected result:** AgentWall evaluates and records traffic, but allows it.
The dashboard shows decisions that guarded or strict mode would refuse.

**Common failure:** The setup command refuses an existing configuration.
Edit only the mode value, then restart the service.

## Move to guarded mode

**Goal:** Enforce matching deny rules after you review monitor records.

Set this value in `agentwall.config.yaml`:

```yaml
enforcement:
  mode: guarded
```

Restart the managed service:

```bash
agentwall stop
agentwall start
```

**Expected result:** Matching deny rules block traffic.
Requests without a matching deny rule can continue.

**Common failure:** A required request matches a deny rule.
Run `agentwall why <subject>`, then change the narrowest related rule.

Mode changes need a restart.
Policy rule changes can use the running policy workflow.

## Move to strict mode

**Goal:** Allow only destinations in the configured allowlist.

Set this value in `agentwall.config.yaml`:

```yaml
enforcement:
  mode: strict
```

Restart the managed service:

```bash
agentwall stop
agentwall start
```

**Expected result:** AgentWall refuses a destination that the allowlist does not name.

**Common failure:** A required subdomain is blocked.
Add that exact hostname because the allowlist does not use wildcard or suffix matches.

Strict mode still controls only traffic that reaches AgentWall.
Install and verify the perimeter when cooperative proxy capture is not sufficient.

## Set approval behavior

**Goal:** Select how AgentWall routes decisions that need operator approval.

Open **Approvals** in the running dashboard.
Select one mode, review it, then apply it.

The matching CLI commands are:

```bash
agentwall approval-mode auto
agentwall approval-mode always
agentwall approval-mode never
```

**Expected result:** The dashboard and `agentwall status` show the selected approval mode.

**Common failure:** The API returns `401`.
Open the dashboard from the bootstrap link or start AgentWall with the generated environment.

`auto` uses policy and risk context.
`always` routes applicable actions to approval.
`never` refuses actions that require approval.

## Use a temporary shield

**Goal:** Apply stricter runtime limits during an event.

```bash
agentwall shield --minutes 15
```

**Expected result:** Status shows shield mode and its expiry.

**Common failure:** The service is not reachable.
Open the bootstrap UI, start the service, then apply shield mode again.

Return to normal runtime limits with:

```bash
agentwall normal
```

## Prove capture

**Goal:** Prove that one declared agent uses AgentWall and does not reach the canary directly.

Use the exact command from onboarding.
Its general form is:

```bash
agentwall verify-capture --agent <id> --command '<cmd>'
```

**Expected result:** The report names the audit record, agent binding tier, and direct-network check.

**Common failure:** The canary receives a direct request.
Correct the proxy or perimeter route before you use the deployment.

## Verify audit evidence

**Goal:** Check local record links, rotated segment links, and external anchor evidence.

```bash
agentwall verify
```

**Expected result:** The command reports `chained`, `linked`, and `anchored` separately.

**Common failure:** The anchored layer is absent or pending.
Run `agentwall anchor`, then wait for external confirmation before you claim anchored evidence.

An anchor detects later record changes.
It does not prove that AgentWall recorded every action.

## Common errors

### The dashboard cannot connect

**Goal:** Restore the service connection.

```bash
agentwall status
```

**Expected result:** The command returns the current dashboard state.

**Common failure:** The connection is refused.
Open `agentwall ui`, then use **Start service**.

### The dashboard returns `401`

**Goal:** use the generated operator credential without printing it.

```bash
agentwall stop
agentwall start
```

**Expected result:** The managed service loads `.agentwall/operator.env` and accepts the local operator session.

**Common failure:** An explicit stale token overrides the generated token.
Remove the stale `AGENTWALL_OPERATOR_TOKEN` value from the process environment, then restart.

### A request returns `403`

**Goal:** Find the exact rule or runtime control that refused the request.

```bash
agentwall why <subject>
```

**Expected result:** The output names matched checks and the narrowest related control.

**Common failure:** The command cannot reproduce a session-only limit.
Open **Status** and **Agents** to inspect the live session state.

### AgentWall shows no traffic

**Goal:** Confirm that the runtime sends traffic through AgentWall.

```bash
agentwall doctor
```

**Expected result:** The capture section names the last seen agent and its binding tier.

**Common failure:** The runtime ignores proxy environment variables.
Use the onboarding environment or install the Linux perimeter.

The default proxy route is cooperative.
A process that bypasses the proxy remains outside AgentWall.
