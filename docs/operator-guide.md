# Operator guide

Use `agentwall ui` for setup and daily service control.

```bash
agentwall ui
```

The command starts the bootstrap UI on `http://127.0.0.1:3001` by default.
It does not require the AgentWall service.
Use the running dashboard after the service starts.

## Two local consoles

The bootstrap UI owns local files and the service process.
It supports setup, initialization, onboarding, start, development start, stop, and service status.

The running dashboard owns policy, sessions, approvals, credentials, evidence, and host operations.
It performs each mutation through a typed action.
It never accepts a shell command string.

Both consoles bind to loopback by default.
Use an explicit option before you allow another host to connect.

## Bootstrap command matrix

| CLI command | Bootstrap UI workflow | API path | Result |
| --- | --- | --- | --- |
| `agentwall ui` | Start the bootstrap UI from a terminal. | `GET /` | Opens the first-run entry point. |
| `agentwall setup` | Select **Setup**, review local values, then confirm. | `POST /api/bootstrap/setup` | Creates safe local files. |
| `agentwall init` | Select **Initialize**, set the mode and network values, then confirm. | `POST /api/bootstrap/init` | Creates the starter configuration and policy. |
| `agentwall onboard <profile>` | Select **Onboard**, choose a profile, set the agent ID, then confirm. | `POST /api/bootstrap/onboard` | Creates one agent identity and shows its environment once. |
| `agentwall start` | Select **Start service**. | `POST /api/bootstrap/start` | Starts the fixed production entry point. |
| `agentwall dev` | Select **Start development service**. | `POST /api/bootstrap/dev` | Starts the fixed development entry point. |
| `agentwall stop` | Select **Stop service**, review the process state, then confirm. | `POST /api/bootstrap/stop` | Stops the service child process. |

`GET /api/bootstrap/status` returns setup and service state.
The bootstrap UI shows `stopped`, `starting`, `running`, or `failed` for the service.

The bootstrap UI accepts no executable name.
It starts only the fixed AgentWall entry points.

## Running mutation matrix

Each row uses `POST /api/operator/actions`.
The request body uses the exact action name in the **Typed action** column.

| CLI command | Running UI workflow | Typed action | Confirmation |
| --- | --- | --- | --- |
| `agentwall approval-mode auto` | Open **Approvals**, select `auto`, then apply. | `approval-mode` | Required before the change. |
| `agentwall approval-mode always` | Open **Approvals**, select `always`, then apply. | `approval-mode` | Required before the change. |
| `agentwall approval-mode never` | Open **Approvals**, select `never`, then apply. | `approval-mode` | Required before the change. |
| `agentwall shield` | Open **Status**, set the shield duration, then enable shield mode. | `shield` | Required before the change. |
| `agentwall normal` | Open **Status**, review the shield state, then select normal mode. | `normal` | Required before the change. |
| `agentwall session-boost --session <id>` | Open **Agents**, select a session, set the multiplier and duration, then apply. | `session-boost` | Required before the change. |
| `agentwall session-reset --session <id>` | Open **Agents**, select a session override, then reset it. | `session-reset` | Required before the change. |
| `agentwall pause --session <id>` | Open **Agents**, select a session, add an optional note, then pause it. | `pause` | Required before the change. |
| `agentwall resume --session <id>` | Open **Agents**, select a paused session, add an optional note, then resume it. | `resume` | Required before the change. |
| `agentwall terminate --session <id> --confirm` | Open **Agents**, select a session, review the warning, then terminate it. | `terminate` | Always required. |
| `agentwall fleet issue --agent <id>` | Open **Agents**, select **Issue credential**, choose an agent, then confirm. | `fleet-issue` | Always required. |
| `agentwall fleet rotate --agent <id>` | Open **Agents**, select a credential, set the overlap, then confirm rotation. | `fleet-rotate` | Always required. |
| `agentwall fleet revoke --credential <id>` | Open **Agents**, select a credential, add a reason, then confirm revocation. | `fleet-revoke` | Always required. |
| `agentwall fleet revoke --agent <id>` | Open **Agents**, select an agent, add a reason, then confirm full revocation. | `fleet-revoke` | Always required. |
| `agentwall anchor` | Open **Evidence**, review the audit path, then create the checkpoint. | `anchor` | Always required. |
| `agentwall verify-capture --agent <id> --command '<cmd>'` | Open **Evidence**, enter the declared agent and command arguments, then run the capture proof. | `verify-capture` | Always required. |
| `agentwall mcp wrap -- <command> [args...]` | Open **Operations**, select a declared server, review the command plan, then add it to the client configuration. | `mcp-wrap` | Always required. |
| `agentwall mcp wrap --http-upstream <url> --http-port <port>` | Open **Operations**, enter the remote MCP URL and local port, then start the wrapper. | `mcp-http-wrap` | Always required. |
| `agentwall mcp stop <wrapper-id>` | Open **Operations**, select the wrapper ID, then stop the wrapper. | `mcp-http-stop` | Always required. |
| `agentwall perimeter install` | Open **Operations**, review the rendered network plan, then confirm installation. | `perimeter-install` | Always required. |
| `agentwall perimeter rollback` | Open **Operations**, review the installed table, then confirm removal. | `perimeter-rollback` | Always required. |
| `agentwall perimeter run -- <command> [args]` | Open **Operations**, select a declared command, review the perimeter plan, then run it. | `perimeter-run` | Always required. |
| `agentwall sandbox build` | Open **Operations**, review the native build inputs, then confirm the build. | `sandbox-build` | Always required. |
| `agentwall sandbox run -- <command> [args]` | Open **Operations**, select a declared command, review the profile, then run it. | `sandbox-run` | Always required. |
| `agentwall intercept init` | Open **Operations**, review the CA path and lifetime, then confirm creation. | `intercept-init` | Always required. |
| `agentwall intercept trust` | Open **Operations**, review the runtime trust change, then confirm the typed workflow. | `intercept-trust` | Always required. |
| `agentwall decoy generate --kind <kind>` | Open **Operations**, set the kind, label, and output path, then confirm creation. | `decoy-generate` | Always required. |

A returned credential secret appears once.
Copy it before you leave the result view.
The UI does not store the secret in browser storage.

Host changes always show a plan before execution.
A missing confirmation returns status `409` and a safe next action.

## Read-only command matrix

The running UI shows status and output for each row.
Each view also shows the exact copyable CLI command.
Read-only actions do not need confirmation.

| CLI command | Running UI view | Typed action or view |
| --- | --- | --- |
| `agentwall doctor` | **Status** shows install, capture, fleet, and audit health. | `doctor` |
| `agentwall status` | **Status** shows the current protection and connection state. | `status` |
| `agentwall verify` | **Evidence** shows the chained, linked, and anchored results. | `verify` |
| `agentwall fleet list` | **Agents** shows credential IDs and states, but never secrets. | `fleet-list` |
| `agentwall mcp status` | **Operations** shows each managed HTTP wrapper, endpoint, server, and wrapper ID. | `mcp-http-list` |
| `agentwall perimeter plan` | **Operations** shows the resolved network plan. | `perimeter-plan` |
| `agentwall perimeter status` | **Operations** shows the installed rule state. | `perimeter-status` |
| `agentwall perimeter verify` | **Operations** shows the end-to-end perimeter result and limits. | `perimeter-verify` |
| `agentwall sandbox probe` | **Operations** shows the kernel capability result. | `sandbox-probe` |
| `agentwall sandbox plan` | **Operations** shows the resolved process profile and gaps. | `sandbox-plan` |
| `agentwall intercept status` | **Operations** shows the CA fingerprint, expiry, and key permissions. | `intercept-status` |
| `agentwall intercept path` | **Operations** shows the absolute CA certificate path. | Interception output view |
| `agentwall decoy list --file <path>` | **Operations** shows safe decoy metadata, but never a generated secret. | `decoy-list` |
| `agentwall why <subject>` | **Policy** shows which checks match the supplied subject. | `why` |
| `agentwall version` | **Status** shows the installed version. | `version` |
| `agentwall help` | **Status** shows CLI help and a copyable command. | `help` |
| `agentwall --help` | **Status** shows the same CLI help. | `help` |
| `agentwall --version` | **Status** shows the same installed version. | `version` |

`GET /api/operator/actions` returns the allowlisted catalog.
The catalog contains no arbitrary shell action.
Unknown actions fail before an executor runs.

## Offline operation

Each UI result includes its matching CLI command.
Use that command when the browser is unavailable.

The API accepts a declared executable and an argument list for typed command actions.
It rejects shell syntax, command substitution, path traversal, absolute executable paths, and undeclared binaries.

No supported service-side mutation stays host-only.
The bootstrap UI owns pre-start mutations.
The running dashboard owns all other supported service-side mutations.

## MCP baseline modes

`agentwall mcp wrap` supports three inventory baseline modes.

| Mode | Behavior | Limit |
| --- | --- | --- |
| `off` | Uses session-only inventory checks. | It stores no durable inventory. |
| `learn` | Stores the first clean inventory for the agent and server. | A poisoned inventory never becomes the baseline. |
| `lock` | Compares each inventory with the stored baseline. | Drift needs approval and a denied inventory never updates the file. |

Use `--baseline-mode off|learn|lock` to select the mode.
Use `--baseline-file <path>` to select the durable store.
The default mode is `off`.

## Operational limits

| Area | Limit |
| --- | --- |
| TLS visibility | AgentWall sees authority and available SNI until the operator enables interception for a reviewed host. |
| Event streams | AgentWall checks stream headers, but it does not inspect the unbuffered event body. |
| Body size | AgentWall scans at most 256 KiB from each proxy body and records partial visibility past the cap. |
| Process attribution | PID and process-name attribution needs Linux `/proc`; failure records an unknown process and does not block. |
| DNS | The perimeter permits one resolver or blocks DNS; permitted DNS remains a possible data path. |
| Fleet scope | Credentials, policy, and live budgets have per-instance scope; instances do not share a clustered control plane. |

## Operator API results

A successful action returns status `200`.
A schema error returns status `400`.
Missing operator authorization returns status `401`.
A rejected origin returns status `403`.
A missing confirmation returns status `409`.

Each result contains `ok`, `action`, `status`, `message`, and `next`.
Some actions also return typed data.
The API does not return raw secrets in status, list, or error data.
