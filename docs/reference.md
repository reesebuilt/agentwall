# API and configuration reference

Use this page to find routes, environment variables, and configuration keys.

## First-run UI

Start the local bootstrap UI:

`agentwall ui`

The UI uses loopback and port `3001` by default. Use `--host`, `--port`, or `--service-port` to change its network settings.

A non-loopback `--host` value exposes the bootstrap UI beyond the local host. The default local bind does not provide remote access.

| Method and path | Purpose | Limit |
| --- | --- | --- |
| `GET /` | Show the bootstrap UI. | The bootstrap server is separate from the AgentWall service. |
| `GET /api/bootstrap/status` | Show setup and service status. | It reports only the service process that this UI controls. |
| `POST /api/bootstrap/setup` | Create the local setup. | The route accepts only the typed setup schema. |
| `POST /api/bootstrap/init` | Initialize AgentWall files. | The route requires the local session cookie and an allowed origin. |
| `POST /api/bootstrap/onboard` | Run the guided onboarding action. | The route requires the local session cookie and an allowed origin. |
| `POST /api/bootstrap/start` | Start `dist/index.js`. | The route does not accept an arbitrary executable. |
| `POST /api/bootstrap/dev` | Start `ts-node src/index.ts`. | Use this action only for local development. |
| `POST /api/bootstrap/stop` | Stop the controlled service. | The route does not stop another AgentWall process. |

## Policy decision example

Ask for a policy decision. The token is mandatory. The route returns `401` without it.

```bash
curl -s http://127.0.0.1:3000/evaluate \
  -H "authorization: Bearer $AGENTWALL_OPERATOR_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"agentId":"demo","plane":"network","action":"http_get",
       "payload":{"url":"http://169.254.169.254/latest/meta-data/"},
       "flow":{"direction":"egress"}}'
```

```json
{"decision":"deny","riskLevel":"critical",
 "matchedRules":["net:block-ssrf-private","net:block-metadata-endpoint"],
 "reasons":["Request targets a private or local network address",
            "Request targets a cloud metadata endpoint"],
 "detections":[{"id":"det.net.ssrf.private","mitreAttack":{"techniqueId":"T1190"}},
               {"id":"det.net.metadata.access","mitreAttack":{"techniqueId":"T1552.005"}}]}
```

The caller must enforce the decision. `/evaluate` does not execute or stop the requested action.

## Authentication

`/health` and `/api/health` are public.

Every other service route requires `Authorization: Bearer $AGENTWALL_OPERATOR_TOKEN`. `/ready` also requires this token.

`AGENTWALL_ALLOW_LOOPBACK_DEV=1` bypasses the token for loopback callers. Use this value only for local development.

The bootstrap API uses its local session cookie instead of `AGENTWALL_OPERATOR_TOKEN`. Each bootstrap mutation also checks the request origin.

## Service routes

```text
POST /evaluate                                          # policy decision
POST /inspect/content                                   # DLP secret and PII scan, redaction
POST /inspect/network                                   # egress and SSRF inspection
POST /inspect/manifest                                  # manifest drift detection
POST /approval/request    GET /approval/pending         # approval queue
POST /approval/:requestId/respond
POST /integrations/communication-channel/guardrail      # channel containment
POST /integrations/damage-control/command-preflight     # shell command preflight
GET  /detections          GET /rules                    # detection catalog, active rules
GET  /api/dashboard/state GET /api/dashboard/events      # operator console state, SSE stream
GET  /api/org/summary                                   # multi-instance summary
POST /reload              GET /reload                   # config and policy reload, see docs/reload.md
GET  /api/fleet                                         # declared agents, live budget counters
GET  /evidence            GET /evidence/session/:id     # read-only evidence viewer, HTML
GET  /api/evidence        GET /api/evidence/session/:id # the same report as JSON
GET  /evidence/fleet      GET /evidence/fleet/host/:id  # read-only fleet evidence, HTML
GET  /api/evidence/fleet  GET /api/evidence/fleet/host/:id # the same report as JSON
GET  /health              GET /ready                    # liveness; /ready needs the token
```

### Route limits

| Capability | Limit |
| --- | --- |
| `/inspect/content` | The configured body-size limit bounds the content scan. |
| `/api/dashboard/events` | The SSE stream reports live state only. It is not the audit record. |
| `/api/org/summary` | It summarizes connected or configured instances only. |
| `/api/fleet` | It reports the declared agents for this instance. It does not discover every host process. |
| Evidence routes | They show records that AgentWall received. They cannot prove that an unobserved action did not occur. |
| `/reload` | A malformed configuration causes the reload to fail. The service does not use the malformed values. |

## Typed operator actions

| Method and path | Purpose | Limit |
| --- | --- | --- |
| `GET /api/operator/actions` | List the supported read-only and mutating actions. | The list contains allowlisted actions only. |
| `POST /api/operator/actions` | Submit one typed operator action. | The route rejects unknown actions and arbitrary shell input. |

A read-only action returns status and output. It also returns a copyable AgentWall CLI command.

A mutating action requires operator authentication. It also requires an allowed origin.

A destructive action returns `409` until the request includes confirmation. A schema error returns `400`.

Missing operator authentication returns `401`. A disallowed origin returns `403`.

A completed action returns `200`. The response contains `ok`, `action`, `status`, `message`, and `next`.

The response can contain typed `data`. It never contains raw secrets in list, status, or error data.

The typed command path accepts only declared binaries and arguments. It rejects shell metacharacters, command substitution, and path traversal.

## Configuration file resolution

AgentWall checks configuration locations in this order:

1. `--config <path>`
2. `$AGENTWALL_CONFIG`
3. `./agentwall.config.yaml`
4. `./agentwall.config.yml`
5. `./examples/config.yaml`

See [`src/config.ts:179-187`](../src/config.ts).

Paths inside the configuration are relative to the working directory. Run AgentWall from the directory that contains the initialized files.

## Environment variables

| Variable | Effect | Limit or default |
| --- | --- | --- |
| `AGENTWALL_OPERATOR_TOKEN` | Sets the bearer token for non-public service routes. | When unset, protected routes return `401`. |
| `AGENTWALL_ALLOW_LOOPBACK_DEV` | Lets loopback callers omit the bearer token when set to `1`. | Use it only for local development. |
| `AGENTWALL_AUDIT_FILE` | Sets the hash-chained audit log path. | It has no default. When unset, AgentWall writes audit events to stdout only. |
| `AGENTWALL_FLEET_EVIDENCE` | Sets the fleet evidence sources file. | When unset, `/evidence/fleet` returns `503` and names this variable. AgentWall reads the file for each request. |
| `AGENTWALL_PROXY_PORT` | Sets the forward proxy port. | When unset or `0`, the proxy does not start. |
| `AGENTWALL_PROXY_HOST` | Sets the proxy bind host. | It defaults to `127.0.0.1`. |
| `AGENTWALL_PROXY_LEDGER` | Sets the flat JSONL destination ledger path. | It has no default. The audit chain remains the record when this variable is unset. |
| `AGENTWALL_AGENT_HOME` | Sets the agent behavior contract directory for dashboard probes. | It defaults to `~/.agentwall/agent`. |
| `AGENTWALL_TELEGRAM_TEST_BOT_TOKEN` | Sets the bot token for the Telegram containment routes. | When unset, AgentWall disables those routes. |
| `AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET` | Sets the secret that Telegram presents to the webhook. | The webhook must receive the same value. |
| `AGENTWALL_TELEGRAM_TEST_AGENT_ID` | Sets the recorded agent id for webhook messages. | It applies only to that webhook. |
| `AGENTWALL_TELEGRAM_TEST_SEND_ENABLED` | Permits outbound sends when set to `1`. | The default permits receive operations only. |
| `AGENTWALL_CONFIG` | Sets an explicit configuration path. | `--config <path>` has higher precedence. |

See [fleet evidence](fleet-evidence.md) and [examples/fleet-evidence.yaml](../examples/fleet-evidence.yaml) for `AGENTWALL_FLEET_EVIDENCE`.

## `fleet` configuration

The optional `fleet` section declares agents that share one host. It gives each declared agent separate identity, egress, and budget values.

When `fleet` is absent, records use the process `comm` as `agentId`. One global allowlist then governs all agents.

A malformed `fleet` section stops startup. AgentWall does not fall back to the global allowlist after a fleet validation error.

| Key | Effect | Limit or default |
| --- | --- | --- |
| `fleet.unmatched` | Controls egress that AgentWall cannot attribute. | `global` uses the process-wide allowlist. `deny` refuses it in guarded and strict modes. Monitor mode records it only. |
| `fleet.minimumMatchTier` | Sets the weakest accepted identity proof. | Use `any`, `uid`, or `credential`. The default is `any`. This key does not govern an unclaimed connection. |
| `fleet.credentialStore` | Sets the issued-credential store path. | It is relative to the configuration file. The default is `fleet-credentials.json` beside that file. Use `agentwall fleet` to manage it. |
| `fleet.agents[].id` | Sets the principal in `agentId`. | `match.subject.agentId` binds to this value in declarative rules. |
| `fleet.agents[].label` | Sets the console name. | It defaults to the id. |
| `fleet.agents[].match.uid` | Matches the socket owner from `/proc/net/tcp`. | This is the only listed signal that an agent cannot assert about itself. |
| `fleet.agents[].match.comm` | Lists accepted process names. | The process declares this value. See [fleet.md](fleet.md). |
| `fleet.agents[].match.credential` | Sets `sha256:<64 hex>`, `env:<VAR>`, or `issued`. | AgentWall matches `Proxy-Authorization` and strips it before forwarding. It rejects literal secrets. |
| `fleet.agents[].egress.allowedHosts` | Replaces the global host allowlist for one agent. | Omit it to inherit the global list. |
| `fleet.agents[].egress.allowedPorts` | Replaces the global port allowlist for one agent. | Omit it to inherit the global list. |
| `fleet.agents[].budget.windowSeconds` | Sets the sliding budget window. | Counters measure only this window. |
| `fleet.agents[].budget.maxRequests` | Sets connections per window. | AgentWall refuses the next excess connection before it opens a socket. |
| `fleet.agents[].budget.maxBytes` | Sets bytes in both directions per window. | Admission control refuses the next connection. AgentWall does not truncate a live connection. |

An `issued` credential uses the digest from `fleet.credentialStore`. AgentWall can rotate it with overlap and revoke it without restart.

AgentWall rejects a configuration digest for an agent that also has an issued credential.

See [Fleet governance](fleet.md) for all fleet validation errors.
