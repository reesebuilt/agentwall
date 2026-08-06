# API and configuration reference

## A policy decision, end to end

Ask for a policy decision. The token is mandatory; without it this returns `401`:

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

## API

Every route except `/health` and `/api/health` requires `Authorization: Bearer <token>`.

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
GET  /health              GET /ready                    # liveness; /ready needs the token
```

## Configuration

Config resolution order: `--config <path>`, `$AGENTWALL_CONFIG`, `./agentwall.config.yaml`,
`./agentwall.config.yml`, `./examples/config.yaml`
([`src/config.ts:179-187`](../src/config.ts)). Paths inside the config are relative to the working
directory, so run Agentwall from the directory you ran `init` in.

| Variable | Effect |
| --- | --- |
| `AGENTWALL_OPERATOR_TOKEN` | Bearer token for every non-public route. Unset means everything returns `401`. |
| `AGENTWALL_ALLOW_LOOPBACK_DEV` | `1` accepts loopback callers without a token. Local development only. |
| `AGENTWALL_AUDIT_FILE` | Path for the hash-chained audit log. No default, by design: a security product should not invent a location in `$HOME`. Unset means stdout only. |
| `AGENTWALL_PROXY_PORT` | Forward proxy port. Unset or `0` means the proxy does not start. |
| `AGENTWALL_PROXY_HOST` | Proxy bind host. Defaults to `127.0.0.1`. |
| `AGENTWALL_PROXY_LEDGER` | Flat JSONL view of destinations, for allowlist analysis. No default, same reason as the audit file. Unset means no flat ledger; the audit chain is still the record. |
| `AGENTWALL_AGENT_HOME` | Directory the dashboard probes for an agent behaviour contract. Defaults to `~/.agentwall/agent`. |
| `AGENTWALL_TELEGRAM_TEST_BOT_TOKEN` | Bot token for the Telegram containment routes. Unset disables them. |
| `AGENTWALL_TELEGRAM_TEST_WEBHOOK_SECRET` | Shared secret Telegram must present on the webhook. |
| `AGENTWALL_TELEGRAM_TEST_AGENT_ID` | Agent id recorded for messages arriving on that webhook. |
| `AGENTWALL_TELEGRAM_TEST_SEND_ENABLED` | `1` permits outbound sends. Default is receive-only. |
| `AGENTWALL_CONFIG` | Explicit config path. |

### `fleet`

Optional. Declares the agents that share this host so that identity, egress allowlists, and
budgets are per-agent instead of per-instance. Omit it and every earlier version's behaviour
is unchanged: records carry the process `comm` as the `agentId` and one allowlist governs
everything.

| Key | Effect |
| --- | --- |
| `fleet.unmatched` | `global` (default) judges unattributed egress by the process-wide allowlist. `deny` refuses it in guarded and strict. Monitor still only records. |
| `fleet.agents[].id` | The principal recorded as `agentId`, and what `match.subject.agentId` in a declarative rule binds to. |
| `fleet.agents[].label` | Human name for the console. Defaults to the id. |
| `fleet.agents[].match.uid` | Socket owner from `/proc/net/tcp`. The only signal an agent cannot assert about itself. |
| `fleet.agents[].match.comm` | Process names to accept. Self-declared by the process; see [fleet.md](fleet.md). |
| `fleet.agents[].match.credential` | `sha256:<64 hex>` or `env:<VAR>`. Matched against `Proxy-Authorization`, which is stripped before the request reaches the destination. A literal secret is rejected at start-up. |
| `fleet.agents[].egress.allowedHosts` | Replaces the global host allowlist for this agent. Omit to inherit it. |
| `fleet.agents[].egress.allowedPorts` | Replaces the global port allowlist for this agent. Omit to inherit it. |
| `fleet.agents[].budget.windowSeconds` | Sliding window the counters are measured over. |
| `fleet.agents[].budget.maxRequests` | Connections per window. Exact: the next one is refused before any socket opens. |
| `fleet.agents[].budget.maxBytes` | Bytes both directions per window. Enforced at admission, so it refuses the next connection rather than truncating a live one. |

A malformed `fleet` section refuses to start rather than falling back, because a match block
with a typo binds nothing and silently drops the agent back to the global allowlist. The full
list of refusals is in [Fleet governance](fleet.md).
