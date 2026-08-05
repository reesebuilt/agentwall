# Agentwall Project Context

Context file for coding agents working in this repository. Humans should read
`CONTRIBUTING.md` first; this file only adds the conventions an agent tends to get wrong.

Source of truth
- config: whatever `AGENTWALL_CONFIG` points at, else `agentwall.config.yaml` in the repo root
- runtime status endpoint: `<base-url>/api/dashboard/state`
- org federation summary endpoint: `<base-url>/api/org/summary`
- `examples/monitor-first.config.yaml` is the bundled starting point and listens on `127.0.0.1:3015`

Working rules
- prefer existing Agentwall CLI and dashboard routes over ad hoc scripts
- preserve `defaultDeny` egress posture and watchdog intent
- an agent harness is an optional external integration, not the Agentwall product center
- keep the model generic: instance → gateway → channel → agent → action → policy

Never commit
- chat/channel/thread ids, host names, LAN or VPN addresses, absolute home paths, or the
  name of any private agent, machine, or service. This is a public repository. Use
  `example.com`, `203.0.113.10` (TEST-NET-3), `agent-1`, `operator`, `<your-host>`, and
  Telegram's documentation chat id `-1001234567890`.

What done means
- the local Agentwall operator path works
- dashboard/control-plane checks are real, not asserted
- `npx tsc --noEmit` and `npm test` both pass
- security-sensitive changes are reviewed, or open findings are named explicitly
