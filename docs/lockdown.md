# Emergency stop (lockdown)

A global stop for the AgentWall process. While it is engaged, egress decided by AgentWall is
denied, and every transition is on the audit chain.

The reason it exists as its own control, rather than as "set the policy to deny everything",
is speed and reversibility: an operator watching something go wrong needs one action that
takes effect immediately, needs no policy file edit, and can be undone by the same person
through the same channel a minute later.

## Four ways to engage it

Every source below is independent, and **any one of them holding is enough**. They are
redundant on purpose. The moment you need an emergency stop is the moment your usual control
path is the thing that is broken, so a stop that only has one door is a stop you cannot
count on.

| Source | Engage | Release |
| --- | --- | --- |
| `config` | Start the process with the lockdown seeded on (`initLockdown({ configActive: true })`) | `releaseLockdown("config")` in-process |
| `api` | `POST /lockdown/engage` | `POST /lockdown/release` |
| `signal` | `kill -USR1 <pid>` | `kill -USR1 <pid>` again — SIGUSR1 toggles |
| `sentinel` | Create the file named by `AGENTWALL_LOCKDOWN_FILE` | Delete that file |

### `config`

For a host that must come up stopped: a machine being rebuilt, a staging box that should
never reach the network until somebody says so, a recovery boot after an incident. Nothing
that arrives over the network can lift it.

### `api`

The normal path. Both routes sit behind the operator bearer token — they are **not** in the
public allowlist in `src/auth/operator.ts`, and must not be added to it. An unauthenticated
caller who could engage the stop would have a one-request denial of service against every
agent on the host.

```
curl -sS -X POST http://127.0.0.1:8080/lockdown/engage \
  -H "Authorization: Bearer $AGENTWALL_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"suspected exfiltration from the research agent"}'
```

`reason` is optional, trimmed, and capped at 512 characters. It is recorded in the audit
event and echoed in every later state response, so write it for the person reading the
timeline next week.

### `signal`

```
kill -USR1 $(pgrep -f 'node .*agentwall')
```

No network, no token, no JSON. This is the path that works when the HTTP surface is wedged
or the operator token is on a laptop that is not in the room.

SIGUSR1 **toggles**: sending it again releases the `signal` hold. It has to toggle, because
the person sending it has no reply channel to read the current state from and needs the same
key to work both ways. SIGUSR2 was not used — common Node tooling claims it — and the
terminating signals already mean something. The cost of a toggle is that two people
signalling at once can cancel each other out, which is one reason the API and sentinel
channels are level-triggered instead.

### `sentinel`

Set `AGENTWALL_LOCKDOWN_FILE=/run/agentwall/STOP` and the process stats that path once a
second. The file existing means stopped; the file being gone means this source is not
holding. Contents are ignored — a directory at the path counts, which is deliberate: the
check is "did somebody put a marker here", and being permissive fails safe.

```
touch /run/agentwall/STOP     # engage
rm /run/agentwall/STOP        # release
```

A file is a source at all because it is the one channel that still works when the HTTP
surface is wedged and the operator has nothing but a shell — a container `exec`, a
config-management run, a cron script, or a mount written from another host. It needs no
credential, no open port, and no live process to accept it: writing the marker before
AgentWall even starts means AgentWall comes up stopped.

Polling rather than watching is a deliberate choice. `fs.watch` does not fire reliably for
file creation on every platform or across network filesystems, and the channel that has to
work when everything else is broken is the wrong place for a best-effort notification API.
The price is stated under Limits.

## Releasing is per source, never global

`POST /lockdown/release` clears the `api` hold and **only** the `api` hold. If the
sentinel file is still on disk, or the process was configured to boot stopped, the lockdown
stays engaged and the response says so:

```json
{
  "released": "api",
  "active": true,
  "sources": ["config", "sentinel"],
  "since": "2026-08-05T14:02:11.418Z",
  "reason": "engaged by configuration at start-up",
  "detail": "Released the 'api' hold, but the lockdown remains ACTIVE, held by: config, sentinel. Each source must be released through the channel that engaged it."
}
```

Note there is no `ok: true` on that response. Release routinely succeeds at what it was asked
to do while the machine stays stopped, and a success flag there reads as "traffic is flowing
again" — which would send an operator away from a host that is still halted.

This is the property that makes the stop trustworthy. If any channel could clear every hold,
then the weakest channel would set the security of all of them: an HTTP caller could undo a
stop that a human engaged from a shell, and a config-seeded stop would last only until the
first API request. Whoever engaged it releases it, through the same door.

`GET /lockdown` reports the whole picture:

```json
{
  "active": true,
  "sources": ["api", "sentinel"],
  "since": "2026-08-05T14:02:11.418Z",
  "reason": "suspected exfiltration from the research agent"
}
```

`sources` is sorted and lists every source currently holding. `since` is the start of the
current active period — the first activation while nothing else held — and it survives
sources coming and going, so it answers "how long has this box been stopped", not "when was
the most recent button pressed". It is absent when nothing holds the stop. `reason` is the
reason attached to the oldest hold still in place.

Re-engaging a source that already holds is a no-op: no second audit record, and `since` is
not restarted. To change a recorded reason, release and engage again.

## What callers see while it is engaged

`decideEgress` in `src/runtime/enforcement.ts` checks the lockdown first, before anything else
it does. While the lockdown is active, every egress attempt it decides comes back:

- `decision: "deny"`, `riskLevel: "critical"`
- reasons naming the stop and every source holding it
- matched rule `governance:lockdown` and detection `det.governance.lockdown.active`

That check sits ahead of the enforcement-mode branch, so **`monitor` mode does not exempt an
attempt from the stop**. Monitor mode's whole purpose is to observe without blocking, and an
emergency stop that observes is not an emergency stop.

The policy engine is still run on the attempt even though the verdict is already decided, so
the record keeps whatever else was wrong with that destination rather than flattening the
incident into "stopped".

## Evidence

Every transition is emitted through the normal audit path, on the `governance` plane, with
action `lockdown:engage` or `lockdown:release`, and metadata naming the source, the
reason, and the full set of holders after the change.

The recorded decision is the resulting posture rather than the verb. Releasing one of two
holds records `deny`/`critical`, because the stop is still engaged when that record is
written; recording `allow` there would put a line in the evidence claiming traffic resumed at
a moment when it had not.

Recording is wrapped so that it cannot fail the transition. The stop engages first and is
recorded second: a full disk must not be able to prevent an emergency stop from taking
effect. The consequence is honest and worth knowing — under a storage fault the lockdown still
works and the record of it may be missing, which the audit chain's own gap accounting
declares (see [Audit evidence format](audit-format.md)).

## Limits

Read these before relying on the lockdown during an incident.

- **It gates AgentWall's decision paths and nothing else.** It is a flag consulted by code
  inside this process. It does not terminate agent processes, does not revoke API keys or
  session tokens, does not close sockets that are already open, and does not roll back
  anything an agent already did.
- **A process that bypasses the proxy is unaffected.** Egress is intercepted because a
  cooperating client honours the standard proxy environment variables. An agent that ignores
  them, dials a raw socket, or runs outside this host never reaches the check.
- **The sentinel poll costs up to one interval.** Default one second. Between `touch` and the
  stop engaging, traffic still flows. If you need it engaged now and the API is reachable,
  use the API; the file is the channel for when it is not.
- **SIGUSR1 toggles, so a duplicate send un-stops you.** A retry loop or two operators acting
  at once can land on the wrong state. Confirm with `GET /lockdown` when you can, or prefer
  the sentinel file, which is level-triggered and idempotent.
- **It is process-local.** Nothing is replicated. Each AgentWall process has its own lockdown,
  and engaging one does not engage the others; state is not persisted across a restart except
  through the `config` and `sentinel` sources, which are re-read at start-up.
- **It is not a substitute for policy.** It is a blunt, temporary posture meant to be held for
  minutes while a human works out what happened, not a way to run a system.
