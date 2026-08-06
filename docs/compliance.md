# Configuration score

Whether the controls AgentWall has are switched on in *your* deployment. This is a different
question from which controls exist, and the two come apart badly in practice: every control
in the [control mapping](owasp-mapping.md) can be present in the code and disabled in the
configuration, and the resulting deployment inspects nothing while looking, from the outside,
exactly like a protected one.

Implemented in [`src/compliance/score.ts`](../src/compliance/score.ts). Call
`scoreConfig(description)` and you get a total, a grade, and a per-category breakdown with
remediation text for anything short of full marks.

Read the [Limits](#limits) section before treating a grade as an answer.

## What you pass in

`scoreConfig` takes a description of the whole deployment, not just the YAML file. Half of
AgentWall's posture lives in environment variables — the operator token, the audit file path,
the proxy port, the kill-switch sentinel — deliberately, because a security product should
not invent a location in `$HOME` or bake a credential into a file people commit. A scorer
that read only the config document would award a clean bill of health to a deployment with no
authentication and no durable audit trail.

So the input is the config document's own keys plus an `env` map:

```ts
scoreConfig({ ...loadConfig(), env: process.env, enforcement: { mode: "strict" } });
```

The `env` map is passed in rather than read from `process.env` inside the function. Reaching
for a global would make the result depend on ambient state the caller cannot see, which is
wrong for something whose whole output is a claim about a specific configuration — and it
would make the same description score differently in a test than in production.

`auth: { operatorTokenSet: true, allowLoopbackDev: false }` is accepted as an alternative to
the corresponding environment variables, for a caller that has already resolved them.

**Absence scores zero, not "unknown".** A scorer that gave the benefit of the doubt would
rate an empty object highly, which is the opposite of useful. The consequence worth knowing:
forget to pass `env` and the result is an F, and that is correct rather than a bug — you have
described a deployment with no operator token.

## Categories and point budget

Fifteen categories, 120 points.

| Category id | What it reads | Max | Full marks require |
| --- | --- | --- | --- |
| `auth.operator-token` | `env.AGENTWALL_OPERATOR_TOKEN` or `auth.operatorTokenSet` | 15 | A token is set |
| `auth.exposure` | `env.AGENTWALL_ALLOW_LOOPBACK_DEV` or `auth.allowLoopbackDev`, against `host` | 10 | The development auth bypass is off |
| `audit.evidence-file` | `env.AGENTWALL_AUDIT_FILE` | 10 | Records go to a file, not just stdout |
| `audit.anchoring` | `audit.anchorIntervalMs` | 5 | A positive anchoring interval |
| `proxy.insertion` | `env.AGENTWALL_PROXY_PORT` (6), `env.AGENTWALL_PROXY_LEDGER` (2) | 8 | Proxy configured, flat ledger configured |
| `enforcement.mode` | `enforcement.mode` | 10 | `strict`, with a populated allowlist |
| `egress.allowlist` | `egress.enabled` (3), `defaultDeny` (3), `allowedHosts` (2), `allowPrivateRanges` (2) | 10 | Enabled, default-deny, hosts listed, private ranges off |
| `policy.default-decision` | `policy.defaultDecision` | 8 | `deny` |
| `policy.rule-file` | `policy.configPath` | 6 | An external policy file is loaded |
| `approval.mode` | `approval.mode` (5), `approval.backend`/`persistencePath` (3) | 8 | `always`, persisted to a file |
| `runtime.rate-limits` | `runtimeGuards.enabled` (3), the three ceilings (3) | 6 | Enabled, all three ceilings positive |
| `dlp.content-scanning` | `dlp.enabled` (4), `dlp.redactSecrets` (2) | 6 | Both on |
| `telemetry.decision-traces` | `telemetry.enabled` and `telemetry.endpoint` | 4 | Enabled with an endpoint |
| `killswitch.sentinel` | `env.AGENTWALL_KILLSWITCH_FILE` (4), `watchdog.enabled` (2), `watchdog.killSwitchMode` (2) | 8 | Sentinel path set, watchdog on, mode `deny_all` |
| `integrity.manifest` | `manifestIntegrity.enabled` (4), `approvedHashesPath` (2) | 6 | Enabled with a persisted hash file |

The weights are a judgement, and the shape of that judgement is worth stating: enforcement
and authentication carry the most because their absence makes the rest decorative, and
telemetry carries the least because it is how you *see* what the boundary did rather than
part of the boundary — the audit chain is the record. Skipping telemetry entirely is a
defensible choice and costs four points.

Every category returns `findings` describing what was actually read, and a `remediation`
string whenever it scored below its max.

## Grades

| Grade | Threshold |
| --- | --- |
| A | 90% or more |
| B | 80% |
| C | 70% |
| D | 60% |
| F | below 60%, or any critical exposure |

## Critical-exposure caps

This is the part of the model that matters most.

A weighted average is the wrong shape for security posture. Fourteen categories scored well
and one catastrophic hole averages out to a B, and a B tells the operator to move on. An
unauthenticated control plane is not eighty-seven percent secure; it is an open door with
excellent logging. So certain findings force `F` regardless of the numeric total and set
`capped` to the reason:

1. **No operator token.** The deployment is either unauthenticated, if the loopback
   development bypass is carrying it, or inert, if nothing is, because every non-public route
   returns 401. Neither is a deployment anyone should be told is a B.
2. **The loopback development bypass enabled while bound to a non-loopback host.** Anyone who
   can reach the listener is an operator. Note that `0.0.0.0` and `::` count as non-loopback
   here, which is the case this check exists to catch: binding every interface is a
   legitimate posture for a container, and it stops being legitimate the moment the auth
   bypass is on.

A cap is a claim that the deployment is **exploitable as configured**, not that it is
suboptimal. The list is deliberately short for exactly that reason. Monitor mode,
default-allow policy, and absent telemetry all cost points and none of them cap, because each
is a legitimate posture for someone who has chosen it — monitor mode in particular is the
recommended first posture while you learn what your agent actually reaches. A cap that fires
on a defensible choice teaches operators to ignore caps.

`capped` includes the numeric total it overrode, so the report says what the arithmetic
thought before the cap intervened.

## Worked shape

A description with every signal set as recommended scores 120/120 and grades A. Remove the
operator token from that same description and the total is 105/120 — comfortably a B on the
arithmetic — and the grade is F with `capped` explaining why. That gap between 87% and F is
the entire point of the model.

## Limits

- **The score reads your configuration, not your running system.** It cannot tell you that
  the process is using the description you handed it, that the audit path is writable, that
  the proxy is reachable, that the token in that environment variable is strong rather than
  the word `token`, or that any of it is working. A high score is a statement about a
  document.
- **It scores a named set of signals, not everything that matters.** Fifteen categories are
  fifteen categories. A high score means nothing on this list is obviously wrong, not that
  the deployment is secure, and a deployment can score A while being wrong in a way this
  model does not look at.
- **The weights and thresholds are a judgement, not a standard.** There is no authority
  behind "15 points for authentication" or "90% is an A". They encode this project's opinion
  about what matters most, they are visible in
  [`src/compliance/score.ts`](../src/compliance/score.ts) so you can disagree with them
  specifically, and a grade is not a certification of anything.
- **A grade is not a mapping.** The [control mapping](owasp-mapping.md) answers which
  controls exist and carries its own, separate limits. Neither page answers the other's
  question, and a good score on this one with a `none` rating on that one means the control
  you need is absent however well you configured the ones that are present.
