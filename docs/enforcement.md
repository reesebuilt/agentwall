# Egress enforcement

Everything else in AgentWall observes. This is the part that refuses.

The forward proxy sees every destination a cooperating agent reaches for and writes it to a
tamper-evident chain. Enforcement turns that observation into a decision: a connection that
policy denies is never opened, and the agent gets a `403` explaining why.

It is off by default. `monitor` is the shipped mode, and an upgrade never changes the mode
you were running, because a security tool that starts blocking traffic on its own is a tool
people uninstall.

## The three modes

| Mode | Blocks | Use it when |
|---|---|---|
| `monitor` | Nothing. Records every destination and reports what the other two modes would have done. | Always, first. |
| `guarded` | Destinations a policy rule denies. Anything no rule matched is allowed. | Your ledger shows the denials are real. |
| `strict` | Every destination outside the egress allowlist. | Your allowlist covers everything the agent legitimately needs. |

### `monitor`

Evaluates the request fully, records the verdict, and always allows the connection.

The verdict's reasons carry the projection:

```
monitor: egress recorded, not gated
monitor: guarded mode would allow
monitor: strict mode would deny — api.vendor.example is not in the egress allowlist
```

Those lines are produced by running the real decision logic for each enforcing mode, not by
a separate estimate of it. What the ledger says `strict` would do is what `strict` does. That
is the property the whole adoption path rests on: you should be able to change modes from
reading, not from trying it in production and watching what breaks.

A monitor verdict's decision is always `allow`, because the connection really was made.
Evidence that recorded a denial for a request that succeeded would be worse than no evidence.

### `guarded`

Enforces `deny` verdicts that a policy rule actually produced. A destination no rule matched
is allowed.

That last sentence is load-bearing: the policy engine's *default* decision is `deny`, so
"nothing matched" comes back from the engine as a denial. Guarded mode deliberately ignores
that default and keys on whether a rule matched. Otherwise switching to guarded would
silently hand you allowlist-only enforcement without an allowlist.

### `strict`

Allowlist-only, on both halves of the destination. The host must appear in
`egress.allowedHosts` **and** the port in `egress.allowedPorts`, or the connection is refused,
whether or not any rule had an opinion about it. Rules still apply on top: an allowlisted
destination that a rule denies is still denied.

Host and port are one destination and are judged together. An agent that can reach
`allowlisted.example.com` on any port it names turns a web allowlist into shell, database, or
admin access on that same host, so an allowlisted host on a port you did not list is a denial,
and the reason names the port and the permitted set rather than only the host.

Matching is an exact hostname match after normalisation — lowercased, IPv6 brackets stripped,
trailing DNS root dot removed. There are no wildcards and no suffix matching. `example.com`
in the allowlist does not permit `api.example.com`; list both.

The allowlist gate does not depend on its own policy rule being present. If you replace the
rule set, strict mode still refuses non-allowlisted hosts — a mode that quietly degraded to
`guarded` because a rule went missing would be the worst kind of failure this design can have.

## Configuring it

```yaml
enforcement:
  mode: monitor          # monitor | guarded | strict

egress:
  allowedHosts:          # strict mode's host allowlist
    - api.vendor.example
    - github.com
  allowedPorts:          # strict mode's port allowlist; both must match
    - 443
```

Omit the `enforcement` section entirely and you get `monitor`. Config files written before
enforcement existed keep working unchanged.

**An unrecognised mode is a hard startup failure, by design.** `mode: strct` does not fall
back to anything:

```
agentwall: invalid enforcement.mode "strct" in /etc/agentwall/config.yaml.
Valid modes are "monitor", "guarded", and "strict". Omit the enforcement section
entirely to use "monitor".
```

Both silent alternatives are worse than not starting. Falling back to `monitor` leaves you
believing you are enforcing while nothing is gated. Falling forward to `strict` turns a typo
into an outage nobody ordered. Refusing to boot is the only outcome that cannot mislead you,
and the message names the file, the key, the rejected value, and the valid set so the fix
takes seconds. This is deliberate, not brittleness.

Mode and allowlist are read once at start-up. Changing either needs a restart, appropriate
ceremony for a change that can take an agent fleet offline. A reload reports both as
restart-required rather than pretending to apply them. Policy *rules* are not part of that
bargain: a hot-reloaded rule takes effect on the next connection without a restart. See
[Config and policy reload](reload.md) for what reloads, what does not, and how a reload is
recorded.

## The recommended adoption path

1. **Run `monitor`.** Point your agents at the proxy and leave it for as long as your traffic
   takes to be representative. A week covers most weekly cron work; a day is usually enough
   for an interactive agent.
2. **Read your ledger.** Set `AGENTWALL_PROXY_LEDGER` for a flat JSON-lines view alongside
   the audit chain. Every line carries the host, port, the originating process where
   attribution succeeded, and the monitor projections. The `strict mode would deny` lines are
   your allowlist to-do list.
3. **Build the allowlist** from the destinations you recognise. Anything you do not recognise
   is the finding you turned this on for.
4. **Switch to `guarded`.** Now a destination a rule denies — a private-range target, a cloud
   metadata endpoint — is actually refused. Unknown destinations still pass, so this cannot
   break a working agent on something you forgot to list.
5. **Switch to `strict`** once the allowlist is complete. At this point an agent that has been
   talked into calling somewhere new fails instead of succeeding.

Steps 4 and 5 are separate on purpose. Guarded proves that blocking works in your environment
and that a `403` propagates through your agent sensibly, without the blast radius of an
incomplete allowlist.

## What a blocked request looks like to the agent

Both proxy paths return `403` with an `X-Agentwall-Block-Reason` header carrying the first
reason from the verdict, so a developer debugging a broken agent sees a cause rather than a
mystery failure.

Plain HTTP:

```
HTTP/1.1 403 Forbidden
X-Agentwall-Block-Reason: api.vendor.example is not in the egress allowlist

agentwall: destination not allowed
```

HTTPS, refused at `CONNECT` before the tunnel exists:

```
HTTP/1.1 403 Forbidden
X-Agentwall-Block-Reason: Request targets a private or local network address
Connection: close
```

No upstream socket is opened on either path. A denied destination does not see a TCP
handshake it could log.

The reason is collapsed to printable ASCII and capped in length before it goes in the header.
Reasons are built from destinations the agent chose, and an unsanitised one would let the
agent inject headers into the proxy's own refusal — or, on the `CONNECT` path where the
response is written to the socket by hand, forge an entire second response.

Most HTTP clients surface a proxy `403` as a connection error rather than as a response, so
expect your agent to report something like "could not reach host", and expect to need the
ledger to find out why. The header is there for whoever thinks to look at the raw exchange.

## The lockdown overrides the mode, including monitor

When the operator lockdown is engaged, every proxied egress attempt is denied with risk
`critical`, in all three modes, with the holding sources named in the reason.

This is the one place monitor mode does not merely observe. An emergency stop that the
majority of deployments ignore because they are still early in their adoption path is not an
emergency stop, it is a status field. The cost is real and worth stating plainly: running
AgentWall in monitor mode does give a component the ability to halt all proxied egress. That
is why the switch has an explicit, audited activation rather than being inferred from health
signals.

The verdict still reports the configured mode truthfully. A monitor-mode ledger shows
`mode: monitor` next to a denial, because both facts matter when you read it back.

## Evidence

Every proxied request produces an audit-chain event carrying the real decision, the real
reasons, the rules that matched, the assessed risk, and the mode that was active. "Allowed"
means something different in monitor than in strict, so a ledger that omitted the mode could
not be read back a month later.

In monitor mode the structured fields — matched rules, detections, risk — describe what
policy actually found. The projections live only in the reasons. A detection named "blocked
egress" attached to a request that was allowed would be a false statement in evidence that
is supposed to be trustworthy, so building an allowlist means grepping the ledger for
`strict mode would deny`, not for a detection id.

Risk is reported as `low` when no rule matched, even though the policy engine classifies
every egress flow as high-risk by construction. That classification is right for a flow
classifier and useless in a ledger — it would stamp a finding on every ordinary model API
call and leave you with nothing to triage.

Three detections are specific to enforcement:

- `det.net.egress.blocked` — strict mode refused a non-allowlisted destination.
  MITRE ATT&CK T1071, Application Layer Protocol (Command and Control).
- `det.governance.lockdown.active` — the emergency stop refused an action.
  MITRE ATT&CK T1489, Service Stop (Impact).
- `det.net.sni.connect-mismatch`: a tunnel whose CONNECT authority and negotiated SNI named
  different hosts. Deliberately unmapped to ATT&CK, because the technique it resembles is one
  this cannot observe. See the limits below, and `unmappedDetections()` for why an honest
  blank beats a wrong technique id.

## What the proxy sees of a TLS connection

A `CONNECT` line is a string the client typed. The proxy now also reads the ClientHello, the
first record of the TLS handshake, which the client sends in the clear before any key
exchange completes. The SNI extension in it carries the hostname the client is actually
asking the server for. Reading it needs no CA, no trust-store change, and no ability to
decrypt anything: this is an observation, not interception.

Two things follow.

**The destination gets a second, better source.** A record for a tunnelled connection carries
`metadata.sni` when a name was recovered. Absent means no name was available, which covers a
client that omits SNI, an Encrypted Client Hello, a non-TLS protocol tunnelled over CONNECT,
and a handshake that never arrived whole. There is no guessing in between.

**Disagreement is recorded and acted on.** When the SNI differs from the CONNECT authority,
the record carries `metadata.sniMismatch` and the rule `net:sni-connect-mismatch`, and policy
is evaluated a second time against the negotiated name. That second evaluation runs only
after the first said allow, so it can refuse what the CONNECT line was permitted to do and
can never permit what it was refused. An IP-literal CONNECT authority always registers as a
disagreement, because an address can never equal a hostname; on that path the flag means the
CONNECT line carried no name to compare, not that anyone lied.

What this does NOT give you is content. See the limits below before drawing a wider
conclusion from it than the code supports.

## Limits

Read these before relying on enforcement for anything.

- **Only traffic through the proxy is governed.** Enforcement is a property of the forward
  proxy, not of the host.
- **Capture is cooperative here, and enforcement does not change that.** A process that
  ignores `HTTP_PROXY` / `HTTPS_PROXY` — because it was written to, because it uses a client
  that does not read them, or because it was told not to — is neither observed nor blocked
  by the forward proxy. It is not that AgentWall allows it; AgentWall never sees it.
- **Transparent redirection is available, separately and opt-in.** The forward proxy adds no
  firewall rules and needs no privilege. A perimeter does: it runs the agent under its own
  UID and has nftables redirect that UID's outbound TCP into the proxy, which removes the
  cooperation requirement at the cost of root, Linux, and a deliberate install. It is off
  unless you set it up, and it does not contain DNS. See [perimeter.md](perimeter.md).
- **Decisions are made from host, port, scheme, and negotiated SNI.** The proxy does not
  terminate TLS, so the body, path, and headers of a request are not visible and cannot
  inform the decision. That is true of plaintext HTTP too, and not only of HTTPS: an http
  request is relayed without its body or path being read, so the limit is a property of the
  proxy rather than of encryption. Terminating TLS would need a CA in every runtime trust
  store, which would break the harness-agnostic property the proxy exists for.
- **Content inspection does not run on proxied traffic at all.** DLP, PII, and injection
  scanning exist, and none of them are on this path. They run on content AgentWall is handed
  directly: `/inspect/*` and `/evaluate` payloads, the MCP frames it wraps, channel messages,
  and watched file writes. A secret in an https body is invisible because the body is
  encrypted; a secret in an http body is invisible because nothing scans it. Neither is
  detected, and a deployment that needs egress content scanning does not get it here.
- **Adding interception is not a small change, and the cost is not only the CA.** Minting a
  leaf certificate per destination means issuing X.509, and Node cannot: `crypto.X509Certificate`
  parses and verifies, it does not sign. Closing this gap therefore means either a fourth
  runtime dependency or shelling out to `openssl` on the connection path. This package has
  exactly three runtime dependencies and keeps it that way on purpose, so that trade is an
  architectural decision rather than an implementation detail, and it is unmade. Anyone
  planning to rely on egress content scanning should read that as "not available", not as
  "coming".
- **The SNI cross-check catches a self-contradicting client, not domain fronting.** A CONNECT
  authority is a string the client typed; the SNI is what it then negotiated. When they
  disagree the proxy records `net:sni-connect-mismatch` and re-evaluates policy against the
  negotiated name, which can only ever add a denial, because it runs after an allow. What it
  cannot see is the fronting case ATT&CK calls T1090.004: there the real destination is in
  the HTTP Host header inside the TLS session, every layer the proxy can read agrees, and the
  connection passes. The detection is left unmapped in the catalog for exactly that reason.
- **A name recovered from a ClientHello is a hostname and nothing else.** No port, no path,
  no header, no body. A client that omits SNI, uses Encrypted Client Hello, or tunnels a
  non-TLS protocol produces no name at all, and the CONNECT authority stands alone. That is
  a fail-open by design: the destination was already authorised before the peek ran.
- **An SNI denial costs the destination a TCP handshake.** A CONNECT-level deny opens no
  upstream socket at all. An SNI-level deny cannot, because the name only exists after the
  tunnel is up: the connection is torn down with zero payload bytes forwarded, but the
  destination did see a connection open and close.
- **Only `deny` is enforceable on a connection.** A rule returning `approve` or `redact` for
  an egress destination is recorded and the connection is allowed. There is nothing to answer
  an approval prompt on a TCP connect, and redaction needs bodies the proxy cannot read. If a
  destination must not be reached, keep it off the allowlist and run `strict`; do not rely on
  an `approve` rule to stop it.
- **The allowlist is global to the process.** One AgentWall instance enforces one allowlist.
  Per-agent allowlists need per-agent instances.
- **`strict` with an empty `allowedHosts` or an empty `allowedPorts` denies everything.** That
  is the honest consequence of allowlist-only rather than a bug, but it is worth knowing
  before a restart. Both lists are allowlists, so empty means nothing is permitted rather than
  everything. The start-up log reports the mode and the allowlist size for exactly this reason.
