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
   your allowlist to-do list. Tunnelled lines also carry `sni`, and `sniMismatch` when it
   differs from the CONNECT authority. Note the shape differs between the two sinks: the flat
   ledger spreads the record, so these are top-level keys, while the audit chain nests them as
   `metadata.sni` and `metadata.sniMismatch`. Grep accordingly.
3. **Build the allowlist** from the destinations you recognise. Anything you do not recognise
   is the finding you turned this on for. Where a line sets `sniMismatch`, allowlist the `sni`
   rather than the CONNECT authority: they disagree, and `sni` is the better-sourced of the
   two. An allowlist built from the typed authority alone can be satisfied by a client that
   names an approved host and then negotiates a different one.
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

Seven detections are specific to enforcement:

- `det.net.egress.blocked` — strict mode refused a non-allowlisted destination.
  MITRE ATT&CK T1071, Application Layer Protocol (Command and Control).
- `det.governance.lockdown.active` — the emergency stop refused an action.
  MITRE ATT&CK T1489, Service Stop (Impact).
- `det.net.sni.connect-mismatch`: a tunnel whose CONNECT authority and negotiated SNI named
  different hosts. Deliberately unmapped to ATT&CK, because the technique it resembles is one
  this cannot observe. See the limits below, and `unmappedDetections()` for why an honest
  blank beats a wrong technique id.
- `det.net.proxy.request_secret`: a plaintext HTTP request carried credential material.
  MITRE ATT&CK T1041, Exfiltration Over C2 Channel.
- `det.net.proxy.request_injection`: a plaintext HTTP request carried injected instructions.
  MITRE ATT&CK T1059, Command and Scripting Interpreter.
- `det.net.proxy.response_injection`: a plaintext HTTP response carried injected
  instructions back to the agent. MITRE ATT&CK T1059.
- `det.net.proxy.response_secret`: a plaintext HTTP response carried credential material
  into the agent's context. Recorded, not refused. MITRE ATT&CK T1552, Unsecured Credentials.

A decoy hit on the proxy path files `identity:deny-decoy-triggered` and
`det.identity.decoy.triggered`, the same ids the rest of the system uses, rather than a
proxy-specific pair. It is the same finding wherever it is seen.

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

## What the proxy reads of a request

Until now, nothing. The DLP engine, the injection scanner, and the decoy tripwires all
existed, were tested, and were wired to zero bytes of proxied traffic: no call site under
`src/proxy/` reached any of them. The documentation described that as a consequence of
encryption, which implied plaintext HTTP was being inspected. It was not.

On plaintext HTTP, and on plaintext HTTP only, the proxy now inspects:

| Surface | Scanned for | On deny |
| --- | --- | --- |
| Request path, including the query string | secrets, PII, injection, decoys | 403 before any upstream socket is opened |
| Request headers | injection and decoys on every header; secrets on every header except `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` | 403 before any upstream socket is opened |
| Request body | secrets, PII, injection, decoys | 403 before any upstream socket is opened |
| Response headers | secrets, PII, injection, decoys | 403, because nothing has been written back yet |
| Response body | secrets, PII, injection, decoys | 403, because nothing has been written back yet |

A secret in a request is refused. Injected instructions in a request or a response are
refused. A decoy anywhere is refused, in guarded and strict, and is refused by the runtime
rather than by a rule so that replacing the rule set cannot switch it off. A secret in a
**response** is recorded and forwarded: an agent reading a credential it is entitled to is
the common case, and denying it breaks far more than it catches. PII is recorded in
`contentPiiTypes` with no rule attached, so a deployment that wants to gate on it can write
one against the marker.

`Authorization` is exempt from credential scanning and from nothing else. A request
authenticating itself to a destination it is already permitted to reach is not exfiltration,
and treating it as such would block every authenticated call an agent makes the moment
guarded mode came on. Decoys and injection patterns are still scanned there, because a decoy
has no false-positive rate to trade against.

Gzip, deflate, and brotli bodies are decompressed for inspection with a bounded output, so a
compressed response is scanned rather than waved through. The bytes forwarded are always the
originals: nothing is rewritten, re-encoded, or stripped, and an allowed exchange is
byte-identical to an unproxied one.

### The byte cap

**256 KiB per body.** The number is the injection scanner's own work cap
(`MAX_SCAN_CHARS`), imported rather than re-guessed, so the proxy never buffers bytes the
scanner would not read and never scans fewer than it holds.

Past the cap the exchange is **not refused**. The first 256 KiB are scanned, the remainder is
streamed through uninspected, `bodyVisibility` on the record reads `partial`, and the reasons
carry `the remainder was forwarded uninspected`. Refusing instead would break ordinary agent
traffic, since a large response is not an attack, to buy protection an adversary evades by
padding, or more simply by using https, which is not inspected at all. What the code will
never do is the third option: truncate quietly and report a clean scan.

Say the consequence plainly. **The request-body scan is evadable by padding.** Put a
quarter-megabyte of filler in front of a credential and it goes out. Treat this control as
one against accident, misconfiguration, and unsophisticated theft, not against an adversary
who is choosing their transport.

Buffering is bounded by time as well as size. A body that goes silent for one second is
released with what has arrived and the rest is streamed; a body that never ends is not large,
it is open, and holding one to scan it is how a proxy hangs the agent it is protecting.

### Streams

`text/event-stream`, `application/x-ndjson`, and `multipart/x-mixed-replace` responses are
**exempt from body inspection entirely**, and the exemption is explicit rather than left for
the idle deadline to discover a second late. MCP carries SSE. An event stream that pauses
between events is behaving correctly, and buffering one to scan it converts a working
transport into a hang. There is no half-measure available: a stream cannot be inspected whole
without ceasing to be a stream.

Their headers are still scanned, so this is not a hole a `Content-Type` opens across the
whole exchange, only across the body it names. The record says `bodyVisibility: stream` and
`responseContentBodyUnscannable: stream`, and the reasons say the body was not inspected.

### Reading the record

`bodyVisibility` is on every proxy record and exists to remove one specific ambiguity: a row
with no findings can mean "nothing was there" or "we could not look", and the second reads
exactly like the first to anyone skimming.

| Value | Meaning |
| --- | --- |
| `tunneled` | CONNECT. Ciphertext. Nothing below the authority was ever readable. |
| `unread` | The exchange ended, or was refused, before there was a body to read. |
| `stream` | An event stream, passed through without buffering, deliberately. |
| `partial` | Read to the cap or to a stall; the remainder was forwarded uninspected. |
| `plaintext` | Read whole and scanned. |

Findings themselves are namespaced by direction, because one exchange has two bodies:
`requestContentSecretTypes`, `responseContentInjectionPatterns`, and so on. Each carries the
class of what was found and `contentSites` carries where: a byte offset for a path or a
body, a header name for a header. **The matched value is never recorded**, in the audit chain
or in the flat ledger. The recorded `path` is the pathname with the query string removed for
the same reason: `?api_key=...` is one of the shapes this scan exists to catch, and writing it
down would put the live credential in the record that reports its detection.

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
- **What informs a decision depends on the scheme, and the split is sharp.** A CONNECT tunnel
  is judged from host, port, scheme, and the SNI the client negotiated: the proxy does not
  terminate TLS, so the path, the headers, and both bodies of an https request are ciphertext
  and no rule can reach them. Terminating TLS would need a CA in every runtime trust store,
  which would break the harness-agnostic property the proxy exists for. A plaintext http
  exchange is judged from all of it, subject to the cap and the stream exemption above.
- **Content inspection on the proxy is plaintext HTTP and nothing else.** An https body is
  invisible because it is encrypted. A CONNECT tunnel carrying HTTP inside it is invisible for
  the same reason. The transparent listener relays raw TCP and parses no messages, so it does
  not inspect content on either scheme; its records say `unread` or `tunneled` rather than
  implying a clean scan. Anyone planning to rely on egress content scanning for https should
  read that as "not available", not as "coming".
- **Adding interception is not a small change, and the cost is not only the CA.** Minting a
  leaf certificate per destination means issuing X.509, and Node cannot: `crypto.X509Certificate`
  parses and verifies, it does not sign. Closing this gap therefore means either a fourth
  runtime dependency or shelling out to `openssl` on the connection path. This package has
  exactly three runtime dependencies and keeps it that way on purpose, so that trade is an
  architectural decision rather than an implementation detail, and it is unmade.
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
- **A clean scan means "no known pattern in the bytes we read".** Both engines are
  deterministic pattern tables. Paraphrase defeats the injection scanner; a token scheme the
  DLP table does not know defeats the DLP. The record says which surfaces were read and how
  much of them, so a clean row can be read for what it is.
- **Only `deny` is enforceable on a connection.** A rule returning `approve` or `redact` for
  an egress destination is recorded and the connection is allowed. There is nothing to answer
  an approval prompt on a TCP connect. Redaction is not performed on a proxied body either,
  even now that plaintext bodies are read: rewriting one in flight means recomputing
  `Content-Length` and re-encoding whatever content or transfer encoding it arrived under, and
  getting that wrong corrupts a live response over a finding that may be a false positive. If
  a destination must not be reached, keep it off the allowlist and run `strict`; do not rely
  on an `approve` rule to stop it.
- **The allowlist is global to the process.** One AgentWall instance enforces one allowlist.
  Per-agent allowlists need per-agent instances.
- **`strict` with an empty `allowedHosts` or an empty `allowedPorts` denies everything.** That
  is the honest consequence of allowlist-only rather than a bug, but it is worth knowing
  before a restart. Both lists are allowlists, so empty means nothing is permitted rather than
  everything. The start-up log reports the mode and the allowlist size for exactly this reason.
