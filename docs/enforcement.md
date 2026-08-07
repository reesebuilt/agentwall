# Egress enforcement

AgentWall enforces egress only on traffic that reaches its proxy.
A process that bypasses the proxy also bypasses these controls.
Use the optional perimeter when you need kernel-enforced capture on Linux.

Run `agentwall ui` for the first setup.
AgentWall services and the UI bind locally by default.
The UI sends each mutation through a typed action.
Read-only operations show status, output, and a copyable CLI command.

## Enforcement modes

AgentWall uses `monitor` by default.
An upgrade does not change the configured mode.

| Mode | Result | Limit |
| --- | --- | --- |
| `monitor` | Evaluates each request and records projections. It allows the request. | It does not enforce policy or allowlist denials. Operator lockdown still denies all proxied egress. |
| `guarded` | Enforces a `deny` from a matched policy rule. | It allows a destination when no rule matches. |
| `strict` | Requires both an allowed host and an allowed port. It also enforces policy denials. | Traffic without a declared fleet identity uses the global lists. Empty global host or port lists deny all destinations. |

### `monitor`

`monitor` runs the real decision logic for `guarded` and `strict`.
It records both projected results in the reasons.
The actual decision remains `allow` because AgentWall made the connection.

```
monitor: egress recorded, not gated
monitor: guarded mode would allow
monitor: strict mode would deny: registry.npmjs.org is not in the egress allowlist
```

Use these projections to prepare policy rules and an allowlist.
Do not treat `monitor` as an enforcement mode.
Operator lockdown is the only mode override.

### `guarded`

`guarded` enforces only a `deny` from a matched policy rule.
The policy engine returns `deny` when no rule matches.
`guarded` ignores that default result and allows the request.
This boundary prevents an accidental allowlist-only policy.

A policy rule that throws is skipped.
That individual rule fails open, but other rules still run.

### `strict`

`strict` requires the host in `egress.allowedHosts`.
It also requires the port in `egress.allowedPorts`.
Both values must match.
A policy rule can still deny an allowlisted destination.
The global egress lists are the default.
A declared fleet agent can set `fleet.agents[].egress.allowedHosts` and `fleet.agents[].egress.allowedPorts`.

Each non-empty scoped list replaces its global list.
It does not add to or intersect with the global list.
An omitted or empty scoped list inherits the related global list.
Host and port lists inherit independently.
Traffic without a declared fleet identity uses both global lists.
Records set `egressAllowlistSource` to `global` or `agent:<id>`.

Include every required destination when a scoped list replaces a global list.

Host matches use normalized exact names.
AgentWall lowercases the name, removes IPv6 brackets, and removes the final DNS root dot.
AgentWall does not support wildcards or suffix matches.
An entry for `github.com` does not allow `api.github.com`.

The strict allowlist gate does not depend on an allowlist policy rule.
A rule-set replacement cannot disable this gate.

## Configuration

```yaml
enforcement:
  mode: monitor          # monitor | guarded | strict

egress:
  allowedHosts:          # strict mode's host allowlist
    - github.com
  allowedPorts:          # strict mode's port allowlist; both must match
    - 443
```

Omit `enforcement` to use `monitor`.

An invalid mode causes a startup failure.
AgentWall does not fall back to `monitor` or `strict`.

```
agentwall: invalid enforcement.mode "strct" in /etc/agentwall/config.yaml.
Valid modes are "monitor", "guarded", and "strict". Omit the enforcement section
entirely to use "monitor".
```

AgentWall reads the mode and allowlist at startup.
Restart AgentWall after you change either value.
A reload reports these values as restart-required.

Policy rules support hot reload.
A reloaded rule applies to the next connection.
Reload parses the configuration and policy before it applies changes.
It replaces the immutable versioned snapshot only after a valid parse.
An invalid file leaves the last valid rules active.
See [Config and policy reload](reload.md).

## Recommended adoption path

1. Run `agentwall ui` for the first setup.
2. Keep the mode at `monitor` until the ledger represents normal traffic.
3. Read the monitor projections and identify each destination.
4. Add recognized destinations to both strict allowlists.
5. Change the mode to `guarded` and confirm that expected denials reach clients.
6. Change the mode to `strict` after the allowlist is complete.

Set `AGENTWALL_PROXY_LEDGER` to write a flat JSON Lines destination ledger.
Each record contains the host and port.
It contains process attribution when AgentWall can identify the process.
It also contains the monitor projections.

A tunneled record can contain `sni` and `sniMismatch`.
The flat ledger stores them as top-level keys.
The audit chain stores them as `metadata.sni` and `metadata.sniMismatch`.
If the names disagree, review and allowlist the SNI name.
The SNI is the negotiated name and is the better source.

## Denied requests

Both forward-proxy paths return `403`.
They set `X-Agentwall-Block-Reason` to the first verdict reason.

Plain HTTP:

```
HTTP/1.1 403 Forbidden
X-Agentwall-Block-Reason: registry.npmjs.org is not in the egress allowlist

agentwall: destination not allowed
```

HTTPS denied at `CONNECT`:

```
HTTP/1.1 403 Forbidden
X-Agentwall-Block-Reason: Request targets a private or local network address
Connection: close
```

AgentWall opens no upstream socket for a `CONNECT` authority denial.
It also opens no upstream socket for a plaintext request denial.
An SNI denial occurs after the upstream connection opens.
AgentWall then closes it before it forwards payload bytes.
The destination sees the TCP connection open and close.

AgentWall converts block reasons to printable ASCII.
It also caps their length before it writes a header.
This prevents response-header injection.

Some HTTP clients report a proxy `403` as a connection error.
Use the ledger to find the refusal reason.

## Operator lockdown

Operator lockdown denies every proxied egress attempt in all modes.
The four independent hold sources are configuration, API, `SIGUSR1`, and the sentinel file.
Any active source keeps lockdown engaged.
Each source releases only its own hold.
Each denial has `critical` risk and names the active sources.
A monitor record still reports `mode: monitor` with the denial.

Lockdown can stop only traffic that reaches an AgentWall proxy.
It cannot stop traffic outside every installed capture path.

## Evidence

Each proxied request produces an audit-chain event.
The event records the actual decision, reasons, matched rules, risk, and active mode.
Monitor projections appear only in the reasons.
Search for `strict mode would deny` when you build an allowlist.

AgentWall reports `low` risk when no rule matches.
This avoids a high-risk finding for every normal egress request.

Enforcement uses these detection IDs:

- `det.net.egress.blocked`: Strict mode refused a destination outside the allowlist. MITRE ATT&CK T1071, Application Layer Protocol (Command and Control).
- `det.governance.lockdown.active`: Lockdown refused an action. MITRE ATT&CK T1489, Service Stop (Impact).
- `det.net.sni.connect-mismatch`: CONNECT and SNI names differed. This detection has no ATT&CK mapping. See `unmappedDetections()`.
- `det.net.proxy.request_secret`: A plaintext HTTP request contained credential material. MITRE ATT&CK T1041, Exfiltration Over C2 Channel.
- `det.net.proxy.request_injection`: A plaintext HTTP request contained injected instructions. MITRE ATT&CK T1059, Command and Scripting Interpreter.
- `det.net.proxy.response_injection`: A plaintext HTTP response contained injected instructions. MITRE ATT&CK T1059.
- `det.net.proxy.response_secret`: A plaintext HTTP response contained credential material. AgentWall records and forwards it. MITRE ATT&CK T1552, Unsecured Credentials.

A proxy decoy hit uses `identity:deny-decoy-triggered` and `det.identity.decoy.triggered`.
AgentWall uses the same IDs on other surfaces.

## TLS destination checks

Without TLS interception, AgentWall reads the CONNECT authority and port.
It also reads the clear ClientHello when one arrives.
The SNI extension supplies the negotiated host name.
AgentWall does not need a CA for this check.

When SNI differs from CONNECT, AgentWall records `metadata.sniMismatch`.
It also records the rule `net:sni-connect-mismatch`.
AgentWall evaluates policy again for the SNI name.
This second pass runs only after the CONNECT pass allows the request.
It can add a denial, but it cannot replace a denial with an allow.

An IP-literal CONNECT with a hostname SNI always records a mismatch.
The address and host name cannot match.

This check has clear limits.
SNI contains no port, path, header, or body.
A client can omit SNI or use Encrypted Client Hello.
A non-TLS protocol can also use CONNECT.
In these cases, the allowed CONNECT authority remains the only destination source.
This boundary fails open after AgentWall authorizes that authority.

The check does not detect domain fronting when CONNECT and SNI agree.
The real HTTP `Host` header remains inside TLS.
The detection therefore has no ATT&CK T1090.004 mapping.

## Content inspection

AgentWall can inspect direct `/inspect/*` and `/evaluate` payloads.
It can also inspect wrapped MCP frames, channel messages, and watched file writes.
The proxy rules below apply only to proxied traffic.

### Plaintext HTTP

The forward proxy inspects these surfaces before their release:

| Surface | Checks | Denial point |
| --- | --- | --- |
| Request path and query | secrets, PII, injection, decoys | Before an upstream socket opens |
| Request headers | injection and decoys on all headers; secrets with listed exceptions | Before an upstream socket opens |
| Request body | secrets, PII, injection, decoys | Before an upstream socket opens |
| Response headers | secrets, PII, injection, decoys | Before a response byte reaches the client |
| Response body | secrets, PII, injection, decoys | Before a response byte reaches the client |

Credential checks exclude `Authorization`, `Proxy-Authorization`, `Cookie`, and `Set-Cookie` request headers.
Injection and decoy checks still inspect these headers.

A request secret causes a denial in `guarded` or `strict`.
An injection result in a request or response causes a denial in `guarded` or `strict`.
A decoy causes a runtime denial in `guarded` and `strict`.
A response secret is recorded and forwarded.
PII appears in `contentPiiTypes` without a built-in deny rule.
A deployment can add a policy rule for that marker.

AgentWall decompresses gzip, deflate, and brotli bodies for inspection.
It forwards the original bytes without a rewrite or re-encode.

### HTTPS

Without interception, HTTPS request and response content remains encrypted.
AgentWall can inspect only the destination data described above.
A clean tunnel record does not prove that the encrypted content was safe.

Opt-in TLS interception can inspect selected forward-proxy CONNECT hosts.
It requires a local CA in the client trust store and an available `openssl` binary.
It does not apply to the transparent perimeter listener.
AgentWall refuses interception startup when CA, key, mint, trust, or `openssl` checks fail.
See [TLS interception](tls-interception.md).

Hosts in `interception.bypassHosts` use a byte-for-byte tunnel.
AgentWall records the bypass, but it does not inspect either body.
This exact-match bypass supports clients with certificate pinning.

### Body limits

AgentWall scans at most 256 KiB per body.
It imports this value from `MAX_SCAN_CHARS`.
After the cap, AgentWall forwards bytes without inspection.
The record sets `bodyVisibility` to `partial`.
The reasons state that AgentWall forwarded the remainder uninspected.

A caller can evade this scan with filler bytes.
Treat it as protection against accidental or unsophisticated disclosure.
Do not treat it as protection against an adversary that selects the transport.

A one-second body stall also ends the buffered inspection period.
AgentWall forwards the received bytes and streams the remainder.
This limit keeps an open body from halting the proxy.

AgentWall does not inspect response bodies with these content types:

- `text/event-stream`
- `application/x-ndjson`
- `multipart/x-mixed-replace`

AgentWall still inspects their headers.
The record sets `bodyVisibility: stream` and `responseContentBodyUnscannable: stream`.
This exemption preserves event-stream behavior.

### Record fields

Every proxy record has `bodyVisibility`.

| Value | Result |
| --- | --- |
| `tunneled` | CONNECT ciphertext. AgentWall did not read content below the authority. |
| `unread` | The exchange ended or failed before a body was available. |
| `stream` | AgentWall forwarded an event stream without body inspection. |
| `partial` | AgentWall reached the cap or stall limit. It forwarded the remainder uninspected. |
| `plaintext` | AgentWall read and scanned the complete body. |

Direction-specific fields include `requestContentSecretTypes` and `responseContentInjectionPatterns`.
`contentSites` identifies the byte offset or header name.
AgentWall never records the matched value.
The recorded `path` excludes the query string to prevent credential disclosure in evidence.

A clean scan means that no known pattern matched the bytes AgentWall read.
The scanners use deterministic pattern tables.
Paraphrase can evade injection checks.
An unknown token format can evade DLP checks.

## Decision limits

A proxy can enforce only a `deny` decision.
A policy result of `approve` or `redact` is recorded, but the connection continues.
The proxy cannot present an approval prompt during a TCP connection.
It does not rewrite a proxied body for redaction.
Use `strict` and the allowlist when a destination must remain unreachable.

The forward proxy relies on cooperative capture by default.
`HTTP_PROXY` and `HTTPS_PROXY` do not constrain a client that ignores them.
AgentWall neither observes nor blocks such a connection.

The optional Linux perimeter redirects TCP for a dedicated agent UID.
It requires root and an explicit install.
It does not contain DNS.
It does not add content inspection to the transparent listener.
See [The perimeter](perimeter.md).
