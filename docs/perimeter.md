# The perimeter

## Proxy environment variables are advisory

`HTTP_PROXY` and `HTTPS_PROXY` are a request, not a constraint. Every control the forward
proxy provides — the allowlist, the policy rules, the audit chain — applies to a connection
only because the client chose to route it through the proxy in the first place.

A process that does not make that choice egresses unobserved. It may be an HTTP client that
never reads those variables, a binary that speaks its own transport, or an agent that was
talked into unsetting them. The result is the same in each case, and it is worse than a
missed block: AgentWall does not allow the connection, it never sees it. Nothing is
recorded, no rule is evaluated, and the ledger's silence is indistinguishable from an agent
that behaved. That is cooperative capture, and a control an agent can decline is not a
control.

The perimeter removes the assumption. The agent stops being asked.

## The model

Three UIDs and a kernel that does the capturing.

| UID | What runs as it | Its outbound TCP |
|---|---|---|
| operator | You. Installing, checking, and removing the ruleset. | Untouched. |
| proxy | The AgentWall process, including the transparent listener. | Exempt from the redirect — it has to reach real destinations on the agent's behalf. |
| agent | The agent and every process it starts. | Redirected to the local proxy port on `:80` and `:443`. Everything else it sends is dropped by the kernel. |

Two nftables chains in a dedicated `inet agentwall` table implement that. A `capture` chain
on the `nat hook output` owner-matches the agent UID and redirects its TCP on ports `80` and
`443` to the proxy port, with the proxy UID accepted first so the proxy is not redirected
into itself. An `egress` chain on the `filter hook output` then permits the post-NAT
connection to the proxy port and ends with a single uid-scoped `drop`.

The capture is scoped to those two ports rather than to all TCP because the proxy reads the
destination out of the stream, and TLS carries no port there. Capturing `:8443` would mean
policing it as `:443` — the right host, the wrong service, under an allow verdict. Scoping
the redirect sends every other port the agent dials to the drop instead, which is a
narrowing: unreachable rather than misrouted.

Be precise about what that narrowing covers, because it is easy to over-read. **The ruleset
decides what the agent may dial. The proxy decides what is opened.** Those are different
sets: the proxy UID is exempt from the redirect and reaches the network directly, which is
the whole design. A plain HTTP request names its own port in the authority, so an agent that
sends `Host: allowlisted.example.com:22` on the captured `:80` has the listener name `:22`,
policy judge `:22`, and — on an allow — the proxy open `:22` and replay the bytes. Port
containment therefore comes from egress policy, not from nftables. See the limits below for
what policy does and does not check.

The drop is the part that matters. A set of redirects over a permissive default contains
nothing: it moves the traffic it knows about and waves through QUIC, raw sockets, ICMP
tunnels, and every protocol nobody thought to name. Redirection is what makes the agent's
traffic inspectable; the default-drop is what makes it *contained*. `status` reports the
perimeter as not installed when the redirect is present and the drop is not, because that
state looks healthy from the outside — traffic flows, the audit chain fills up, the proxy is
clearly working — and it contains nothing.

Both chains carry `policy accept`. They see every locally generated packet on the host, not
just the agent's, so a drop policy would take the machine off the network. Containment comes
from the explicit uid-scoped rules, never from a chain default.

The table is AgentWall's own and is never merged into an operator's existing table, which is
what makes `rollback` a single `delete table` and makes re-applying the ruleset safe.

### The listener the rules point at

The redirect needs something on the other end. The transparent listener is configured, not
environment-gated, because it is only meaningful alongside the nftables rules that feed it:

```yaml
transparent:
  port: 8080
  host: 127.0.0.1   # optional; this is the default
  tlsPort: 443      # optional; this is the default
```

Omit the section and the listener does not start. `port` must be the same port the perimeter
redirects to (`--proxy-port`), or every contained connection lands on a closed socket.

`tlsPort` is the second thing that has to agree. SNI names a host and nothing else, the
redirect has already replaced the socket's local port with the proxy's, and Node cannot ask
the kernel for the original — so a captured TLS connection's real port is not recoverable at
all. `tlsPort` is always a declaration by the operator, never something the listener can
verify, and that stays true whatever the ruleset does.

The captured set is the constant `{ 80, 443 }` and is not configurable; `PerimeterSpec` fixes
it. `tlsPort` defaults to `443`, so the two agree out of the box and there is exactly one
correct value. Note what `tlsPort` does *not* do: it is a listener option, and the kernel
never sees it. Changing it does not change what is captured — it only changes what the
listener claims a captured connection was for. Set it to `8443` and every captured TLS
connection, including the ordinary ones to `:443`, is policed and then dialled as `:8443`:
the right host, the wrong service, under an allow verdict. Leave it alone unless you have
also changed what the ruleset captures.

Two consequences follow, and they are not symmetric. Because nftables matches ports and not
protocols, a TLS stream deliberately sent to port `80` is captured, named by its SNI, and
attributed to `tlsPort` — for TLS the port really is pinned, and that window is one port
wide. Plain HTTP is the opposite: it names its own port in the `Host:` authority, so the
captured set does not bound the ports an HTTP request can reach. See the limits for what
that means and where port containment actually has to come from.

Give it a port of its own. `AGENTWALL_PROXY_PORT` starts the `CONNECT` forward proxy, and
the two are separate listeners in one process that cannot share a number. A failed bind is
reported through the listener's error path rather than being fatal, and the startup log line
names the port it intended to use, so a log line is not by itself proof that the listener
came up. Confirm with a real connection — see [Confirming it contains](#confirming-it-contains).

## Naming a destination without proxy headers

A redirected connection carries no destination. There is no `CONNECT` line and no
absolute-URI request line, because the client believes it is talking straight to the origin.
The kernel still knows the original address and would hand it over through
`getsockopt(SO_ORIGINAL_DST)`, but Node exposes no such call and a native addon is out of the
question: this package's runtime dependency list is exactly three packages, and keeping it
there is a deliberate supply-chain property.

So the destination is recovered from the stream itself:

- **TLS** — the `server_name` extension of the ClientHello. SNI names a host and nothing
  else, and the redirect has already replaced the socket's local port with the proxy's, so
  the original port is genuinely not in the connection. The listener assumes the configured
  `transparent.tlsPort`, which defaults to `443`.
- **Plain HTTP** — the `Host:` header of the first request head, which does carry a port.
- **Neither** — the connection is denied and closed.

That last case is the design's fail-closed edge, and it is a deny on purpose: a destination
that cannot be named cannot be policed. There is nothing to match against an allowlist,
nothing to hand a policy rule, and nowhere to connect even if something returned "allow" —
so `decide` is not consulted at all. The refusal is structural. Allowing it instead would
punch an unpoliceable hole through the middle of an enforcement control, and it would be
exactly the shape a channel takes when it is trying not to be described.

The refusal is still recorded, so it appears in the audit chain as a decision rather than as
a network glitch someone has to go and diagnose. Its record names the host `<unknown>` —
angle brackets are not legal in a DNS name, so it can never collide with a real destination —
with port `0`, method `UNKNOWN`, decision `deny`, no matched rules, and the reason:

```
no SNI or Host header: the destination could not be named
```

The scheme is `https` when the first buffered byte was a TLS handshake byte and `http`
otherwise, which is the only thing about the connection that was ever knowable.

What a refused client actually sees depends on which side of the handshake it is on. A plain
HTTP denial gets a `403` with an `X-Agentwall-Block-Reason` header, the same as the forward
proxy. A TLS denial is made before the ClientHello has been answered, so there is no session
and no application layer to carry an error over; the connection closes with zero bytes
written and the client sees a reset with no reason attached. That is the ceiling of a
pre-handshake refusal, not an oversight — the alternative is terminating TLS, which needs a
CA in every runtime trust store and is what this design exists to avoid. The reason lives in
the audit chain, which is where an operator diagnosing the reset should look.

A `decide` callback that throws is treated the same way a failed control should be: the
connection is denied. Allowing on error would make every bug in policy evaluation an open
door.

Six cases land in the unnameable bucket and are worth knowing before they surprise you: a TLS
connection to a bare IP literal; a client that omits SNI; a ClientHello fragmented across TLS
*records*, or larger than the peek buffer, neither of which is reassembled; HTTP/2 with prior
knowledge, whose preface is not an HTTP/1 request line; a request head carrying two `Host:`
headers or an obs-folded header, refused rather than resolved because picking one of two
`Host:` values is the exact ambiguity request smuggling is built on; and an authority
containing characters that do not belong in one. Ordinary TCP segmentation is not on that
list — a ClientHello split across packets is reassembled normally.

## The lifecycle

```
agentwall perimeter <subcommand> [options]
```

| Subcommand | Needs privilege | Effect |
|---|---|---|
| `plan` | no | Renders the ruleset and the resolved spec. Changes nothing. |
| `install` | yes | Applies the ruleset through `nft -f -`. |
| `status` | `CAP_NET_ADMIN`, to read the table | Reports whether the redirect and the drop are present and correct. |
| `verify` | `CAP_NET_ADMIN`, to read the table | `status`, plus what is and is not contained, in writing. |
| `run -- <cmd>` | yes | Runs a command as the agent UID, inside a perimeter that is verified to exist. |
| `rollback` | yes | Deletes the `inet agentwall` table. |

Options, shared by every subcommand that takes a spec:

```
--agent-uid <n>       uid the agent runs as (env AGENTWALL_AGENT_UID, default 61001)
--proxy-uid <n>       uid the proxy runs as (env AGENTWALL_PROXY_UID, default 61002)
--proxy-port <n>      port the proxy listens on (env AGENTWALL_PROXY_PORT, default 8080)
--dns-resolver <ip>   the single resolver the agent may query; omitted means no DNS at all
--allow-loopback      let the agent reach loopback services besides the proxy (default: off)
--agent-gid <n>       gid for `run` (default: the agent uid's primary group from /etc/passwd)
```

Flag beats environment variable beats built-in default. `--dns-resolver` must be a bare IPv4
or IPv6 literal: a hostname would have to be resolved to be written into a rule, and
resolving it needs the DNS that rule is what permits. An IPv6 resolver renders as `ip6 daddr`
rather than `ip daddr`.

`help`, `--help`, and `-h` print the full usage text and exit `0`. Other exit codes are `0`
for ok, `1` for not installed or refused, and `2` for bad usage or a spec that could never be
installed — that message names the offending field. `run` returns the contained command's own
status, so wrapping a build in the perimeter never hides that build failing.

### `plan` first, always

`plan` is the recommended first step and the only subcommand that both works unprivileged and
changes nothing. This writes host firewall rules whose whole purpose is to drop traffic; an
operator should read them before they land, not after an agent stops working.

```bash
agentwall perimeter plan \
  --agent-uid 61001 --proxy-uid 61002 --proxy-port 8080 --dns-resolver 10.0.0.53
```

Every value carries where it came from, so a guess is never presented as a fact:

```
# agentwall perimeter plan — resolved spec
#   agentUid       61001  (flag)
#   proxyUid       61002  (flag)
#   proxyPort      8080  (flag)
#   dnsResolver    10.0.0.53  (flag)
#   allowLoopback  false  (default)
#
# Nothing has been applied. Review the rules below, then either
#   agentwall perimeter plan [same options] | sudo nft -f -
# or `sudo agentwall perimeter install` with the same options.
```

Then the ruleset. Rules only below; the real output annotates each one:

```
add table inet agentwall
delete table inet agentwall

table inet agentwall {
	chain capture {
		type nat hook output priority dstnat; policy accept;
		meta skuid 61002 accept
		meta skuid 61001 tcp dport { 80, 443 } redirect to :8080
	}

	chain egress {
		type filter hook output priority filter; policy accept;
		meta skuid 61002 accept
		meta skuid 61001 ip daddr 127.0.0.1 tcp dport 8080 accept
		meta skuid 61001 ip6 daddr ::1 tcp dport 8080 accept
		meta skuid 61001 ip daddr 10.0.0.53 udp dport 53 accept
		meta skuid 61001 ip daddr 10.0.0.53 tcp dport 53 accept
		meta skuid 61001 drop
	}
}
```

Everything `plan` prints is either a comment or a valid `nft` statement, so its whole stdout
pipes into `nft` unchanged — an operator who has just read the rules can apply exactly the
bytes they read rather than re-running a command and trusting it produced the same thing:

```bash
agentwall perimeter plan --agent-uid 61001 --proxy-uid 61002 --proxy-port 8080 | sudo nft -f -
```

The output is deterministic — no timestamps, no hostnames — so two plans can be diffed and
show only what you changed. The `add`/`delete` pair at the top makes it idempotent: `add` is a
no-op when the table already exists, so the pair always has something to remove and always
leaves exactly one `agentwall` table however many times it is applied. `nft` loads a `-f`
file as one transaction, so there is no window where the old table is gone and the new one is
not yet there.

Omitting `--agent-uid` and `--proxy-uid` gives you placeholder values so that `plan` works on
a host where the accounts do not exist yet — reading the rules is the step that teaches you
which accounts you need. A placeholder draws a warning on stderr, because installing a
perimeter around a UID nothing runs as contains nothing.

### `install`

```bash
sudo agentwall perimeter install \
  --agent-uid 61001 --proxy-uid 61002 --proxy-port 8080 --dns-resolver 10.0.0.53
```

```
Perimeter installed. uid 61001 now reaches the network only through
the proxy on port 8080. Confirm with `agentwall perimeter verify`.
```

Unprivileged, it refuses and points at `plan` rather than half-applying anything. If `nft`
rejects the ruleset, nothing is applied — the transaction property again — and the `nft`
error is printed verbatim.

### `status`

```bash
sudo agentwall perimeter status --agent-uid 61001 --proxy-uid 61002 --proxy-port 8080
```

```
Perimeter installed: uid 61001 is redirected to port 8080
and dropped by default. The proxy uid is exempt.
```

It checks invariants, not text. You may add your own rules to the table; a status command
that demanded a byte-for-byte match with `plan` would cry wolf at every local adjustment
until it was ignored. What it insists on is the set of properties that cannot be missing
without the perimeter being decoration: the table exists, the agent's TCP is redirected to
the port the proxy is actually on, the proxy is exempted *before* that redirect, and the last
word on the agent's traffic is a drop. Anything else prints as a problem list and exits `1`:

```
Perimeter NOT correctly installed.
  redirect present: true
  default-drop present: false
```

It also fails a perimeter that is installed but captures the wrong thing, in three ways. A
redirect that takes every TCP port is reported as capturing everything. A redirect that names
any port outside `{ 80, 443 }` is reported with the offending port named. And a redirect
whose `tcp dport` expression cannot be resolved to a port list — a named set, for instance —
is reported as unverifiable, with the expression quoted and an instruction to confirm the
capture by hand, because a check that cannot read a rule must say so rather than pass it.

The reason is the same in all three: the proxy cannot recover a port from the stream, so a
connection captured on any other port is policed and recorded as `443` of the same host — the
wrong service, under an allow verdict, written into a signed ledger. A capture *narrower*
than `{ 80, 443 }` is reported healthy, because an uncaptured port meets the default-drop and
a refusal is not a lie. All three problems set the perimeter to not-installed, which is also
what makes `run` refuse to start the agent.

"Could not read the table" and "not installed" are kept apart. Listing a table needs
`CAP_NET_ADMIN`, so the common failure is a permission error, and reporting that as "not
installed" would push you into reinstalling — or into concluding an agent is unprotected when
it is fine. An unknown state is not an absent one.

### `verify`

Everything `status` does, plus the boundary of the claim, printed every time:

```bash
sudo agentwall perimeter verify --agent-uid 61001 --proxy-uid 61002 --proxy-port 8080
```

```
Contained:
  - every TCP connection uid 61001 opens to port 80 or 443 is redirected to the local
    proxy on port 8080, whatever destination the process asked for and with no client
    cooperation.
  - everything else uid 61001 sends is dropped by the kernel before it leaves the host:
    UDP, QUIC, ICMP, raw sockets, and TCP to any other port. The capture is scoped to the
    ports whose destination the proxy can recover from the stream, so an unnameable
    destination is refused rather than policed as something it is not.
  - DNS: only 10.0.0.53 on port 53. Any other resolver is dropped.
Not contained:
  - any process running as a uid other than 61001. The perimeter is per-uid.
  - root. Root can flush this table, so containment holds only while the agent is not root
    and cannot obtain it.
  - unix domain sockets, filesystem writes, and anything else that never reaches the
    network stack. Those are other planes' problem.
  - what is inside a TLS session. The proxy does not terminate TLS; it decides from the
    destination the stream names, and denies a stream that names none.
  - ports. The kernel captures :80 and :443 and drops the rest, but the proxy connects on
    the agent's behalf to whatever the stream names, and an HTTP request may name its own
    port via `Host: host:PORT`. Nothing is misrouted — the verdict is evaluated against
    exactly the port that gets opened — but this ruleset makes no port unreachable. Port
    containment comes from egress policy, so a port-blind allowlist allows every port.
  - the port of a TLS stream sent to :80. The kernel matches ports, not protocols, so such
    a stream is still attributed to 443 of the host its SNI names.
```

A containment control described only by what it blocks invites the reader to assume it blocks
everything else too. Printing the gaps next to the guarantees, on every run, is the cheapest
defence against a threat model built on a feature summary. `verify` exits with `status`'s
code, so a deployment script can gate on it.

### `run -- <cmd>`

```bash
sudo agentwall perimeter run \
  --agent-uid 61001 --proxy-uid 61002 --proxy-port 8080 -- npx my-agent
```

It checks the perimeter is correctly installed and **refuses to start the command if it is
not**. That check is not a convenience. An agent that believes it is contained when it is not
is the worst thing this feature can produce: you have already decided it is safe to hand it a
broader task precisely because the box exists, and there is no failure signal anywhere —
traffic flows, the chain fills with the subset that happens to reach the proxy, and the
unrestricted part is invisible.

It drops both uid and gid, defaulting the gid to the agent UID's primary group read from
`/etc/passwd`; pass `--agent-gid` when that lookup cannot find one. It also strips
`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lowercase spellings from the environment
it hands the command. The perimeter is transparent, so a client that still believes it has an
HTTP proxy would send `CONNECT` to a listener expecting a raw ClientHello, and you would be
left debugging a protocol error that has nothing to do with your policy.

Node sets uid and gid but does not call `initgroups(3)`, so supplementary groups inherited
from the invoking process still apply. On a stock host root has none beyond gid 0; on a host
where root has been added to extra groups, launch the agent from a systemd unit or a
container instead.

### `rollback`

```bash
sudo agentwall perimeter rollback
```

```
Perimeter removed. The agent uid now reaches the network directly.
```

It needs no spec options — it deletes the whole `inet agentwall` table, which is the entire
footprint. A table that is not there is the state rollback wants, so that reports success
rather than an error.

## Confirming it contains

The claim is that a process which ignores proxy environment variables is still governed. That
is checkable, and it should be checked rather than trusted, because every symptom of a
perimeter that is not working looks like a perimeter that is.

Set up an enforcing deployment first: `transparent.port` matching `--proxy-port`,
[enforcement](enforcement.md) in `strict` with a real allowlist, and `AGENTWALL_AUDIT_FILE`
pointed at a path that survives a restart.

**Check one — a deliberately uncooperative client is still recorded.** Reach an allowlisted
destination with nothing in the environment to cooperate with, and with the client instructed
not to use a proxy even if it found one:

```bash
sudo agentwall perimeter run --agent-uid 61001 --proxy-uid 61002 --proxy-port 8080 \
  -- curl -sS --noproxy '*' https://api.vendor.example/health
```

The request should succeed, and the audit chain should carry it:

```bash
grep '"transportMode":"transparent"' /var/lib/agentwall/audit.jsonl | tail -1
```

**Check two — a non-allowlisted destination is still refused.** Same conditions, a host that
is not on the allowlist:

```bash
sudo agentwall perimeter run --agent-uid 61001 --proxy-uid 61002 --proxy-port 8080 \
  -- curl -sS --noproxy '*' https://not-allowlisted.example/
```

`curl` reports a connection reset — a TLS denial is made before the handshake, so there is no
channel to explain itself over — and the audit chain carries the `deny` with the reason and
the `det.net.egress.blocked` detection.

**The control.** Run both commands again with the perimeter rolled back and the agent pointed
at the `CONNECT` proxy through `HTTPS_PROXY`. Both now succeed and neither appears anywhere,
because `--noproxy '*'` is all it takes to walk past a cooperative control. That difference —
recorded and refused versus invisible — is the whole of what the perimeter buys, and it is
the only way to confirm the claim rather than believe it.

Note where the evidence lands. Transparent records go to the audit chain only. The flat
`AGENTWALL_PROXY_LEDGER` view is written by the forward proxy alone, so grepping the ledger
for a contained connection will find nothing even when containment is working perfectly. The
audit chain is the record either way; see the [audit evidence format](audit-format.md).
Records from both paths carry a `transportMode` of `forward` or `transparent`, which is the
field that tells you which one you are reading.

## Limits

Read all of these. Several of them are holes, and they are not going to be described as
anything else.

- **The ruleset parses, but has not been loaded into a kernel by this project's tests.**
  `nft` accepts the generated file as syntactically valid, and a test asserts that on every
  run wherever `nft` is installed. That is the parser's verdict, not the kernel's: whether the
  chain types, hook and priority pairs, and `inet`-family NAT support are accepted at load
  time is only settled the first time you run `install` on a real host. The development
  machine restricts unprivileged user namespaces, so no netns load could be performed there.
  Run `plan`, read it, then `install` on a host you can afford to have refuse it, and treat
  the first `verify` as the real test.
- **DNS still leaves the host directly, and DNS is an exfiltration channel.** The agent
  resolves a name before it connects, so port 53 has to be permitted for anything at all to
  work. `--dns-resolver` narrows that to a single address on both transports, and omitting it
  denies DNS entirely, but neither closes the channel: queries to the permitted resolver never
  touch the proxy, are never policed, and a name is a place to put data. This is a known,
  unclosed hole in the model. Point the agent at a resolver you control and log there.
- **ECH or ESNI hides the SNI, so such a client is refused rather than inspected.** The
  destination is unnameable, the refusal is structural, and the connection dies. That fails
  closed, which is correct, but the honest consequence is that it breaks that client rather
  than containing it. The same applies to any TLS connection that carries no name at all: a
  bare IP literal, or a client that simply omits the extension.
- **The agent dials only `:80` and `:443`, but that is not a limit on the ports it can
  reach.** The nftables rules narrow what the *agent* may send to, not what the *proxy* opens
  on its behalf, and the proxy UID is exempt from the redirect by design. A plain HTTP request
  carries its own port in the authority, so `Host: allowlisted.example.com:22` sent on the
  captured `:80` is named as `:22` and judged as `:22`. Port containment therefore comes from
  egress policy, not from nftables, and the ruleset alone should never be read as pinning the
  reachable port set.
- **Egress policy does check the port, in `strict` only.** The strict gate requires the host
  to be in `egress.allowedHosts` and the port in `egress.allowedPorts`; a non-allowlisted port
  on an allowlisted host is denied, carrying `net:deny-egress-port-not-allowlisted` and
  `det.net.egress.port_blocked`, with the port and the permitted set named in the reason.
  `guarded` and `monitor` do not gate on it — the allowlist pair is a strict-mode control,
  exactly as the host half is — so a perimeter running in `guarded` still reaches any port on
  a host no rule denies. Pair the perimeter with `strict` if the port set matters.
- **A captured connection that is neither TLS nor HTTP is refused, not understood.** On the
  two captured ports there are two parsers and no third, so a database wire protocol, SSH, or
  HTTP/2 with prior knowledge fails to name a destination and is denied. TLS is where the
  port genuinely is pinned: SNI carries no port, so a captured TLS connection is always
  opened on `transparent.tlsPort`, and a TLS stream deliberately sent to `:80` is attributed
  to `443` of the host its SNI names. That asymmetry is the thing to remember — HTTP can name
  a port, TLS cannot.
- **Root and an nftables-capable kernel are required to install, and this is Linux only.**
  `install`, `rollback`, and `run` need root outright; `status` and `verify` need
  `CAP_NET_ADMIN` to read the table. `plan` is the only subcommand that needs nothing.
  nftables has no equivalent on macOS or Windows, and `plan` will happily render a ruleset on
  those hosts that nothing there can apply.
- **It binds a UID, not a person or a program.** Every rule matches `meta skuid`. Anything
  running as the agent UID is contained, including things you did not mean to contain, and
  anything running as another UID is not, including a second copy of the agent started the
  ordinary way. Root is specifically not contained: root can flush the table, so containment
  holds only while the agent is not root and cannot become root. `plan` refuses to build a
  perimeter around UID 0 for that reason, and refuses to exempt UID 0 because that would
  exempt every root process on the host rather than the proxy.
- **`--allow-loopback` lets the agent reach local services, which this model does not
  protect.** It is off by default and it is a deliberate hole when you open it: loopback is
  exempted from both the redirect and the drop, so those connections are neither policed nor
  recorded. A local service can itself be a route off the host, and nothing here inspects what
  the agent asks it to do.
- **Transparent-mode records are unattributed.** The `client` on every record from this path
  is `pid: null, comm: null`, and the audit event carries `agentId: "unattributed"` with `pid`
  and `comm` of `"unknown"`. The `/proc` attribution the forward proxy performs is a
  module-private helper in that file and is not shared, so rather than keeping a second copy of
  a security-relevant lookup to drift, the transparent path says "unknown" honestly. The
  destination, the decision, the reasons, the byte counts, and the hash chain are all still
  there; the name of the calling process is not. Lifting that helper into a shared module is
  the follow-up.

Two more properties that are not limits of the perimeter but are inherited from what it sits
in front of: the proxy never terminates TLS, so bodies, paths, and headers of an HTTPS request
cannot inform a decision, and only `deny` is enforceable on a connection. Both are covered in
[egress enforcement](enforcement.md), and the [threat model](threat-model.md) states what the
system as a whole does and does not defend.
