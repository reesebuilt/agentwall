# TLS interception

Terminating TLS is the only way to read an https body, and reading https bodies is the only way
to make a clean DLP history over https mean anything. It is also the most invasive thing this
project can be asked to do, so it is off unless an operator turns it on, and turning it on has a
cost that is stated here rather than buried.

Read [what installing a CA means for your threat
model](#what-installing-a-ca-means-for-your-threat-model) before you enable this. It is the
section that matters.

## What this changes

Before interception, an https destination was a hostname and a port. That was not a gap in the
policy engine, it was the ceiling of an observer. The forward proxy sees the authority on a
`CONNECT` line. The transparent listener sees an SNI name. Neither can read a path, a header, or a
body, because the session is encrypted between the agent and the origin and this process is
relaying bytes it cannot decode.

The consequence is worse than a missing feature. Every content scanner in AgentWall was wired to
an https flow that could hand it a destination and nothing else, so it answered "nothing found"
every time, and that answer is indistinguishable in the ledger from a real clean scan. A clean DLP
history over https was ambiguous between two very different statements: **nothing was
exfiltrated**, and **we could not see**.

With interception on, for the hosts the operator chose, one decrypted HTTP exchange at a time
becomes inspectable and reaches `decide` as an ordinary egress event:

- **The request path**, including the query string, which is where a surprising amount of data
  leaves in the first place.
- **The request headers**, lowercased, with repeated names joined rather than one winning. A
  scanner shown only the first of two `x-api-key` headers would report a clean read of a value it
  never looked at.
- **The request body**, decompressed for inspection when the encoding says to.
- **The response status and headers.**
- **The response body**, decompressed the same way.

Policy is asked twice per exchange, at the two moments where the answer can still change what
happens. The request pass runs before anything is opened upstream, so a denial costs the
destination nothing, not even a TCP handshake. The response pass runs before a single byte is
written back to the client.

That second pass is the one that matters most for a tool-using agent. **A poisoned tool result
arrives in a response body**, and a control that only reads requests cannot see it at all. On a
deny, the upstream socket is destroyed and the client gets a `403` with the reason, having never
received the payload.

Two scope statements, both of which you should have before you plan a deployment:

- **This is the `CONNECT` forward-proxy path only.** The interceptor is handed to
  `createForwardProxy` and to nothing else. The perimeter's transparent listener is not wired to
  one, so a perimeter-captured https connection is still named by its SNI and tunnelled. See
  [the perimeter](perimeter.md).
- **Two kinds of record are produced.** The connection keeps its own record, whose byte counts are
  the encrypted totals for the whole tunnel, because counting the plaintext there would mean
  attaching a listener that steals the bytes the TLS stack is about to read. Each inner HTTP
  exchange then files its own record with the path, the decision actually enforced on it, and how
  much of its body was readable.

## It is off by default, and why

Absent config means absent capability. There is no `interception` section in a shipped config,
nothing creates a CA on your behalf, and the code in `src/proxy/tls-intercept.ts` never runs.
`interception.enabled` has to be `true` and a CA has to exist on disk before a single byte is
decrypted.

This is not the usual conservative default that a config file might drift past. It is a refusal to
ship a capability that would make the tool a party to every https session on the host without the
operator having said so. A security tool that decrypts its operator's traffic because it shipped
that way has not earned the trust it is asking for.

Enabling it is a deliberate act with a cost. The cost is the next section, and it is not small.

## What installing a CA means for your threat model

To intercept, AgentWall mints a certificate for the site the agent asked for and signs it with a
local CA. For the agent to accept that certificate, the CA has to be installed as trusted.

**A CA in a trust store is a key that can impersonate every site to this host.** Not the hosts you
listed. Every site. Whoever holds `<caDir>/ca.key` can mint a certificate for your bank, your
identity provider, your package registry, your cloud console, and anything on this host that
trusts that CA will accept it without complaint. Installing it is the same decision, in kind, as
handing a third party a signing key for the entire web as your machine sees it. The third party
here is AgentWall, and after you install it AgentWall is a party to every intercepted https
session the agent makes.

What the code actually does to contain that, and nothing beyond this list:

- **The key is mode 0600, and that is enforced rather than suggested.** `inspectCa` stats the key
  and records a problem if any bit outside owner read/write is set. Interception refuses to start
  while that problem is present. A key readable by the operator's group is a key readable by every
  process running as any member of that group, which on a developer box is most of them.
- **The key's bytes never enter this process.** The CA directory is created `0700` before anything
  is written into it. `inspectCa` opens the key only to `stat` it. The minter proves the key exists
  with a `statSync` and then passes `openssl` the *path*, never the contents, so the key is never
  in this heap where a heap dump, an error serialiser, a log line, an audit record, or a dashboard
  response could reach it. The only CA value any of those surfaces carry is the SHA-256 fingerprint
  of the certificate, which is public data.
- **`pathlen:0` on the CA.** `basicConstraints=critical,CA:TRUE,pathlen:0` is set explicitly rather
  than inherited from an `openssl.cnf` that differs across distributions. The CA can sign leaves and
  cannot sign another CA, so a stolen key cannot be used to issue a sub-CA that outlives revoking
  this one.
- **825 days on the CA, 30 days on every leaf.** A leaf is disposable and losing one costs a
  re-mint.
- **Leaf private keys never leave this process.** Node generates each leaf keypair itself with
  `crypto.generateKeyPairSync`, and `openssl` is handed only the public half. The private key is
  never written to disk and never appears in an argv. The one spawn per hostname reads two
  temporary files, an SPKI public key and a config stanza naming the host, and neither is a secret:
  they live in a `mkdtemp` directory created `0700` and are removed immediately afterwards.
- **Every leaf is `basicConstraints=critical,CA:FALSE`.** A leaked leaf is one certificate for one
  host, not a second issuer.
- **Generation refuses to overwrite.** An existing CA in the target directory is an error, not a
  silent replacement, because replacing it would invalidate every leaf already minted and leave the
  previous certificate installed in trust stores as a key nobody can account for. Rotation means
  deliberately removing the directory.

Now the residual risk, stated plainly, because the list above is easy to read as more protection
than it is:

**None of it helps if the key is read by something running as the same user.** Mode 0600 stops
other users. It does not stop the agent you are containing if that agent runs as the operator UID,
it does not stop a compromised dependency in this process, and it does not stop anyone with root.
Every mitigation above is a mitigation against another account or a later theft, not against code
already executing as you.

The recommendation that follows from that: **do not enable interception on a shared or
multi-tenant host.** Enable it on a machine where the set of principals that can read a 0600 file
owned by the AgentWall user is a set you can name. If you cannot name that set, the honest
posture is to leave interception off and keep the ambiguity, because the ambiguity is cheaper than
a universal signing key on a box you do not control.

## `openssl` is a precondition

`openssl` is a precondition of interception in exactly the way root and Linux are preconditions of
[the perimeter](perimeter.md): a stated requirement, checked before the feature claims to work,
named in the refusal when it is missing. It is not an npm dependency, and adding it does not
change `package.json`.

The check runs the binary rather than looking for a file, because a binary that exists and cannot
execute, or one whose libraries are missing, should fail at startup instead of failing later on a
connection an operator believed was being inspected.

Why a subprocess instead of doing it in Node: **Node cannot issue an X.509 certificate.** Note the
narrowness of that claim. Key generation *is* in the standard library, which is why the leaf
keypairs are made in process and `openssl` never sees a private key. It is ISSUANCE that is
missing. `crypto.X509Certificate` parses and inspects certificates and exposes no static issuer,
and `crypto.Certificate` is the legacy SPKAC helper and is not a CA. There is no signing API to
call, so in-process minting would mean taking a certificate library from npm.

That is the trade being refused. This package's runtime dependency list is exactly three packages
(`fastify`, `js-yaml`, `zod`), and keeping it there is a deliberate supply-chain property rather
than minimalism for its own sake. The npm graph is the surface that actually gets attacked:
typosquats, compromised maintainer accounts, and package names hallucinated by a model and then
registered by somebody who noticed. A system binary your distribution already ships and patches is
not in that threat class. A fourth npm dependency, pulled in to do cryptography, is a larger risk
than shelling out to a binary you already have.

Shelling out to system tooling is also the established pattern here, not an exception invented for
this feature. AgentWall already spawns `nft` at three sites in `src/perimeter/index.ts` (loading
the ruleset, deleting the table, and reading it back), `systemctl` in `src/routes/dashboard.ts`,
and the wrapped server in `src/mcp/stdio.ts`. `openssl` sits in that category.

Every `openssl` invocation follows the same convention as `nft`: an argv array with `shell: false`,
a timeout, and a bounded output buffer. There is no shell to inject into. The only value that
reaches either a spawn argument or a config file from an untrusted source is the hostname being
minted for, and the config file is the reason that matters: `-extfile` puts the hostname in front
of a parser where a newline would append a directive. It passes a charset allowlist first that
admits letters, digits, hyphen and underscore per label and nothing else, so there is no newline,
no `=`, no `[`, no quote, no semicolon, no backtick, no slash, no dot-dot, no NUL, and no CR to
smuggle. A name that fails that check is not minted for and the connection is tunnelled.

## Configuration

```yaml
interception:
  # Required, and the whole switch. Omit this section entirely and interception does not exist:
  # no CA is read, nothing is decrypted, and the proxy behaves exactly as it did before.
  enabled: true

  # Where the CA lives. Precedence is this key, then AGENTWALL_CA_DIR, then ./agentwall-ca
  # relative to the working directory. Resolved to an absolute path before anything uses it.
  caDir: /var/lib/agentwall/ca

  # Hosts to tunnel instead of intercepting. EXACT match after normalisation (lowercased, IPv6
  # brackets stripped). No wildcards, no suffix matching: "example.com" here does NOT cover
  # "api.example.com". List every host you mean.
  bypassHosts:
    - login.microsoftonline.com
    - api.pinned-vendor.example

  # Runtimes YOU state you installed the CA into. This is an assertion AgentWall cannot verify,
  # and it exists only so a failed trust probe does not block a start that is actually fine.
  # It is logged as an assertion. It proves nothing.
  trustInstalledFor:
    - python-certifi
    - go-1.22-container
```

`bypassHosts` is exact match on purpose, and the reason is worth stating because the first instinct
on reading it is that a wildcard would be more convenient. The egress allowlist in
`src/runtime/enforcement.ts` matches the same way, and a second, looser convention beside it would
be a bypass waiting to happen: `*.example.com` written by one operator and read as a literal by the
other half of the codebase silently covers nothing, or silently covers everything, depending on
which half wins. One convention across both lists means a host is either written out or it is not
covered, and that is checkable by reading the config.

`trustInstalledFor` is not a capability and does not install anything. It is the operator asserting
that trust exists somewhere this process cannot look, and its only effect is to let interception
start when the trust probe fails for a reason that is not a mistake. When it is used, the boot log
says the probe failed and names the assertion as yours.

## Certificate pinning breaks, and here is the escape hatch

A client that pins a certificate or a public key is doing exactly what pinning is for when it
rejects an intercepted connection: the certificate it is offered was signed by your local CA and
not by the authority it was told to expect. It refuses the handshake and the connection fails.
This is not a bug to work around and there is no setting that makes a pinned client accept a minted
certificate.

The symptom lands on the TLS socket's error path, is counted as a failure, and is reported through
`onError` naming the host, so it appears as a named interception failure rather than as an
unexplained connection reset the operator has to go and diagnose.

The escape hatch is `bypassHosts`. A host on that list is tunnelled byte for byte, the way every
https connection was tunnelled before this feature existed, so the pinned client works and the rest
of your interception stays on. You do not have to disable the whole control because one vendor pins.

What a bypass costs, stated so the ledger is never read as more than it is:

- **A bypassed host's bodies are not inspected.** Not sampled, not partially read. The connection is
  relayed and nothing in it is scanned.
- **Its records say `bypassed`, not `intercepted`.** The value is set at the moment the bypass
  decision is made, and the record carries the reason: that the host is on `interception.bypassHosts`,
  so this connection was tunnelled and its body was never read. `bypassed` is deliberately a
  different value from `tunneled`, because "opaque because you chose it" and "opaque because that is
  all this path ever sees" are different claims and a reviewer should be able to tell them apart.

## How to tell what was actually seen

Every egress audit record carries a `bodyVisibility` field. It exists because a DLP history with no
findings is ambiguous, and a reviewer has to be able to resolve that ambiguity **per record**,
without knowing what the configuration was on the day the record was written. The field is always
present: the proxy layer labels what it knows, and anything it did not label is filled in on the
way to the audit record with `tunneled` for https and `plaintext` for http, which is what those
records honestly were.

| Value | What it claims | Written when |
|---|---|---|
| `tunneled` | A host and a port and nothing else. `CONNECT` relayed byte for byte. | Interception is off, or the name cannot be minted for (an IPv6 literal, or anything that is not a plausible hostname or IPv4 address). |
| `bypassed` | Deliberately opaque, by operator choice. | The host is on `interception.bypassHosts`. |
| `plaintext` | A whole body, read because it was never encrypted. | The unencrypted http path, where there was never anything to decrypt. |
| `intercepted` | A whole https body, read because TLS was terminated. | The body was buffered to its end and decoded. |
| `partial` | A prefix was scanned; the remainder was forwarded unread. | The 256 KiB inspection cap or the 1 second stall timer won, or the content encoding could not be decoded. |
| `stream` | Never buffered, on purpose. | The content type is one of `text/event-stream`, `application/x-ndjson`, `application/grpc`. |

Two properties of the field that make it usable as evidence:

- **An exchange claims the weaker of its two halves.** A whole request body with a truncated
  response body is `partial`, not `intercepted`, because a record describes one exchange and has to
  say the weaker thing or it overstates what was seen.
- **The reason travels with it.** When a body could not be fully read, the specific limit (the cap,
  the stall, the undecodable encoding) is appended to the record's reasons and to
  `metadata.interceptBodyLimit`. A record never says "scanned, nothing found" about bytes nobody
  decoded.

`partial` and `stream` bound **inspection**, never delivery. When the cap is hit mid-chunk the
remainder is pushed back and piped on, so the prefix plus the remainder is byte-identical to what
arrived. A body larger than the cap is scanned in part and delivered in full.

## Refusing rather than degrading

Interception is resolved before the proxy listens. Every precondition is checked at startup, and a
failure prints the reason and the fix to stderr and exits non-zero. Nothing is deferred to the
first connection, and there is no path on which interception quietly becomes a pass-through.

| Precondition | What happens when it fails |
|---|---|
| `openssl` on PATH and runnable | Refuses to start, names the PATH searched or the exit status, and points at the install command. |
| A CA certificate and key in `caDir` | Refuses to start and tells you to run `agentwall intercept init`. |
| CA key no wider than 0600 | Refuses to start, prints the actual mode, and gives the `chmod` that fixes it. |
| CA certificate not expired | Refuses to start and names the expiry date. |
| The CA can actually sign | Refuses to start. A CA that exists and cannot mint is the same class of failure as a ruleset that exists and never loaded. |
| Something trusts the CA | Refuses to start unless `trustInstalledFor` declares an install this process cannot see. |

The reason this is a hard refusal rather than a warning and a fallback is that **this project has
already shipped the alternative twice**, and both times the control looked like it was passing:

- An **nftables ruleset that never loaded**, because `redirect` is a reserved keyword in nft. The
  file was generated, the command ran, and nothing was contained.
- A **gitleaks config that reported a clean tree**, because it inherited no rules. Zero findings,
  zero coverage, and a green check.

An operator who enabled interception and got blind tunnelling would be the third instance, and it
would be the worst of the three, because the artefact it produces is a clean DLP history over
traffic nothing read. Refusing to start is loud, happens in front of the terminal you started it
from, and is recoverable in a minute. The alternative is quiet and is discovered after an incident.

The same principle governs every partial read: a body this could not fully scan is recorded as
`partial` or as a stated limit, never as clean.

## What is still opaque

Interception narrows the blind spot. It does not close it, and the list below is what remains.

- **Bypassed hosts.** Relayed unread, by your choice, recorded as `bypassed`.
- **Everything on the transparent path.** The interceptor is wired to the `CONNECT` forward proxy
  only, so a perimeter-captured https connection is named by SNI and tunnelled, exactly as before.
- **Non-`CONNECT` and non-TLS tunnels.** Interception hangs off the `CONNECT` handler. Plain http
  was always readable and does not go through this path at all; anything else that reaches the
  proxy as a raw relay is not decrypted.
- **Names that cannot be minted for.** IPv6 literals are refused deliberately (bracket stripping,
  zone identifiers, and the several legal spellings of one address are a cache-key correctness
  problem this does not solve), as is anything that is not a plausible hostname or an IPv4 literal.
  Those connections tunnel and their records say `tunneled` with the reason.
- **Bodies past the 256 KiB inspection cap**, and bodies that go quiet for more than 1 second.
  Recorded `partial`, the prefix is scanned, and the unread remainder is forwarded **unread but not
  truncated**: the destination and the client both receive every byte that was sent.
- **Streaming content types.** `text/event-stream`, `application/x-ndjson`, and
  `application/grpc` are never buffered, because buffering a stream converts it into a hang. They
  are forwarded unread and recorded `stream`, which is an admission rather than a pass.
- **Content encodings zlib cannot decode.** `gzip`, `deflate`, and `br` are decoded for inspection.
  Anything else is recorded as a stated limit with no text, never as a clean scan.
- **Bodies that trip the 4 MiB decompression bound.** The bound is handed to zlib as
  `maxOutputLength` so a compression bomb is refused before the allocation happens, and the refusal
  is recorded as a limit rather than as a clean read.
- **Clients that pin.** They break rather than being inspected, and the fix is a bypass, which is
  another opaque host.
- **Clients whose runtime does not trust the CA.** They fail certificate verification inside the
  agent. Nothing is silently downgraded to make them work.
- **QUIC and HTTP/3.** They do not use `CONNECT` and do not reach this path at all.
- **HTTP/2 is downgraded, not just unread.** The intercepted server advertises no ALPN protocols
  and the inner parser is Node's HTTP/1.1 server, so a client that would have negotiated h2 with
  the real upstream speaks HTTP/1.1 through an intercepted connection instead. That is a behaviour
  change worth knowing before you debug a throughput or head-of-line regression. A request the
  parser rejects has its socket closed rather than being forwarded unexamined.
- **Anything the perimeter does not redirect in the first place**, and anything that never reaches
  the proxy because the client declined to cooperate. Interception reads what arrives; it does not
  capture. See [the perimeter](perimeter.md) for that half.

One more limit, on the check rather than on the traffic. **The trust probe speaks only for the
AgentWall Node process.** It answers its question by handshaking against a leaf the CA just signed,
using the ambient trust store, which is a real measurement and not a guess about where a bundle
lives on this distribution. But the agent being proxied may be Python trusting certifi, Go trusting
its own bundle, `curl` trusting the system store, or a container image with a bundle baked in, and
this probe cannot see any of them. A passing probe is a necessary condition, never a sufficient
one, and `trustInstalledFor` is how you tell AgentWall about the runtimes it cannot check. It takes
your word for it and says so.

## Operator walkthrough

Four subcommands, none of which turn interception on by themselves. Exit codes are `0` for ok, `1`
for a failure, and `2` for bad usage. `--ca-dir <path>` works on all four and follows the same
precedence as the config key: the flag, then `AGENTWALL_CA_DIR`, then `./agentwall-ca`.

**1. Create the CA.**

```bash
agentwall intercept init --ca-dir /var/lib/agentwall/ca
```

Creates the directory `0700`, writes `ca.crt` (`0644`) and `ca.key` (`0600`), then prints both
paths, the `sha256:` fingerprint, the warning that whoever reads the key can impersonate every site
to this host, and the command to run next. `--days <n>` overrides the 825 day lifetime. Running it
against a directory that already holds a CA exits `1` and changes nothing: overwriting would
invalidate every leaf already minted and leave the old certificate installed in trust stores as a
key nobody can account for. To rotate, remove the directory deliberately and re-run.

**2. Install trust, in every runtime that needs it.**

```bash
agentwall intercept trust --ca-dir /var/lib/agentwall/ca
```

Prints the install commands for Debian/Ubuntu, RHEL/Fedora, Node, Python, and Go. It prints them
rather than running them, because installing a signing key into a system trust store is a decision
an operator makes, not one a tool makes on their behalf. `--json` emits the same content as
`{caCertPath, fingerprint, instructions}` for scripted installs. Exits `1` if there is no CA yet.

Two things to know before you follow the output:

- **`NODE_EXTRA_CA_CERTS` is read once, at Node startup.** Exporting it in a shell where AgentWall
  is already running does nothing. Set it and restart the process.
- **The system trust store does not cover runtimes that ship their own bundle.** Python certifi,
  Go, and container images each keep their own, which is why they are listed separately. Installing
  into the system store and assuming the agent picked it up is the most common way this ends up half
  working.

`agentwall intercept path` prints only the absolute path to `ca.crt` on stdout, so it composes:

```bash
export NODE_EXTRA_CA_CERTS="$(agentwall intercept path --ca-dir /var/lib/agentwall/ca)"
```

**3. Check the CA before you rely on it.**

```bash
agentwall intercept status --ca-dir /var/lib/agentwall/ca
```

Prints six labelled lines to stdout: openssl (present with its version, or missing with the reason
it could not run), the CA directory, the certificate path (or `absent`), the fingerprint, the
expiry with `(EXPIRED)` appended when it is, and the key mode. Problems go to stderr, all of them
rather than only the first, so fixing one does not mean re-running to discover the next, and
`status > file` still leaves the operator looking at what is wrong. The key path appears only
inside a problem, such as the mode complaint that names it alongside the `chmod` that fixes it; the
key's bytes are never read.

It exits `0` only when openssl is present, the CA exists, and the problem list is empty, which
makes it safe as a deployment gate. Read what a clean run does not claim, and it says this itself:
these are properties of the files on disk. They are not evidence that anything trusts the CA, and
not a statement that interception is enabled.

**4. Enable it, and restart.**

Add the [`interception` section](#configuration) to your config and restart AgentWall. The
preconditions are all checked at startup, so either the process comes up with interception active
or it exits telling you exactly which one failed and how to fix it.

On a successful start the log carries a warning naming the CA directory, the bypass list, the
openssl version, the CA fingerprint and expiry, and the result of the trust probe. It is a warning
rather than an info line on purpose: from that moment AgentWall is terminating TLS for every https
host not on the bypass list, and anyone who can read the CA private key can impersonate every site
to this host.
