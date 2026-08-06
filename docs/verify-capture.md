# Proving an agent is actually captured

`agentwall verify-capture` makes one agent fetch a single-use canary URL, then asserts three
things separately and tells you which of them held.

```
agentwall verify-capture --agent <id> [--command '<cmd>'] [options]
```

It exists because configuration is not the hard part. Proof is. Three controls in this
repository shipped green and non-functional: `perimeter install` never installed anything
because nft refused the socket it was handed, the gitleaks config scanned nothing because it
inherited no rules, and content inspection ran on zero proxied traffic because the egress
attempt could not carry a body. Each of them passed its own check. An integration story that
told you "your proxy environment variables are set" would be the fourth.

## What it does

1. Binds a canary: an HTTP listener on an ephemeral loopback port, checked against the forward
   proxy's own port, carrying a fresh 256-bit token in its path. Nothing else on the host can
   be mistaken for that request, and nothing can guess the URL.
2. Makes the agent fetch it, either by running a command you give it or by printing the URL
   and waiting.
3. Reads the audit chain, reads what arrived at the canary, and reports three assertions.

```
$ agentwall verify-capture --agent scraper --proxy http://127.0.0.1:3128 \
    --command 'AW_COMM=aw-scraper HTTPS_PROXY=http://127.0.0.1:3128 my-agent fetch {url}'

CAPTURED  agent "scraper"
  canary   http://127.0.0.1:46029/agentwall-canary/34872101...398f5d
  chain    /var/lib/agentwall/audit.jsonl

PASS  recorded in the audit chain
      1 record(s) for this token. First: chain index 214, decision "allow",
      127.0.0.1:46029 via the forward transport in monitor mode.
PASS  bound to the expected agent
      bound to "scraper" at tier comm (weak): the process name, and nothing else. WEAK.
      comm is a 16-byte label the process writes itself [...]
PASS  the canary was NOT reached directly
      1 request(s) reached the canary and each has a chain record. Independently
      confirmed: every connection to the canary came from pid 1967816, the process
      listening on proxy port 3128. The hop came from AgentWall.
```

Exit status is `0` when all three pass, `1` when the agent is not captured or a bypass was
found, and `2` when the check could not be completed, so a script can tell "it failed" apart
from "it never ran". `--json` prints the whole report, assertions, canary hits, matched
records and all.

## The three assertions, and why they are separate

### 1. A record for this exact request is in the audit chain

The weakest of the three on its own. It proves the proxy saw something. It does not prove
everything went through the proxy, which is the next two assertions' job.

### 2. The record binds it to the named agent, and at which tier

`credential`, `uid+comm`, `uid` and `comm`, strongest first. The tier is always printed,
because "captured" and "captured, bound by comm only" are materially different statements and
an operator told only the first has been misled by omission.

| Tier | Strength | What it actually is |
| --- | --- | --- |
| `credential` | strong | A secret presented on the proxy connection. Unforgeable by a process that cannot read it, forgeable by any process that can, which on a single-uid host is most of them. |
| `uid+comm` | moderate | The kernel's owner of the socket, narrowed by a process name. Exactly as strong as its uid half. |
| `uid` | moderate | The kernel's owner of the socket. Real and coarse: agents sharing a uid are indistinguishable. |
| `comm` | weak | The process name, and nothing else. `process.title` sets it to any string the process likes. |

Two failures land here and both matter:

**Undeclared traffic.** When no declared agent claims a connection, the registry records the
process comm as the id with `agentDeclared=false` and `agentMatchedOn=none`. That is
*unattributed* traffic, and it never satisfies a check for a named agent. The check requires
all three of the declaration flag, a real tier, and the id, precisely because a process that
sets its own comm to a declared agent's id produces a record carrying that id. Comparing the
id alone would let any process on the box impersonate any agent in this report.

**A tier weaker than the one you configured.** An agent declaring a credential that binds by
comm instead is an agent that is not presenting the credential. The check still passes, and it
says so:

```
  WEAKER THAN CONFIGURED: configured to bind at tier credential, actually bound at tier
  comm. The proxy credential is not being presented on this connection, so the strong
  binding the config promises is not in force.
```

### 3. The canary was NOT reached directly

This is the point of the command.

A request that arrives at the canary with no corresponding chain record is an agent that
reached the network without passing through AgentWall. A check that looked only for a chain
record would report "captured" while half that agent's traffic went around the proxy, which is
exactly the failure this repository keeps finding.

```
BYPASS DETECTED  agent "scraper"

FAIL  recorded in the audit chain
      the canary was reached 1 time(s) and no record for this token exists in the chain.
FAIL  the canary was NOT reached directly
      BYPASS. 1 of 1 request(s) reached the canary with no matching chain record.
      Reached by: GET /agentwall-canary/7d394f...c759 from pid 1967895 (comm aw-scraper,
      uid 1001). That traffic left this host's control without passing through AgentWall.
```

Two independent signals feed this assertion, and they are reported separately:

**Hit count against record count.** The canary token is single-use: the first presentation is
served, and every later one is refused `410 Gone` and recorded as a replay. The listener stays
open, so an agent that is captured *and* also goes around produces two hits and one record.
That partial bypass is the case a naive check gets wrong, because the chain record it finds is
real and correctly bound.

**Peer attribution.** The pid that opened the connection to the canary is resolved through
`/proc/net/tcp`, and compared against the pid holding the listening socket on the proxy port.
This is a measurement, not a correlation, and it is what lets the report name the process that
escaped rather than saying "something".

It is three-valued on purpose. A resolved pid that is not the proxy's is evidence of a direct
connection. A pid that could not be resolved is no evidence at all, and the report says
`Peer attribution unavailable` rather than contradicting a chain record that may well be
correct. Attribution is best-effort by contract: a `/proc` race, an unreadable
`/proc/<pid>/fd` when AgentWall runs as another uid, or a non-Linux host all yield no pid.
Treating that as "not the proxy" would fail every correctly captured agent on those hosts.

Pass `--proxy <url>` to enable this second signal. Without it, or without the environment's
`HTTPS_PROXY`/`HTTP_PROXY`, the assertion rests on the chain correlation alone and says so.

## Driving the fetch

### `--command '<cmd>'`

Runs through `/bin/sh -c`. `{url}` is substituted wherever it appears; with no placeholder the
URL is appended as the last argument. `AGENTWALL_CANARY_URL` is exported into the child either
way.

**The child's environment is inherited and never augmented.** `verify-capture` does not inject
`HTTPS_PROXY` into the command it runs. Injecting it would measure this command's environment
rather than your agent's configuration, and would report "captured" for an agent that is not
configured at all. Whatever proxy settings your agent normally runs with are the ones under
test. This is also how you deliberately construct a bypass, to check that the check works: run
the same fetch with the proxy variables unset.

### Interactive mode

Omit `--command`. The URL and the prompt go to stderr, the report goes to stdout, so `--json`
stays a single parseable document.

```
$ agentwall verify-capture --agent claude-code --proxy http://127.0.0.1:3128
Have claude-code fetch this URL, then this check will continue:

    http://127.0.0.1:33419/agentwall-canary/6ee77ac9...889bb

Waiting up to 120s. Press Enter when the agent has tried, [...]
```

It returns on whichever comes first: the canary being hit, a line on stdin, or `--timeout`.
The stdin path is there because a proxy that *denies* the destination means the canary is
never reached, and waiting for a hit would then hang until the timeout.

## NO_PROXY, and why it makes this check refuse to answer

`NO_PROXY` is a list of destinations the client is told to reach *without* a proxy. The canary
binds `127.0.0.1` by default, so an environment carrying

```
export NO_PROXY='localhost,127.0.0.1,::1'
```

fetches the canary directly by construction. Before judging anything, `verify-capture` reads
the `NO_PROXY` the fetch will inherit and matches it against the canary host. If it matches, a
direct hit is **not** reported as a bypass. The outcome is `INCONCLUSIVE`, exit 2, naming the
entry:

```
INCONCLUSIVE  agent "scraper"
  WARNING  NO_PROXY contains "127.0.0.1", which covers the canary at 127.0.0.1:46029.
           Every address NO_PROXY covers is one this agent is told to reach
           without AgentWall. Narrow it, or pass --host to move the canary.
```

A check whose own environment pre-decided the answer must not claim either answer. It also
must not pretend nothing is wrong, and this is the part worth sitting with: **every address in
`NO_PROXY` is an address the agent is told to reach without AgentWall.** On a real host that
list usually includes local databases, anything forwarded to loopback over SSH, and any local
proxy that itself reaches the internet. A loopback exemption added so an agent can read the
AgentWall dashboard buys that convenience at the price of an un-governed path to all of
loopback. Most agents never call the dashboard; the operator reaches it from a browser or the
CLI, and neither of those runs with the agent's proxy environment. Where an agent genuinely
needs it, allowlist `127.0.0.1` in that agent's `egress` block instead of exempting it from the
proxy.

### What actually matches, measured

`NO_PROXY` is honoured by the client, not enforced by anything, so this was measured rather
than assumed. Two independent rigs, one for this command and one for the onboarding profiles,
drove each runtime at an origin through a local proxy and counted which listener received the
request:

| Runtime | `NO_PROXY=<host>` | `NO_PROXY=<host>:<other port>` |
| --- | --- | --- |
| curl 8.5.0 | exempts | does **not** exempt: the port is compared |
| python `requests` 2.31.0 | exempts | does **not** exempt |
| node 24 global `fetch` | never proxies at all unless `NODE_USE_ENV_PROXY=1` | with that set: does **not** exempt |

Go was not tested by either rig, so nothing here claims anything about it.

So the match is graded rather than binary. Comma-separated entries; `*` matches everything; a
leading dot or a bare name matches by domain suffix; an exact host matches itself.

- A bare host, or `*`, is **exempted**. Every runtime measured skips the proxy, so a direct hit
  proves nothing and the verdict degrades to `INCONCLUSIVE`.
- A `:port` entry naming some other port is **possible**. All three compare the port, so it is
  inert for them, and the verdict *stands*. It is still named in the report, because three
  runtimes are not every runtime and an operator chasing a bypass should know the entry exists.

Suppressing a bypass on a maybe would be the same unverified confidence as raising one, in the
more comfortable direction. The whole list is walked, and both `NO_PROXY` and `no_proxy`, before
answering: `NO_PROXY=127.0.0.1:3000,127.0.0.1` resolves to **exempted** on the second entry, so
a narrow entry cannot mask a broad one that follows it.

To get a real answer with an exemption in place, either narrow `NO_PROXY` or pass `--host` with
an address it does not match. If the client ignored `NO_PROXY` and went through the proxy
anyway, a chain record exists and the check judges normally; the warning stays.

## Reading the other outcomes

**`INCONCLUSIVE`, exit 2.** Nothing reached the canary and nothing reached the chain. The agent
never fetched the URL. All three assertions read `????`, because silence is not evidence for
either answer. Check the fetch command actually ran; a non-zero exit is printed.

**`INCONCLUSIVE` with the canary reached.** The check's own environment exempted the canary
from the proxy, so a direct hit proves nothing about the agent. See the `NO_PROXY` section
above; the report names the entry and the fix.

**`CAPTURED` with the canary never reached.** The chain has a record with `decision: "deny"`.
AgentWall saw the request and refused the destination, so the canary never heard from it. That
is capture and enforcement together, and it is the normal result in `strict` mode unless the
canary's loopback address is on the agent's allowlist. It is a pass.

## Options

| Flag | Meaning |
| --- | --- |
| `--agent <id>` | Declared agent the traffic must bind to. Required. |
| `--command '<cmd>'` | Shell command that makes the agent fetch. Omit for interactive mode. |
| `--audit <path>` | Audit chain file. Defaults to `$AGENTWALL_AUDIT_FILE`. |
| `--config <path>` | Config naming the fleet. Defaults to the usual discovery. |
| `--proxy <url>` | Proxy the agent uses. Enables the peer-pid check. |
| `--host <addr>` | Interface the canary binds. Default `127.0.0.1`. |
| `--timeout <ms>` | How long to wait for the fetch. Default 120000. |
| `--settle-ms <ms>` | How long to wait for the chain to catch up. Default 3000. |
| `--json` | Machine-readable report. |

The only required input beyond `--agent` is the chain: export `AGENTWALL_AUDIT_FILE` or pass
`--audit`. An agent that is not declared in the config is still checked against the chain; the
report just cannot say what tier to expect.

## Limits

**It does not prove the agent has no other egress path.** This is the largest limit and it
cannot be engineered away. The check proves the route the agent took for THIS request, at this
moment, with this configuration. An agent with a second path it simply did not use during the
check will pass. `verify-capture` measures the path exercised; closing the other paths is what
[the perimeter](perimeter.md) and [the sandbox](sandbox.md) are for, and neither of those is
proven by this command either.

**It proves capture for one request, not for a workload.** One canary fetch says the agent's
HTTP client honoured the proxy for one plain HTTP GET. A harness that routes its own tool calls
through the proxy and shells out to something that does not will pass this check and leak
through the other path. Run it against each way the agent makes requests.

**Plain HTTP only.** The token has to be visible to the proxy, and an https destination is a
CONNECT tunnel with no visible path. The canary is HTTP on loopback for that reason. An agent
that honours `HTTP_PROXY` and ignores `HTTPS_PROXY` will pass here and bypass on https;
`verify-capture` cannot see that, and the two variables are worth setting and checking
separately by other means.

**Presence in the chain is checked, not chain integrity.** A record could be present and the
chain still broken or unanchored. Run [`agentwall verify`](verification.md) for that; it is a
different question with a different answer.

**Peer attribution is best-effort and Linux-only.** Where it is unavailable the result rests on
the chain correlation, and the report labels it `unavailable` rather than guessing. The
independent confirmation is a strengthening signal, not a precondition.

**A transparent perimeter changes what "direct" means.** With `agentwall perimeter` installed,
a fetch that ignores the proxy environment may still be redirected into the transparent
listener and appear in the chain. That is a true result, not a false pass: the traffic really
was captured. It does mean this check cannot be used to prove that a specific *insertion
mechanism* is the one doing the work; the record's `transportMode` field says which one did.

**The canary is loopback by default.** If AgentWall runs in another network namespace or a
container, it cannot reach `127.0.0.1` in your namespace. Use `--host` to bind an address both
sides share, and note that the peer-pid confirmation is unavailable across a host boundary
because the proxy's pid is not in your `/proc`.

**A pass says nothing about what the traffic contained.** This is a routing proof. What the
proxy then does with the request is [enforcement](enforcement.md), and what it can read of the
body is [content inspection](tls-interception.md).
