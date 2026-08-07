# Wrapping an MCP server

An MCP server is a program your agent's client launches and then trusts: it advertises tools,
reads files, calls APIs, and returns text that lands directly in the agent's context. Wrapping
puts AgentWall on that connection.

`agentwall mcp wrap` launches the server as a child process and sits between the client and the
server on the stdio transport. Every JSON-RPC frame in both directions goes through the ordered
gates before it is forwarded, and every decision is recorded in the same hash-chained audit format
as the rest of the system. The client's own configuration changes by one line; the server itself is
unmodified and does not know the wrapper is there.

A server the client does not launch at all - one it reaches over a URL - is wrapped a different
way, by a local listener that speaks the same transport and calls the same gates. That is
[below](#wrapping-a-remote-server-over-http).

## The command

```bash
agentwall mcp wrap [--server-name <name>] [--agent-id <id>] -- <command> [args...]
```

- `--server-name <name>` is the name recorded for this server. It defaults to the basename of the
  executable, which is usually the launcher rather than the server, so it is worth setting.
- `--agent-id <id>` is the agent the traffic is attributed to. Unset records `unattributed`, which
  is honest but not useful when you run more than one client.
- Everything after `--` is the server's own command line and is passed through untouched. Its flags
  are its own: `-- my-server --port 9000` launches `my-server --port 9000`.

The wrapper exits with the server's exit status, so a client that watches exit codes cannot tell
the difference between a wrapped server and the server it wraps.

## A worked example

A filesystem server as a client would normally launch it:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

The same server, wrapped:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentwall",
      "args": [
        "mcp", "wrap",
        "--server-name", "filesystem",
        "--agent-id", "desktop-client",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

To watch it by hand before wiring a client to it, run the same command in a terminal and type a
frame at it. It speaks newline-delimited JSON-RPC on stdin and stdout:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | agentwall mcp wrap --server-name filesystem -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## Wrapping a remote server over HTTP

A client configured with a URL launches nothing, so there is no child process to sit inside. The
insertion point that does exist is the URL: AgentWall opens a local listener speaking the same
Streamable HTTP transport, the client is pointed at that instead of at the remote server, and the
listener forwards upstream only what the gates allow through.

The gates are the same objects, called from the same place, and the audit record is the same
record. That is the property worth holding on to: a decision must not depend on which transport
carried the frame, so a call refused over stdio is refused over HTTP for the same reason and with
the same evidence.

Use the CLI form:

```bash
agentwall mcp wrap \
  --http-upstream https://mcp.example.com/mcp \
  --http-host 127.0.0.1 \
  --http-port 8931 \
  --server-name example-remote \
  --agent-id desktop-client
```

Point the MCP client to `http://127.0.0.1:8931/mcp`.
Press `Ctrl-C` to stop a wrapper that the CLI starts.

The running dashboard can also manage an HTTP wrapper.
Open **Operations**, select **Start MCP HTTP wrapper**, and confirm the plan.
The dashboard shows the local endpoint and a wrapper ID.
Use **List MCP HTTP wrappers** to copy the endpoint or ID.
Use **Stop MCP HTTP wrapper** to close one managed wrapper.

The programmatic API remains available for host integrations:

```ts
import { runMcpHttpWrap } from "@repsecure/agentwall/dist/mcp/wrap";

const listener = await runMcpHttpWrap({
  upstreamUrl: "https://mcp.example.com/mcp",
  listenHost: "127.0.0.1",
  listenPort: 8931,
  serverName: "example-remote",
  agentId: "desktop-client",
});

await listener.close();
```

| Option | Flag the CLI will use | What it does |
| --- | --- | --- |
| `upstreamUrl` | `--http-upstream` | Absolute `http:` or `https:` URL of the server being wrapped. Anything else refuses to start. |
| `listenPort` | `--http-port` | Port for the local listener. `0` takes an ephemeral port. |
| `listenHost` | `--http-host` | Interface to bind. Defaults to `127.0.0.1`. A non-loopback bind requires a token. |
| `authToken` | `--http-auth-token-file` | Bearer token clients must present. Optional on loopback, required otherwise. |
| `maxBodyBytes` | - | Request-body ceiling. Defaults to 8 MiB, the same ceiling the stdio framing uses. |
| `serverName`, `agentId`, `sessionId`, `onAuditEvent` | - | As on the stdio path. `serverName` defaults to the upstream host. |

### What the listener covers

- A `POST` carrying one JSON-RPC frame, or a JSON array batch. Each frame in a batch is evaluated on
  its own: a batch of three with one refusal forwards two frames and answers the third with an
  error. A batch where nothing survives never reaches the upstream at all.
- The response to that POST, whether it is a JSON body or a `text/event-stream`.
- The `GET` stream a server uses to push frames the client did not ask for. That traffic is the
  least prompted thing on this transport, and it goes through the response gates like everything
  else.
- The `DELETE` that ends a session.

Any other method is refused with a 405. The listener never emits CORS headers, so a browser cannot
read its responses cross-origin.

### Authentication, and why a loopback listener still checks `Host`

A listener on a routable interface without a token is an open proxy into the wrapped server for
anything that can route to it, so binding one refuses to start rather than starting and warning.
The error names the flag and what to do about it. When a token is set it is required as
`Authorization: Bearer <token>` and compared in constant time, and it is stripped before anything
goes upstream - a local credential replayed to a remote server is a leak nothing downstream would
notice. When no token is set, an `Authorization` header cannot be AgentWall's, so it is treated as
the operator's own upstream credential and passed through untouched.

A tokenless loopback listener additionally requires the request's `Host` authority to be a loopback
name on the port it actually bound. This is the DNS-rebinding check. A page in the operator's
browser can be served from a name the attacker controls whose DNS answer flips to `127.0.0.1` after
the page loads; the browser then sends requests here while treating them as same-origin with the
attacker's page. Everything about such a request looks local - the peer address genuinely is
loopback - except the `Host` header, which still carries the attacker's name. Pinning it is what
breaks the attack. A configured token defeats the same attack on its own, so the check is not
applied when one is set, which keeps a deployment behind a reverse proxy working.

Requests carry a size ceiling of 8 MiB by default; a body above it is answered with a 413 and
nothing is forwarded. A body that is not JSON-RPC at all is refused with a 400, recorded as a
malformed frame, and not forwarded: bytes AgentWall could not parse are bytes it could not scan,
and sending them upstream to see what the server makes of them is the delegation this listener
exists to prevent.

### What a block looks like on HTTP

A blocked frame comes back as the same JSON-RPC error the stdio path produces, on the same id, with
**HTTP status 200**. The refusal is a valid JSON-RPC response and the transport worked perfectly;
returning a 4xx or 5xx would tell the client the exchange failed, and clients retry failed
exchanges - which would mean retrying a decision that will not change, against a server that never
saw any of it.

On a streaming response the posture is different, and stricter. When a gate refuses an event, the
error is written and **the stream is ended**. Skipping the offending event and continuing would look
like enforcement without being any: the events are pieces of one response, so whatever a later event
completes has usually already been delivered by the earlier ones, and a client that keeps receiving
a stream reads it as a stream that was fine. Ending it is the only signal this transport has for
"the rest of this response is not coming". The cost is real: a false positive kills a whole response
rather than one event of it.

## What each gate checks

The gates run in a fixed order, and the order is a contract rather than an implementation detail.
Inventory runs before argument scanning because a poisoned tool description is what talks a model
into building malicious arguments in the first place, and policy runs last because it is the only
gate that needs to see what the earlier gates found.

| Gate | Applies to | What it checks |
| --- | --- | --- |
| `frame_integrity` | every frame | The JSON-RPC envelope: the version is exactly `2.0`, a request carries a method, a response carries exactly one of result or error. Everything here is a property of the envelope, so it holds before anything inside the frame is trusted. The frame-size ceiling and the newline delimiting are enforced earlier still, by the parser: a line that does not parse never becomes a frame and is never forwarded. |
| `tool_inventory` | `tools/list` results | Every advertised descriptor is injection-scanned. Agentwall compares the complete standard descriptor, including input and output schemas, annotations, icons, and metadata. New, removed, or changed fields are drift. A malformed page is denied before it crosses the boundary. |
| `input_scan` | `tools/call` requests | The call's arguments, serialized first so nested structures get the same treatment as top-level strings, then run through the secret and PII scanner and the injection patterns across every normalization pass (zero-width characters, homoglyphs, leetspeak, whitespace, base64, hex). Normalization is why an obfuscated instruction trips the same pattern as a plain one. Secrets redact rather than deny: the call is usually legitimate and the credential inside it is the problem. |
| `policy` | every frame | The existing PolicyEngine, on the existing rules, with the frame expressed as an `AgentContext` and the earlier gates' findings attached as metadata. Tool calls are the `tool` plane; tool results are the `content` plane, tagged untrusted tool output. There is no separate MCP rule language. The engine's default-deny for actions no rule models is deliberately not inherited here: a frame no rule describes is recorded as a miss, and an operator who wants default-deny for MCP writes it as a rule, so the audit record can name the rule that decided. |
| `response_scan` | every server frame | The server's result, and its error too, because an error message is server-controlled text the agent reads. Injection denies at critical: the content has reached the point where the model consumes it and there is no gate downstream. Secrets redact instead, because a server returning a credential is usually doing its job badly rather than maliciously and the rest of the response is still useful. |

A gate that does not apply to a frame contributes nothing, and the pipeline stops at the first
block, so an audit record's gate list is what was actually inspected rather than a fixed five. A
gate that fails outright denies and names itself: a control that failed open would report
"inspected" while inspecting nothing, which is worse than no control, and the price is that a bug
in a scanner refuses frames instead of quietly passing them.

The recorded tool inventory is baselined only from a complete `tools/list` result that was
actually forwarded. Agentwall keeps concurrent cursor sequences separate and compares additions
before it forwards each page. An unknown cursor, a malformed descriptor, or a malformed page fails
closed. An inventory that was blocked never becomes the approved baseline.

## What a blocked call looks like

The client sees a normal JSON-RPC error against the id it sent. Nothing about the transport looks
broken, and the server never received the frame:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32001,
    "message": "tool write_file is not approved for this agent",
    "data": {
      "detections": ["det.mcp.tool.blocked"],
      "gate": "policy"
    }
  }
}
```

`-32001` is the code for a frame AgentWall refused. The `data` block names the gate that decided
and the detection ids it raised, and those are the same ids that appear in the audit record, which
is what lets you join a client-side log to the chain afterwards.

A call that policy holds for a human is refused the same way, with a message that says so:

```json
{
  "jsonrpc": "2.0",
  "id": 43,
  "error": {
    "code": -32001,
    "message": "MCP tools/call requires operator approval: shell execution requires an operator decision"
  }
}
```

A blocked *notification* produces no error, because a JSON-RPC notification has no id to answer on.
It is dropped, and the audit record is the only place it appears.

## MCP decisions in the audit chain

Every evaluated frame produces one audit record, in the same format and the same hash chain as an
egress decision or an HTTP API decision. A client frame is recorded on the `tool` plane, a server
frame on the `content` plane with untrusted tool-output provenance:

```json
{
  "id": "0f1e...",
  "timestamp": "2026-01-14T09:12:44.108Z",
  "agentId": "desktop-client",
  "sessionId": "5c9d...",
  "plane": "tool",
  "action": "mcp:tools/call",
  "decision": "deny",
  "riskLevel": "critical",
  "matchedRules": ["mcp:policy"],
  "reasons": ["tool write_file is not approved for this agent"],
  "requiresApproval": false,
  "highRiskFlow": true,
  "detections": [{ "id": "det.mcp.tool.blocked", "ruleId": "mcp:policy", "...": "..." }],
  "metadata": {
    "mcpServer": "filesystem",
    "mcpMethod": "tools/call",
    "mcpTool": "write_file",
    "direction": "client_to_server",
    "mcpTransport": "stdio",
    "mcpGate": "policy",
    "commandHash": "9f2b..."
  },
  "integrity": { "chainIndex": 12, "hash": "...", "previousHash": "...", "algorithm": "sha256", "status": "chained-local" }
}
```

Reading it:

- `action` is `mcp:<method>`. A response is recorded under the method of the request it answers, so
  a result is attributable to the call that produced it even though a JSON-RPC response carries no
  method of its own.
- `matchedRules` names the gates that returned something other than allow, prefixed `mcp:` so a
  gate name can never be mistaken for a policy rule id.
- `commandHash` is the SHA-256 of the executable that was launched. A server whose hash changes
  between runs is a supply-chain event.
- `mcpTransport` is `stdio` or `http`, and it is on every record because the rest of the metadata
  means different things on each. An HTTP record carries `mcpUpstream` - the upstream's origin and
  path, with any userinfo and query string dropped, because that is where a deployment hides a
  credential - and carries no `commandHash`, since nothing on this side of the connection pins a
  remote server.
- One wrap invocation is one `sessionId`, so a server's whole conversation groups without inferring
  it from timestamps.

The frame's own contents are deliberately absent. MCP params and results routinely carry file
contents, tokens, and message bodies, and an audit file that quoted them would become the most
sensitive file on the host. The record names the server, the method, the tool, and the decision,
which is what reconstructing the decision needs.

## Limits

Read these before relying on wrapping for anything.

- **Stdio and Streamable HTTP are wrapped; no other transport is.** A server launched as a child
  process and spoken to over stdin and stdout is wrapped. A remote server is wrapped when the client
  is pointed at the local HTTP listener: the POST of a frame or a batch, the JSON or
  `text/event-stream` response to it, the GET stream and the DELETE all pass the gates. Two things
  follow from that. A client still configured with the upstream URL directly is unwrapped, because
  the listener protects traffic that goes through it rather than traffic that exists; and any other
  transport, including WebSocket, is not intercepted at all.
- **HTTP mode has no CLI flag yet.** It is reachable through `runMcpHttpWrap` from a host process.
  The flag names in this document are the ones the CLI will use; until that wiring lands, there is
  no shell invocation of HTTP mode.
- **A remote server is not fingerprinted.** `commandHash` pins a binary this host launched, and
  nothing on this side of an HTTP connection pins the server at the other end. Wrapping a remote
  server gives you gating and evidence; it does not tell you the server is the one you configured
  yesterday. What authenticates the upstream is its TLS certificate and whatever credential you give
  it, neither of which AgentWall checks on your behalf.
- **The HTTP listener does not terminate TLS for its own clients.** It speaks plain HTTP on the
  interface it binds, which is why loopback is the default and why a non-loopback bind demands a
  token. Exposing it beyond the host means putting a TLS terminator in front of it.
- **A refused event ends a whole streaming response.** On `text/event-stream` a block terminates the
  stream rather than dropping the one event, because a stream that keeps flowing after a detection
  has already delivered the payload the detection was about. The consequence to plan for is that a
  false positive on event four costs the client events five onward, not just event four.
- **Approval decisions block, they do not prompt.** Neither MCP transport has a side channel to ask
  a human anything, and holding a frame open until an operator answers would stall the client for as
  long as the operator is away. A frame policy would route for approval is refused with an error
  that says so. The approval queue is reachable over the HTTP API; nothing makes an MCP call wait
  for it.
- **Tool-poisoning detection is pattern-based.** The inventory and response gates match known
  phrasings of instruction override, exfiltration directives, role manipulation, tool coercion, and
  state poisoning, across several normalization passes. A novel phrasing that no pattern describes
  will pass. Pattern matching raises the cost of an attack; it does not close the category.
- **The command hash pins the binary, not what it loads.** `commandHash` covers the bytes of the
  file that was executed. It says nothing about what that file reads at runtime: a launcher such as
  `npx` is pinned only as a launcher, and its hash will not change when the package it fetches does.
  For the same reason the hash is absent, not fatal, when the executable cannot be read - an
  unhashable server is a weaker guarantee, not a reason to refuse to gate its traffic.
- **A wrap process records into its own chain.** `agentwall mcp wrap` is a separate process from the
  server started by `agentwall start`, and it registers no durable sink: its records are chained
  in memory and handed to the `onAuditEvent` hook of `runMcpWrap`, which is how an embedding process
  routes them into storage it owns. Writing them into the running service's audit file is not
  something to arrange by pointing both processes at the same path - two independent writers produce
  duplicate chain indexes and broken links, which `verify` reports as tampering. Until a
  single-writer arrangement exists, the hook is the integration point.
