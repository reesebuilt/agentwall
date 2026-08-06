# Wrapping an MCP server

An MCP server is a program your agent's client launches and then trusts: it advertises tools,
reads files, calls APIs, and returns text that lands directly in the agent's context. Wrapping
puts AgentWall on that connection.

`agentwall mcp wrap` launches the server as a child process and sits between the client and the
server on the stdio transport. Every JSON-RPC frame in both directions goes through the ordered
gates before it is forwarded, and every decision is recorded in the same hash-chained audit format
as the rest of the system. The client's own configuration changes by one line; the server itself is
unmodified and does not know the wrapper is there.

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

## What each gate checks

The gates run in a fixed order, and the order is a contract rather than an implementation detail.
Inventory runs before argument scanning because a poisoned tool description is what talks a model
into building malicious arguments in the first place, and policy runs last because it is the only
gate that needs to see what the earlier gates found.

| Gate | Applies to | What it checks |
| --- | --- | --- |
| `frame_integrity` | every frame | The JSON-RPC envelope: the version is exactly `2.0`, a request carries a method, a response carries exactly one of result or error. Everything here is a property of the envelope, so it holds before anything inside the frame is trusted. The frame-size ceiling and the newline delimiting are enforced earlier still, by the parser: a line that does not parse never becomes a frame and is never forwarded. |
| `tool_inventory` | `tools/list` results | Every advertised tool's name and description, injection-scanned, and the whole list compared against the inventory this session already accepted. A description is read by the model as guidance, which makes it executable text in all but name, and a tool that appears or changes its description mid-session is drift - which is how a server quietly expands what it can be asked to do. |
| `input_scan` | `tools/call` requests | The call's arguments, serialized first so nested structures get the same treatment as top-level strings, then run through the secret and PII scanner and the injection patterns across every normalization pass (zero-width characters, homoglyphs, leetspeak, whitespace, base64, hex). Normalization is why an obfuscated instruction trips the same pattern as a plain one. Secrets redact rather than deny: the call is usually legitimate and the credential inside it is the problem. |
| `policy` | every frame | The existing PolicyEngine, on the existing rules, with the frame expressed as an `AgentContext` and the earlier gates' findings attached as metadata. Tool calls are the `tool` plane; tool results are the `content` plane, tagged untrusted tool output. There is no separate MCP rule language. The engine's default-deny for actions no rule models is deliberately not inherited here: a frame no rule describes is recorded as a miss, and an operator who wants default-deny for MCP writes it as a rule, so the audit record can name the rule that decided. |
| `response_scan` | every server frame | The server's result, and its error too, because an error message is server-controlled text the agent reads. Injection denies at critical: the content has reached the point where the model consumes it and there is no gate downstream. Secrets redact instead, because a server returning a credential is usually doing its job badly rather than maliciously and the rest of the response is still useful. |

A gate that does not apply to a frame contributes nothing, and the pipeline stops at the first
block, so an audit record's gate list is what was actually inspected rather than a fixed five. A
gate that fails outright denies and names itself: a control that failed open would report
"inspected" while inspecting nothing, which is worse than no control, and the price is that a bug
in a scanner refuses frames instead of quietly passing them.

The recorded tool inventory is baselined only from a `tools/list` result that was actually
forwarded. An inventory that was blocked never becomes the approved baseline, because a poisoned
list that quietly became the reference would make every later comparison come back clean. The
first `tools/list` of a session reports no drift, because there is nothing yet for it to have
drifted from.

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
- One wrap invocation is one `sessionId`, so a server's whole conversation groups without inferring
  it from timestamps.

The frame's own contents are deliberately absent. MCP params and results routinely carry file
contents, tokens, and message bodies, and an audit file that quoted them would become the most
sensitive file on the host. The record names the server, the method, the tool, and the decision,
which is what reconstructing the decision needs.

## Limits

Read these before relying on wrapping for anything.

- **Stdio transport only.** A server launched as a child process and spoken to over stdin and
  stdout is wrapped. The HTTP and SSE MCP transports are not: nothing here intercepts them, and a
  client configured to reach a server over a URL is unwrapped even while another server on the same
  client is wrapped.
- **Approval decisions block, they do not prompt.** There is no side channel on a stdio transport
  to ask a human anything, and holding a frame open until an operator answers would stall the
  client's stream for as long as the operator is away. A frame policy would route for approval is
  refused with an error that says so. The approval queue is reachable over the HTTP API; nothing
  makes an MCP call wait for it.
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
