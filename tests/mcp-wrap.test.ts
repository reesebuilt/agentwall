import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { createHash } from "crypto";
import { PassThrough } from "stream";

import { AuditEvent } from "../src/types";
import { resetAuditChain } from "../src/audit/logger";
import {
  FrameDirection,
  JsonRpcFrame,
  MCP_BLOCKED_ERROR_CODE,
  McpBaselineDecision,
  McpBaselineMode,
  McpEvaluation,
  McpToolDescriptor,
} from "../src/mcp/types";

/**
 * The gates are stubbed here, deliberately.
 *
 * This file is about the composition layer: that a verdict reaches the client as the right
 * JSON-RPC outcome, that every verdict lands in the audit chain with enough metadata to be read a
 * month later, and that a tool inventory is baselined only from a frame that was actually
 * forwarded. Feeding it real gate verdicts would tie those assertions to the current pattern set,
 * so tuning a pattern would break tests about audit metadata. The gates' own behaviour is covered
 * where the gates live.
 *
 * Everything else is real: a real child process, the real stdio transport, the real audit logger
 * and its hash chain.
 */
type GateHook = (
  frame: JsonRpcFrame,
  direction: FrameDirection,
  context: { baselineDecision?: McpBaselineDecision },
) => McpEvaluation;

let mockEvaluate: GateHook = () => mockAllow();
const mockInventories: McpToolDescriptor[][] = [];

jest.mock("../src/mcp/gates", () => ({
  evaluateFrame: (
    frame: JsonRpcFrame,
    direction: FrameDirection,
    context: { baselineDecision?: McpBaselineDecision },
  ) => mockEvaluate(frame, direction, context),
  recordToolInventory: (ctx: { approvedTools?: McpToolDescriptor[] }, tools: McpToolDescriptor[]) => {
    ctx.approvedTools = [...tools];
    mockInventories.push([...tools]);
  },
}));

function mockAllow(overrides: Partial<McpEvaluation> = {}): McpEvaluation {
  return {
    decision: "allow",
    riskLevel: "low",
    reasons: [],
    detectionIds: [],
    outcomes: [],
    ...overrides,
  };
}

// Imported after jest.mock so the wrapper binds to the stubbed gates.
import { buildServerIdentity, runMcpWrap } from "../src/mcp/wrap";
import { parseMcpArgs } from "../src/cli";

/**
 * A minimal MCP-shaped server: newline-delimited JSON-RPC in, one response per request out.
 *
 * It echoes back the method and params it received, which is how a test tells the difference
 * between a frame that was forwarded, a frame that was redacted before forwarding, and a frame the
 * server never saw at all.
 */
const CHILD_SERVER = `
let buffered = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffered += chunk;
  for (;;) {
    const newline = buffered.indexOf("\\n");
    if (newline === -1) break;
    const line = buffered.slice(0, newline).trim();
    buffered = buffered.slice(newline + 1);
    if (line.length === 0) continue;
    const frame = JSON.parse(line);
    if (frame.id === undefined || frame.id === null) continue;
    const result = frame.method === "tools/list"
      ? { tools: [{ name: "read_file", description: "Read a file" }, { name: "write_file" }] }
      : { saw: frame.method, params: frame.params === undefined ? null : frame.params };
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: frame.id, result }) + "\\n");
  }
});
process.stdin.on("end", () => process.exit(0));
`;

/** Same protocol, but exits nonzero so the wrapper's exit-code passthrough is observable. */
const CHILD_FAILING_SERVER = `
process.stdin.resume();
process.stdin.on("end", () => process.exit(3));
`;

interface WrapHarness {
  /** Stream the "client" writes request frames into. */
  client: PassThrough;
  /** Frames the client has received: forwarded server responses, and blocks the gates produced. */
  frames: JsonRpcFrame[];
  /** Audit events this wrap produced, in chain order. */
  events: AuditEvent[];
  /** Resolves with the server's exit code. */
  finished: Promise<number>;
  /** Resolves once at least `count` frames have reached the client; rejects if the server exits first. */
  awaitFrames(count: number): Promise<JsonRpcFrame[]>;
}

const tempPaths: string[] = [];

function startWrap(
  script: string = CHILD_SERVER,
  baseline?: { mode: McpBaselineMode; file: string },
): WrapHarness {
  const client = new PassThrough();
  const toClient = new PassThrough();
  const childErrors = new PassThrough();
  childErrors.resume(); // a chatty server must not stall on an unread stderr

  const frames: JsonRpcFrame[] = [];
  const waiting: Array<{ count: number; resolve: () => void }> = [];
  let buffered = "";
  toClient.setEncoding("utf8");
  toClient.on("data", (chunk: string) => {
    buffered += chunk;
    for (;;) {
      const newline = buffered.indexOf("\n");
      if (newline === -1) break;
      const line = buffered.slice(0, newline).trim();
      buffered = buffered.slice(newline + 1);
      if (line.length === 0) continue;
      const parsed: JsonRpcFrame = JSON.parse(line);
      frames.push(parsed);
    }
    for (let i = waiting.length - 1; i >= 0; i -= 1) {
      if (frames.length >= waiting[i].count) waiting.splice(i, 1)[0].resolve();
    }
  });

  const events: AuditEvent[] = [];
  const finished = runMcpWrap({
    command: [process.execPath, "-e", script],
    serverName: "trivial-server",
    agentId: "test-agent",
    onAuditEvent: (event) => {
      // emit() is the only producer of these and it returns AuditEvent; the hook is typed unknown
      // so the MCP plane does not have to export the audit shape.
      const recorded = event as AuditEvent;
      events.push(recorded);
    },
    stdin: client,
    stdout: toClient,
    stderr: childErrors,
    baselineMode: baseline?.mode,
    baselineFile: baseline?.file,
  });

  // A server that dies before it answers should fail a test with that fact rather than with a bare
  // timeout. One derived promise, with its own catch, so the loser of the race below is always
  // observed and never surfaces as an unhandled rejection.
  const exitedEarly = finished.then((code) => {
    throw new Error(`server exited with status ${code} before the expected frames arrived`);
  });
  exitedEarly.catch(() => {});

  return {
    client,
    frames,
    events,
    finished,
    async awaitFrames(count: number): Promise<JsonRpcFrame[]> {
      if (frames.length < count) {
        // Resolved by the 'data' event that completes the count: no polling and no fixed delay, so
        // the test is as fast as the transport and never races a tuned duration. The executor form
        // is deliberate; this project's lib is ES2022, which predates Promise.withResolvers.
        const arrived = new Promise<void>((resolve) => {
          waiting.push({ count, resolve });
        });
        await Promise.race([arrived, exitedEarly]);
      }
      return frames;
    },
  };
}

function send(harness: WrapHarness, frame: JsonRpcFrame): void {
  harness.client.write(`${JSON.stringify(frame)}\n`);
}

/** Close the client stream and let the server exit, so no test leaves a child behind. */
async function shutdown(harness: WrapHarness): Promise<number> {
  harness.client.end();
  return harness.finished;
}

function toolCall(id: number, name: string, args: Record<string, unknown> = {}): JsonRpcFrame {
  return { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } };
}

beforeEach(() => {
  resetAuditChain();
  mockEvaluate = () => mockAllow();
  mockInventories.length = 0;
});

afterEach(() => {
  resetAuditChain();
  while (tempPaths.length) {
    fs.rmSync(tempPaths.pop()!, { recursive: true, force: true });
  }
});

describe("buildServerIdentity", () => {
  it("names the server after its executable and fingerprints the binary", () => {
    const identity = buildServerIdentity(["/bin/echo"]);

    expect(identity.serverName).toBe("echo");
    expect(identity.command).toEqual(["/bin/echo"]);
    expect(identity.commandHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("hashes the bytes of the launched file, not its path", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aw-mcp-"));
    tempPaths.push(dir);
    const file = path.join(dir, "fake-server");
    const bytes = Buffer.from("#!/bin/sh\necho not a real server\n");
    fs.writeFileSync(file, bytes);

    expect(buildServerIdentity([file]).commandHash).toBe(createHash("sha256").update(bytes).digest("hex"));
  });

  it("records no hash for a command it cannot read, and does not throw", () => {
    const identity = buildServerIdentity(["definitely-not-a-real-binary-xyz", "--stdio"]);

    expect(identity.serverName).toBe("definitely-not-a-real-binary-xyz");
    expect(identity.command).toEqual(["definitely-not-a-real-binary-xyz", "--stdio"]);
    expect(identity.commandHash).toBeUndefined();
  });

  it("records no hash when the command resolves to something that is not a file", () => {
    expect(buildServerIdentity([os.tmpdir()]).commandHash).toBeUndefined();
  });

  it("prefers an explicit server name over the executable basename", () => {
    expect(buildServerIdentity(["/usr/bin/env", "node", "server.js"], "filesystem").serverName).toBe("filesystem");
  });

  it("refuses a command with nothing to launch", () => {
    expect(() => buildServerIdentity([])).toThrow(/nothing to wrap/);
  });
});

describe("runMcpWrap", () => {
  it("forwards an allowed tools/call and records both directions in the audit chain", async () => {
    const harness = startWrap();

    send(harness, toolCall(1, "read_file", { path: "/tmp/notes.txt" }));
    await harness.awaitFrames(1);

    expect(harness.frames[0].id).toBe(1);
    expect(harness.frames[0].result).toEqual({
      saw: "tools/call",
      params: { name: "read_file", arguments: { path: "/tmp/notes.txt" } },
    });

    // Both records exist by now: each is written before its frame is passed on.
    expect(harness.events).toHaveLength(2);

    const request = harness.events.find((event) => event.metadata?.direction === "client_to_server");
    expect(request?.action).toBe("mcp:tools/call");
    expect(request?.plane).toBe("tool");
    expect(request?.decision).toBe("allow");
    expect(request?.agentId).toBe("test-agent");
    expect(request?.metadata?.mcpServer).toBe("trivial-server");
    expect(request?.metadata?.mcpMethod).toBe("tools/call");
    expect(request?.metadata?.mcpTool).toBe("read_file");
    expect(request?.metadata?.commandHash).toMatch(/^[0-9a-f]{64}$/);

    // A response carries no method, so naming it proves the request correlation works.
    const response = harness.events.find((event) => event.metadata?.direction === "server_to_client");
    expect(response?.plane).toBe("content");
    expect(response?.metadata?.mcpMethod).toBe("tools/call");
    expect(response?.provenance).toEqual([{ source: "tool_output", trustLabel: "untrusted" }]);

    // Frame bodies are not evidence this tool is willing to store: the record names the call.
    expect(JSON.stringify(harness.events)).not.toContain("/tmp/notes.txt");

    // One wrap invocation is one session, and every record links into one chain.
    expect(new Set(harness.events.map((event) => event.sessionId)).size).toBe(1);
    expect(harness.events.map((event) => event.integrity.chainIndex)).toEqual([0, 1]);

    expect(await shutdown(harness)).toBe(0);
  }, 15000);

  it("answers a denied frame with a JSON-RPC error and never lets it reach the server", async () => {
    const harness = startWrap();
    mockEvaluate = (frame) =>
      frame.id === 1
        ? mockAllow({
            decision: "deny",
            riskLevel: "critical",
            reasons: ["tool write_file is not approved for this agent"],
            detectionIds: ["det.mcp.tool.blocked"],
            blockingGate: "policy",
            outcomes: [
              {
                gate: "policy",
                decision: "deny",
                riskLevel: "critical",
                reasons: ["tool write_file is not approved for this agent"],
                detectionIds: ["det.mcp.tool.blocked"],
              },
            ],
          })
        : mockAllow();

    send(harness, toolCall(1, "write_file", { path: "/etc/passwd", contents: "x" }));
    send(harness, toolCall(2, "read_file", { path: "/tmp/notes.txt" }));
    await harness.awaitFrames(2);

    // The block is synthesised locally and only the second call reached the server, so a result for
    // id 1 would mean the deny leaked.
    expect(harness.frames.map((frame) => frame.id)).toEqual([1, 2]);
    expect(harness.frames[0].result).toBeUndefined();
    expect(harness.frames[0].error?.code).toBe(MCP_BLOCKED_ERROR_CODE);
    expect(harness.frames[0].error?.message).toBe("tool write_file is not approved for this agent");
    expect(harness.frames[0].error?.data).toEqual({
      detections: ["det.mcp.tool.blocked"],
      gate: "policy",
    });
    expect(harness.frames[1].result).toEqual({
      saw: "tools/call",
      params: { name: "read_file", arguments: { path: "/tmp/notes.txt" } },
    });

    const denied = harness.events.filter((event) => event.decision === "deny");
    expect(denied).toHaveLength(1);
    expect(denied[0].riskLevel).toBe("critical");
    expect(denied[0].action).toBe("mcp:tools/call");
    expect(denied[0].metadata?.mcpTool).toBe("write_file");
    expect(denied[0].metadata?.mcpGate).toBe("policy");
    expect(denied[0].matchedRules).toEqual(["mcp:policy"]);
    expect(denied[0].reasons).toEqual(["tool write_file is not approved for this agent"]);
    expect(denied[0].highRiskFlow).toBe(true);
    expect(denied[0].detections?.map((detection) => detection.id)).toEqual(["det.mcp.tool.blocked"]);

    expect(await shutdown(harness)).toBe(0);
  }, 15000);

  it("blocks a call that needs approval and records it as held for a human", async () => {
    const harness = startWrap();
    mockEvaluate = () =>
      mockAllow({
        decision: "approve",
        riskLevel: "high",
        reasons: ["shell execution requires an operator decision"],
        blockingGate: "policy",
        outcomes: [
          {
            gate: "policy",
            decision: "approve",
            riskLevel: "high",
            reasons: ["shell execution requires an operator decision"],
            detectionIds: [],
          },
        ],
      });

    send(harness, toolCall(7, "run_shell", { command: "rm -rf /" }));
    await harness.awaitFrames(1);

    expect(harness.frames[0].error?.code).toBe(MCP_BLOCKED_ERROR_CODE);
    expect(harness.frames[0].error?.message).toBe(
      "MCP tools/call requires operator approval: shell execution requires an operator decision"
    );

    // The record says what happened: policy asked for a human, and the call did not run.
    expect(harness.events[0].decision).toBe("approve");
    expect(harness.events[0].requiresApproval).toBe(true);
    expect(harness.events[0].metadata?.mcpTool).toBe("run_shell");

    expect(await shutdown(harness)).toBe(0);
  }, 15000);

  it("forwards the redacted frame when the gates redact", async () => {
    const harness = startWrap();
    mockEvaluate = (frame, direction) =>
      direction === "client_to_server"
        ? mockAllow({
            decision: "redact",
            riskLevel: "medium",
            reasons: ["secret material removed from tool arguments"],
            redactedFrame: {
              jsonrpc: "2.0",
              id: frame.id,
              method: "tools/call",
              params: { name: "read_file", arguments: { token: "[REDACTED]" } },
            },
          })
        : mockAllow();

    send(harness, toolCall(4, "read_file", { token: "AKIAIOSFODNN7EXAMPLE" }));
    await harness.awaitFrames(1);

    // The server echoes what it received, so this is what actually crossed the boundary.
    expect(harness.frames[0].result).toEqual({
      saw: "tools/call",
      params: { name: "read_file", arguments: { token: "[REDACTED]" } },
    });
    expect(JSON.stringify(harness.frames)).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(harness.events[0].decision).toBe("redact");

    expect(await shutdown(harness)).toBe(0);
  }, 15000);

  it("baselines the advertised tool inventory from a forwarded tools/list result", async () => {
    const harness = startWrap();

    send(harness, { jsonrpc: "2.0", id: 9, method: "tools/list" });
    await harness.awaitFrames(1);

    expect(mockInventories).toEqual([
      [{ name: "read_file", description: "Read a file" }, { name: "write_file" }],
    ]);

    expect(await shutdown(harness)).toBe(0);
  }, 15000);

  it("does not baseline an inventory the gates denied", async () => {
    const harness = startWrap();
    mockEvaluate = (_frame, direction) =>
      direction === "server_to_client"
        ? mockAllow({
            decision: "deny",
            riskLevel: "high",
            reasons: ["advertised tool description carries an instruction override"],
            detectionIds: ["inj.instruction_override.ignore_previous"],
            blockingGate: "tool_inventory",
            outcomes: [
              {
                gate: "tool_inventory",
                decision: "deny",
                riskLevel: "high",
                reasons: ["advertised tool description carries an instruction override"],
                detectionIds: ["inj.instruction_override.ignore_previous"],
              },
            ],
          })
        : mockAllow();

    send(harness, { jsonrpc: "2.0", id: 11, method: "tools/list" });
    await harness.awaitFrames(1);

    expect(harness.frames[0].error?.code).toBe(MCP_BLOCKED_ERROR_CODE);
    // A poisoned list that became the baseline would make the next tools/list look clean.
    expect(mockInventories).toHaveLength(0);

    const blocked = harness.events.find((event) => event.decision === "deny");
    expect(blocked?.plane).toBe("content");
    expect(blocked?.detections?.[0]).toEqual({
      id: "inj.instruction_override.ignore_previous",
      ruleId: "mcp:tool_inventory",
      name: "inj.instruction_override.ignore_previous",
      description: "Raised by the MCP tool inventory gate.",
      severity: "high",
    });

    expect(await shutdown(harness)).toBe(0);
  }, 15000);

  it("records the baseline mode, state, path, and drift without frame content", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aw-mcp-baseline-audit-"));
    tempPaths.push(dir);
    const baselineFile = path.join(dir, "baselines.json");
    const harness = startWrap(CHILD_SERVER, { mode: "lock", file: baselineFile });
    mockEvaluate = (_frame, direction, context) => {
      if (direction === "server_to_client") {
        context.baselineDecision = {
          state: "drift",
          drift: ['"write_file" is new since approval'],
        };
        return mockAllow({
          decision: "approve",
          riskLevel: "high",
          reasons: ["tool inventory drifted"],
          detectionIds: ["det.mcp.tool.drift"],
        });
      }
      return mockAllow();
    };

    send(harness, { jsonrpc: "2.0", id: 12, method: "tools/list" });
    await harness.awaitFrames(1);

    const response = harness.events.find(
      (event) => event.metadata?.direction === "server_to_client",
    );
    expect(response?.metadata).toMatchObject({
      mcpBaselineMode: "lock",
      mcpBaselineState: "drift",
      mcpBaselinePath: baselineFile,
      mcpBaselineDrift: JSON.stringify(['"write_file" is new since approval']),
    });
    expect(JSON.stringify(response)).not.toContain("Read a file");

    expect(await shutdown(harness)).toBe(0);
  }, 15000);

  it("exits with the server's own status", async () => {
    const harness = startWrap(CHILD_FAILING_SERVER);

    expect(await shutdown(harness)).toBe(3);
  }, 15000);
});

describe("mcp CLI arguments", () => {
  it("takes everything after -- as the server command", () => {
    expect(parseMcpArgs(["wrap", "--", "node", "-e", "process.stdin.resume()"])).toEqual({
      command: ["node", "-e", "process.stdin.resume()"],
    });
  });

  it("reads our own options before the separator", () => {
    expect(
      parseMcpArgs([
        "wrap",
        "--server-name",
        "filesystem",
        "--agent-id",
        "desktop-client",
        "--",
        "npx",
        "-y",
        "server",
        "/tmp",
      ])
    ).toEqual({
      serverName: "filesystem",
      agentId: "desktop-client",
      command: ["npx", "-y", "server", "/tmp"],
    });
  });

  it("parses persistent baseline options before the server command", () => {
    expect(
      parseMcpArgs([
        "wrap",
        "--baseline-mode",
        "lock",
        "--baseline-file",
        "/tmp/mcp-baselines.json",
        "--",
        "server",
      ])
    ).toEqual({
      baselineMode: "lock",
      baselineFile: "/tmp/mcp-baselines.json",
      command: ["server"],
    });
  });

  it("rejects an invalid baseline mode before launch", () => {
    expect(() =>
      parseMcpArgs(["wrap", "--baseline-mode", "strict", "--", "server"])
    ).toThrow(/--baseline-mode must be off, learn, or lock/);
  });

  it("does not interpret the server's own flags as ours", () => {
    expect(parseMcpArgs(["wrap", "--", "my-server", "--server-name", "spoofed", "--port", "8080"])).toEqual({
      command: ["my-server", "--server-name", "spoofed", "--port", "8080"],
    });
  });

  it("requires the separator", () => {
    expect(() => parseMcpArgs(["wrap"])).toThrow(/after --/);
    expect(() => parseMcpArgs(["wrap", "--server-name", "filesystem"])).toThrow(/after --/);
  });

  it("requires a command after the separator", () => {
    expect(() => parseMcpArgs(["wrap", "--"])).toThrow(/nothing to wrap/);
  });

  it("rejects an unknown subcommand and names the one that exists", () => {
    expect(() => parseMcpArgs(["bogus"])).toThrow(/Unknown mcp subcommand: bogus/);
    expect(() => parseMcpArgs(["bogus"])).toThrow(/wrap/);
    expect(() => parseMcpArgs([])).toThrow(/mcp subcommand required/);
  });

  it("rejects an unknown option and an option missing its value", () => {
    expect(() => parseMcpArgs(["wrap", "--nope", "x", "--", "server"])).toThrow(/Unknown mcp wrap option: --nope/);
    expect(() => parseMcpArgs(["wrap", "--server-name", "--", "server"])).toThrow(/--server-name needs a value/);
  });
});
