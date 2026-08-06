import { describe, expect, it } from "@jest/globals";
import { createFrameParser, serializeFrame } from "../src/mcp/framing";
import { JsonRpcFrame } from "../src/mcp/types";

const request: JsonRpcFrame = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "read_file" } };
const response: JsonRpcFrame = { jsonrpc: "2.0", id: 1, result: { content: "ok" } };

describe("createFrameParser", () => {
  it("parses a single newline-terminated frame", () => {
    const parser = createFrameParser();
    const outcome = parser.push(serializeFrame(request));

    expect(outcome.frames).toEqual([request]);
    expect(outcome.malformed).toEqual([]);
  });

  it("parses two frames delivered in one chunk", () => {
    const parser = createFrameParser();
    const outcome = parser.push(Buffer.concat([serializeFrame(request), serializeFrame(response)]));

    expect(outcome.frames).toEqual([request, response]);
    expect(outcome.malformed).toEqual([]);
  });

  it("reassembles one frame split across three chunks", () => {
    const wire = serializeFrame(request);
    const first = wire.subarray(0, 8);
    const second = wire.subarray(8, wire.length - 4);
    const third = wire.subarray(wire.length - 4);
    const parser = createFrameParser();

    expect(parser.push(first).frames).toEqual([]);
    expect(parser.push(second).frames).toEqual([]);

    const outcome = parser.push(third);
    expect(outcome.frames).toEqual([request]);
    expect(outcome.malformed).toEqual([]);
  });

  it("keeps a multibyte character intact when the chunk boundary splits it", () => {
    const frame: JsonRpcFrame = { jsonrpc: "2.0", id: 2, method: "notify", params: { text: "日本語 \u{1F512} done" } };
    const wire = serializeFrame(frame);
    // Cut two bytes into the four-byte lock emoji: a parser that decoded each
    // chunk on arrival would emit U+FFFD here and hand the scanners text the
    // sender never wrote.
    const cut = wire.indexOf(Buffer.from("\u{1F512}", "utf8")) + 2;
    const parser = createFrameParser();

    expect(parser.push(wire.subarray(0, cut)).frames).toEqual([]);

    const outcome = parser.push(wire.subarray(cut));
    expect(outcome.frames).toEqual([frame]);
    expect(JSON.stringify(outcome.frames[0])).not.toContain("\uFFFD");
  });

  it("survives a split at every byte offset of a multibyte payload", () => {
    const frame: JsonRpcFrame = { jsonrpc: "2.0", id: "ünï", method: "汉字/测试", params: { emoji: "🛡️🔥" } };
    const wire = serializeFrame(frame);

    for (let cut = 1; cut < wire.length; cut++) {
      const parser = createFrameParser();
      const first = parser.push(wire.subarray(0, cut));
      const second = parser.push(wire.subarray(cut));

      expect([...first.frames, ...second.frames]).toEqual([frame]);
      expect([...first.malformed, ...second.malformed]).toEqual([]);
    }
  });

  it("routes unparseable JSON to malformed rather than frames", () => {
    const parser = createFrameParser();
    const outcome = parser.push(Buffer.from('{"jsonrpc":"2.0","id":1,\n', "utf8"));

    expect(outcome.frames).toEqual([]);
    expect(outcome.malformed).toEqual(['{"jsonrpc":"2.0","id":1,']);
  });

  it("routes valid JSON that is not a JSON-RPC envelope to malformed", () => {
    const parser = createFrameParser();
    const outcome = parser.push(
      Buffer.from(
        [
          '[{"jsonrpc":"2.0","id":1}]',
          '"a bare string"',
          "42",
          "null",
          '{"id":1,"method":"tools/list"}',
          '{"jsonrpc":"1.0","id":1,"method":"tools/list"}',
        ].join("\n") + "\n",
        "utf8",
      ),
    );

    expect(outcome.frames).toEqual([]);
    expect(outcome.malformed).toHaveLength(6);
    expect(outcome.malformed[4]).toBe('{"id":1,"method":"tools/list"}');
  });

  it("keeps parsing after a complete line exceeds maxFrameBytes", () => {
    // Ceiling sits above a normal frame and below the bad line, so the rejection
    // is attributable to the oversized line and not to a stingy fixture.
    const parser = createFrameParser({ maxFrameBytes: 256 });
    const oversized = Buffer.from(`${"x".repeat(500)}\n`, "utf8");

    const rejected = parser.push(Buffer.concat([oversized, serializeFrame(request)]));

    expect(rejected.frames).toEqual([request]);
    expect(rejected.malformed).toHaveLength(1);
    expect(rejected.malformed[0]).toContain("exceeded maxFrameBytes");
  });

  it("drops an unterminated oversized line and resynchronises on the next newline", () => {
    const parser = createFrameParser({ maxFrameBytes: 256 });

    // No newline anywhere: the ceiling has to fire on the pending buffer, or an
    // endless line grows the buffer until the wrapper dies.
    const first = parser.push(Buffer.from("y".repeat(300), "utf8"));
    expect(first.frames).toEqual([]);
    expect(first.malformed).toHaveLength(1);
    expect(first.malformed[0]).toContain("exceeded maxFrameBytes");

    // More of the same doomed line, still unterminated: reported once, not twice.
    expect(parser.push(Buffer.from("y".repeat(300), "utf8")).malformed).toEqual([]);

    // The tail of the bad line is discarded and the frame behind it parses.
    const resumed = parser.push(Buffer.concat([Buffer.from("yyy\n", "utf8"), serializeFrame(response)]));
    expect(resumed.frames).toEqual([response]);
    expect(resumed.malformed).toEqual([]);
  });

  it("bounds what an oversized line contributes to the malformed report", () => {
    const parser = createFrameParser({ maxFrameBytes: 1024 });
    const outcome = parser.push(Buffer.from(`${"z".repeat(100_000)}\n`, "utf8"));

    expect(outcome.malformed).toHaveLength(1);
    expect(outcome.malformed[0].length).toBeLessThan(500);
  });

  it("ignores blank and whitespace-only lines", () => {
    const parser = createFrameParser();
    const outcome = parser.push(
      Buffer.concat([
        Buffer.from("\n   \n\t\n\r\n", "utf8"),
        serializeFrame(request),
        Buffer.from("\n\n", "utf8"),
      ]),
    );

    expect(outcome.frames).toEqual([request]);
    expect(outcome.malformed).toEqual([]);
  });

  it("reports an unterminated tail at flush even when its bytes are valid JSON", () => {
    const parser = createFrameParser();
    const wire = serializeFrame(request);
    parser.push(wire.subarray(0, wire.length - 1));

    const outcome = parser.flush();
    expect(outcome.frames).toEqual([]);
    expect(outcome.malformed).toEqual([JSON.stringify(request)]);
  });

  it("returns nothing at flush when the stream ended on a frame boundary", () => {
    const parser = createFrameParser();
    parser.push(serializeFrame(request));

    expect(parser.flush()).toEqual({ frames: [], malformed: [] });
  });

  it("returns nothing at flush when only whitespace is pending", () => {
    const parser = createFrameParser();
    parser.push(Buffer.from("  \t", "utf8"));

    expect(parser.flush()).toEqual({ frames: [], malformed: [] });
  });
});

describe("serializeFrame", () => {
  it("emits compact JSON with exactly one trailing newline", () => {
    const wire = serializeFrame(request).toString("utf8");

    expect(wire.endsWith("\n")).toBe(true);
    expect(wire.split("\n")).toHaveLength(2);
    expect(wire).toBe(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}\n`);
  });

  it("round-trips a frame carrying newlines inside a string", () => {
    const frame: JsonRpcFrame = { jsonrpc: "2.0", id: 3, result: { text: "line one\nline two\n" } };
    const parser = createFrameParser();

    const outcome = parser.push(serializeFrame(frame));
    expect(outcome.frames).toEqual([frame]);
    expect(outcome.malformed).toEqual([]);
  });
});
