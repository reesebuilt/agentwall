import { JsonRpcFrame } from "./types";

/**
 * Newline-delimited JSON-RPC framing for the MCP stdio transport.
 *
 * Why a hand-written parser: this sits in the path of every frame the agent
 * exchanges with a wrapped server, so whatever parses it is part of the trust
 * story. The entire job is "find 0x0A, decode the bytes before it", which does
 * not justify importing code we do not control into the security path.
 *
 * Two properties matter more than throughput:
 *
 * 1. Chunk boundaries are arbitrary. A pipe read can end mid-frame, mid-line or
 *    mid-codepoint, so bytes accumulate as a Buffer and only complete lines are
 *    decoded. Decoding each chunk as it arrives would replace any UTF-8 sequence
 *    straddling the boundary with U+FFFD, quietly mutating tool arguments before
 *    a scanner ever sees them.
 * 2. Anything that does not parse is reported, never guessed at. A caller that
 *    cannot read a frame cannot police it, so malformed lines come back on their
 *    own channel and the transport fails closed on them.
 *
 * This layer answers "is this a JSON-RPC 2.0 envelope"; it does not answer "is
 * this a coherent MCP message". That second question belongs to the gates, and
 * splitting it here would put protocol judgement in two places that then have to
 * be kept in agreement.
 */

/**
 * UTF-8 newline.
 *
 * Scanning for it byte-wise is safe by construction: every byte of a multibyte
 * UTF-8 sequence has its high bit set, so a 0x0A byte can only ever be a real
 * delimiter and never the tail of a character.
 */
const NEWLINE = 0x0a;

/**
 * Default ceiling on one frame: 8 MiB.
 *
 * Without a ceiling, anything that can write to the parser can emit an endless
 * line containing no newline at all, and the buffer grows until the wrapper is
 * OOM-killed. Killing the wrapper is precisely how you get an agent talking to
 * an unwrapped server, so an unbounded buffer here is a denial-of-service
 * primitive aimed at the security component itself. 8 MiB is generous for real
 * traffic — tool results carrying file contents or base64 images sit well under
 * it — and the overflow path drops the pending line and resynchronises on the
 * next newline rather than trying to salvage a frame it never fully saw.
 */
const DEFAULT_MAX_FRAME_BYTES = 8 * 1024 * 1024;

/** How much of an oversized line survives into the operator's log. */
const OVERSIZE_EXCERPT_BYTES = 200;

const EMPTY = Buffer.alloc(0);

/**
 * Result of feeding bytes to the parser.
 *
 * Frames and malformed lines are separate channels rather than one tagged list
 * because callers treat them differently: frames go to the gates, malformed
 * lines go to the audit trail and nowhere else. Ordering is preserved within
 * each channel; a malformed line sitting between two good frames loses its
 * position relative to them, which costs log precision and nothing else,
 * because nothing malformed is ever forwarded.
 */
export interface ParseOutcome {
  frames: JsonRpcFrame[];
  malformed: string[];
}

/** Stateful, single-stream parser. One per direction; never share instances. */
export interface FrameParser {
  push(chunk: Buffer): ParseOutcome;
  flush(): ParseOutcome;
}

/**
 * Structural admission test, not validation.
 *
 * This answers one question: is the value a JSON-RPC 2.0 envelope at all? Arrays,
 * bare scalars, nulls and objects without the version marker are not, and are
 * reported as malformed instead of being handed on as if they were protocol.
 * Whether a genuine envelope is a well-formed request, response or notification
 * — id present exactly when it should be, result exclusive of error — is the
 * frame_integrity gate's decision, and it is left there so that every rejection
 * for protocol reasons carries a gate outcome the audit trail can show.
 */
function isJsonRpcFrame(value: unknown): value is JsonRpcFrame {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  return "jsonrpc" in value && value.jsonrpc === "2.0";
}

/**
 * Report an oversized line without holding on to it.
 *
 * The rule everywhere else is that a malformed line comes back as its raw text,
 * and that is exactly what cannot be honoured here: returning a line we refused
 * for its size only moves the memory cost into the log. The caller gets a bounded
 * prefix plus an explicit marker. The prefix may end mid-codepoint; it is a
 * diagnostic for a human reading a log, not a payload anything acts on.
 */
function oversizeExcerpt(line: Buffer, maxFrameBytes: number): string {
  const prefix = line.toString("utf8", 0, Math.min(line.length, OVERSIZE_EXCERPT_BYTES));
  return `${prefix}[agentwall: frame exceeded maxFrameBytes (${maxFrameBytes}); line discarded]`;
}

/**
 * Create a parser over one byte stream.
 *
 * The parser is deliberately stateful and deliberately not reentrant: it holds
 * the tail of the last chunk, so feeding two interleaved streams through one
 * instance would splice their bytes together into frames neither side sent.
 */
export function createFrameParser(opts: { maxFrameBytes?: number } = {}): FrameParser {
  const maxFrameBytes = opts.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;

  /** Bytes seen since the last newline. */
  let pending: Buffer = EMPTY;
  /** True while discarding the tail of a line already rejected for its size. */
  let resyncing = false;

  function readLine(line: Buffer, outcome: ParseOutcome): void {
    const text = line.toString("utf8");
    // Blank and whitespace-only lines are protocol noise, not errors: writers
    // pad with newlines, and a CRLF stream leaves a stray \r behind. Reporting
    // them as malformed would train operators to ignore the malformed channel,
    // which is the one channel that must stay worth reading.
    if (text.trim().length === 0) {
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      outcome.malformed.push(text);
      return;
    }

    if (!isJsonRpcFrame(parsed)) {
      outcome.malformed.push(text);
      return;
    }
    outcome.frames.push(parsed);
  }

  function push(chunk: Buffer): ParseOutcome {
    const outcome: ParseOutcome = { frames: [], malformed: [] };
    pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);

    for (;;) {
      const nl = pending.indexOf(NEWLINE);

      if (resyncing) {
        if (nl === -1) {
          // Still inside the rejected line. Drop what we hold; the excerpt was
          // already reported and keeping these bytes would restore the exact
          // unbounded growth the ceiling exists to prevent.
          pending = EMPTY;
          break;
        }
        pending = pending.subarray(nl + 1);
        resyncing = false;
        continue;
      }

      if (nl === -1) {
        // No terminator yet. If what we already hold exceeds the ceiling the
        // line is doomed whatever follows it, so report now and drop rather than
        // wait for a newline whose arrival the writer controls and may withhold.
        if (pending.length > maxFrameBytes) {
          outcome.malformed.push(oversizeExcerpt(pending, maxFrameBytes));
          pending = EMPTY;
          resyncing = true;
        }
        break;
      }

      const line = pending.subarray(0, nl);
      pending = pending.subarray(nl + 1);

      if (line.length > maxFrameBytes) {
        outcome.malformed.push(oversizeExcerpt(line, maxFrameBytes));
        continue;
      }
      readLine(line, outcome);
    }

    return outcome;
  }

  /**
   * Stream end.
   *
   * A trailing line with no newline is malformed even when its bytes happen to
   * be valid JSON: the transport delimits frames with \n, so an undelimited tail
   * is indistinguishable from a frame cut in half when the pipe closed. Deciding
   * "it looked complete" is how a truncated frame gets forwarded as a whole one.
   */
  function flush(): ParseOutcome {
    const outcome: ParseOutcome = { frames: [], malformed: [] };
    const tail = pending;
    pending = EMPTY;
    // Whatever remains of an over-long line has already been reported once.
    // Reporting the same line twice would make the malformed count lie.
    const suppressed = resyncing;
    resyncing = false;

    if (suppressed || tail.length === 0) {
      return outcome;
    }
    const text = tail.toString("utf8");
    if (text.trim().length === 0) {
      return outcome;
    }
    outcome.malformed.push(text);
    return outcome;
  }

  return { push, flush };
}

/**
 * Encode a frame for the wire: compact JSON plus exactly one newline.
 *
 * Compact is not cosmetic. An embedded newline would split one frame into two on
 * the far side, and since JSON.stringify escapes newlines inside strings the
 * only way to emit a raw one is to ask for indentation — which is why nothing
 * here ever does.
 *
 * A frame that cannot be stringified (a cycle, a BigInt) throws rather than
 * degrading into a placeholder. A caller handing us an unserialisable frame has
 * a bug, and substituting something writable would put bytes on the wire that no
 * gate ever evaluated.
 */
export function serializeFrame(frame: JsonRpcFrame): Buffer {
  return Buffer.from(`${JSON.stringify(frame)}\n`, "utf8");
}
