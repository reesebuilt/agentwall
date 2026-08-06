import { ChildProcessWithoutNullStreams, spawn } from "child_process";
import { constants as osConstants } from "os";
import { FrameAction, FrameDirection, JsonRpcFrame } from "./types";
import { createFrameParser, ParseOutcome, serializeFrame } from "./framing";

/**
 * The stdio interception point.
 *
 * AgentWall runs the MCP server as its own child and holds both ends of the
 * pipe: the client's stdin arrives here first, the server's stdout leaves here
 * last. Nothing crosses in either direction without passing an interceptor, so
 * "protected" can mean every frame rather than every frame we happened to notice.
 *
 * The wrapper owns no policy on purpose. It parses, hands each frame to a
 * callback, and does what the returned FrameAction says. Where that decision
 * came from — gates, engine, hash chain — is not this file's business, which is
 * what keeps the transport testable without a policy engine and the policy
 * testable without a subprocess.
 *
 * Failure posture is closed. A line that will not parse is not forwarded, and an
 * interceptor that throws blocks rather than passes: a scanner crashing is the
 * moment you least want an unscanned frame going through.
 *
 * Scope limit worth stating plainly: this protects the stdio conversation, not
 * the server process. A wrapped server can still open its own sockets, read its
 * own files and spawn its own children, none of which travels over the pipe we
 * hold. The egress and tool planes are what cover that ground; wrapping stdio
 * buys visibility into the protocol, not a sandbox.
 */

/** JSON-RPC's reserved "Internal error". Used only when an interceptor throws. */
const JSONRPC_INTERNAL_ERROR = -32603;

export interface StdioWrapOptions {
  /** argv of the MCP server, command[0] being the executable. Never shell-parsed. */
  command: string[];
  /** Gate a frame travelling client to server. Awaited before the next one starts. */
  onClientFrame: (frame: JsonRpcFrame) => Promise<FrameAction>;
  /** Gate a frame travelling server to client. Awaited before the next one starts. */
  onServerFrame: (frame: JsonRpcFrame) => Promise<FrameAction>;
  /** Called for every line that did not parse. Such lines are never forwarded. */
  onMalformed?: (raw: string, direction: FrameDirection) => void;
  /** Injectable for tests; defaults to the wrapper process's own stdio. */
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
}

/**
 * Write and respect backpressure.
 *
 * Awaiting drain is what keeps memory bounded when the far side reads slower
 * than the near side writes. Ignoring write()'s return value buys throughput by
 * queueing unbounded frames in the process heap, which is the same failure the
 * frame-size ceiling exists to prevent, just relocated. close and error resolve
 * too: a stream that will never drain must not deadlock the whole direction
 * behind it, and the exit path is already on its way by then.
 */
function write(stream: NodeJS.WritableStream, payload: Buffer): Promise<void> {
  return new Promise((resolve) => {
    let accepted: boolean;
    try {
      accepted = stream.write(payload);
    } catch {
      // Writing to a torn-down pipe. The peer is gone; there is nothing to say
      // to it and nothing to recover.
      resolve();
      return;
    }
    if (accepted) {
      resolve();
      return;
    }
    const done = (): void => {
      stream.removeListener("drain", done);
      stream.removeListener("close", done);
      stream.removeListener("error", done);
      resolve();
    };
    stream.once("drain", done);
    stream.once("close", done);
    stream.once("error", done);
  });
}

/**
 * Exit code for a child that may have died by signal.
 *
 * A signalled child has no exit code of its own, so this uses the shell
 * convention of 128 + signal number, which every wrapper-aware script already
 * reads correctly. An unrecognised signal name degrades to a bare 128 instead of
 * inventing a number: vague beats wrong when the value is what a caller branches
 * on.
 */
function exitCodeFor(code: number | null, signal: NodeJS.Signals | null): number {
  if (code !== null) {
    return code;
  }
  if (signal === null) {
    return 0;
  }
  // The type claims every signal name maps to a number; the platform disagrees.
  // os.constants.signals omits names the running OS does not implement, so an
  // absent entry is a real runtime case rather than defensive padding.
  const number: number | undefined = osConstants.signals[signal];
  return typeof number === "number" ? 128 + number : 128;
}

/**
 * Run an MCP server as a child and police both directions of its stdio.
 *
 * Resolves with the child's exit code once it has exited and both direction
 * queues have drained. Rejects only when the child could not be started at all:
 * a wrapper that cannot launch the server has nothing to protect, and returning
 * a plausible exit code for that would report a clean run of a process that
 * never existed.
 */
export function runStdioWrapper(opts: StdioWrapOptions): Promise<number> {
  const clientIn = opts.stdin ?? process.stdin;
  const clientOut = opts.stdout ?? process.stdout;
  const errOut = opts.stderr ?? process.stderr;

  return new Promise<number>((resolve, reject) => {
    if (opts.command.length === 0) {
      reject(new Error("agentwall: cannot wrap an MCP server without a command"));
      return;
    }

    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn(opts.command[0], opts.command.slice(1), {
        stdio: ["pipe", "pipe", "pipe"],
        // Never a shell. The command is operator-supplied argv, and routing argv
        // through a shell turns a server path containing ; or $( ) into
        // execution of something nobody wrote down. Losing glob and pipeline
        // syntax here is the point rather than a limitation: an MCP server is an
        // executable and arguments, not a command line.
        shell: false,
      });
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      reject(new Error(`agentwall: failed to start MCP server "${opts.command.join(" ")}": ${detail}`));
      return;
    }

    const clientParser = createFrameParser();
    const serverParser = createFrameParser();

    let settled = false;
    let childStdinClosed = false;

    /**
     * Diagnostics from the wrapper itself, on the operator's channel.
     *
     * Prefixed so a wrapped server's own stderr stays attributable. If even this
     * write fails the channel is gone and there is no second place to complain
     * to; losing a log line must not take down the frame path.
     */
    const note = (message: string): void => {
      try {
        errOut.write(`agentwall: ${message}\n`);
      } catch {
        /* the operator's channel is gone; nothing better to do with this */
      }
    };

    /**
     * One promise chain per direction.
     *
     * Interceptors are async, so dispatching them as frames arrive would let a
     * fast decision overtake a slow one and put frames on the wire in an order
     * the sender never used. That is a correctness break, not a performance
     * detail: servers process requests in arrival order, and a reordered
     * notification stream — progress, cancellation, logging — describes
     * something that did not happen. Each direction therefore awaits its own
     * predecessor before starting the next frame.
     *
     * The two chains stay independent of one another. A slow inbound scan must
     * not stall responses the client is already waiting on, and the directions
     * carry no shared ordering guarantee for a caller to rely on.
     */
    let clientChain: Promise<void> = Promise.resolve();
    let serverChain: Promise<void> = Promise.resolve();

    const enqueue = (direction: FrameDirection, step: () => Promise<void>): void => {
      const onStepError = (err: unknown): void => {
        note(`${direction} handler failed: ${err instanceof Error ? err.message : String(err)}`);
      };
      if (direction === "client_to_server") {
        clientChain = clientChain.then(step).catch(onStepError);
      } else {
        serverChain = serverChain.then(step).catch(onStepError);
      }
    };

    /**
     * Run an interceptor, treating a thrown error as a block.
     *
     * An interceptor that throws has told us nothing about the frame. Forwarding
     * on that basis would mean a crashing scanner silently becomes an open gate,
     * which is the worst available reading of "the check did not complete".
     */
    const decide = async (run: () => Promise<FrameAction>): Promise<FrameAction> => {
      try {
        return await run();
      } catch (err) {
        note(`frame evaluation failed, blocking: ${err instanceof Error ? err.message : String(err)}`);
        return {
          kind: "block",
          error: { code: JSONRPC_INTERNAL_ERROR, message: "agentwall: frame evaluation failed" },
        };
      }
    };

    /**
     * Answer a blocked frame on the client's channel.
     *
     * A request gets an error response so the caller sees a refusal instead of a
     * hang. A notification carries no id, so there is nobody to answer and the
     * only honest move is to drop it: JSON-RPC's fire-and-forget half gives the
     * sender no way to be told, and that is a real limit of the protocol rather
     * than something the wrapper can paper over. An explicit null id is answered
     * with null, which is what JSON-RPC prescribes when a response cannot be
     * correlated.
     */
    const refuse = async (frame: JsonRpcFrame, error: { code: number; message: string; data?: unknown }): Promise<void> => {
      if (frame.id === undefined) {
        return;
      }
      await write(clientOut, serializeFrame({ jsonrpc: "2.0", id: frame.id, error }));
    };

    const handleClient = async (frame: JsonRpcFrame): Promise<void> => {
      const action = await decide(() => opts.onClientFrame(frame));
      if (action.kind === "forward") {
        if (childStdinClosed) {
          return;
        }
        await write(child.stdin, serializeFrame(action.frame));
        return;
      }
      await refuse(frame, action.error);
    };

    const handleServer = async (frame: JsonRpcFrame): Promise<void> => {
      const action = await decide(() => opts.onServerFrame(frame));
      if (action.kind === "forward") {
        await write(clientOut, serializeFrame(action.frame));
        return;
      }
      // A blocked response is replaced by an error on the same id, so the
      // client's pending call resolves as a refusal rather than waiting out a
      // timeout. A blocked server notification has no id to replace and is
      // dropped; the client is never told, which is the same protocol limit as
      // on the inbound side.
      await refuse(frame, action.error);
    };

    const dispatch = (outcome: ParseOutcome, direction: FrameDirection): void => {
      // Malformed lines ride the same chain as frames so their callbacks keep
      // arrival order across chunks. Nothing malformed is forwarded in either
      // case; the queue is only there to keep the audit sequence readable.
      for (const raw of outcome.malformed) {
        enqueue(direction, async () => {
          opts.onMalformed?.(raw, direction);
        });
      }
      for (const frame of outcome.frames) {
        enqueue(direction, () => (direction === "client_to_server" ? handleClient(frame) : handleServer(frame)));
      }
    };

    /**
     * Chunks arrive as Buffers because nothing sets an encoding on these streams.
     * That is deliberate: a stream decoding on our behalf would already have
     * mangled any UTF-8 sequence split across a read boundary before the parser
     * could see the bytes. The string branch exists so an injected stream that
     * does set an encoding still works, at that stream's own risk.
     */
    const toBuffer = (chunk: string | Buffer): Buffer =>
      typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;

    const onClientData = (chunk: string | Buffer): void => {
      dispatch(clientParser.push(toBuffer(chunk)), "client_to_server");
    };

    const onClientEnd = (): void => {
      dispatch(clientParser.flush(), "client_to_server");
      // Close the child's stdin behind everything already accepted. Ending it
      // straight away would race the last frames still queued and the server
      // would see a session truncated by its own firewall.
      enqueue("client_to_server", async () => {
        if (childStdinClosed) {
          return;
        }
        childStdinClosed = true;
        try {
          child.stdin.end();
        } catch {
          /* pipe already gone; the child is on its way out */
        }
      });
    };

    const onClientError = (err: Error): void => {
      note(`client stdin error: ${err.message}`);
    };

    clientIn.on("data", onClientData);
    clientIn.on("end", onClientEnd);
    clientIn.on("error", onClientError);

    child.stdout.on("data", (chunk: string | Buffer) => {
      dispatch(serverParser.push(toBuffer(chunk)), "server_to_client");
    });
    child.stdout.on("end", () => {
      dispatch(serverParser.flush(), "server_to_client");
    });
    child.stdout.on("error", (err: Error) => {
      note(`server stdout error: ${err.message}`);
    });

    // EPIPE on the child's stdin means the server exited while we still had a
    // frame for it. That is a shutdown, not a wrapper fault: the exit code is
    // the real signal and it is already on its way.
    child.stdin.on("error", () => {
      childStdinClosed = true;
    });
    child.stdin.on("close", () => {
      childStdinClosed = true;
    });

    // The server's diagnostics belong to the operator, byte for byte. Filtering
    // them is not this layer's job, and swallowing them would make a wrapped
    // server harder to debug than an unwrapped one — a reliable way to get the
    // wrapper removed. end:false keeps our stderr open after the child's closes.
    child.stderr.pipe(errOut, { end: false });
    child.stderr.on("error", () => {
      /* the child's diagnostics channel died; the frame path is unaffected */
    });

    /**
     * Relay shutdown signals rather than dying first.
     *
     * This process is the child's only parent. Exiting on SIGINT without passing
     * it down leaves the MCP server running with its pipes attached to nothing:
     * an orphan still holding whatever credentials and file handles it was given.
     * So the signal goes down and the promise settles when the child actually
     * exits, which is also what makes the reported exit code true.
     */
    const relaySignal = (signal: NodeJS.Signals) => (): void => {
      if (child.killed || child.exitCode !== null) {
        return;
      }
      try {
        child.kill(signal);
      } catch {
        /* already reaped between the check and the call */
      }
    };
    const onSigint = relaySignal("SIGINT");
    const onSigterm = relaySignal("SIGTERM");
    process.on("SIGINT", onSigint);
    process.on("SIGTERM", onSigterm);

    const cleanup = (): void => {
      process.removeListener("SIGINT", onSigint);
      process.removeListener("SIGTERM", onSigterm);
      clientIn.removeListener("data", onClientData);
      clientIn.removeListener("end", onClientEnd);
      clientIn.removeListener("error", onClientError);
      // Stop pulling on the client's stdin. A live data listener on process.stdin
      // holds the event loop open, and a wrapper whose caller cannot exit is
      // indistinguishable from a hung server.
      clientIn.pause();
      child.stderr.unpipe(errOut);
    };

    child.on("error", (err: Error) => {
      if (settled) {
        // Post-spawn errors (a kill that lost a race with reaping, say) are
        // noise once the exit path is running.
        note(`child process error after exit: ${err.message}`);
        return;
      }
      settled = true;
      cleanup();
      reject(new Error(`agentwall: failed to start MCP server "${opts.command.join(" ")}": ${err.message}`));
    });

    child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) {
        return;
      }
      settled = true;
      void (async () => {
        // Frames accepted before the child closed may still be mid-flight, and a
        // decision that never reached the client is a decision that did not
        // happen. Each pass can append more work — the last frame's write can
        // queue behind a drain — so this runs to a fixpoint rather than awaiting
        // one snapshot of the chains.
        let seenClient: Promise<void> | undefined;
        let seenServer: Promise<void> | undefined;
        while (seenClient !== clientChain || seenServer !== serverChain) {
          seenClient = clientChain;
          seenServer = serverChain;
          await Promise.all([seenClient, seenServer]);
        }
        cleanup();
        resolve(exitCodeFor(code, signal));
      })();
    });
  });
}
