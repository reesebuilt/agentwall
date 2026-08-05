import {
  appendFileSync,
  closeSync,
  unlinkSync,
  writeFileSync,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
} from "fs";
import { dirname } from "path";
import { AuditEvent } from "../types";
import { AuditChainState, findDuplicateKey } from "./chain";

/**
 * Durable JSONL sink for the audit chain.
 *
 * Why this exists: the chain is only tamper-evident if it is COMPLETE. `stdoutSink`
 * alone sends the record to stdout and, under systemd, into journald, which
 * rate-limits (RateLimitBurst defaults to 10000/30s) and vacuums. A dropped entry is
 * indistinguishable from a deleted one, so rate limiting silently destroys the exact
 * property the hash chain exists to provide.
 *
 * This file must be owned EXCLUSIVELY by this sink. Do not also point systemd's
 * StandardOutput at it: stdout carries pino lines and a plaintext startup banner, and a
 * verifier should never have to filter noise out of its own source of truth.
 */

/**
 * What can be PROVEN about the pid recorded in a lock file.
 *
 * The only status that permits a reclaim is proof that the previous writer can never
 * append again. "I could not tell" is not that proof and must never be rounded down to
 * it. See {@link classifyLockOwner} for the bug that behaviour caused.
 */
export type LockOwnerStatus =
  /** kill(pid, 0) answered ESRCH: no such process. The only authoritative death. */
  | { kind: "gone" }
  /** Alive, and its argv identifies it as an agentwall. */
  | { kind: "holding"; cmdline: string }
  /** Alive, but its argv shows the kernel handed the pid to something unrelated. */
  | { kind: "recycled"; cmdline: string }
  /** Alive, identity unverifiable. Callers MUST fail closed. */
  | { kind: "indeterminate"; reason: string };

/**
 * The two syscalls behind {@link classifyLockOwner}, injectable because their interesting
 * failures (EPERM from a foreign uid, an unreadable /proc under a `hidepid=` mount or a
 * pid namespace) cannot be staged from a test process on demand.
 */
export interface LockOwnerProbe {
  /** Signal-0 liveness check. Throws ESRCH when gone, EPERM when alive but not ours. */
  liveness(pid: number): void;
  /** The owner's argv as /proc exposes it (NUL separated). Throws when unreadable. */
  cmdline(pid: number): string;
}

export const procLockOwnerProbe: LockOwnerProbe = {
  liveness: (pid) => {
    process.kill(pid, 0);
  },
  cmdline: (pid) => readFileSync(`/proc/${pid}/cmdline`, "utf8"),
};

/**
 * Decide what the lock's owning pid actually is.
 *
 * The bug this replaces: the /proc read was wrapped in a catch that swallowed every
 * failure into `cmdline = ""`, which then failed the "agentwall" test, so a live writer's
 * lock was reclaimed whenever its identity merely could not be read. Two processes then
 * appended to the same file, interleaving two hash chains into one, permanently
 * destroying the integrity proof the lock exists to protect. Liveness and identity are
 * separate questions and only the first has an authoritative answer.
 */
export function classifyLockOwner(
  pid: number,
  probe: LockOwnerProbe = procLockOwnerProbe
): LockOwnerStatus {
  try {
    probe.liveness(pid);
  } catch (err) {
    // ESRCH is the ONLY errno that means "no such process". EPERM means the pid exists
    // and belongs to another uid; anything else means the check itself failed. Neither is
    // permission to take the lock, so both fall through to the identity check.
    if ((err as NodeJS.ErrnoException).code === "ESRCH") return { kind: "gone" };
  }
  let cmdline: string;
  try {
    cmdline = probe.cmdline(pid);
  } catch (err) {
    return {
      kind: "indeterminate",
      reason:
        `pid ${pid} is alive but its identity could not be read from ` +
        `/proc/${pid}/cmdline (${(err as Error).message})`,
    };
  }
  // Liveness alone is not enough: the kernel recycles pids, so an unrelated process
  // inheriting the number would otherwise wedge startup forever and silently end the
  // trial. A successful but EMPTY read lands here too: that is a zombie or a kernel
  // thread, which holds no descriptors and cannot append, so reclaiming is safe.
  return cmdline.includes("agentwall")
    ? { kind: "holding", cmdline }
    : { kind: "recycled", cmdline };
}

/**
 * Claim exclusive write ownership of the audit file.
 *
 * The chain's integrity assumes exactly ONE writer, forever. Two processes appending
 * independently each seed their own chain and interleave, producing a file where every
 * record is individually valid and the sequence is nonsense. That is not hypothetical:
 * a stray foreground `agentwall start` alongside the service does exactly this.
 * Fail loudly instead.
 *
 * Exported with an injectable probe because this reclaim decision is the security
 * boundary of the whole audit chain and needs direct coverage.
 */
export function claimWriter(
  path: string,
  probe: LockOwnerProbe = procLockOwnerProbe
): void {
  const lock = path + ".lock";
  try {
    const fd = openSync(lock, "wx");            // O_CREAT|O_EXCL: fails if held
    writeFileSync(lock, String(process.pid));
    closeSync(fd);
  } catch {
    // Held. Take it over only if the owner is provably unable to append again.
    let owner = 0;
    try {
      owner = parseInt(readFileSync(lock, "utf8").trim(), 10);
    } catch {
      /* unreadable lock treated as stale */
    }
    if (owner > 0) {                            // also filters NaN from a garbled lock
      const status = classifyLockOwner(owner, probe);
      if (status.kind === "holding") {
        throw new Error(
          `audit file ${path} is already owned by pid ${owner}. Refusing to start a second ` +
            `writer: concurrent appends would interleave two hash chains into one file.`
        );
      }
      if (status.kind === "indeterminate") {
        throw new Error(
          `audit file ${path} is locked by pid ${owner}, which is STILL RUNNING, and this ` +
            `process cannot confirm what it is: ${status.reason}. Refusing to reclaim the ` +
            `lock: stealing it from a live writer would interleave two hash chains into one ` +
            `file and destroy the audit integrity proof. Verify pid ${owner} yourself. ` +
            `If it is not an agentwall, stop it or delete ${lock} by hand.`
        );
      }
    }
    writeFileSync(lock, String(process.pid));   // owner provably gone, or pid recycled
  }
  const release = () => {
    try {
      unlinkSync(lock);
    } catch {
      /* ignore */
    }
  };
  process.once("exit", release);
  process.once("SIGINT", () => {
    release();
    process.exit(130);
  });
  process.once("SIGTERM", () => {
    release();
    process.exit(143);
  });
}

/** One audit record per line, nothing else in the file. */
export function createFileSink(path: string): (event: AuditEvent) => void {
  mkdirSync(dirname(path), { recursive: true });
  claimWriter(path);
  return (event: AuditEvent) => {
    // Flag "a" opens O_APPEND, so the kernel makes the seek-to-end and the write a
    // single atomic operation against the file offset. That is the guarantee that keeps
    // records from interleaving, not PIPE_BUF, which governs pipes and is only 4096 on
    // Linux, well under a typical record carrying full detections.
    appendFileSync(path, JSON.stringify(event) + "\n", { encoding: "utf8" });
  };
}

export interface ChainResume {
  state: AuditChainState;
  /** null when the chain resumed cleanly. Set when a NEW chain is starting. */
  discontinuity: string | null;
}

/**
 * Recover chain state from the tail of an existing audit file.
 *
 * Without this the chain restarts at index 0 on every process start. Under
 * `Restart=always` a crash loop therefore produces several disjoint chains that each
 * verify internally. That is worse than no chain, because a verifier passes while the
 * record has holes.
 *
 * Reads backwards from EOF so startup cost does not grow with the log. Returns the
 * reason on failure instead of silently starting over: a new chain is a real event and
 * the caller must be able to record it.
 */
export function resumeChainState(path: string): ChainResume {
  const fresh: AuditChainState = { chainIndex: 0, previousHash: null };
  if (!existsSync(path)) {
    return { state: fresh, discontinuity: null }; // genuinely first run
  }

  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const size = fstatSync(fd).size;
    if (size === 0) return { state: fresh, discontinuity: null };

    const CHUNK = 8192;
    let tail = "";
    let pos = size;
    let candidates: string[] = [];

    while (pos > 0) {
      const len = Math.min(CHUNK, pos);
      pos -= len;
      const buf = Buffer.alloc(len);
      readSync(fd, buf, 0, len, pos);
      tail = buf.toString("utf8") + tail;

      // The final record must be bounded on BOTH sides before we trust it. Records end
      // in "\n", so a single newline is always present after the first chunk and would
      // accept a truncated fragment for any record larger than CHUNK, which then fails
      // to parse and silently restarts the chain. Requiring two newlines means we have
      // seen the delimiter that opens the last line as well as the one that closes it.
      // A single-record file terminates via pos === 0 instead.
      const newlines = (tail.match(/\n/g) ?? []).length;
      // Need >= 3 delimiters (rather than 2) so the window holds a COMPLETE
      // second-to-last record too, which the torn-tail fallback needs to resume from.
      if (pos === 0 || newlines >= 3) {
        candidates = tail.split("\n").filter((l) => l.trim() !== "");
        // The first element may be a fragment unless we read to the start of the file.
        if (pos > 0 && candidates.length > 0) candidates = candidates.slice(1);
        break;
      }
    }

    if (candidates.length === 0) {
      return { state: fresh, discontinuity: "audit file had no parseable record" };
    }

    // Walk back from the end for the last record that actually parses. A process killed
    // mid-write leaves a torn final line; discarding the whole chain over one torn record
    // would throw away every prior record's continuity. Resume from the last good one and
    // scope the discontinuity to what was actually lost.
    let torn = 0;
    for (let i = candidates.length - 1; i >= 0; i--) {
      let parsed: AuditEvent;
      try {
        parsed = JSON.parse(candidates[i]) as AuditEvent;
      } catch {
        torn++;
        continue;
      }
      const integrity = parsed?.integrity;
      if (!integrity || typeof integrity.chainIndex !== "number" || typeof integrity.hash !== "string") {
        torn++;
        continue;
      }
      return {
        state: { chainIndex: integrity.chainIndex + 1, previousHash: integrity.hash },
        discontinuity:
          torn === 0
            ? null
            : `resumed from the last intact record; discarded ${torn} torn record(s) at the tail`,
      };
    }
    return { state: fresh, discontinuity: "no intact record found in the audit tail" };
  } catch (err) {
    // A truncated or corrupt tail must not stop the service booting. Starting fresh is
    // the safe failure, but it is NOT a silent one: the caller records the break.
    return {
      state: fresh,
      discontinuity: `could not read prior chain tail: ${(err as Error).message}`,
    };
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
}

export interface ChainVerification {
  ok: boolean;
  records: number;
  problems: string[];
  /**
   * Findings that are reported but do not condemn the file. Only a torn tail lands here:
   * it is damage a crash produces, not evidence of an edit, so it is surfaced without
   * failing the layer.
   */
  notes: string[];
}

/**
 * Verify a JSONL audit file end to end: every hash reproducible from its own payload,
 * every record linked to its predecessor, no gaps in the index sequence. Gaps are
 * reported rather than tolerated: that is the entire point of the structure.
 */
export function verifyChainFile(
  path: string,
  rehash: (event: AuditEvent) => string
): ChainVerification {
  const problems: string[] = [];
  const notes: string[] = [];
  if (!existsSync(path)) return { ok: false, records: 0, problems: ["file does not exist"], notes };

  const raw = readFileSync(path, "utf8");
  // Whether the file ends with its terminator is the whole distinction between a hard kill
  // and an edit, and a filtered split destroys it, so it is read off the raw bytes first.
  // Only the trailing chunk can be unterminated: every earlier one was followed by an LF.
  const chunks = raw.split("\n");
  const unterminated = raw.endsWith("\n") ? -1 : chunks.length - 1;
  const lines: { text: string; torn: boolean }[] = [];
  chunks.forEach((text, i) => {
    if (text.trim() === "") return;
    lines.push({ text, torn: i === unterminated });
  });

  let expectedIndex: number | null = null;
  let expectedPrev: string | null = null;

  lines.forEach(({ text: line, torn }, i) => {
    // Checked on the raw bytes, because JSON.parse silently collapses a duplicate member
    // and the evidence of it is gone the moment the line is parsed. Such a record counts
    // toward nothing: it does not advance the expected index or the expected link, so the
    // records around it are judged against each other rather than against a line whose
    // meaning depends on which parser read it.
    const duplicate = findDuplicateKey(line);
    if (duplicate !== null) {
      problems.push(
        `line ${i + 1}: dup-key, two members named ${JSON.stringify(duplicate)}, so what this record says ` +
          "depends on which parser reads it",
      );
      return;
    }
    let ev: AuditEvent;
    try {
      ev = JSON.parse(line) as AuditEvent;
    } catch {
      if (torn) {
        // A process killed mid-append leaves exactly one partial line: the last, with no
        // terminator. Calling that a broken chain sends an operator hunting a tamperer
        // through a log that was never touched, and a security tool that cries wolf on
        // every hard kill gets its alerts ignored. The complete records before it still
        // chain, so it is named and the file stands. An unparseable line ANYWHERE else,
        // or one that carries its terminator, was not produced by an interrupted append
        // and stays fatal.
        notes.push(
          `line ${i + 1}: torn-tail, the final line has no terminator and does not parse, ` +
            "which is what a hard kill mid-append leaves; the records before it are complete",
        );
        return;
      }
      problems.push(`line ${i + 1}: not valid JSON`);
      return;
    }
    const integ = ev?.integrity;
    if (!integ) {
      problems.push(`line ${i + 1}: missing integrity block`);
      return;
    }
    if (expectedIndex !== null && integ.chainIndex !== expectedIndex) {
      problems.push(
        `line ${i + 1}: chainIndex ${integ.chainIndex}, expected ${expectedIndex} (gap or silent restart)`
      );
    }
    if (expectedPrev !== null && integ.previousHash !== expectedPrev) {
      problems.push(`line ${i + 1}: previousHash does not link to the preceding record`);
    }
    if (rehash(ev) !== integ.hash) {
      problems.push(`line ${i + 1}: hash mismatch, record altered after write`);
    }
    expectedIndex = integ.chainIndex + 1;
    expectedPrev = integ.hash;
  });

  return { ok: problems.length === 0, records: lines.length, problems, notes };
}
