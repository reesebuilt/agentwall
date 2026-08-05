import { afterEach, describe, expect, it } from "@jest/globals";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  claimWriter,
  classifyLockOwner,
  createFileSink,
  LockOwnerProbe,
  verifyChainFile,
} from "../src/audit/file-sink";
import { chainAuditEvent, rehashAuditEvent } from "../src/audit/chain";
import { AuditEvent } from "../src/types";

/**
 * The audit chain is only a proof if exactly one process ever appends to the file. These
 * tests pin the reclaim decision in claimWriter(), because getting it wrong does not throw
 * or corrupt anything visibly; it silently produces a file with two interleaved hash
 * chains, which no later verification can untangle.
 */

const HELD_BY = 4242; // an arbitrary pid; the injected probe decides what it "is"

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    fs.rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

/** A temp audit path whose lock is already held by `owner`. */
function lockedAuditPath(owner: number): { auditPath: string; lockPath: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-audit-sink-"));
  tempDirs.push(dir);
  const auditPath = path.join(dir, "audit.jsonl");
  const lockPath = auditPath + ".lock";
  fs.writeFileSync(lockPath, String(owner));
  return { auditPath, lockPath };
}

/** Defaults to "alive, and it is an agentwall"; override either half per test. */
function probe(over: Partial<LockOwnerProbe> = {}): LockOwnerProbe {
  return {
    liveness: over.liveness ?? (() => {}),
    cmdline:
      over.cmdline ?? (() => "/usr/bin/node\u0000/opt/agentwall/dist/index.js\u0000"),
  };
}

function errno(code: string, message: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

const unreadableProc = () =>
  errno("EACCES", `EACCES: permission denied, open '/proc/${HELD_BY}/cmdline'`);

describe("audit lock ownership classification", () => {
  it("reports a provably absent pid as gone", () => {
    const status = classifyLockOwner(
      HELD_BY,
      probe({
        liveness: () => {
          throw errno("ESRCH", `ESRCH: no such process, kill ${HELD_BY}`);
        },
      })
    );
    expect(status.kind).toBe("gone");
  });

  it("reports an alive pid with an unreadable /proc entry as indeterminate, not gone", () => {
    const status = classifyLockOwner(
      HELD_BY,
      probe({
        cmdline: () => {
          throw unreadableProc();
        },
      })
    );
    expect(status.kind).toBe("indeterminate");
    if (status.kind !== "indeterminate") throw new Error("unreachable");
    // The message is the whole point: an audit sink that refuses to start has to be
    // diagnosable from the log line alone.
    expect(status.reason).toContain(`pid ${HELD_BY} is alive`);
    expect(status.reason).toContain(`/proc/${HELD_BY}/cmdline`);
    expect(status.reason).toContain("EACCES");
  });

  it("treats EPERM from the liveness check as alive, never as a dead owner", () => {
    // EPERM means the pid exists and belongs to another uid. Under hidepid= or a foreign
    // uid, the /proc read fails too, so the two cases are easy to collapse into
    // "reclaim it", which would steal a lock from a living writer.
    const status = classifyLockOwner(
      HELD_BY,
      probe({
        liveness: () => {
          throw errno("EPERM", `EPERM: operation not permitted, kill ${HELD_BY}`);
        },
        cmdline: () => {
          throw unreadableProc();
        },
      })
    );
    expect(status.kind).toBe("indeterminate");
  });

  it("separates a live agentwall from a recycled pid", () => {
    expect(classifyLockOwner(HELD_BY, probe()).kind).toBe("holding");
    expect(
      classifyLockOwner(HELD_BY, probe({ cmdline: () => "/usr/sbin/sshd\u0000-D\u0000" }))
        .kind
    ).toBe("recycled");
  });

  it("uses real kill(2) and /proc semantics when no probe is injected", () => {
    // Reaped by the time spawnSync returns, so signal 0 must report ESRCH.
    const reaped = spawnSync("/bin/true").pid;
    expect(typeof reaped).toBe("number");
    expect(classifyLockOwner(reaped!).kind).toBe("gone");

    // pid 1 exists: EPERM as an unprivileged caller, success as root. Never "gone".
    expect(classifyLockOwner(1).kind).not.toBe("gone");

    // This process is alive and its /proc entry is readable, so the real probe must reach
    // a verdict rather than fail closed. Which verdict depends on the runner's argv.
    expect(["holding", "recycled"]).toContain(classifyLockOwner(process.pid).kind);
  });
});

describe("audit writer lock claim", () => {
  it("refuses to reclaim a lock whose owner is alive but unidentifiable", () => {
    const { auditPath, lockPath } = lockedAuditPath(HELD_BY);
    const blindProbe = probe({
      cmdline: () => {
        throw unreadableProc();
      },
    });

    expect(() => claimWriter(auditPath, blindProbe)).toThrow(/STILL RUNNING/);
    expect(() => claimWriter(auditPath, blindProbe)).toThrow(
      new RegExp(`/proc/${HELD_BY}/cmdline`)
    );
    expect(() => claimWriter(auditPath, blindProbe)).toThrow(/Refusing to reclaim/);

    // The regression this guards: the old code swallowed the /proc failure into an empty
    // cmdline, concluded "not an agentwall", and rewrote the lock with its own pid, so a
    // still-appending writer lost the lock and two hash chains merged into one file.
    expect(fs.readFileSync(lockPath, "utf8")).toBe(String(HELD_BY));
  });

  it("refuses to reclaim a lock held by a live agentwall", () => {
    const { auditPath, lockPath } = lockedAuditPath(HELD_BY);
    expect(() => claimWriter(auditPath, probe())).toThrow(
      new RegExp(`already owned by pid ${HELD_BY}`)
    );
    expect(fs.readFileSync(lockPath, "utf8")).toBe(String(HELD_BY));
  });

  it("reclaims the lock when the owner is provably dead", () => {
    const { auditPath, lockPath } = lockedAuditPath(HELD_BY);
    claimWriter(
      auditPath,
      probe({
        liveness: () => {
          throw errno("ESRCH", `ESRCH: no such process, kill ${HELD_BY}`);
        },
      })
    );
    expect(fs.readFileSync(lockPath, "utf8")).toBe(String(process.pid));
  });

  it("reclaims the lock when the pid is alive but demonstrably not an agentwall", () => {
    // Otherwise a recycled pid would wedge startup forever with no way back.
    const { auditPath, lockPath } = lockedAuditPath(HELD_BY);
    claimWriter(auditPath, probe({ cmdline: () => "/lib/systemd/systemd-udevd\u0000" }));
    expect(fs.readFileSync(lockPath, "utf8")).toBe(String(process.pid));
  });

  it("claims an unheld lock and appends one record per line", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-audit-sink-"));
    tempDirs.push(dir);
    const auditPath = path.join(dir, "nested", "audit.jsonl");

    const sink = createFileSink(auditPath);
    const event: AuditEvent = {
      id: "evt-1",
      timestamp: "2026-08-04T00:00:00.000Z",
      agentId: "agent-1",
      plane: "network",
      action: "http.request",
      decision: "allow",
      riskLevel: "low",
      matchedRules: [],
      reasons: [],
      requiresApproval: false,
      highRiskFlow: false,
      integrity: {
        chainIndex: 0,
        hash: "a".repeat(64),
        previousHash: null,
        algorithm: "sha256",
        status: "chained-local",
      },
    };
    sink(event);
    sink({ ...event, id: "evt-2", integrity: { ...event.integrity, chainIndex: 1 } });

    expect(fs.readFileSync(auditPath + ".lock", "utf8")).toBe(String(process.pid));
    const lines = fs.readFileSync(auditPath, "utf8").trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[1]).id).toBe("evt-2");
  });
});

/**
 * A torn tail against interior corruption.
 *
 * A hard kill mid-append leaves exactly one partial line and it is always the last, with no
 * terminator. Calling that a broken chain sends an operator hunting a tamperer who does not
 * exist, so the two are told apart on the one signal that separates them. That boundary is the
 * whole distinction, and it is pinned from both sides here: move the same damaged bytes off
 * the end, or give them a terminator, and they are an edit again.
 */
describe("verifyChainFile torn tail", () => {
  function chainedLines(count: number): string[] {
    const lines: string[] = [];
    let previousHash: string | null = null;
    for (let i = 0; i < count; i++) {
      const event = chainAuditEvent(
        {
          id: `evt-${i}`,
          timestamp: "2026-08-04T00:00:00.000Z",
          agentId: "agent-1",
          plane: "network",
          action: "http.request",
          decision: "allow",
          riskLevel: "low",
          matchedRules: [],
          reasons: [],
          requiresApproval: false,
          highRiskFlow: false,
        },
        { chainIndex: i, previousHash }
      );
      lines.push(JSON.stringify(event));
      previousHash = event.integrity.hash;
    }
    return lines;
  }

  function auditFile(contents: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-torn-tail-"));
    tempDirs.push(dir);
    const auditPath = path.join(dir, "audit.jsonl");
    fs.writeFileSync(auditPath, contents);
    return auditPath;
  }

  it("names a partial final line a torn tail and leaves the chain standing", () => {
    const lines = chainedLines(3);
    const file = auditFile(`${lines.join("\n")}\n${lines[2].slice(0, 64)}`);

    const result = verifyChainFile(file, rehashAuditEvent);
    expect(result.problems).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.notes.join("\n")).toMatch(/line 4: torn-tail/);
  });

  it("fails a truncated line in the middle of a file as corruption", () => {
    // The same damaged bytes, moved off the end. No interrupted append can put a partial
    // line in front of complete ones, so this is an edit and stays fatal.
    const lines = chainedLines(3);
    const file = auditFile(`${lines[0]}\n${lines[1].slice(0, 64)}\n${lines[2]}\n`);

    const result = verifyChainFile(file, rehashAuditEvent);
    expect(result.ok).toBe(false);
    expect(result.notes).toEqual([]);
    expect(result.problems.join("\n")).toMatch(/line 2: not valid JSON/);
  });

  it("fails a partial last line that still carries its terminator", () => {
    // A truncation followed by a newline was not left by a kill part way through the write:
    // the terminator is proof that something wrote after the record was cut short.
    const lines = chainedLines(3);
    const file = auditFile(`${lines.join("\n")}\n${lines[2].slice(0, 64)}\n`);

    const result = verifyChainFile(file, rehashAuditEvent);
    expect(result.ok).toBe(false);
    expect(result.notes).toEqual([]);
    expect(result.problems.join("\n")).toMatch(/line 4: not valid JSON/);
  });

  it("keeps an intact file free of both problems and notes", () => {
    const file = auditFile(`${chainedLines(3).join("\n")}\n`);

    const result = verifyChainFile(file, rehashAuditEvent);
    expect(result).toMatchObject({ ok: true, records: 3, problems: [], notes: [] });
  });
});
