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
} from "../src/audit/file-sink";
import { AuditEvent } from "../src/types";

/**
 * The audit chain is only a proof if exactly one process ever appends to the file. These
 * tests pin the reclaim decision in claimWriter(), because getting it wrong does not throw
 * or corrupt anything visibly — it silently produces a file with two interleaved hash
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
    // cmdline, concluded "not an agentwall", and rewrote the lock with its own pid — so a
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
