import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  auditDropStats,
  emit,
  registerAuditSink,
  resetAuditChain,
} from "../src/audit/logger";
import { createFileSink, verifyChainFile } from "../src/audit/file-sink";
import { AUDIT_CHAIN_GAP_ACTION, chainAuditEvent, rehashAuditEvent } from "../src/audit/chain";
import { AgentContext, AuditEvent, PolicyResult } from "../src/types";

/**
 * What happens to the chain when storage refuses a record.
 *
 * The failure these pin is not a crash. Advancing the chain before the sinks ran left the
 * next record linked to a predecessor that was never written, so a full disk produced the
 * index jump and broken link of a DELETED record: byte for byte the finding the corpus
 * forgery b3-record-removed produces. An operator cannot act on an alert that says tampering
 * when the truth is a full partition.
 */

const tempDirs: string[] = [];

function tempAuditPath(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentwall-durability-"));
  tempDirs.push(dir);
  return path.join(dir, "audit.jsonl");
}

function ctx(action: string): AgentContext {
  return {
    agentId: "durability-agent",
    sessionId: "durability-session",
    plane: "network",
    action,
    payload: {},
    metadata: { host: "example.com" },
  } as AgentContext;
}

const allowed: PolicyResult = {
  decision: "allow",
  riskLevel: "low",
  matchedRules: [],
  reasons: ["test"],
  requiresApproval: false,
  highRiskFlow: false,
  detections: [],
};

function recordsOf(auditPath: string): AuditEvent[] {
  return fs
    .readFileSync(auditPath, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as AuditEvent);
}

/**
 * A durable sink that writes through to a real file until `refuse` is set, then throws the
 * way appendFileSync throws on a full partition.
 */
function refusableFileSink(auditPath: string): { refuse: (on: boolean) => void } {
  const write = createFileSink(auditPath);
  let refusing = false;
  registerAuditSink(
    (event) => {
      if (refusing) throw new Error(`audit append to ${auditPath} failed: ENOSPC: no space left on device`);
      write(event);
    },
    { durable: true },
  );
  return { refuse: (on: boolean) => (refusing = on) };
}

beforeEach(() => {
  resetAuditChain();
});

afterEach(() => {
  resetAuditChain();
  jest.restoreAllMocks();
  while (tempDirs.length) {
    fs.rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("audit chain durability under a refusing sink", () => {
  it("keeps the file contiguous across records the durable sink refused", () => {
    const auditPath = tempAuditPath();
    const sink = refusableFileSink(auditPath);

    emit(ctx("before"), allowed);
    sink.refuse(true);
    emit(ctx("lost-1"), allowed);
    emit(ctx("lost-2"), allowed);
    sink.refuse(false);
    emit(ctx("after"), allowed);

    const verification = verifyChainFile(auditPath, rehashAuditEvent);
    // The whole point: nothing here may read as an edit or a removal.
    expect(verification.problems).toEqual([]);
    expect(verification.ok).toBe(true);

    const written = recordsOf(auditPath);
    expect(written.map((r) => r.action)).toEqual(["before", AUDIT_CHAIN_GAP_ACTION, "after"]);
    expect(written.map((r) => r.integrity.chainIndex)).toEqual([0, 1, 2]);
    expect(written[1].integrity.previousHash).toBe(written[0].integrity.hash);
    expect(written[2].integrity.previousHash).toBe(written[1].integrity.hash);
  });

  it("declares how many records were lost, and reports it without failing the layer", () => {
    const auditPath = tempAuditPath();
    const sink = refusableFileSink(auditPath);

    emit(ctx("before"), allowed);
    sink.refuse(true);
    emit(ctx("lost-1"), allowed);
    emit(ctx("lost-2"), allowed);
    emit(ctx("lost-3"), allowed);
    sink.refuse(false);
    emit(ctx("after"), allowed);

    const marker = recordsOf(auditPath)[1];
    expect(marker.action).toBe(AUDIT_CHAIN_GAP_ACTION);
    expect(marker.metadata?.droppedRecords).toBe("3");
    expect(marker.metadata?.reason).toContain("ENOSPC");
    expect(marker.decision).toBe("deny");

    const verification = verifyChainFile(auditPath, rehashAuditEvent);
    expect(verification.problems).toEqual([]);
    expect(verification.notes).toHaveLength(1);
    expect(verification.notes[0]).toContain("chain-gap-declared");
    expect(verification.notes[0]).toContain("3 record(s)");
  });

  it("counts one gap declaration per outage, not per recovery", () => {
    const auditPath = tempAuditPath();
    const sink = refusableFileSink(auditPath);

    sink.refuse(true);
    emit(ctx("lost-1"), allowed);
    sink.refuse(false);
    emit(ctx("recovered-1"), allowed);
    sink.refuse(true);
    emit(ctx("lost-2"), allowed);
    sink.refuse(false);
    emit(ctx("recovered-2"), allowed);

    expect(recordsOf(auditPath).map((r) => r.action)).toEqual([
      AUDIT_CHAIN_GAP_ACTION,
      "recovered-1",
      AUDIT_CHAIN_GAP_ACTION,
      "recovered-2",
    ]);
    expect(verifyChainFile(auditPath, rehashAuditEvent).problems).toEqual([]);
  });

  it("writes no declaration while storage is still refusing", () => {
    const auditPath = tempAuditPath();
    const sink = refusableFileSink(auditPath);

    emit(ctx("before"), allowed);
    sink.refuse(true);
    emit(ctx("lost-1"), allowed);
    emit(ctx("lost-2"), allowed);

    // Nothing can be written to a partition that is refusing writes, marker included.
    expect(recordsOf(auditPath).map((r) => r.action)).toEqual(["before"]);
    expect(auditDropStats()).toMatchObject({ dropped: 2, undeclared: 2 });
    expect(auditDropStats().reason).toContain("ENOSPC");
  });

  it("puts the refused record on stderr without an integrity block", () => {
    const auditPath = tempAuditPath();
    const sink = refusableFileSink(auditPath);
    const lines: string[] = [];
    jest.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
      lines.push(String(chunk));
      return true;
    });

    sink.refuse(true);
    emit(ctx("lost-1"), allowed);

    expect(lines).toHaveLength(1);
    const dropped = JSON.parse(lines[0]) as {
      agentwall_audit_dropped: { reason: string; record: Record<string, unknown> };
    };
    expect(dropped.agentwall_audit_dropped.record.action).toBe("lost-1");
    // An index it was chained at now belongs to a different record, so publishing the block
    // would hand a reader a hash that verifies against nothing.
    expect(dropped.agentwall_audit_dropped.record.integrity).toBeUndefined();
    expect(dropped.agentwall_audit_dropped.reason).toContain("ENOSPC");
  });

  it("survives stderr being as full as the audit file", () => {
    const auditPath = tempAuditPath();
    const sink = refusableFileSink(auditPath);
    // With fd 2 on a regular file, Node backs process.stderr with a synchronous writer that
    // throws ENOSPC straight back out of write(). emit() is called inline by the route
    // handlers, so an escape here turns a full partition into a 500 on every request.
    jest.spyOn(process.stderr, "write").mockImplementation(() => {
      const err = new Error("ENOSPC: no space left on device, write") as NodeJS.ErrnoException;
      err.code = "ENOSPC";
      throw err;
    });

    sink.refuse(true);
    expect(() => emit(ctx("lost-1"), allowed)).not.toThrow();
    expect(() => emit(ctx("lost-2"), allowed)).not.toThrow();

    expect(auditDropStats()).toMatchObject({ dropped: 2, undeclared: 2 });

    // Recovery still declares the loss, so the only thing given up is the console copy.
    sink.refuse(false);
    jest.restoreAllMocks();
    emit(ctx("after"), allowed);
    expect(recordsOf(auditPath)[0].metadata?.droppedRecords).toBe("2");
  });

  it("does not let a failed console write terminate the process", () => {
    // A stream backed by a regular file reports a failed writeSync as an 'error' event
    // instead of throwing out of write(), so the try/catch around each sink never sees it.
    // An 'error' event with no listener is rethrown by EventEmitter and kills the process,
    // which on a full partition means the console copy of a record takes down egress
    // gating. Emitting one here is exactly what node does in that case.
    expect(() => process.stderr.emit("error", new Error("ENOSPC: no space left on device"))).not.toThrow();
    expect(() => process.stdout.emit("error", new Error("ENOSPC: no space left on device"))).not.toThrow();
  });

  it("shows an observer only the records the evidence stream accepted", () => {
    const auditPath = tempAuditPath();
    const sink = refusableFileSink(auditPath);
    const observed: string[] = [];
    registerAuditSink((event) => observed.push(event.action));

    emit(ctx("before"), allowed);
    sink.refuse(true);
    emit(ctx("lost-1"), allowed);
    sink.refuse(false);
    emit(ctx("after"), allowed);

    expect(observed).toEqual(["before", AUDIT_CHAIN_GAP_ACTION, "after"]);
  });

  it("lets the chain advance when only an observer fails", () => {
    const auditPath = tempAuditPath();
    refusableFileSink(auditPath);
    registerAuditSink(() => {
      throw new Error("console gone");
    });

    emit(ctx("one"), allowed);
    emit(ctx("two"), allowed);

    expect(recordsOf(auditPath).map((r) => r.integrity.chainIndex)).toEqual([0, 1]);
    expect(verifyChainFile(auditPath, rehashAuditEvent).problems).toEqual([]);
    expect(auditDropStats().dropped).toBe(0);
  });

  it("advances the chain normally when no sink is durable", () => {
    const observed: number[] = [];
    registerAuditSink((event) => observed.push(event.integrity.chainIndex));

    emit(ctx("one"), allowed);
    emit(ctx("two"), allowed);

    expect(observed).toEqual([0, 1]);
    expect(auditDropStats().dropped).toBe(0);
  });
});

describe("partial append rollback", () => {
  it("removes bytes a short write left behind so the next record parses", () => {
    const auditPath = tempAuditPath();
    // ENOSPC on a partly-filled page: the kernel copies what fits and reports the shortfall.
    let shortWrite = false;
    const write = createFileSink(auditPath, (target, data) => {
      if (!shortWrite) {
        fs.appendFileSync(target, data);
        return;
      }
      fs.appendFileSync(target, data.slice(0, 40));
      const err = new Error("ENOSPC: no space left on device, write") as NodeJS.ErrnoException;
      err.code = "ENOSPC";
      throw err;
    });

    const first = chainAuditEvent(
      { ...ctx("first"), id: "a", timestamp: "2026-01-01T00:00:00.000Z", ...allowed } as unknown as Omit<
        AuditEvent,
        "integrity"
      >,
      { chainIndex: 0, previousHash: null },
    );
    write(first);
    const goodLength = fs.statSync(auditPath).size;

    const second = chainAuditEvent(
      { ...ctx("second"), id: "b", timestamp: "2026-01-01T00:00:01.000Z", ...allowed } as unknown as Omit<
        AuditEvent,
        "integrity"
      >,
      { chainIndex: 1, previousHash: first.integrity.hash },
    );
    shortWrite = true;
    expect(() => write(second)).toThrow(/rolled back/);

    // Without the rollback the fragment stays and the next append fuses onto its line,
    // destroying a record that WAS written on top of the one that was not.
    expect(fs.statSync(auditPath).size).toBe(goodLength);

    shortWrite = false;
    write(second);
    expect(recordsOf(auditPath).map((r) => r.action)).toEqual(["first", "second"]);
    expect(verifyChainFile(auditPath, rehashAuditEvent).problems).toEqual([]);
  });
});

describe("a declaration is not a licence", () => {
  it("still reports an index gap that follows a gap declaration", () => {
    const auditPath = tempAuditPath();
    const first = chainAuditEvent(
      {
        id: "gap",
        timestamp: "2026-01-01T00:00:00.000Z",
        agentId: "agentwall",
        plane: "governance",
        action: AUDIT_CHAIN_GAP_ACTION,
        decision: "deny",
        riskLevel: "critical",
        matchedRules: [],
        reasons: ["2 audit record(s) could not be written and are absent from this chain"],
        requiresApproval: false,
        highRiskFlow: false,
        detections: [],
        metadata: { droppedRecords: "2" },
      },
      { chainIndex: 0, previousHash: null },
    );
    // A record removed after the declaration, which the declaration must not absolve.
    const jumped = chainAuditEvent(
      { ...ctx("later"), id: "c", timestamp: "2026-01-01T00:00:02.000Z", ...allowed } as unknown as Omit<
        AuditEvent,
        "integrity"
      >,
      { chainIndex: 5, previousHash: first.integrity.hash },
    );
    fs.writeFileSync(auditPath, `${JSON.stringify(first)}\n${JSON.stringify(jumped)}\n`);

    const verification = verifyChainFile(auditPath, rehashAuditEvent);
    expect(verification.ok).toBe(false);
    expect(verification.problems.join(" ")).toContain("gap or silent restart");
    expect(verification.notes.join(" ")).toContain("chain-gap-declared");
  });
});
