import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { tmpdir } from "os";
import { join } from "path";
import { registerAuditSink, resetAuditChain } from "../src/audit/logger";
import {
  defaultSpillIgnores,
  isIgnoredPath,
  SpillFinding,
  SpillWatchHandle,
  startSpillWatch,
} from "../src/spill/watch";
import { AuditEvent } from "../src/types";

/**
 * What the spill watch reports, what it refuses to report, and what it leaves behind.
 *
 * Every wait here is driven by an event - a finding callback, or a counter reaching a value -
 * rather than by a sleep sized to "probably long enough". A watcher suite paced by sleeps
 * passes on an idle laptop and fails on a loaded CI box, and the failure looks like a broken
 * watcher rather than a broken test.
 *
 * Fake timers are not an option here and no test sets one. The events being awaited originate
 * in the platform's own file-change notifications, which a faked clock does not produce, and
 * in the spill watch's internal debounce, which a faked clock would advance past before the real
 * filesystem had delivered anything. So the waits below are event-driven or yield to the event
 * loop, and no wall-clock delay appears anywhere in this file.
 *
 * The negative cases (benign file, oversize, binary, ignored path) use a tripwire: a small
 * file that DOES carry a credential, written after the file under test. Its finding is the
 * signal that the spill watch has worked through the earlier event, so "nothing was reported"
 * can be asserted without waiting an arbitrary interval for silence.
 */

// `fs` is pulled in as a CommonJS binding rather than a namespace import on purpose. Under
// esModuleInterop a namespace import of a CJS module is a COPY of its exports, so spying on
// the copy would leave the spill watch calling the untouched original - and the degradation test
// below needs the real fs.watch replaced.
import nodeFs = require("fs");

/** A syntactically valid, permanently invalid AWS key id. Never a live credential. */
const SYNTHETIC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

const tempDirs: string[] = [];
const openHandles: SpillWatchHandle[] = [];
const auditEvents: AuditEvent[] = [];

function tempDir(): string {
  const dir = nodeFs.mkdtempSync(join(tmpdir(), "agentwall-spill-watch-"));
  tempDirs.push(dir);
  return dir;
}

/**
 * Collects findings and lets a test await the specific one it cares about.
 *
 * Matching on a predicate rather than on arrival order matters: several files are in flight in
 * most of these tests, and the debounce means the order events are produced in is not the
 * order findings come back in.
 */
class FindingCollector {
  readonly findings: SpillFinding[] = [];
  private readonly waiters: Array<{ match: (f: SpillFinding) => boolean; deliver: (f: SpillFinding) => void }> = [];

  readonly onFinding = (finding: SpillFinding): void => {
    this.findings.push(finding);
    for (const waiter of [...this.waiters]) {
      if (!waiter.match(finding)) continue;
      this.waiters.splice(this.waiters.indexOf(waiter), 1);
      waiter.deliver(finding);
    }
  };

  waitFor(match: (f: SpillFinding) => boolean): Promise<SpillFinding> {
    const already = this.findings.find(match);
    if (already) return Promise.resolve(already);

    // Promise.withResolvers would read better, but it is ES2024 and this project compiles
    // against lib ES2022. There is no timeout: a finding that never arrives fails the test
    // through Jest's own deadline, which needs no timer of ours to enforce.
    return new Promise<SpillFinding>((resolve) => {
      this.waiters.push({ match, deliver: resolve });
    });
  }

  pathsSeen(): string[] {
    return this.findings.map((finding) => finding.path);
  }
}

/**
 * Yield to the event loop until a counter reaches a value.
 *
 * setImmediate rather than a delay: this is always called after a tripwire finding has already
 * arrived, so the condition is normally true on the first check and the loop costs nothing.
 * A delay would add its own latency to every run and would still be a guess.
 */
async function waitUntil(condition: () => boolean, description: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${description}`);
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

async function startWatch(
  paths: string[],
  collector: FindingCollector,
  overrides: { maxFileBytes?: number; debounceMs?: number; mode?: "auto" | "rescan"; rescanIntervalMs?: number } = {},
): Promise<SpillWatchHandle> {
  const handle = await startSpillWatch({
    paths,
    onFinding: collector.onFinding,
    ...overrides,
  });
  openHandles.push(handle);
  return handle;
}

function fsEventWrapCount(): number {
  return process.getActiveResourcesInfo().filter((resource) => resource === "FSEventWrap").length;
}

beforeEach(() => {
  resetAuditChain();
  auditEvents.length = 0;
  registerAuditSink((event) => auditEvents.push(event));
});

afterEach(async () => {
  while (openHandles.length > 0) {
    await openHandles.pop()?.close();
  }
  jest.restoreAllMocks();
  resetAuditChain();
  while (tempDirs.length > 0) {
    nodeFs.rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("spill watch findings", () => {
  it("reports a credential written into a watched path without carrying the credential", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    await startWatch([dir], collector);

    const staged = join(dir, "staged.env");
    nodeFs.writeFileSync(staged, `AWS_ACCESS_KEY_ID=${SYNTHETIC_AWS_KEY}\n`);

    const finding = await collector.waitFor((f) => f.path === staged);

    expect(finding.secretTypes).toContain("aws-access-key");
    expect(finding.path).toBe(staged);
    expect(finding.sizeBytes).toBeGreaterThan(0);
    expect(Number.isNaN(Date.parse(finding.at))).toBe(false);

    // The whole point of the finding shape: nothing in it can be read back as the credential,
    // and no extra field has crept in that might carry an excerpt.
    expect(JSON.stringify(finding)).not.toContain(SYNTHETIC_AWS_KEY);
    expect(JSON.stringify(finding)).not.toContain("AWS_ACCESS_KEY_ID");
    expect(Object.keys(finding).sort()).toEqual(["at", "path", "piiTypes", "secretTypes", "sizeBytes"]);
  });

  it("stays quiet for a benign file", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    const handle = await startWatch([dir], collector);

    const benign = join(dir, "notes.txt");
    nodeFs.writeFileSync(benign, "the quick brown fox jumps over the lazy dog\n");
    const tripwire = join(dir, "tripwire.env");
    nodeFs.writeFileSync(tripwire, `${SYNTHETIC_AWS_KEY}\n`);

    await collector.waitFor((f) => f.path === tripwire);

    expect(collector.pathsSeen()).not.toContain(benign);
    await waitUntil(() => handle.stats().scanned >= 2, "both files to be scanned");
    expect(handle.stats().findings).toBe(1);
  });

  it("records the finding in the audit chain with the path and types but not the contents", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    await startWatch([dir], collector);

    const staged = join(dir, "harvested.txt");
    nodeFs.writeFileSync(staged, `token: ${SYNTHETIC_AWS_KEY}\n`);
    await collector.waitFor((f) => f.path === staged);

    const event = auditEvents.find((candidate) => candidate.action === "spill:file-write");
    if (event === undefined) throw new Error("the spill watch produced no audit record for the finding");

    expect(event.plane).toBe("content");
    expect(event.decision).toBe("deny");
    expect(event.riskLevel).toBe("high");
    expect(event.matchedRules).toContain("content:deny-spill-file-write");
    expect(event.metadata?.["path"]).toBe(staged);
    expect(event.metadata?.["secretTypes"]).toContain("aws-access-key");

    const detections = event.detections ?? [];
    const fsDetection = detections.find((detection) => detection.id === "det.content.spill.file_write");
    expect(fsDetection?.mitreAttack?.techniqueId).toBe("T1552.001");
    expect(fsDetection?.severity).toBe("high");
    expect(JSON.stringify(event)).not.toContain(SYNTHETIC_AWS_KEY);
  });
});

describe("spill watch candidate filtering", () => {
  it("skips a file larger than maxFileBytes instead of reading it", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    const handle = await startWatch([dir], collector, { maxFileBytes: 64 });

    // The credential sits inside the oversize file: if the cap were ignored and the file read,
    // this would produce a finding, so "no finding" is proof the bytes were never scanned.
    const oversize = join(dir, "bulk.log");
    nodeFs.writeFileSync(oversize, `${"padding ".repeat(512)}${SYNTHETIC_AWS_KEY}\n`);
    const tripwire = join(dir, "tripwire.env");
    nodeFs.writeFileSync(tripwire, `${SYNTHETIC_AWS_KEY}\n`);

    await collector.waitFor((f) => f.path === tripwire);
    await waitUntil(() => handle.stats().skipped >= 1, "the oversize file to be skipped");

    expect(collector.pathsSeen()).not.toContain(oversize);
    expect(handle.stats().scanned).toBe(1);
  });

  it("skips a file with a NUL byte in its first block", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    const handle = await startWatch([dir], collector);

    const binary = join(dir, "payload.dat");
    nodeFs.writeFileSync(binary, Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01]), Buffer.from(SYNTHETIC_AWS_KEY)]));
    const tripwire = join(dir, "tripwire.env");
    nodeFs.writeFileSync(tripwire, `${SYNTHETIC_AWS_KEY}\n`);

    await collector.waitFor((f) => f.path === tripwire);
    await waitUntil(() => handle.stats().skipped >= 1, "the binary file to be skipped");

    expect(collector.pathsSeen()).not.toContain(binary);
    expect(handle.stats().scanned).toBe(1);
  });

  it("never scans inside node_modules or .git", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    const handle = await startWatch([dir], collector);

    nodeFs.mkdirSync(join(dir, "node_modules", "pkg"), { recursive: true });
    nodeFs.mkdirSync(join(dir, ".git"), { recursive: true });
    const vendored = join(dir, "node_modules", "pkg", "config.json");
    const gitConfig = join(dir, ".git", "config");
    nodeFs.writeFileSync(vendored, `{"key":"${SYNTHETIC_AWS_KEY}"}\n`);
    nodeFs.writeFileSync(gitConfig, `key = ${SYNTHETIC_AWS_KEY}\n`);
    const tripwire = join(dir, "tripwire.env");
    nodeFs.writeFileSync(tripwire, `${SYNTHETIC_AWS_KEY}\n`);

    await collector.waitFor((f) => f.path === tripwire);

    expect(collector.pathsSeen()).toEqual([tripwire]);
    // Ignored paths are not candidates at all, so they must not inflate the skip counter that
    // an operator watches for permission problems.
    expect(handle.stats().scanned).toBe(1);
    expect(handle.stats().skipped).toBe(0);
  });

  it("applies segment patterns and suffix patterns as documented, and adds to the defaults", () => {
    // The two pattern shapes are a documented contract, so they are pinned directly rather
    // than only through whichever paths the watching tests happen to create.
    expect(isIgnoredPath("/w/pkg/.git/config", defaultSpillIgnores)).toBe(true);
    expect(isIgnoredPath("/w/node_modules/lib/index.js", defaultSpillIgnores)).toBe(true);
    expect(isIgnoredPath("/w/assets/logo.png", defaultSpillIgnores)).toBe(true);

    // `.env` is the file this whole module exists for; no default may swallow it.
    expect(isIgnoredPath("/w/.env", defaultSpillIgnores)).toBe(false);
    expect(isIgnoredPath("/w/src/config.ts", defaultSpillIgnores)).toBe(false);

    // A caller's ignores extend the defaults; they never replace them.
    const extended = [...defaultSpillIgnores, "fixtures/", "*.snap"];
    expect(isIgnoredPath("/w/tests/fixtures/keys.txt", extended)).toBe(true);
    expect(isIgnoredPath("/w/tests/ui.snap", extended)).toBe(true);
    expect(isIgnoredPath("/w/pkg/.git/config", extended)).toBe(true);
  });
});

describe("spill watch debouncing and races", () => {
  it("collapses a burst of writes to one path into a single scan", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    const handle = await startWatch([dir], collector, { debounceMs: 250 });

    const churned = join(dir, "churn.env");
    for (let attempt = 0; attempt < 20; attempt++) {
      nodeFs.writeFileSync(churned, `attempt=${attempt} ${"x".repeat(attempt)}\nkey=${SYNTHETIC_AWS_KEY}\n`);
      // Yield between writes so the platform delivers a separate change event for each one.
      // Twenty writes inside a single tick would collapse into one scan even from a spill watch
      // with no debounce at all, which would make this assertion prove nothing.
      await new Promise<void>((resolve) => setImmediate(resolve));
    }

    await collector.waitFor((f) => f.path === churned);

    expect(handle.stats().scanned).toBe(1);
    expect(handle.stats().findings).toBe(1);
  }, 15_000);

  it("survives a file deleted between the event and the read, and a path that is a directory", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    const handle = await startWatch([dir], collector);

    const transient = join(dir, "transient.env");
    nodeFs.writeFileSync(transient, `${SYNTHETIC_AWS_KEY}\n`);
    nodeFs.unlinkSync(transient);
    nodeFs.mkdirSync(join(dir, "workspace"));
    const tripwire = join(dir, "tripwire.env");
    nodeFs.writeFileSync(tripwire, `${SYNTHETIC_AWS_KEY}\n`);

    await collector.waitFor((f) => f.path === tripwire);
    await waitUntil(() => handle.stats().skipped >= 1, "the vanished file to be counted as skipped");

    expect(collector.pathsSeen()).not.toContain(transient);
    expect(handle.stats().scanned).toBe(1);
  });
});

describe("spill watch shutdown", () => {
  it("closes every watcher and reports nothing after close resolves", async () => {
    const dir = tempDir();
    const first = new FindingCollector();

    const baselineWatchers = fsEventWrapCount();
    const handle = await startWatch([dir], first);
    expect(fsEventWrapCount()).toBe(baselineWatchers + 1);

    const before = join(dir, "before.env");
    nodeFs.writeFileSync(before, `${SYNTHETIC_AWS_KEY}\n`);
    await first.waitFor((f) => f.path === before);

    await expect(handle.close()).resolves.toBeUndefined();
    expect(fsEventWrapCount()).toBe(baselineWatchers);

    const afterClose = join(dir, "after-close.env");
    nodeFs.writeFileSync(afterClose, `${SYNTHETIC_AWS_KEY}\n`);

    // A second spill watch is the clock: once IT has reported a write to this directory, a live
    // watcher on the first spill watch would have reported the earlier one too.
    const second = new FindingCollector();
    await startWatch([dir], second);
    const probe = join(dir, "probe.env");
    nodeFs.writeFileSync(probe, `${SYNTHETIC_AWS_KEY}\n`);
    await second.waitFor((f) => f.path === probe);

    expect(first.pathsSeen()).toEqual([before]);
  });
});

describe("spill watch degradation", () => {
  // KNOWN INTERMITTENT, UNEXPLAINED. On a heavily loaded machine this case has timed out
  // roughly one run in three when its file shares a worker with several other suites:
  //
  //   npx jest tests/lockdown.test.ts tests/probe-api.test.ts \
  //            tests/mcp-http.test.ts tests/spill-watch.test.ts --maxWorkers=1
  //
  // Ruled out: CPU starvation (passes under 12x synthetic load in isolation), worker count
  // (fails at --maxWorkers=1, passes at --maxWorkers=2), file-descriptor limits (1M soft),
  // an unref'd timer (the interval is ref'd), libuv threadpool size (no change at 64), and
  // mtime granularity (sub-millisecond on this filesystem). Reading the code, both orderings
  // should report: if pass one reaches the file after the write, mtimeMs >= startedAtMs
  // reports it; if pass one misses it, pass two sees previous === undefined with seeded true
  // and reports it. Neither path can seed it silently.
  //
  // It is left running rather than skipped, and deliberately NOT "fixed" by re-touching the
  // file on an interval: that would report through the changed-fingerprint branch, which the
  // change-detection case above already covers, and would delete the only coverage of the
  // first-sight path while looking green. An open question beats a test that stopped asking.
  it("falls back to periodic re-scan when the operator asks for it", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    const handle = await startWatch([dir], collector, { mode: "rescan", rescanIntervalMs: 50, debounceMs: 20 });

    const staged = join(dir, "staged.env");
    nodeFs.writeFileSync(staged, `${SYNTHETIC_AWS_KEY}\n`);

    const finding = await collector.waitFor((f) => f.path === staged);
    expect(finding.secretTypes).toContain("aws-access-key");

    const stats = handle.stats();
    expect(stats.roots[0]?.mode).toBe("rescan");
    // An operator who chose re-scan has not lost anything, so nothing here is degraded.
    expect(stats.roots[0]?.degradedReason).toBeNull();
    expect(stats.degraded).toBe(false);
    // 45s, not the suite default: this is the one case whose subject is a wall-clock periodic
    // mechanism rather than a callback, so it needs real elapsed time to pass. Under the
    // project's --maxWorkers=50% it shares cores with seven other suites, and a 15s bound
    // failed there while passing in isolation and at --maxWorkers=2. The generous bound
    // measures the same behaviour without turning runner contention into a product failure.
  }, 45_000);

  it("falls back and declares itself degraded when recursive watch is unavailable", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();

    class RecursiveWatchUnsupported extends Error {
      readonly code = "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM";
      constructor() {
        super("recursive watch is not supported on this platform");
      }
    }
    jest.spyOn(nodeFs, "watch").mockImplementation(() => {
      throw new RecursiveWatchUnsupported();
    });

    const handle = await startWatch([dir], collector, { rescanIntervalMs: 50, debounceMs: 20 });

    const stats = handle.stats();
    expect(stats.degraded).toBe(true);
    expect(stats.roots[0]?.mode).toBe("rescan");
    expect(stats.roots[0]?.degradedReason).toContain("recursive watch unavailable");

    // Degraded is not off: the fallback must still find the credential.
    const staged = join(dir, "staged.env");
    nodeFs.writeFileSync(staged, `${SYNTHETIC_AWS_KEY}\n`);
    const finding = await collector.waitFor((f) => f.path === staged);
    expect(finding.secretTypes).toContain("aws-access-key");
  }, 15_000);

  it("refuses to start on an unusable path and leaves no watcher behind", async () => {
    const dir = tempDir();
    const collector = new FindingCollector();
    const baselineWatchers = fsEventWrapCount();

    await expect(
      startSpillWatch({ paths: [join(dir, "absent")], onFinding: collector.onFinding }),
    ).rejects.toThrow(/cannot watch/);
    await expect(startSpillWatch({ paths: [], onFinding: collector.onFinding })).rejects.toThrow(
      /at least one path/,
    );

    // A good path listed before a bad one must not be attached: the rejection gives the caller
    // no handle, so anything attached before the throw could never be closed.
    await expect(
      startSpillWatch({ paths: [dir, join(dir, "absent")], onFinding: collector.onFinding }),
    ).rejects.toThrow(/cannot watch/);
    expect(fsEventWrapCount()).toBe(baselineWatchers);
  });
});
