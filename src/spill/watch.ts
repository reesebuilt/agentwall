import { Dirent, FSWatcher, Stats, watch } from "fs";
import { FileHandle, open, readdir, stat } from "fs/promises";
import { join, resolve, sep } from "path";
import { emit } from "../audit/logger";
import { scanText } from "../planes/identity/dlp";
import { detectionsForRules } from "../policy/detections";
import { AgentContext, PolicyResult } from "../types";

/**
 * Spill watch: the disk half of the exfiltration picture.
 *
 * AgentWall watches egress. An agent that harvests a credential and writes it into a file in
 * its own workspace has not egressed anything yet, so nothing in the network plane sees it -
 * and the staging step is the one that happens first. The commit, the upload, or the human
 * who later pastes the file elsewhere all come after. This module watches the paths an
 * operator names and reports credential material appearing in them.
 *
 * It is an observer, not a gate. By the time an event arrives the bytes are already on disk;
 * `close()` cannot unwrite them and neither can a policy decision. The value is that the
 * write joins the audit chain at the moment it happens rather than being reconstructed
 * afterwards from a git history that may never have been pushed.
 *
 * Deliberately not wired into boot. Which paths to watch is an operator decision with real
 * cost (an inotify watch per directory, a scan per write), and a default that guessed would
 * either watch nothing useful or watch a home directory. Construct it yourself.
 */

/** 1 MiB. Past this a file is fingerprinted and declined rather than read - see `inspect`. */
const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;

/** Editors and compilers write a file several times per save; one save should cost one scan. */
const DEFAULT_DEBOUNCE_MS = 100;

/** Only used in periodic re-scan mode. Frequent enough to be useful, slow enough to be cheap. */
const DEFAULT_RESCAN_INTERVAL_MS = 2_000;

/**
 * Entries a single re-scan pass will look at before giving up on the rest of the tree.
 *
 * Unbounded, a pass over a large tree would hold the event loop for as long as the walk takes
 * and then start again on the next tick. Bounded, it visits part of the tree and says so
 * through `stats().roots[].truncated`, which is a problem an operator can act on.
 */
const DEFAULT_RESCAN_ENTRY_CAP = 5_000;

/**
 * How far behind `Date.now()` a filesystem mtime may sit for a write that happened after it.
 *
 * They are not the same clock. `Date.now()` reads CLOCK_REALTIME; Linux stamps inode times
 * from the coarse clock, which only advances on a timer tick, so a write issued strictly after
 * a `Date.now()` reading is routinely stamped earlier than it. Measured on ext4 at
 * CONFIG_HZ=1000: 19,999 of 20,000 writes came back with an mtime up to 1.41 ms older than the
 * `Date.now()` reading that immediately preceded them. Coarser kernels and network
 * filesystems that take their timestamps from a server clock are further out again.
 *
 * A whole second, because the two errors are not comparable in cost: too small and a
 * credential write is dropped silently and permanently, too large and a file touched shortly
 * before start-up is reported once.
 */
const MTIME_CLOCK_LAG_MS = 1_000;

/** A NUL in the first 8 KiB is the cheapest reliable "this is not text" signal available. */
const BINARY_SNIFF_BYTES = 8 * 1024;

const RULE_ID = "content:deny-spill-file-write";
const AUDIT_ACTION = "spill:file-write";

/**
 * The observer's identity in the audit record.
 *
 * Fixed, not configurable, because it names the thing that saw the write and not the thing
 * that performed it. `fs.watch` reports that a path changed; it does not report which process
 * changed it. An option here would invite an operator to fill in an agent id the spill watch
 * cannot actually verify, turning a known gap into a false attribution.
 */
const SPILL_WATCH_AGENT_ID = "spill-watch";

/**
 * Paths never worth scanning.
 *
 * Two shapes, distinguished by syntax so an operator can predict which applies:
 *   - trailing `/`  -> matches a whole path segment (`.git/` ignores `<root>/a/.git/config`)
 *   - leading `*.` or `.` -> matches a filename suffix (`*.png` ignores `logo.png`)
 *   - anything else -> matches a whole segment or an exact filename
 *
 * Dotfiles are deliberately NOT ignored as a class. `.env` is the single most likely place a
 * harvested credential lands, and a rule that skipped it would remove the main reason to run
 * this at all.
 */
export const defaultSpillIgnores: readonly string[] = [
  ".git/",
  "node_modules/",
  "dist/",
  "build/",
  "coverage/",
  ".venv/",
  "__pycache__/",
  "*.png",
  "*.jpg",
  "*.jpeg",
  "*.gif",
  "*.webp",
  "*.bmp",
  "*.ico",
  "*.pdf",
  "*.zip",
  "*.gz",
  "*.tgz",
  "*.tar",
  "*.bz2",
  "*.xz",
  "*.7z",
  "*.rar",
  "*.mp3",
  "*.mp4",
  "*.mov",
  "*.avi",
  "*.mkv",
  "*.wav",
  "*.flac",
  "*.ogg",
  "*.webm",
  "*.woff",
  "*.woff2",
  "*.ttf",
  "*.otf",
  "*.eot",
  "*.so",
  "*.dylib",
  "*.dll",
  "*.exe",
  "*.bin",
  "*.o",
  "*.a",
  "*.class",
  "*.jar",
  "*.wasm",
  "*.node",
  "*.pyc",
  "*.db",
  "*.sqlite",
  "*.iso",
  "*.img",
];

/** How a root is being observed right now. */
export type SpillWatchMode = "watch" | "rescan";

export interface SpillWatchOptions {
  /** Directories to watch. Each must exist and be a directory at start-up, or start fails. */
  paths: string[];
  /**
   * Extra ignores, in the syntax described on `defaultSpillIgnores`. These ADD to the
   * defaults; the defaults cannot be switched off. Watching inside `.git/` or `node_modules/`
   * is therefore not possible today - name a path outside them instead.
   */
  ignore?: string[];
  /** Default 1 MiB. Larger files are fingerprinted and skipped, never read. */
  maxFileBytes?: number;
  /** Default 100 ms. Events for one path inside this window collapse into one scan. */
  debounceMs?: number;
  /**
   * `auto` (default) tries a native recursive watch and falls back to periodic re-scan if the
   * platform refuses. `rescan` skips the native watch entirely, which is the right choice on
   * network filesystems and some container bind mounts: inotify never sees a write made by
   * the other side of an NFS or SMB mount, so a native watch there reports nothing forever
   * while looking perfectly healthy.
   */
  mode?: "auto" | "rescan";
  /** Default 2000 ms. Only used by roots in re-scan mode. */
  rescanIntervalMs?: number;
  /** Default 5000. Entries one re-scan pass will visit before reporting itself truncated. */
  rescanEntryCap?: number;
  onFinding: (f: SpillFinding) => void;
}

/**
 * What the spill watch says about a file.
 *
 * Note what is absent: the contents, the matched text, and any excerpt around it. A spill watch
 * that quoted the credential it found would copy that credential into the finding, into the
 * audit chain, and into whatever the operator's `onFinding` does with it - recreating the
 * exposure it exists to report, in a file that is often more widely readable than the
 * original. The type name and the size are enough to find the file and act.
 */
export interface SpillFinding {
  path: string;
  secretTypes: string[];
  piiTypes: string[];
  at: string;
  sizeBytes: number;
}

export interface SpillRootStatus {
  path: string;
  mode: SpillWatchMode;
  /**
   * Why the native watch was abandoned, or null. Non-null means AgentWall wanted a native
   * watch and could not have one: coverage is now only as fresh as `rescanIntervalMs`.
   */
  degradedReason: string | null;
  /** The last re-scan pass hit the entry cap and did not see the whole tree. */
  truncated: boolean;
}

export interface SpillWatchStats {
  /** Files read and scanned. */
  scanned: number;
  /**
   * Candidates the spill watch declined: too large, binary, vanished, not a regular file, or
   * unreadable. Also incremented once per unreadable directory per re-scan pass, so a
   * `skipped` that climbs while nothing is being written is a permissions problem rather than
   * activity. Ignored paths are not counted here - they were never candidates.
   */
  skipped: number;
  findings: number;
  /** True when any root lost its native watch. Check this; a silent spill watch looks identical. */
  degraded: boolean;
  roots: SpillRootStatus[];
}

export interface SpillWatchHandle {
  close(): Promise<void>;
  stats(): SpillWatchStats;
}

interface RootState {
  path: string;
  mode: SpillWatchMode;
  degradedReason: string | null;
  truncated: boolean;
  watcher: FSWatcher | null;
  timer: NodeJS.Timeout | undefined;
  /** absolute path -> metadata fingerprint. Only populated for roots in re-scan mode. */
  seen: Map<string, string>;
  seeded: boolean;
  passInFlight: boolean;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function isIgnoredPath(target: string, patterns: readonly string[]): boolean {
  const normalized = target.split(sep).join("/");
  const segments = normalized.split("/").filter((part) => part !== "");
  const base = segments[segments.length - 1] ?? "";

  for (const raw of patterns) {
    if (raw === "") continue;

    if (raw.endsWith("/")) {
      const segment = raw.slice(0, -1);
      if (segment !== "" && segments.includes(segment)) return true;
      continue;
    }

    if (raw.startsWith("*.") || raw.startsWith(".")) {
      const suffix = raw.startsWith("*") ? raw.slice(1) : raw;
      if (base.length > suffix.length && base.endsWith(suffix)) return true;
      if (segments.includes(raw)) return true;
      continue;
    }

    if (segments.includes(raw)) return true;
  }

  return false;
}

/**
 * Read `length` bytes into `buffer` at `offset`, tolerating short reads.
 *
 * A single `read()` is allowed to return fewer bytes than asked for, and does on pipes,
 * network filesystems, and files being appended to as they are read. Assuming otherwise
 * produces a truncated scan that reports "no secret found" - the failure mode that matters
 * most here, because it is indistinguishable from a clean file. Returns bytes actually read;
 * a short return means the file shrank underneath us.
 */
async function readFully(handle: FileHandle, buffer: Buffer, offset: number, length: number): Promise<number> {
  let filled = 0;
  while (filled < length) {
    const { bytesRead } = await handle.read(buffer, offset + filled, length - filled, offset + filled);
    if (bytesRead === 0) break;
    filled += bytesRead;
  }
  return filled;
}

class SpillWatch implements SpillWatchHandle {
  private readonly roots: RootState[] = [];
  private readonly ignore: readonly string[];
  private readonly maxFileBytes: number;
  private readonly debounceMs: number;
  private readonly rescanIntervalMs: number;
  private readonly rescanEntryCap: number;
  private readonly watchMode: "auto" | "rescan";
  private readonly onFinding: (finding: SpillFinding) => void;
  private readonly pending = new Map<string, NodeJS.Timeout>();
  private readonly inFlight = new Set<Promise<void>>();
  private readonly startedAtMs = Date.now();

  private scanned = 0;
  private skipped = 0;
  private findings = 0;
  private closed = false;

  constructor(options: SpillWatchOptions) {
    this.ignore = [...defaultSpillIgnores, ...(options.ignore ?? [])];
    this.maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.debounceMs = options.debounceMs ?? DEFAULT_DEBOUNCE_MS;
    this.rescanIntervalMs = options.rescanIntervalMs ?? DEFAULT_RESCAN_INTERVAL_MS;
    this.rescanEntryCap = options.rescanEntryCap ?? DEFAULT_RESCAN_ENTRY_CAP;
    this.watchMode = options.mode ?? "auto";
    this.onFinding = options.onFinding;
  }

  /**
   * Attach to every root, failing loudly if one is unusable.
   *
   * A path that does not exist is an operator typo, and the spill watch's whole failure mode is
   * being silently pointed at nothing, so this throws instead of watching the rest and hoping
   * the mistake is noticed.
   *
   * Every path is checked before any watcher is attached. Attaching as it went would leave a
   * live inotify watch behind when a later path turned out to be a typo, and the caller has no
   * handle to close it with - the constructor threw.
   *
   * Resolves once every root is actually armed, which for a re-scan root means its seeding
   * pass has finished. See the comment on that await below.
   */
  async start(paths: string[]): Promise<void> {
    if (paths.length === 0) {
      throw new Error("spill watch needs at least one path to watch");
    }

    const rootPaths: string[] = [];
    for (const candidate of paths) {
      const rootPath = resolve(candidate);
      let stats: Stats;
      try {
        stats = await stat(rootPath);
      } catch (error) {
        throw new Error(`spill watch cannot watch ${rootPath}: ${errorMessage(error)}`);
      }
      if (!stats.isDirectory()) {
        throw new Error(`spill watch cannot watch ${rootPath}: not a directory`);
      }
      rootPaths.push(rootPath);
    }

    // A re-scan root's first pass is the snapshot every later pass compares against, so until
    // it lands the root cannot tell a write from the tree it started with and has to fall back
    // to the mtime rule in `rescanPass`. Resolving before it lands would hand the caller a
    // handle whose behaviour on their very first write depends on whether that write beat a
    // `readdir`. Collected and awaited together so several roots seed concurrently.
    const seeding: Promise<void>[] = [];
    for (const rootPath of rootPaths) {
      const root: RootState = {
        path: rootPath,
        mode: "watch",
        degradedReason: null,
        truncated: false,
        watcher: null,
        timer: undefined,
        seen: new Map(),
        seeded: false,
        passInFlight: false,
      };
      this.roots.push(root);

      seeding.push(this.watchMode === "rescan" ? this.beginRescan(root) : this.beginWatch(root));
    }

    // Neither call rejects: a native watch that cannot start degrades into a re-scan, and
    // `rescanPass` buries its own IO failures in `skipped`. A root in native watch mode
    // resolves immediately, so this costs nothing in the ordinary case.
    await Promise.all(seeding);
  }

  stats(): SpillWatchStats {
    return {
      scanned: this.scanned,
      skipped: this.skipped,
      findings: this.findings,
      degraded: this.roots.some((root) => root.degradedReason !== null),
      roots: this.roots.map((root) => ({
        path: root.path,
        mode: root.mode,
        degradedReason: root.degradedReason,
        truncated: root.truncated,
      })),
    };
  }

  async close(): Promise<void> {
    this.closed = true;

    for (const root of this.roots) {
      if (root.watcher) {
        try {
          root.watcher.close();
        } catch {
          // A watcher the platform already tore down throws on close. Nothing to recover.
        }
        root.watcher = null;
      }
      clearInterval(root.timer);
      root.timer = undefined;
    }

    for (const timer of this.pending.values()) {
      clearTimeout(timer);
    }
    this.pending.clear();

    // Scans already running are awaited rather than abandoned, so close() resolving means no
    // callback can still fire. They check `closed` before reporting, so nothing observed
    // during the shutdown window reaches the operator's handler after they asked it to stop.
    while (this.inFlight.size > 0) {
      await Promise.allSettled([...this.inFlight]);
    }
  }

  private beginWatch(root: RootState): Promise<void> {
    try {
      const watcher = watch(root.path, { recursive: true, persistent: true }, (_event, filename) => {
        // Node delivers a null filename when it knows something changed but not what. There is
        // nothing to scan from that, and re-walking the tree on every such event would turn a
        // busy directory into a scan storm, so it is dropped.
        if (filename === null || filename === undefined) return;
        this.schedule(join(root.path, filename.toString()));
      });

      // Recursive watch can also fail after it starts: an inotify limit reached as the tree
      // grows, or a watched directory removed underneath us. Falling back here is what keeps
      // "the watch died an hour ago" from being indistinguishable from "nothing happened".
      watcher.on("error", (error) => {
        // An event handler cannot await the fallback's seeding pass. It is tracked in-flight
        // regardless, so `close()` still waits for it.
        void this.degrade(root, `native watch failed: ${errorMessage(error)}`);
      });

      root.watcher = watcher;
      root.mode = "watch";
      return Promise.resolve();
    } catch (error) {
      // Recursive watch is not available on every platform, and Node reports that by throwing
      // from watch() rather than by returning a watcher that never fires.
      return this.degrade(root, `recursive watch unavailable: ${errorMessage(error)}`);
    }
  }

  private degrade(root: RootState, reason: string): Promise<void> {
    if (this.closed || root.mode === "rescan") return Promise.resolve();
    if (root.watcher) {
      try {
        root.watcher.close();
      } catch {
        // Already dead; the fallback below is what matters.
      }
      root.watcher = null;
    }
    root.degradedReason = reason;
    return this.beginRescan(root);
  }

  /**
   * Put a root into periodic re-scan and hand back its seeding pass.
   *
   * The promise covers the FIRST pass only, never the interval: it is what a caller waits on
   * to know the root has a snapshot. Every pass, including this one, is tracked in `inFlight`
   * so `close()` still waits for whatever is walking.
   */
  private beginRescan(root: RootState): Promise<void> {
    if (this.closed || root.timer !== undefined) return Promise.resolve();
    root.mode = "rescan";
    const seeding = this.rescanPass(root);
    this.track(seeding);
    root.timer = setInterval(() => {
      this.track(this.rescanPass(root));
    }, this.rescanIntervalMs);
    return seeding;
  }

  /**
   * One bounded walk of a root, scanning whatever changed since the previous pass.
   *
   * The first pass seeds state rather than reporting the entire tree, because a spill watch
   * reports writes it observes and the contents of the tree at start-up are not writes it
   * observed. Files whose mtime is newer than the spill watch's own start are the exception:
   * those did happen on its watch, and reporting them is what closes the gap when a native
   * watch fails part-way through a run and the fallback has no prior snapshot to compare to,
   * or when something writes into the tree while this very pass is walking it.
   */
  private async rescanPass(root: RootState): Promise<void> {
    if (this.closed || root.passInFlight) return;
    root.passInFlight = true;

    try {
      const visited = new Set<string>();
      const queue: string[] = [root.path];
      let budget = this.rescanEntryCap;
      let truncated = false;

      while (queue.length > 0 && !truncated) {
        if (this.closed) return;
        const dir = queue.shift();
        if (dir === undefined) break;

        let entries: Dirent[];
        try {
          entries = await readdir(dir, { withFileTypes: true });
        } catch {
          // A directory the spill watch cannot read is a blind spot, not a non-event.
          this.skipped++;
          continue;
        }

        for (const entry of entries) {
          if (budget <= 0) {
            truncated = true;
            break;
          }
          budget--;

          const absolute = join(dir, entry.name);
          if (isIgnoredPath(absolute, this.ignore)) continue;
          if (entry.isDirectory()) {
            queue.push(absolute);
            continue;
          }
          // Symlinks are not followed: a link pointing outside the watched roots would scan
          // files the operator never asked about, and a link pointing inside them would
          // report the same write twice.
          if (!entry.isFile()) continue;

          visited.add(absolute);

          let stats: Stats;
          try {
            stats = await stat(absolute);
          } catch {
            continue; // Vanished mid-walk. The next pass will not find it either.
          }

          // Identity from metadata, not content: hashing the bytes is exactly the cost the
          // size cap exists to avoid, and would make a 2 GiB artifact more expensive to skip
          // than to scan. Size, mtime and inode change on any ordinary write; the case this
          // misses is a same-size, same-inode rewrite inside one mtime tick.
          const fingerprint = `${stats.size}:${stats.mtimeMs}:${stats.ino}`;
          const previous = root.seen.get(absolute);
          root.seen.set(absolute, fingerprint);

          if (previous === undefined) {
            // Once seeded, first sight is proof enough. Before that, mtime is the only evidence
            // of whether the file predates the spill watch - and it has to be read with the
            // clock lag allowed for. A zero-tolerance comparison files writes that landed just
            // after start-up into `seen` without ever scanning them, and no later pass can
            // recover them: their fingerprint never changes again, so they are invisible for
            // the lifetime of the watch.
            if (root.seeded || stats.mtimeMs >= this.startedAtMs - MTIME_CLOCK_LAG_MS) {
              this.schedule(absolute);
            }
            continue;
          }
          if (previous !== fingerprint) this.schedule(absolute);
        }
      }

      // Only a complete pass may forget files: after a truncated one, "not visited" means
      // "ran out of budget", and dropping those would re-report the whole tail next pass.
      if (!truncated) {
        for (const known of [...root.seen.keys()]) {
          if (!visited.has(known)) root.seen.delete(known);
        }
      }

      root.truncated = truncated;
      root.seeded = true;
    } finally {
      root.passInFlight = false;
    }
  }

  private schedule(target: string): void {
    if (this.closed) return;
    if (isIgnoredPath(target, this.ignore)) return;

    const existing = this.pending.get(target);
    if (existing) clearTimeout(existing);

    this.pending.set(
      target,
      setTimeout(() => {
        this.pending.delete(target);
        this.track(this.inspect(target));
      }, this.debounceMs),
    );
  }

  private track(work: Promise<void>): void {
    this.inFlight.add(work);
    void work.finally(() => {
      this.inFlight.delete(work);
    });
  }

  /**
   * Open, qualify, and scan one file. Never throws.
   *
   * Everything here races the writer: the file can be deleted between the event and the open,
   * replaced by a directory, or made unreadable. A watcher that threw on any of those would
   * take down the spill watch on ordinary workspace churn, so every failure lands in `skipped`
   * where it stays visible without being fatal.
   */
  private async inspect(target: string): Promise<void> {
    if (this.closed) return;

    let handle: FileHandle | null = null;
    try {
      handle = await open(target, "r");
      const stats = await handle.stat();

      if (!stats.isFile()) {
        this.skipped++;
        return;
      }
      if (stats.size > this.maxFileBytes) {
        this.skipped++;
        return;
      }

      const sniffLength = Math.min(BINARY_SNIFF_BYTES, stats.size);
      const buffer = Buffer.allocUnsafe(stats.size);
      let filled = await readFully(handle, buffer, 0, sniffLength);

      // A NUL byte early in the file means the DLP patterns would be matching against decoded
      // garbage: expensive, and prone to producing "secrets" out of compressed noise.
      if (buffer.subarray(0, filled).includes(0)) {
        this.skipped++;
        return;
      }

      if (stats.size > filled) {
        filled += await readFully(handle, buffer, filled, stats.size - filled);
      }

      const result = scanText(buffer.subarray(0, filled).toString("utf8"));
      this.scanned++;

      // PII alone is not a finding. The PII patterns include a plain email address, which
      // appears in most source trees, so reporting on it would bury the credential writes this
      // exists for. PII is carried alongside a secret as context, never as the trigger.
      if (!result.containsSecrets) return;
      if (this.closed) return;

      const finding: SpillFinding = {
        path: target,
        secretTypes: result.secretTypes,
        piiTypes: result.piiTypes,
        at: new Date().toISOString(),
        sizeBytes: stats.size,
      };
      this.findings++;
      this.record(finding);

      try {
        this.onFinding(finding);
      } catch {
        // An operator callback that throws stops that one report, not the spill watch.
      }
    } catch {
      this.skipped++;
    } finally {
      if (handle) {
        try {
          await handle.close();
        } catch {
          // Closing a descriptor whose file vanished is not a failure worth reporting.
        }
      }
    }
  }

  /**
   * Put the finding in the audit chain.
   *
   * The decision recorded is `deny`, which is a verdict and not an intervention: the write
   * already completed and nothing here can undo it. Recording it as `allow` would be worse -
   * it would tell an operator reviewing the chain that AgentWall considered this acceptable.
   *
   * Only metadata is passed. `emit` persists `metadata` and not `payload`, and metadata here
   * carries the path, the type names, and the size. The file's contents never enter this
   * function, so no future change to what `emit` stores can leak them.
   */
  private record(finding: SpillFinding): void {
    const context: AgentContext = {
      agentId: SPILL_WATCH_AGENT_ID,
      plane: "content",
      action: AUDIT_ACTION,
      payload: {},
      metadata: {
        path: finding.path,
        secretTypes: finding.secretTypes.join(","),
        piiTypes: finding.piiTypes.join(","),
        sizeBytes: String(finding.sizeBytes),
        observedAt: finding.at,
      },
      flow: {
        direction: "internal",
        channel: "filesystem",
        target: finding.path,
        labels: finding.piiTypes.length > 0 ? ["secret_material", "pii"] : ["secret_material"],
        crossesBoundary: false,
        highRisk: true,
      },
    };

    const result: PolicyResult = {
      decision: "deny",
      riskLevel: "high",
      matchedRules: [RULE_ID],
      reasons: ["Credential material was written to a watched filesystem path"],
      requiresApproval: false,
      highRiskFlow: true,
      detections: detectionsForRules([RULE_ID]),
    };

    try {
      emit(context, result);
    } catch {
      // Matching the proxy and the MCP wrapper: a storage fault must not stop the observer.
    }
  }
}

export async function startSpillWatch(opts: SpillWatchOptions): Promise<SpillWatchHandle> {
  const watcher = new SpillWatch(opts);
  await watcher.start(opts.paths);
  return watcher;
}
