# Filesystem sentinel

AgentWall watches egress. An agent that harvests a credential and writes it into a file in
its own workspace has not sent anything anywhere yet, so nothing in the network plane sees
it — and that write is the step that happens first. The commit, the upload, or the person who
later pastes the file into a chat all come after. The filesystem sentinel watches the
directories you name and reports credential material appearing in them.

It is an observer, not a gate. By the time an event arrives the bytes are already on disk.
What you get is the write recorded in the audit chain at the moment it happened, instead of
reconstructed later from a git history that may never have been pushed.

It is a library, not a service. Nothing starts it for you: which paths to watch is an
operator decision with real cost, and a default would either watch nothing useful or watch
your home directory.

## Starting it

```ts
import { startFilesystemSentinel } from "@repsecure/agentwall/dist/sentinel/filesystem";

const sentinel = await startFilesystemSentinel({
  paths: ["/srv/agent/workspace", "/srv/agent/scratch"],
  onFinding: (finding) => {
    console.error(`credential written: ${finding.path} (${finding.secretTypes.join(", ")})`);
  },
});

// ... later
await sentinel.close();
```

`startFilesystemSentinel` rejects if a named path does not exist or is not a directory. That
is deliberate: the sentinel's characteristic failure is being pointed at nothing and saying
nothing about it, so a typo fails at start-up rather than at review time.

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `paths` | required | Directories to watch, recursively. |
| `onFinding` | required | Called once per finding. Throwing from it drops that report, not the sentinel. |
| `ignore` | `[]` | Extra ignores, added to the built-in list. See below. |
| `maxFileBytes` | `1048576` | Files larger than this are skipped without being read. |
| `debounceMs` | `100` | Events for one path inside this window collapse into a single scan. |
| `mode` | `"auto"` | `"auto"` prefers a native recursive watch; `"rescan"` polls instead. |
| `rescanIntervalMs` | `2000` | Interval between passes for a root in re-scan mode. |
| `rescanEntryCap` | `5000` | Entries one re-scan pass visits before reporting itself truncated. |

### Ignores

Patterns come in two shapes, distinguished by syntax:

- trailing `/` matches a whole path segment — `.git/` ignores `<root>/pkg/.git/config`
- leading `*.` or `.` matches a filename suffix — `*.png` ignores `logo.png`
- anything else matches a whole segment or an exact filename

The built-in list covers `.git/`, `node_modules/`, `dist/`, `build/`, `coverage/`, `.venv/`,
`__pycache__/`, and the usual binary, archive, media, and font suffixes. Anything you pass in
`ignore` is **added** to that list; the built-ins cannot be switched off, so watching inside
`node_modules/` is not possible today.

Dotfiles are deliberately not ignored as a class. `.env` is the most likely place a harvested
credential lands, and skipping it would remove most of the reason to run this.

Two more things are never scanned: files whose first 8 KiB contain a NUL byte, because
matching credential patterns against decoded binary is wasted work that invents matches out of
compressed noise, and files over `maxFileBytes`, which are identified by size, mtime and inode
rather than by reading them.

## The platform caveat, and what happens instead

`fs.watch` with `{ recursive: true }` is not available on every platform, and it can also die
after it starts — an inotify watch limit reached as the tree grows, or a watched directory
removed underneath it. Both cases are detected, and the affected root switches to a bounded
periodic re-scan: a walk that compares each file's size, mtime and inode against the previous
pass and scans whatever changed.

There is a third case the sentinel cannot detect, and you have to handle yourself. On network
filesystems (NFS, SMB) and some container bind mounts, inotify never sees a write made by the
other side of the mount. The native watch reports nothing, forever, while looking perfectly
healthy. Pass `mode: "rescan"` for roots on those filesystems.

Degradation is visible, because a sentinel that quietly stopped watching is worse than no
sentinel:

```ts
const stats = sentinel.stats();
// { scanned, skipped, findings, degraded, roots: [{ path, mode, degradedReason, truncated }] }
```

- `degraded` is true when any root wanted a native watch and could not have one. Coverage on
  that root is now only as fresh as `rescanIntervalMs`. Alert on this.
- `roots[].mode` is `"watch"` or `"rescan"`. `"rescan"` with a null `degradedReason` is the
  mode you asked for and is not a fault.
- `roots[].truncated` means the last re-scan pass hit `rescanEntryCap` and did not see the
  whole tree. Raise the cap or watch a narrower path.
- `skipped` counts candidates the sentinel declined: too large, binary, vanished before it
  could be read, not a regular file, or unreadable. Unreadable directories add one per pass, so
  a `skipped` that climbs while nothing is being written is a permissions problem rather than
  activity. Ignored paths are not counted — they were never candidates.

## What a finding contains

```ts
{
  path: "/srv/agent/workspace/.env",
  secretTypes: ["aws-access-key"],
  piiTypes: [],
  at: "2026-08-05T14:02:11.104Z",
  sizeBytes: 812
}
```

And what it deliberately does not contain: the file's contents, the matched text, and any
excerpt around it. A sentinel that quoted the credential it found would copy that credential
into the finding, into the audit chain, and into whatever your handler does with it —
recreating the exposure it exists to report, in a file that is often more widely readable than
the original. The type name and the size are enough to find the file and act.

Each finding also joins the audit chain as an event with plane `content`, action
`fs:secret-written`, decision `deny`, and risk `high`, carrying the same fields and nothing
more. The decision is a verdict, not an intervention: the write already completed. Recording
it as an allow would tell an analyst reading the chain that staging a credential on disk was
considered acceptable.

The event's agent id is the fixed string `filesystem-sentinel`, which names the observer and
not the writer — see the limits below.

PII alone is not a finding. The PII patterns include a plain email address, which appears in
most source trees, so reporting on it would bury the credential writes this exists for. PII
found in a file that also carries a secret is reported alongside it as context.

## Limits

- **It sees only the paths you name.** A credential written one directory above a watched root
  is invisible. There is no ambient coverage of the filesystem.
- **It cannot say who wrote the file.** `fs.watch` reports that a path changed; it does not
  report which process changed it. Per-write process attribution is not something the OS
  offers through this interface, so the audit record names the sentinel as the observer and
  makes no claim about the writer. Correlating a finding with a process is your job, using the
  timestamp and whatever process accounting you already run.
- **A write followed by a delete faster than `debounceMs` can be missed.** The scan happens
  after the window closes; if the file is gone by then the attempt is counted in `skipped`
  and no finding is produced. Lowering `debounceMs` narrows the window at the cost of scanning
  the same file several times per save.
- **It reads only the first `maxFileBytes` of a file.** A credential past that offset in a
  file that is otherwise under the cap is not seen, and a file over the cap is not read at all.
- **In re-scan mode, anything changed and changed back between passes is invisible**, as is
  any write to a symlinked file — symlinks are not followed, because a link out of the watched
  tree would scan files you never asked about.
- **It detects what the DLP patterns detect.** A credential in a format those patterns do not
  cover, or one the agent encoded or split across lines before writing, does not produce a
  finding. This raises the cost of staging a credential on disk; it does not make it
  impossible.
- **It is not a gate.** Nothing here prevents the write, and `close()` does not unwrite
  anything. Treat a finding as evidence that an incident is already in progress.
