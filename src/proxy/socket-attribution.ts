import { readdirSync, readFileSync, readlinkSync } from "fs";

/**
 * Map a local TCP socket back to the process, and the uid, that opened it.
 *
 * This is what lets the ledger name the process that actually made the call, rather than
 * "unknown", WITHOUT harness cooperation, which is the point of a harness-agnostic
 * design. /proc/net/tcp turns a local port into a socket inode; /proc/<pid>/fd finds the
 * owner. Linux-specific and best-effort by design: attribution failing must never break
 * egress, and it must never be read as evidence of anything either. A caller that treats a
 * null pid as "not the process I expected" turns a /proc race into a false accusation.
 *
 * The uid comes out of the SAME /proc/net/tcp line as the inode (column 7), so it costs
 * nothing beyond a second array index and, unlike the pid, survives the case where the fd
 * walk finds nothing. That difference matters for identity: a uid is a kernel fact a process
 * cannot change without privilege, whereas `comm` is a 16-byte label the process writes
 * itself. Measured on this host: Node rewrites its own comm to "MainThread" at startup, and
 * `process.title = "aw-scraper"` sets it to anything the process likes. src/fleet/registry.ts
 * ranks the signals accordingly.
 *
 * Shared by the forward proxy, which resolves the client end of every proxied connection,
 * and by `verify-capture`, which resolves the far end of a canary hit to find out whether
 * AgentWall or the agent itself opened it. Two copies of a /proc parser would be free to
 * drift, and the two callers would then disagree about which process made one connection.
 */

/**
 * Attribution cost control.
 *
 * Resolving a connection to a process is two steps: read /proc/net/tcp to map the
 * client port to a socket inode (cheap), then find which process holds that inode
 * (expensive: walking every /proc/<pid>/fd measured ~44ms, scaling with total FDs).
 *
 * Caching the inode is useless: every connection has a fresh one, so it never hits.
 * What repeats is the PROCESS. An agent fleet is a handful of long-lived clients
 * opening many connections, so recently-seen pids are checked first; only a
 * genuinely new process pays the full walk.
 *
 * The walk is SYNCHRONOUS and blocks the event loop for its duration (~44ms cold,
 * ~1.6ms warm). An async-fs version was tried and reverted: per-fd awaits made it
 * roughly 4x worse (0.95s vs 0.38s per request) because microtask overhead dominates
 * a walk of thousands of descriptors. The hot-pid cache is what keeps the blocking
 * rare rather than async I/O, so a burst of connections from NEW processes will
 * serialise. That is a known cost, not an oversight.
 */
const HOT_PID_MAX = 16;
const hotPids: number[] = [];

/** Everything /proc can say about one socket's owner. Nulls mean "unknown", never "no". */
export interface SocketOwner {
  pid: number | null;
  comm: string | null;
  uid: number | null;
}

/** /proc/net/tcp state column for a listening socket. */
const TCP_LISTEN = "0A";

function unknownOwner(): SocketOwner {
  return { pid: null, comm: null, uid: null };
}

function touchHotPid(pid: number): void {
  const i = hotPids.indexOf(pid);
  if (i !== -1) hotPids.splice(i, 1);
  hotPids.unshift(pid);
  if (hotPids.length > HOT_PID_MAX) hotPids.length = HOT_PID_MAX;
}

/**
 * The kernel's name for a process, or null when it is gone or unreadable.
 *
 * Exported so a caller that has a pid from somewhere other than `attributeSocket` can name it
 * without a second copy of this read. Remember what comm is worth: the process wrote it itself.
 */
export function processComm(pid: number): string | null {
  try {
    return readFileSync(`/proc/${pid}/comm`, "utf8").trim();
  } catch {
    return null;
  }
}

/** Does this pid hold the socket? One readdir of a single process. */
function pidHoldsInode(pid: number, target: string): boolean {
  let fds: string[];
  try {
    fds = readdirSync(`/proc/${pid}/fd`);
  } catch {
    return false;
  }
  for (const fd of fds) {
    try {
      if (readlinkSync(`/proc/${pid}/fd/${fd}`) === target) return true;
    } catch {
      /* fd vanished mid-scan */
    }
  }
  return false;
}

/** Hex port as /proc/net/tcp writes it, e.g. 3128 becomes "0C38". */
function hexPort(port: number): string {
  return port.toString(16).toUpperCase().padStart(4, "0");
}

/** Walk every /proc/<pid>/fd, hot pids first, for the holder of one socket inode. */
function pidHoldingInode(inode: string): number | null {
  const target = `socket:[${inode}]`;

  for (const pid of [...hotPids]) {
    if (pidHoldsInode(pid, target)) {
      touchHotPid(pid);
      return pid;
    }
  }

  let entries: string[];
  try {
    entries = readdirSync("/proc");
  } catch {
    return null;
  }
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    if (pidHoldsInode(pid, target)) {
      touchHotPid(pid);
      return pid;
    }
  }
  return null;
}

/** Read both TCP tables once, handing each row's columns to a visitor. */
function eachTcpRow(visit: (cols: string[]) => void): void {
  // Both tables, all the way through. Stopping at the first hit is what let a listening
  // socket stand in for a connection, and a v4 row and a v6 row that both match are two
  // candidates, not one answer.
  for (const table of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    let content: string;
    try {
      content = readFileSync(table, "utf8");
    } catch {
      continue;
    }
    for (const line of content.split("\n").slice(1)) {
      const cols = line.trim().split(/\s+/);
      if (cols.length < 10) continue;
      visit(cols);
    }
  }
}

/**
 * Resolve one connection to the process, and the uid, that opened it.
 *
 * `localPort` and `remotePort` are that socket's own two ends, as the kernel records them on
 * its /proc row. A server identifying the peer that connected to it therefore passes
 * `(socket.remotePort, socket.localPort)`: the peer's local port is this server's remote one.
 *
 * Both ends are required, and the row has to match both. A match on the client's port alone
 * names the wrong process, reliably rather than occasionally: /proc/net/tcp lists LISTENING
 * sockets before established ones, so any process listening on an address whose port happens
 * to equal this client's ephemeral source port is found first, and the ledger attributes the
 * call to it. Ephemeral ports and service ports come out of the same 16 bits, so the collision
 * arrives without anyone arranging it. A wrong pid is worse than no pid: an operator sees a
 * named process that never made the call, and the one that did is invisible.
 *
 * Where the evidence is ambiguous, nothing is named. Two rows can share both ports only if
 * they differ in an address, and addresses are not compared here, so a second candidate means
 * this function cannot tell which socket it was asked about. Declining is the honest answer and
 * it costs nothing: attribution is best-effort and the connection proceeds either way. That
 * covers the uid as well: it is read off the same row as the inode, so an ambiguous row makes
 * the owner as unknowable as the process.
 */
export function attributeSocket(localPort: number, remotePort: number): SocketOwner {
  if (!localPort || !remotePort) return unknownOwner();
  try {
    const wantLocal = `:${hexPort(localPort)}`;
    const wantRemote = `:${hexPort(remotePort)}`;
    // Dynamic membership, and the count is the decision, so a keyed collection rather than a
    // lookup table. Inode to uid, because both come off the same row and the uid outlives the
    // fd walk: a socket whose owning process cannot be found still has an owning user.
    const candidates = new Map<string, number | null>();

    eachTcpRow((cols) => {
      if (cols[1].endsWith(wantLocal) && cols[2].endsWith(wantRemote)) {
        // Column 7 is the socket owner's uid. Parsed defensively rather than trusted: a
        // malformed row must degrade to "unknown", never to uid 0, which would hand a
        // root-scoped agent identity to whoever produced the bad line.
        const parsed = Number(cols[7]);
        candidates.set(cols[9], Number.isInteger(parsed) && parsed >= 0 ? parsed : null);
      }
    });

    if (candidates.size !== 1) return unknownOwner();
    const [[inode, uid]] = candidates;

    const pid = pidHoldingInode(inode);
    return pid === null ? { pid: null, comm: null, uid } : { pid, comm: processComm(pid), uid };
  } catch {
    return unknownOwner();
  }
}

/**
 * Every pid holding a LISTEN socket on one local port.
 *
 * A set rather than one answer because a service that binds 0.0.0.0 and :: has two rows, a
 * pre-forking server has one row per worker, and SO_REUSEPORT allows several unrelated
 * processes on one port. Returning the first would let `verify-capture` compare a canary's
 * peer against the wrong half of a dual-stack bind and call a captured agent a bypass.
 *
 * Empty means "could not tell", not "nothing is listening": the fd walk needs read access to
 * the target's /proc/<pid>/fd, which a different uid does not have. Callers must treat an
 * empty result as unavailable evidence.
 */
export function listenerPids(port: number): Set<number> {
  const pids = new Set<number>();
  if (!port) return pids;
  try {
    const wantLocal = `:${hexPort(port)}`;
    const inodes = new Set<string>();
    eachTcpRow((cols) => {
      if (cols[3] === TCP_LISTEN && cols[1].endsWith(wantLocal)) inodes.add(cols[9]);
    });
    for (const inode of inodes) {
      const pid = pidHoldingInode(inode);
      if (pid !== null) pids.add(pid);
    }
  } catch {
    /* best effort, same contract as attributeSocket */
  }
  return pids;
}
