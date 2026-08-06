# The sandbox

## The perimeter contains packets, not processes

`docs/perimeter.md` describes a control that makes an agent's network traffic unavoidable: the
kernel redirects a uid's outbound TCP into the proxy and drops everything else it sends. That is
a real control and it closes a real hole, but read what it constrains. Packets. A process
contained by the perimeter can still open every file its uid can open.

For most of AgentWall's history that was the right place to stop, because the threat model was an
agent that is trusted at runtime and questionable at policy time: it will do what it was asked,
and the question is whether what it was asked is allowed. Under that model, watching egress and
scanning content is proportionate.

Prompt injection breaks the model. An agent that reads a hostile web page, a hostile issue
comment, or a hostile file in a repository can be redirected mid-task into doing something it was
never asked to do, using credentials it legitimately holds. At that point the agent is untrusted
at RUNTIME, and no amount of policy evaluation helps, because the agent is the thing evaluating.

The sandbox answers that model. It puts a kernel boundary around the process itself, before any
of AgentWall's own code runs. An agent that is talked into reading `~/.ssh/id_ed25519` under this
sandbox does not get a policy verdict, a scanner finding, or a ledger entry. It gets `EACCES`
from the kernel, and there is nothing in the prompt that can change that.

The two controls answer different questions and neither replaces the other:

| | Perimeter | Sandbox |
|---|---|---|
| Unit of containment | A uid's packets | One process and its children |
| Mechanism | nftables redirect and drop | Landlock LSM, seccomp BPF |
| Needs root | Yes, to install | No, ever |
| Stops unobserved egress | Yes | Partly: TCP ports only, ABI 4 and up |
| Stops reading a credential file | No | Yes |
| Survives the agent unsetting an env var | Yes | Yes |

Run both. They compose, with one important exception described under
[Why there is no network namespace here](#why-there-is-no-network-namespace-here).

## What actually enforces this

Two Linux kernel features, in this order.

**Landlock** is a Linux Security Module that lets an unprivileged process permanently restrict
its own filesystem access, and from ABI 4 its own TCP ports. It is inherited across `fork` and
`execve`, it cannot be relaxed once applied, and it needs no root, no capability, and no setuid
binary. It is the boundary.

**seccomp** filters syscalls. AgentWall installs a small denylist of calls no agent runtime
issues, as defence in depth behind Landlock. It is not the boundary, and the reasons are stated
in [The seccomp filter](#the-seccomp-filter).

Both are applied by `agentwall-sandbox`, a small launcher compiled from
`native/agentwall-sandbox.c`. It exists because Landlock and seccomp are per-process credentials
that must be installed after `fork` and before `execve`, and Node offers no pre-exec hook and no
way to issue a raw syscall. The launcher reads a profile, makes four syscalls, and becomes your
command. It is not setuid and never needs to be.

## Requirements, and how to check rather than assume

| Capability | Landlock ABI | Kernel | What you lose without it |
|---|---|---|---|
| Filesystem confinement | 1 | 5.13 | Everything. The sandbox refuses to run. |
| Rename and link across rules (`REFER`) | 2 | 5.19 | Moves between two permitted directories are refused. |
| `TRUNCATE` right | 3 | 6.2 | A file under a read-only path can still be emptied with `truncate(2)`. |
| TCP connect and bind scoping | 4 | 6.7 | `--restrict-net` does nothing. The launcher says so, loudly, on every run. |
| `IOCTL_DEV` right | 5 | 6.10 | Device ioctls on permitted device nodes are unrestricted. |

Do not infer any of this from a version string. A distribution kernel can carry a 6.8 version
number with Landlock compiled in but absent from the boot-time LSM list, and `uname` would report
a capability that is not there. Measure it:

```
$ agentwall sandbox probe
launcher:        /path/to/dist/native/agentwall-sandbox
kernel:          6.8.0-136-generic
landlock ABI:    4
  filesystem:    yes (ABI 1, Linux 5.13)
  truncate:      yes (ABI 3, Linux 6.2)
  tcp ports:     yes (ABI 4, Linux 6.7)
  device ioctl:  no (ABI 5, Linux 6.10)
seccomp filter:  yes
  denied calls:  50
architecture:    supported
```

That ABI number comes from `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`,
which is the kernel answering, not a lookup table. `agentwall sandbox probe --json` gives the
same thing for a deployment check, and exits non-zero when the ABI is 0.

**macOS and Windows are not supported.** Landlock and seccomp are Linux kernel interfaces with no
equivalent. Pipelock reaches macOS through `sandbox-exec` and dynamic SBPL profiles; AgentWall has
nothing there, and `agentwall sandbox` on a non-Linux host refuses rather than degrading to
something that looks similar. That is a real gap, not a design position.

## Building the launcher

```
npm run build:sandbox     # in a checkout
agentwall sandbox build   # anywhere the packaged CLI is installed
```

This is an explicit step rather than a `postinstall` hook. A package that silently invokes a C
compiler during install is a supply-chain smell anywhere, and a poor look in one whose pitch is
that you can audit what it does. It is also the moment you decide to trust a binary that will
hold the filesystem boundary for your agent, and that should be a command you typed.

The build refuses to report success unless the binary it produced answers `--probe`, and it
prints the measured ABI so a kernel that cannot enforce what you expect is visible at build time
rather than at incident time. If you would rather build elsewhere, point
`AGENTWALL_SANDBOX_HELPER` at the result.

Requirements: a C compiler. No libseccomp, no libcap, no Landlock userspace library. The kernel
UAPI constants are reproduced in `native/agentwall-sandbox.c` with the ABI that introduced each
one, so they can be checked against `include/uapi/linux/landlock.h` directly. Adding three
library dependencies to the one component that decides what an agent may read was not a trade
worth making.

### Checking your own build

The launcher is built on your machine, so you can rebuild it and compare rather than trusting a
binary someone handed you:

```
AGENTWALL_SANDBOX_OUT_DIR=/tmp/check bash scripts/build-sandbox-helper.sh
sha256sum /tmp/check/agentwall-sandbox dist/native/agentwall-sandbox
```

Those two digests match. Measured on this project's development host, gcc 13.3.0: two builds a
second apart, into different output paths, produced byte-identical binaries, and `strings` finds
neither a build path nor a date embedded in the result. So a rebuild on the same toolchain is a
real check, and a digest that changes when you did not change the source is worth investigating.

What that check does NOT give you is a digest comparable with anyone else's. The bytes depend on
the compiler and the C library that produced them, so a different gcc version, clang instead of
gcc, or a different distribution will all yield a different and equally correct binary. There is
no published checksum for this launcher to compare against, deliberately: it is not a release
artifact, and a checksum nobody can independently reproduce, sitting in a manifest next to ones
they can, teaches people the manifest means something it does not.

## Using it

```
agentwall sandbox plan --workdir /srv/agent/work            # render, change nothing
agentwall sandbox run  --workdir /srv/agent/work -- node agent.js
```

No root. `plan` is the only subcommand you should skip reading the output of, and only after you
have read it once.

| Flag | Effect |
|---|---|
| `--workdir <path>` | The one directory the command may write to. Defaults to the current directory. |
| `--allow-read <path>` | Widen the profile by one read-only path. Repeatable. |
| `--allow-write <path>` | Widen the profile by one writable path. Repeatable. |
| `--allow-exec <path>` | Widen the profile by one executable path. Repeatable. |
| `--allow-tcp <port>` | Permit outbound TCP to one port. Repeatable. Implies `--restrict-net`. |
| `--allow-bind <port>` | Permit listening on one port. Repeatable. Implies `--restrict-net`. |
| `--restrict-net` | Confine TCP to the permitted ports. Needs ABI 4. |
| `--seccomp off\|errno\|kill` | Syscall filter action. Default `errno`. |
| `--require-abi <n>` | Refuse to run below this Landlock ABI. |
| `--allow-degraded` | Run with no Landlock at all, printing what is unprotected on every run. |

### What the default profile grants

Read and execute on `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, plus the running Node binary when
a version manager has put it somewhere else. Read on `/etc`, `/proc`, and
`/sys/devices/system/cpu`. Read and write on the character devices `/dev/null`, `/dev/zero`,
`/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`. Write on the workdir, and on a private
`.agentwall-tmp` inside it which `run` exports as `TMPDIR`.

That is the entire list. Everything else on the filesystem is refused, and the refusals are not
enumerated anywhere because the profile is an allowlist: your home directory, your SSH keys, your
cloud credentials, your shell history, your browser profile, your other checkouts, `/root`,
`/var`, and `/opt` are all absent by construction rather than by exclusion rule.

Two grants in that list are wider than they look and are called out rather than buried.

**`/proc` is granted whole, not as `/proc/self`.** Node reads `/proc/stat` and `/proc/cpuinfo`
for `os.cpus()`, `/proc/meminfo` for heap sizing, and `/proc/self/maps` during startup; denying
any of them produces failures far from their cause. What this grants beyond `/proc/self` is the
ability to enumerate other processes running as the same uid and read their command lines and
environments. Landlock cannot narrow it: procfs visibility is controlled by the `hidepid=` mount
option, not by path rules. If that matters in your deployment, mount `/proc` with `hidepid=2`, or
give the agent its own uid so there is nothing interesting to enumerate.

**Shared `/tmp` is deliberately not granted.** It is a place to drop an executable and a place to
read what another process left behind. The private temp inside the workdir costs nothing and
removes the category. If something you run insists on `/tmp`, `--allow-write /tmp` is there, and
you should know that you have opened it.

## Proving it, rather than believing it

A test that asserts a rendered profile contains `fs read /etc` proves that a string says so. It
proves nothing about whether any kernel refused anything. The only claims worth making here are
comparisons: the same binary, the same argument, run twice, once bare and once sandboxed.

Here is one you can run yourself in under a minute. Substitute any file you own that the sandbox
does not grant.

```
$ cat ~/.ssh/config | wc -c
954

$ agentwall sandbox run --workdir /tmp/demo -- cat ~/.ssh/config
agentwall-sandbox: landlock abi=4 fs-rules=17 skipped=0 net=off net-rules=0 ioctl-dev=unavailable seccomp=errno filter-insns=119
cat: /home/you/.ssh/config: Permission denied
```

The file has not moved, its permissions have not changed, and your uid can still read it. The
process was refused by the kernel because no rule in its Landlock domain covered that path.

A fuller measurement, from a script that stands in for an injected agent and reports only whether
the kernel let it look:

```
=========== BASELINE: plain node, no sandbox ===========
/home/you/.ssh                     -> LEAKED: 18 entries listed
/home/you/.ssh/config              -> LEAKED: 954 bytes read
/home/you/.gnupg                   -> LEAKED: 6 entries listed
/home/you/.config                  -> LEAKED: 105 entries listed
/etc/shadow                        -> EACCES (open)
/tmp/awdemo/work-file.txt          -> LEAKED: 45 bytes read

=========== SANDBOXED: agentwall sandbox run ===========
/home/you/.ssh                     -> EACCES (scandir)
/home/you/.ssh/config              -> EACCES (open)
/home/you/.gnupg                   -> EACCES (scandir)
/home/you/.config                  -> EACCES (scandir)
/etc/shadow                        -> EACCES (open)
/tmp/awdemo/work-file.txt          -> LEAKED: 45 bytes read
```

`/etc/shadow` is the control: it fails in both runs, because ordinary file permissions already
refused it. The work file is the other control: it succeeds in both, because the profile grants
it. Everything in between changed only because of Landlock.

`tests/sandbox-kernel.test.ts` runs exactly this shape of comparison against the real LSM, and
`tests/sandbox-profile.test.ts` covers the decisions that are text. The kernel suite needs no
privilege, so it is a real enforcement test in CI rather than one that is skipped forever. When a
host cannot support it, it skips by name with the measured reason printed, and a companion test
fails if that reason is missing. A green run on a kernel without Landlock can never be mistaken
for a green run that proved something.

## The seccomp filter

A denylist of 50 syscalls, run with `SECCOMP_RET_ERRNO(EPERM)` by default. `agentwall-sandbox
--list-denied` prints the current list with numbers, and is the authority; this section explains
the shape.

Denied, grouped by what each would buy an attacker who already has code execution as the agent:

- **New namespaces**: `unshare`, `setns`, and `clone` with `CLONE_NEWUSER` filtered out of
  `args[0]`. This is the escape hatch that turns code execution into fresh kernel attack surface,
  and it is also what would let a process leave the perimeter's network namespace.
- **Mount table manipulation**: `mount`, `umount2`, `pivot_root`, `chroot`, `move_mount`,
  `open_tree`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`. Landlock rules are
  pinned to paths, and remounting moves the paths.
- **Path-free filesystem access**: `open_by_handle_at`, `name_to_handle_at`. These reach a file
  without walking a path, and therefore without meeting a Landlock path rule.
- **Kernel code loading and reboot**: `init_module`, `finit_module`, `delete_module`,
  `kexec_load`, `kexec_file_load`, `reboot`.
- **Large kernel attack surfaces**: `bpf`, `perf_event_open`, `userfaultfd`, and the `io_uring`
  family. io_uring matters twice over: it is a recurring source of kernel vulnerabilities, and
  operations submitted through its ring are not seen by a seccomp filter at all. Landlock still
  applies to them, so this is not the boundary, but leaving a seccomp bypass open next to a
  seccomp filter is not a defensible default.
- **Reaching into other processes**: `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`.
- **Host-wide state**: `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`, `sethostname`,
  `setdomainname`, `swapon`, `swapoff`, `acct`, `quotactl`, `syslog`.
- **Kernel keyring**: `add_key`, `request_key`, `keyctl`.
- **Direct hardware and legacy loaders**: `ioperm`, `iopl`, `modify_ldt`, `uselib`.
- **Terminal input injection**: `ioctl` with `TIOCSTI` or `TIOCLINUX`, filtered on `args[1]`. An
  agent sharing a tty with its operator can otherwise push characters into that terminal's input
  queue and type commands as the operator.
- **`clone3`**, returned as `ENOSYS` rather than `EPERM`. Its flags live in a struct that seccomp
  cannot dereference, so `CLONE_NEWUSER` cannot be filtered there and the call is refused whole.
  The errno is load bearing: glibc's `__clone_internal` tries `clone3` first and falls back to
  `clone` only on `ENOSYS`. Return anything else and every `pthread_create` fails, which means
  every Node worker thread fails.

### Why a denylist, stated plainly

An allowlist is the stronger construction and this is not one. The reason is that an allowlist
tight enough to be interesting breaks Node in ways that surface hours later inside libuv, on a
code path nobody exercised, and the operator's fix is to turn the sandbox off. That takes the
Landlock protection with it, and Landlock is the part that actually holds. A smaller control that
stays on is worth more than a larger one that gets disabled.

So the denylist is what it is: every entry is a call no agent runtime makes in normal operation,
chosen so a false positive would be a bug report rather than a mystery. It was tested rather than
reasoned about. Under the full default profile with all 50 denials active, a Node 24 process
passes filesystem reads and writes, `crypto.randomBytes`, `os.cpus`, `child_process`,
`worker_threads`, the libuv thread pool, and TCP listen plus connect. The `clone3` and `io_uring`
denials are the two most likely to bite a future runtime, and they are the two that were verified
by running the runtime rather than by reading its source.

**A denylist can never be complete.** Treat it as defence in depth behind Landlock, never as the
boundary.

`--seccomp kill` swaps `EPERM` for `SECCOMP_RET_KILL_PROCESS`. Louder, and usually the right
instinct for a security control, but a false positive then becomes an agent that dies mid-task
for reasons nobody can reproduce. `EPERM` leaves a failed syscall, an error the runtime can
report, and a process alive to report it.

## Why there is no network namespace here

Pipelock lists network namespace isolation among its Linux controls, and this section explains
why AgentWall deliberately does not have it. This is the most important paragraph in the document
for anyone planning to add one.

**nftables tables are per network namespace.** The perimeter installs its rules in an
`inet agentwall` table in the namespace it runs in. Move the agent into a fresh network
namespace and it is no longer in that namespace, so the uid-based redirect does not apply to it
and neither does the default drop. The perimeter would still report itself installed, because it
is: `nft list table inet agentwall` in the original namespace returns exactly what it did before.
The sandbox would report itself installed, because it is.

The operator would then be running two controls and protected by neither, with two green
statuses. That is strictly worse than running only one, because the second green status is what
convinces them to widen the task.

This repository has already been burned by that exact failure shape once. An earlier perimeter
shipped using `redirect` as an nftables chain name, which nft rejects as a reserved statement
keyword. The ruleset failed to load, nothing downstream noticed, and the only thing that caught
it was handing the file to a real `nft`. A silent composition failure between two controls that
each believe they are working is the same bug wearing different clothes, and it is harder to
catch because both halves are individually correct.

So the network control here is **Landlock TCP port scoping**, which needs ABI 4 and composes
rather than conflicts. It restricts the same process, in the same namespace, using the same
credential-inheritance model as the filesystem rules. The perimeter keeps its redirect, the
sandbox independently refuses connects to ports outside the profile, and the two agree without
either depending on the other being correct:

```
$ agentwall sandbox run --workdir /srv/work --allow-tcp 3128 -- node agent.js
```

Measured on this project's development host, with only port 19731 permitted:

```
                   bare              sandboxed
connect 19731  ->  ECONNREFUSED      ECONNREFUSED   (permitted; nothing listening)
connect 19732  ->  ECONNREFUSED      EACCES         (refused by Landlock)
connect 3128   ->  CONNECTED         EACCES         (refused by Landlock)
bind    19733  ->  BOUND             EACCES         (refused by Landlock)
```

Port 3128 was a live proxy at the time, so the bare run really did connect. The sandboxed run
never reached it.

The seccomp denylist closes the other half of this: because `unshare`, `setns` and
`clone(CLONE_NEWUSER)` are all refused, a process launched under the sandbox cannot create a
network namespace even if something talks it into trying.

### What was measured, and how big the hole actually is

The namespace claim above is not reasoning. It was measured on a disposable lab VM, kernel
`6.8.0-136-generic` with nftables 1.0.9, during the perimeter containment work on branch
`agent/8.7-containment-proof`: inside a fresh namespace, `unshare -Urn -- nft list tables` shows
no `agentwall` table while the host namespace has one. The perimeter's own containment was
confirmed on the same VM across 29 probes with two independent oracles, uid-scoped nft counters
and tcpdump on the wire, agreeing on every one.

Three qualifiers keep that from being overstated, because the hole is real but smaller than the
mechanism suggests.

**A bare network namespace is self-denial, not escape.** A fresh netns has a down `lo`, no route
and no peer interface, so `connect()` returns `ENETUNREACH`. It becomes an actual way out only
with a userspace connectivity helper such as slirp4netns, pasta, passt or `lxc-user-nic`, or a
writable container socket. The danger is not that the agent gains the network, it is that it
leaves the table while every status stays green.

**A user namespace alone does NOT break the perimeter.** This was the good news from the same
measurement. With `kernel.apparmor_restrict_unprivileged_userns` lowered to 0, `unshare -Ur`
gives uid 0 inside the namespace and the perimeter still holds: TCP to an arbitrary address and
port is dropped, TCP to 443 is still redirected to the proxy. `meta skuid` matches the real kuid
in the initial user namespace, not the namespace-local one. The network namespace is the part
that matters; the user namespace is only the usual way an unprivileged process gets one.

**On a stock Ubuntu 24.04 host the agent cannot get there today.** Measured on this project's
development host: `kernel.apparmor_restrict_unprivileged_userns = 1`, and `unshare -Urn` fails
with `write failed /proc/self/uid_map: Operation not permitted`. Worth noticing precisely what
that means, because it is the argument for the seccomp denial rather than against it: the raw
`unshare(CLONE_NEWUSER)` syscall still SUCCEEDS on that host (measured, `rc=0`), and only the
later `uid_map` write is refused. The AppArmor restriction blocks the useful outcome; the seccomp
denial blocks the syscall. So the correct claim is that this closes a real hole that is currently
unreachable on a default Ubuntu install, not that the perimeter leaks today. An operator who
lowers that sysctl, or runs a distribution that does not ship the restriction, is relying on the
seccomp filter instead.

If a network namespace is ever added, it has to own the perimeter's rules too, install them
inside the new namespace, and make the perimeter's `status` and `verify` report on the namespace
the agent is actually in. Anything short of that reintroduces the two-green-statuses failure.

## Degradation

An operator who believes a process is confined and is wrong is worse off than one who knows it is
not. The first has already widened what they will let the agent attempt, and an unconfined run
produces no signal anywhere: the work completes, the ledger fills with whatever happened to be
observed, and the unprotected part is invisible.

So there is no silent no-op anywhere in this feature.

| Condition | What happens |
|---|---|
| Launcher not built | `run` refuses, lists every path it searched, and prints the build command. |
| Kernel has no Landlock | `run` refuses. `--allow-degraded` overrides, and prints `DEGRADED: no Landlock on this kernel. The filesystem is NOT confined.` on every single run. |
| Kernel ABI below `--require-abi` | `run` refuses, naming both numbers. `--allow-degraded` does NOT override this: it answers "is no Landlock acceptable", and `--require-abi` is a different question you already answered. |
| `--restrict-net` below ABI 4 | Runs, prints `DEGRADED`, and says how many net rules were not installed. Filesystem confinement is unaffected. |
| ABI below 3 | Runs, prints `DEGRADED` about the missing `TRUNCATE` right. |
| A profile path does not exist | Skipped with a per-path warning naming the path and the errno. Refusing would make the sandbox unusable across distributions; skipping quietly would turn a typo in a write path into an agent that cannot work for no visible reason. |
| Profile arrives truncated | Refused. A truncated profile can drop the trailing `seccomp` line, which would silently produce a weaker sandbox than was asked for, so the launcher requires a terminating `end` line. |
| seccomp requested, kernel has no filter mode | Refused, with `--seccomp off` named as the way through. |

Every run that starts a command also prints one summary line to stderr naming what was installed:

```
agentwall-sandbox: landlock abi=4 fs-rules=17 skipped=0 net=tcp net-rules=2 ioctl-dev=unavailable seccomp=errno filter-insns=119
```

The process also gets `AGENTWALL_SANDBOX` in its environment, holding the measured ABI and the
seccomp mode, so a harness can record what it was actually running under rather than what it
intended to run under.

## What this does not confine

Read this section as carefully as the rest. Everything below is outside the boundary.

**Anything not on this host.** The sandbox restricts one process tree on one machine. Credentials
the agent legitimately holds in its environment still work against remote services, and the
remote service has no idea a sandbox exists. That is what the proxy, the policy engine and the
audit chain are for.

**Whatever you granted.** `--allow-read /home/you` produces a sandbox that permits reading
`/home/you`. The default profile is the security posture; every flag that widens it is a decision
you are making. `agentwall sandbox plan` prints the whole profile precisely so this is inspectable
before you rely on it.

**UDP, ICMP, raw sockets, and unix domain sockets.** Landlock's network support covers TCP
`connect` and `bind` only. The perimeter's default drop does cover UDP, which is one of the
concrete reasons to run both.

**DNS, when the perimeter has been given a resolver.** This one is measured, not theoretical, and
it is the sharpest edge in the composed posture. `agentwall perimeter --dns-resolver <ip>` opens
port 53 to that resolver for the agent uid. On the lab VM used for the perimeter containment
work, an attacker-chosen payload was pushed off the host inside a DNS QNAME and 142 bytes came
back, and TCP/53 to the same resolver carried a full bidirectional stream. Neither control closes
it. Landlock cannot: port 53 has to be permitted for DNS to work at all, so scoping it out only
turns the hole into a broken resolver. The sandbox does close the TCP half if you simply never
pass `--allow-tcp 53`, which leaves the UDP half open and unobserved.

The posture that closes it is the perimeter's own default: name no resolver. The agent then gets
no DNS, which is correct under the perimeter model because the agent does not need to resolve
anything. Its TCP is redirected to the proxy, and the proxy does the resolving. Name a resolver
only when you have decided that an exfiltration channel neither control can see is an acceptable
cost, and know that you decided it.

**Abstract unix sockets and signals to same-uid processes.** Landlock gained scoping for these in
ABI 6 (Linux 6.12). Below that, a sandboxed process can still connect to an abstract unix socket
and signal other processes running as its uid. If that matters, give the agent its own uid.

**`/proc` enumeration of same-uid processes**, as described above.

**Device ioctls on granted device nodes**, below ABI 5.

**Truncation of files under read-only paths**, below ABI 3.

**Syscalls not on the denylist.** A denylist is not an allowlist, and this one is 50 entries
against several hundred syscalls.

**A kernel vulnerability.** Landlock and seccomp are enforced by the kernel; a bug in the kernel
is a bug in the boundary. Both features reduce the reachable attack surface substantially, which
is part of why `bpf`, `perf_event_open`, `userfaultfd` and `io_uring` are denied, but neither is a
hypervisor. If your threat model needs one, use one.

**Root.** Nothing here constrains root, and nothing here should be run as root. Landlock does
apply to a root process that installs it, but root can do a great deal that never touches a
Landlock hook.

**Processes already running.** This applies at `execve`. It does not reach back to something that
started earlier.

## Composing with the perimeter

The intended posture on a Linux host, in order:

```
PERIM="--agent-uid 61001 --proxy-uid 61002 --proxy-port 8080"
agentwall perimeter plan $PERIM | sudo nft -f -
agentwall perimeter verify $PERIM
sudo agentwall perimeter run $PERIM -- \
  agentwall sandbox run --workdir /srv/agent/work --allow-tcp 80 --allow-tcp 443 -- node agent.js
```

The pipe form rather than `agentwall perimeter install` is deliberate. The containment work on
branch `agent/8.7-containment-proof` found that `install` never worked on any host: it fed the
ruleset to nft through `spawnSync("nft", ["-f", "-"], { input })`, libuv backs child stdio with a
unix socket, and nft stats `/dev/stdin`, finds neither a regular file nor a fifo, and refuses the
transaction with `Not a regular file: "/dev/stdin"`. The documented pipe recipe always worked,
which is exactly why the defect stayed hidden. Use the pipe until that fix has landed.

`perimeter run` drops to the agent uid, then `sandbox run` applies Landlock and seccomp to that
already-dropped process. The order matters: Landlock is inherited across `execve` and cannot be
relaxed, so applying it before the uid change would be fine too, but dropping privilege first
means the sandbox is applied by an unprivileged process, which is the smaller thing to trust.

The profile is handed to the launcher over a pipe on file descriptor 3 rather than through a
file, for two reasons. A temporary file is readable by anything else running as the same uid
between the write and the exec. And in the composed form above the writer is root while the
reader has already dropped to the agent uid, so a root-owned temporary file would be unreadable
at exactly the moment it was needed.

**Stated limit on this section.** Everything above about the sandbox half has been measured. The
composed invocation has not: installing the perimeter needs root and writes host firewall rules,
so it was not exercised on the machine this feature was built on. What is known is that the two
controls use independent kernel mechanisms in the same network namespace, that `perimeter run`
drops privilege with `spawnSync` and an argument array before exec'ing whatever follows `--`, and
that the profile-over-fd-3 design exists specifically to survive that uid change. What has not
been observed is the whole chain running end to end. Treat the ordering above as reasoned rather
than measured until you have run `agentwall perimeter verify` and the sandbox's own summary line
on the same host and seen both.

### The published container image does not carry the launcher

That is a decision rather than an omission. The image built by this repository's `Dockerfile` is
the AgentWall control plane: its entrypoint is the server, and the agent it protects runs
somewhere else and points at the proxy. The sandbox wraps the AGENT process, so the launcher
belongs wherever the agent runs, not in the control plane's image. Building it there would mean
adding a C compiler to the build stage for a command that image never issues.

If your agent does run inside a container, build the launcher in that container's image with
`npm run build:sandbox`, or build it once elsewhere and mount it with `AGENTWALL_SANDBOX_HELPER`
pointed at the mount. Note that a container is not a substitute: the default container runtime
profile still lets a process inside it read every file in its own filesystem, which is the exact
thing Landlock is here to stop.

## Related

- [The perimeter](perimeter.md): containing a uid's packets with nftables.
- [Threat model](threat-model.md): what AgentWall defends against and what it does not.
- [Spill watch](spill-watch.md): detecting credentials written to disk. The sentinel detects;
  the sandbox prevents. They are complementary, and a finding from spill watch inside a sandboxed
  workdir is a much smaller blast radius than the same finding outside one.
