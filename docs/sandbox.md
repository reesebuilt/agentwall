# The sandbox

## Purpose

The AgentWall sandbox confines one Linux process and its children. The Linux kernel enforces the boundary before AgentWall starts the command.

The sandbox uses Landlock for filesystem access and TCP ports. It uses seccomp as a second control for selected system calls.

The perimeter and sandbox protect different resources.

| Control | Scope | Limit |
| --- | --- | --- |
| Perimeter | One uid's packets | It does not restrict files. It needs root to install nftables rules. |
| Sandbox | One process tree | It does not provide complete network isolation. It never needs root. |

Run both controls when the host supports them. Do not treat either control as a replacement for the other.

## Operator workflow

1. Build the launcher.
2. Probe the host kernel.
3. Review the sandbox plan.
4. Run the command.
5. Read the summary line for each run.

The sandbox refuses unsupported filesystem confinement by default. `--allow-degraded` is the only explicit exception for a kernel without Landlock.

## Kernel requirements

The sandbox supports Linux only. `agentwall sandbox` refuses to run on macOS and Windows.

Do not use the kernel version alone to judge support. A distribution can compile Landlock but omit it from the active LSM list.

| Capability | Landlock ABI | Kernel | Behavior without it |
| --- | --- | --- | --- |
| Filesystem confinement | 1 | 5.13 | The sandbox refuses to run. |
| Rename and link across rules with `REFER` | 2 | 5.19 | The kernel refuses moves between two permitted directories. |
| `TRUNCATE` right | 3 | 6.2 | A process can empty a file under a read-only path with `truncate(2)`. |
| TCP connect and bind scoping | 4 | 6.7 | `--restrict-net` installs no network rule and reports degraded operation. |
| `IOCTL_DEV` right | 5 | 6.10 | Device ioctls remain unrestricted on permitted device nodes. |
| Abstract Unix socket and signal scoping | 6 | 6.12 | Same-uid abstract sockets and signals remain reachable. |

Probe the actual kernel:

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

The launcher gets the ABI from `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`. The kernel returns this value.

`agentwall sandbox probe --json` returns the same data for a deployment check. It exits with a nonzero status when the ABI is `0`.

## Build the launcher

Build the launcher from a checkout or an installed package:

```
npm run build:sandbox     # in a checkout
agentwall sandbox build   # anywhere the packaged CLI is installed
```

The build needs a C compiler. It does not need libseccomp, libcap, or a Landlock userspace library.

The source is `native/agentwall-sandbox.c`. It contains the kernel UAPI constants and the ABI that introduced each constant.

The build checks the launcher with `--probe`. It refuses to report success when the probe fails.

Set `AGENTWALL_SANDBOX_HELPER` to use a launcher from another location.

### Compare a local rebuild

Build into a separate output directory:

```
AGENTWALL_SANDBOX_OUT_DIR=/tmp/check bash scripts/build-sandbox-helper.sh
sha256sum /tmp/check/agentwall-sandbox dist/native/agentwall-sandbox
```

The same source and toolchain can produce matching digests. A compiler, C library, or distribution change can produce different valid bytes.

The project does not publish one launcher checksum. The launcher is not a release artifact that every toolchain can reproduce byte for byte.

## Plan and run

Review the profile before the first run:

```
agentwall sandbox plan --workdir /srv/agent/work            # render, change nothing
agentwall sandbox run  --workdir /srv/agent/work -- node agent.js
```

Do not run the launcher as root.

| Option | Effect | Limit |
| --- | --- | --- |
| `--workdir <path>` | Grants write access to one work directory. | It defaults to the current directory. |
| `--allow-read <path>` | Adds one read-only path. | Repeat the option for more paths. Each path widens access. |
| `--allow-write <path>` | Adds one writable path. | Repeat the option for more paths. Each path widens access. |
| `--allow-exec <path>` | Adds one executable path. | Repeat the option for more paths. Each path widens access. |
| `--allow-tcp <port>` | Permits outbound TCP to one port. | Repeat the option for more ports. It implies `--restrict-net`. |
| `--allow-bind <port>` | Permits TCP listen on one port. | Repeat the option for more ports. It implies `--restrict-net`. |
| `--restrict-net` | Confines TCP connect and bind to permitted ports. | It needs Landlock ABI 4. It does not cover UDP. |
| `--seccomp off\|errno\|kill` | Selects the system call filter action. | The default is `errno`. `off` removes this defense layer. |
| `--require-abi <n>` | Refuses a kernel below the specified ABI. | `--allow-degraded` does not override this value. |
| `--allow-degraded` | Permits a run without Landlock. | It prints the missing protection for each run. It does not satisfy `--require-abi`. |

## Default filesystem profile

The default profile grants read and execute access to these paths:

- `/usr`
- `/bin`
- `/sbin`
- `/lib`
- `/lib64`
- The active Node binary when a version manager stores it elsewhere

It grants read access to these paths:

- `/etc`
- `/proc`
- `/sys/devices/system/cpu`

It grants read and write access to these character devices:

- `/dev/null`
- `/dev/zero`
- `/dev/full`
- `/dev/random`
- `/dev/urandom`
- `/dev/tty`

The profile grants write access to the work directory. It creates `.agentwall-tmp` inside that directory and exports it as `TMPDIR`.

The allowlist grants nothing else. It does not grant home directories, SSH keys, cloud credentials, browser profiles, other checkouts, `/root`, `/var`, or `/opt`.

### `/proc` limit

The profile grants all of `/proc`. Node needs `/proc/stat`, `/proc/cpuinfo`, `/proc/meminfo`, and `/proc/self/maps`.

This grant can expose command lines and environments for other processes with the same uid. Landlock cannot narrow procfs visibility to `/proc/self`.

Mount `/proc` with `hidepid=2` when the host supports this setting. Give the agent a separate uid when same-uid process data matters.

### Temporary file limit

The profile does not grant shared `/tmp`. Shared `/tmp` can expose another process's files and accept new executables.

Use the private `TMPDIR` in the work directory. `--allow-write /tmp` opens the shared directory to the process tree.

## Degraded behavior

The sandbox never changes to a silent no-op.

| Condition | Result |
| --- | --- |
| Launcher not built | `run` refuses. It lists each searched path and prints the build command. |
| Kernel has no Landlock | `run` refuses. `--allow-degraded` permits the run and prints `DEGRADED: no Landlock on this kernel. The filesystem is NOT confined.` each time. |
| Kernel ABI below `--require-abi` | `run` refuses and reports both ABI values. `--allow-degraded` does not override this result. |
| `--restrict-net` below ABI 4 | The command runs. The launcher prints `DEGRADED` and the number of skipped network rules. Filesystem confinement remains active. |
| ABI below 3 | The command runs. The launcher reports the missing `TRUNCATE` right. |
| A profile path does not exist | The launcher skips that path. It prints the path and errno. |
| Profile input is truncated | The launcher refuses the profile because it lacks the terminating `end` line. |
| seccomp filter mode is unavailable | The launcher refuses a requested filter. It names `--seccomp off` as the explicit alternative. |

A skipped path can remove access that the command needs. Read every skipped-path warning.

Each started command produces one summary line on stderr:

```
agentwall-sandbox: landlock abi=4 fs-rules=17 skipped=0 net=tcp net-rules=2 ioctl-dev=unavailable seccomp=errno filter-insns=119
```

The command also receives `AGENTWALL_SANDBOX`. This environment variable contains the measured ABI and seccomp mode.

Record the measured value. Do not record only the requested profile.

## Enforcement design

`agentwall-sandbox` applies Landlock and seccomp after `fork` and before `execve`. The launcher then becomes the requested command.

Landlock restrictions pass to child processes through `fork` and `execve`. The process cannot relax them after installation.

The launcher is not setuid. It uses no capability and needs no root access.

### Landlock boundary

Landlock controls filesystem access. ABI 4 also controls TCP connect and bind ports.

A missing allowlist rule causes the kernel to return `EACCES`. AgentWall does not need a policy decision for that refusal.

Landlock does not protect a remote service from a credential that the process already holds. Use the proxy, policy engine, and audit chain for remote actions.

### seccomp defense layer

The default seccomp mode denies 50 system calls with `SECCOMP_RET_ERRNO(EPERM)`. Run `agentwall-sandbox --list-denied` to get the authoritative current list.

The denied calls cover these groups:

- New namespaces: `unshare`, `setns`, and `clone` with `CLONE_NEWUSER`.
- Mount changes: `mount`, `umount2`, `pivot_root`, `chroot`, `move_mount`, `open_tree`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, and `mount_setattr`.
- Path-free file access: `open_by_handle_at` and `name_to_handle_at`.
- Kernel code and reboot: `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, and `reboot`.
- Large kernel surfaces: `bpf`, `perf_event_open`, `userfaultfd`, and the `io_uring` family.
- Other process access: `ptrace`, `process_vm_readv`, `process_vm_writev`, and `kcmp`.
- Host-wide state: `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`, `sethostname`, `setdomainname`, `swapon`, `swapoff`, `acct`, `quotactl`, and `syslog`.
- Kernel keyring: `add_key`, `request_key`, and `keyctl`.
- Hardware and legacy loaders: `ioperm`, `iopl`, `modify_ldt`, and `uselib`.
- Terminal input injection: `ioctl` with `TIOCSTI` or `TIOCLINUX` in `args[1]`.
- `clone3`: the filter returns `ENOSYS` for the complete call.

The `clone3` flags are in a structure that seccomp cannot inspect. The `ENOSYS` result lets glibc fall back to `clone` for threads.

The filter uses a denylist because a strict allowlist can break Node on delayed libuv paths. The default denylist supports common Node runtime operations.

These operations include filesystem access, `crypto.randomBytes`, `os.cpus`, child processes, worker threads, the libuv thread pool, and TCP connect and listen.

A denylist cannot cover every system call. Treat seccomp as defense in depth behind Landlock.

`--seccomp kill` uses `SECCOMP_RET_KILL_PROCESS` instead of `EPERM`. A false positive then stops the complete process without a recoverable runtime error.

## Network behavior

Landlock ABI 4 scopes TCP ports. It does not scope destination addresses.

Permit one proxy port when the process must use an AgentWall proxy:

```
$ agentwall sandbox run --workdir /srv/work --allow-tcp 3128 -- node agent.js
```

A measured port check produced this result:

```
                   bare              sandboxed
connect 19731  ->  ECONNREFUSED      ECONNREFUSED   (permitted; nothing listening)
connect 19732  ->  ECONNREFUSED      EACCES         (refused by Landlock)
connect 3128   ->  CONNECTED         EACCES         (refused by Landlock)
bind    19733  ->  BOUND             EACCES         (refused by Landlock)
```

The sandbox refuses TCP connect and bind outside the allowed ports. It does not redirect traffic or inspect content.

### Network namespace boundary

The sandbox does not create a network namespace. nftables tables belong to one network namespace.

A new network namespace would leave the perimeter's `inet agentwall` table. Both controls could then report success in different namespaces.

The seccomp filter denies `unshare`, `setns`, and `clone(CLONE_NEWUSER)`. A sandboxed process therefore cannot create its own network namespace through those calls.

A new bare network namespace has no route by default. A connectivity helper or writable container socket could add a path later.

A user namespace alone does not bypass the uid-based perimeter. The network namespace creates the composition risk.

A future network namespace feature must install perimeter rules inside that namespace. Its `status` and `verify` results must inspect the agent's namespace.

### DNS limits

The sandbox is not a DNS control. Landlock network rules cover TCP only.

The perimeter default blocks port 53 with other non-permitted traffic. Name lookup then fails for clients that need DNS.

`agentwall perimeter --dns-resolver <ip>` permits port 53 to one resolver. This creates a DNS data channel that neither control inspects.

An attacker can place data in DNS queries. TCP port 53 can also carry a bidirectional stream when the sandbox permits that port.

Do not pass `--allow-tcp 53` unless the command needs TCP DNS. This does not close the UDP DNS channel.

A per-application address override can avoid client DNS when that client supports it. The proxy still uses the hostname from SNI for its upstream connection.

Do not use a host-wide `/etc/hosts` false address for this purpose. The local proxy reads the same file and can connect to the false address.

The sandbox grants read access to `/etc`, so static host entries can resolve. It does not grant `/run` by default.

On a systemd-resolved host, `/etc/resolv.conf` can point into `/run/systemd/resolve`. The default profile can block that resolved path.

`--allow-read /run` can restore access on that layout. Treat this result as a distribution property, not as a DNS security control.

When the perimeter uses an external resolver, configure the agent's `resolv.conf` for that resolver. A systemd-resolved symlink can restore its managed content.

The proxy evaluates policy against the recovered hostname. It does not evaluate policy against the address that the agent dialed.

The sandbox has no mount namespace. It cannot give the agent a private `/etc/hosts` while the local proxy keeps the host file.

## Verify kernel enforcement

Compare the same file access without and with the sandbox:

```
$ cat ~/.ssh/config | wc -c
954

$ agentwall sandbox run --workdir /tmp/demo -- cat ~/.ssh/config
agentwall-sandbox: landlock abi=4 fs-rules=17 skipped=0 net=off net-rules=0 ioctl-dev=unavailable seccomp=errno filter-insns=119
cat: /home/you/.ssh/config: Permission denied
```

The uid can still read the file outside the sandbox. The Landlock domain returns `EACCES` inside the sandbox.

A broader comparison produces this shape:

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

`/etc/shadow` fails in both runs because normal file permissions deny it. The work file succeeds because the sandbox grants it.

`tests/sandbox-kernel.test.ts` compares real kernel behavior. It needs no privilege.

`tests/sandbox-profile.test.ts` checks profile decisions. A kernel suite skip includes the measured reason.

## Security limits

Keep each limit with the related control decision.

| Limit | Effect | Mitigation |
| --- | --- | --- |
| Remote services | Existing environment credentials still work remotely. | Use proxy policy and audit controls. Remove unnecessary credentials. |
| Granted paths | A broad `--allow-read` or `--allow-write` option creates broad access. | Review `agentwall sandbox plan` before the run. |
| UDP, ICMP, raw sockets, and Unix sockets | Landlock TCP rules do not cover them. | Use the perimeter for UDP egress. Use a separate uid for same-uid local resources. |
| Same-uid processes below ABI 6 | Abstract Unix sockets and process signals remain reachable. | Give the agent its own uid. |
| `/proc` | The process can enumerate same-uid process data. | Use `hidepid=2` or a separate uid. |
| Device ioctls below ABI 5 | Permitted device nodes allow unrestricted ioctls. | Do not grant unnecessary devices. Require ABI 5 when needed. |
| Read-only files below ABI 3 | `truncate(2)` can empty a file. | Require ABI 3 or later. |
| seccomp denylist | Unlisted system calls remain available. | Treat Landlock as the main boundary. |
| Kernel defects | A kernel vulnerability can affect both controls. | Keep the kernel current. Use a virtual machine when the threat model requires a hypervisor. |
| Root | Root can bypass controls outside Landlock hooks. | Never run the agent or launcher as root. |
| Existing processes | The sandbox applies at `execve` and does not change an earlier process. | Start the complete process tree through `agentwall sandbox run`. |

## Compose with the perimeter

Use this order on a supported Linux host:

```
PERIM="--agent-uid 61001 --proxy-uid 61002 --proxy-port 8080"
agentwall perimeter plan $PERIM | sudo nft -f -
agentwall perimeter verify $PERIM
sudo agentwall perimeter run $PERIM -- \
  agentwall sandbox run --workdir /srv/agent/work --allow-tcp 80 --allow-tcp 443 -- node agent.js
```

The pipe sends the ruleset to a real file stream for `nft`. The current `agentwall perimeter install` path can fail because `nft` rejects its socket-backed `/dev/stdin`.

Use the pipe form until that install path changes.

`perimeter run` changes to the agent uid first. `sandbox run` then applies Landlock and seccomp to that unprivileged process.

The launcher receives its profile on file descriptor 3. This pipe avoids a temporary file and survives the uid change.

The sandbox half was measured on the development host. The complete composed command was not measured there because perimeter installation changes host firewall rules.

Confirm `agentwall perimeter verify` on the target host. Confirm the sandbox summary line on the same host.

## Container limit

The published AgentWall container image does not include the sandbox launcher. That image runs the control plane, not the protected agent process.

Build the launcher in the agent container with `npm run build:sandbox`. You can also mount a launcher and set `AGENTWALL_SANDBOX_HELPER`.

A container does not replace the sandbox. A default container profile can still read every file inside its own filesystem.

## Related documents

- [The perimeter](perimeter.md) explains uid packet containment with nftables.
- [Threat model](threat-model.md) defines protected and unprotected cases.
- [Spill watch](spill-watch.md) detects credentials written to disk. The sandbox limits where the process can write.
