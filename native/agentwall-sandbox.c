/*
 * agentwall-sandbox: apply Landlock and seccomp to this process, then execve the agent.
 *
 * Why a separate binary at all. Landlock and seccomp are per-process credentials that must be
 * installed AFTER fork and BEFORE exec. Node offers no pre-exec hook on spawn, and it cannot
 * issue raw syscalls without a native addon, so the only honest way to get kernel enforcement in
 * front of an agent is a launcher that restricts itself and then becomes the agent. This file is
 * that launcher and nothing else: it reads a profile, calls four syscalls, and execs.
 *
 * It is written against raw syscall numbers with no libseccomp, no libcap and no landlock
 * userspace library. Those libraries are the usual way to do this and they are also three more
 * supply-chain edges on the one component in the tree that decides what the agent may touch. The
 * kernel UAPI constants are stable, small, and reproduced here with the ABI version that added
 * each one, so a reviewer can check them against include/uapi/linux/landlock.h directly.
 *
 * What this enforces and what it does not is stated in docs/sandbox.md. The short form:
 *   - Landlock confines filesystem access to declared paths. The kernel refuses everything else.
 *   - Landlock ABI 4 and up additionally confines outbound TCP connect and TCP bind to declared
 *     ports. Below ABI 4 the kernel has no such hook and the launcher says so out loud.
 *   - seccomp denies a named list of syscalls an agent has no business issuing. It is a denylist,
 *     not an allowlist, and a denylist can never be complete. It is defence in depth behind
 *     Landlock, not the boundary.
 *
 * Degradation is loud on purpose. An operator who believes a process is sandboxed and is wrong is
 * worse off than one who knows it is not, so every right that could not be installed is printed,
 * and a profile that asks for more than the kernel can give fails closed unless the operator has
 * explicitly said otherwise.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>

/* ------------------------------------------------------------------ exit codes */

/* The sandbox could not be installed as asked. The agent was NOT started. */
#define EXIT_SANDBOX_FAILED 125
/* The command exists but could not be executed. Matches the shell and env(1) convention. */
#define EXIT_CANNOT_EXEC 126
/* The command was not found. Matches the shell and env(1) convention. */
#define EXIT_NOT_FOUND 127

/* ------------------------------------------------------- landlock UAPI, reproduced */

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#define AW_LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define AW_LANDLOCK_RULE_PATH_BENEATH 1
#define AW_LANDLOCK_RULE_NET_PORT 2

/* Filesystem access rights. The trailing comment is the Landlock ABI that introduced the bit. */
#define AW_FS_EXECUTE (1ULL << 0)     /* abi 1 */
#define AW_FS_WRITE_FILE (1ULL << 1)  /* abi 1 */
#define AW_FS_READ_FILE (1ULL << 2)   /* abi 1 */
#define AW_FS_READ_DIR (1ULL << 3)    /* abi 1 */
#define AW_FS_REMOVE_DIR (1ULL << 4)  /* abi 1 */
#define AW_FS_REMOVE_FILE (1ULL << 5) /* abi 1 */
#define AW_FS_MAKE_CHAR (1ULL << 6)   /* abi 1 */
#define AW_FS_MAKE_DIR (1ULL << 7)    /* abi 1 */
#define AW_FS_MAKE_REG (1ULL << 8)    /* abi 1 */
#define AW_FS_MAKE_SOCK (1ULL << 9)   /* abi 1 */
#define AW_FS_MAKE_FIFO (1ULL << 10)  /* abi 1 */
#define AW_FS_MAKE_BLOCK (1ULL << 11) /* abi 1 */
#define AW_FS_MAKE_SYM (1ULL << 12)   /* abi 1 */
#define AW_FS_REFER (1ULL << 13)      /* abi 2 */
#define AW_FS_TRUNCATE (1ULL << 14)   /* abi 3 */
#define AW_FS_IOCTL_DEV (1ULL << 15)  /* abi 5 */

#define AW_NET_BIND_TCP (1ULL << 0)    /* abi 4 */
#define AW_NET_CONNECT_TCP (1ULL << 1) /* abi 4 */

/*
 * The full set this launcher knows how to handle, by ABI. handled_access_fs must never name a bit
 * the running kernel does not know: landlock_create_ruleset rejects the whole ruleset with EINVAL
 * if it does, which would turn a too-new profile into no sandbox at all.
 */
#define AW_FS_ABI1                                                                          \
  (AW_FS_EXECUTE | AW_FS_WRITE_FILE | AW_FS_READ_FILE | AW_FS_READ_DIR | AW_FS_REMOVE_DIR |  \
   AW_FS_REMOVE_FILE | AW_FS_MAKE_CHAR | AW_FS_MAKE_DIR | AW_FS_MAKE_REG | AW_FS_MAKE_SOCK | \
   AW_FS_MAKE_FIFO | AW_FS_MAKE_BLOCK | AW_FS_MAKE_SYM)

/*
 * The subset of rights that mean anything on a path that is not a directory.
 *
 * landlock_add_rule returns EINVAL, and the whole ruleset is then abandoned, if a rule on a
 * regular file carries a directory-only right such as READ_DIR or MAKE_REG. This is not
 * theoretical: the first end-to-end run of this launcher failed exactly here, because version
 * managers install the Node binary outside /usr and the profile therefore names the executable
 * file itself rather than a directory containing it. A rendered-profile test would never have
 * found it, and the failure was total rather than partial: no sandbox at all, not a slightly
 * loose one.
 */
#define AW_FS_FILE_APPLICABLE \
  (AW_FS_EXECUTE | AW_FS_WRITE_FILE | AW_FS_READ_FILE | AW_FS_TRUNCATE | AW_FS_IOCTL_DEV)

struct aw_ruleset_attr {
  uint64_t handled_access_fs;
  uint64_t handled_access_net;
};

struct aw_path_beneath_attr {
  uint64_t allowed_access;
  int32_t parent_fd;
} __attribute__((packed));

struct aw_net_port_attr {
  uint64_t allowed_access;
  uint64_t port;
};

/* ------------------------------------------------------------------ profile model */

#define MAX_FS_RULES 256
#define MAX_NET_RULES 64
#define MAX_PROFILE_BYTES 262144
#define MAX_PATH_LEN 4096

enum fs_mode { FS_READ, FS_EXEC, FS_WRITE, FS_RWDEV };

struct fs_rule {
  enum fs_mode mode;
  char path[MAX_PATH_LEN];
};

struct net_rule {
  int bind; /* 0 = connect, 1 = bind */
  uint64_t port;
};

enum seccomp_action { SECCOMP_OFF, SECCOMP_ERRNO, SECCOMP_KILL };

struct profile {
  int version;
  struct fs_rule fs[MAX_FS_RULES];
  size_t fs_count;
  struct net_rule net[MAX_NET_RULES];
  size_t net_count;
  /* Whether Landlock should handle network access at all. Without it, TCP is unconstrained. */
  int net_restrict;
  enum seccomp_action seccomp;
  /* Minimum Landlock ABI the operator will accept. 0 means "whatever the kernel has". */
  int require_abi;
  /* Permit running with no Landlock at all. Off by default: refuse rather than pretend. */
  int allow_degraded;
  /* Saw the terminating `end` line, so the profile is known complete rather than truncated. */
  int terminated;
};

/* ------------------------------------------------------------------------ logging */

static const char *PROG = "agentwall-sandbox";

static void warn_line(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "%s: ", PROG);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
}

static void fail(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "%s: ", PROG);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  fprintf(stderr, "%s: refusing to start the command uncontained.\n", PROG);
  exit(EXIT_SANDBOX_FAILED);
}

/* ------------------------------------------------------------------ landlock probe */

/* Returns the kernel's Landlock ABI version, 0 when Landlock is compiled out or disabled. */
static int landlock_abi(void) {
  long v = syscall(__NR_landlock_create_ruleset, NULL, 0, AW_LANDLOCK_CREATE_RULESET_VERSION);
  if (v < 0) return 0;
  return (int)v;
}

/* The filesystem rights this launcher will ask the kernel to handle at the measured ABI. */
static uint64_t fs_handled_for_abi(int abi) {
  uint64_t handled = AW_FS_ABI1;
  if (abi >= 2) handled |= AW_FS_REFER;
  if (abi >= 3) handled |= AW_FS_TRUNCATE;
  if (abi >= 5) handled |= AW_FS_IOCTL_DEV;
  return handled;
}

static uint64_t fs_rights_for_mode(enum fs_mode mode, uint64_t handled) {
  uint64_t rights = 0;
  switch (mode) {
    case FS_READ:
      rights = AW_FS_READ_FILE | AW_FS_READ_DIR;
      break;
    case FS_EXEC:
      rights = AW_FS_READ_FILE | AW_FS_READ_DIR | AW_FS_EXECUTE;
      break;
    case FS_WRITE:
      rights = AW_FS_READ_FILE | AW_FS_READ_DIR | AW_FS_WRITE_FILE | AW_FS_TRUNCATE |
               AW_FS_MAKE_REG | AW_FS_MAKE_DIR | AW_FS_MAKE_SYM | AW_FS_MAKE_FIFO |
               AW_FS_MAKE_SOCK | AW_FS_REMOVE_FILE | AW_FS_REMOVE_DIR | AW_FS_REFER;
      break;
    case FS_RWDEV:
      /*
       * Character devices a runtime cannot live without: /dev/null, /dev/urandom, /dev/tty.
       * IOCTL_DEV is included where the kernel knows it, because a tty that cannot be queried
       * for its window size is a tty most programs decide is broken.
       */
      rights = AW_FS_READ_FILE | AW_FS_WRITE_FILE | AW_FS_IOCTL_DEV;
      break;
  }
  /* Never request a right the ruleset does not handle: landlock_add_rule returns EINVAL. */
  return rights & handled;
}

/* ------------------------------------------------------------- seccomp denylist */

/*
 * The denylist. Every entry is a syscall no agent runtime issues in normal operation, chosen so
 * that a false positive is a bug report rather than a mystery. It is deliberately not an
 * allowlist: an allowlist tight enough to be interesting breaks Node in ways that surface hours
 * later inside libuv, and a control operators switch off is worth less than a smaller control
 * they leave on.
 *
 * Grouped by what each would buy an attacker who already has code execution as the agent.
 */
struct deny_entry {
  const char *name;
  int nr;
  /* Errno returned when the action is "errno". ENOSYS where a caller has a documented fallback. */
  int err;
};

#define DENY(sym, errcode)    \
  {                           \
#sym, __NR_##sym, errcode \
  }

static const struct deny_entry DENYLIST[] = {
/* New namespaces. The escape hatch that turns code execution into fresh kernel attack surface. */
#ifdef __NR_unshare
    DENY(unshare, EPERM),
#endif
#ifdef __NR_setns
    DENY(setns, EPERM),
#endif
/* Mount table manipulation. Landlock rules are pinned to paths; remounting moves the paths. */
#ifdef __NR_mount
    DENY(mount, EPERM),
#endif
#ifdef __NR_umount2
    DENY(umount2, EPERM),
#endif
#ifdef __NR_mount_setattr
    DENY(mount_setattr, EPERM),
#endif
#ifdef __NR_move_mount
    DENY(move_mount, EPERM),
#endif
#ifdef __NR_open_tree
    DENY(open_tree, EPERM),
#endif
#ifdef __NR_fsopen
    DENY(fsopen, EPERM),
#endif
#ifdef __NR_fsconfig
    DENY(fsconfig, EPERM),
#endif
#ifdef __NR_fsmount
    DENY(fsmount, EPERM),
#endif
#ifdef __NR_fspick
    DENY(fspick, EPERM),
#endif
#ifdef __NR_pivot_root
    DENY(pivot_root, EPERM),
#endif
#ifdef __NR_chroot
    DENY(chroot, EPERM),
#endif
/* Filesystem access that walks no path, and therefore meets no Landlock path rule. */
#ifdef __NR_open_by_handle_at
    DENY(open_by_handle_at, EPERM),
#endif
#ifdef __NR_name_to_handle_at
    DENY(name_to_handle_at, EPERM),
#endif
/* Kernel code loading and the reboot path. */
#ifdef __NR_init_module
    DENY(init_module, EPERM),
#endif
#ifdef __NR_finit_module
    DENY(finit_module, EPERM),
#endif
#ifdef __NR_delete_module
    DENY(delete_module, EPERM),
#endif
#ifdef __NR_kexec_load
    DENY(kexec_load, EPERM),
#endif
#ifdef __NR_kexec_file_load
    DENY(kexec_file_load, EPERM),
#endif
#ifdef __NR_reboot
    DENY(reboot, EPERM),
#endif
/* Large kernel attack surfaces with no agent use case. */
#ifdef __NR_bpf
    DENY(bpf, EPERM),
#endif
#ifdef __NR_perf_event_open
    DENY(perf_event_open, EPERM),
#endif
#ifdef __NR_userfaultfd
    DENY(userfaultfd, EPERM),
#endif
/*
 * io_uring submits file and socket operations through a shared ring, and those submissions are
 * not seen by this filter at all. Landlock still applies to them, so this is not the boundary,
 * but leaving a seccomp bypass open next to a seccomp filter is not a defensible default.
 * Node's libuv probes io_uring_setup and falls back to its thread pool when it fails.
 */
#ifdef __NR_io_uring_setup
    DENY(io_uring_setup, EPERM),
#endif
#ifdef __NR_io_uring_enter
    DENY(io_uring_enter, EPERM),
#endif
#ifdef __NR_io_uring_register
    DENY(io_uring_register, EPERM),
#endif
/* Reaching into other processes. Landlock scopes ptrace to the domain; this closes the rest. */
#ifdef __NR_ptrace
    DENY(ptrace, EPERM),
#endif
#ifdef __NR_process_vm_readv
    DENY(process_vm_readv, EPERM),
#endif
#ifdef __NR_process_vm_writev
    DENY(process_vm_writev, EPERM),
#endif
#ifdef __NR_kcmp
    DENY(kcmp, EPERM),
#endif
/* Host-wide state an agent has no business setting. */
#ifdef __NR_settimeofday
    DENY(settimeofday, EPERM),
#endif
#ifdef __NR_clock_settime
    DENY(clock_settime, EPERM),
#endif
#ifdef __NR_clock_adjtime
    DENY(clock_adjtime, EPERM),
#endif
#ifdef __NR_adjtimex
    DENY(adjtimex, EPERM),
#endif
#ifdef __NR_sethostname
    DENY(sethostname, EPERM),
#endif
#ifdef __NR_setdomainname
    DENY(setdomainname, EPERM),
#endif
#ifdef __NR_swapon
    DENY(swapon, EPERM),
#endif
#ifdef __NR_swapoff
    DENY(swapoff, EPERM),
#endif
#ifdef __NR_acct
    DENY(acct, EPERM),
#endif
#ifdef __NR_quotactl
    DENY(quotactl, EPERM),
#endif
#ifdef __NR_syslog
    DENY(syslog, EPERM),
#endif
/* Kernel keyring. Credentials the agent should never be able to enumerate or add to. */
#ifdef __NR_add_key
    DENY(add_key, EPERM),
#endif
#ifdef __NR_request_key
    DENY(request_key, EPERM),
#endif
#ifdef __NR_keyctl
    DENY(keyctl, EPERM),
#endif
/* Direct hardware access, x86 only, and legacy loaders nothing modern uses. */
#ifdef __NR_ioperm
    DENY(ioperm, EPERM),
#endif
#ifdef __NR_iopl
    DENY(iopl, EPERM),
#endif
#ifdef __NR_modify_ldt
    DENY(modify_ldt, EPERM),
#endif
#ifdef __NR_uselib
    DENY(uselib, EPERM),
#endif
/*
 * clone3 passes its flags in a struct that seccomp cannot dereference, so CLONE_NEWUSER cannot be
 * filtered there. ENOSYS rather than EPERM is load bearing: glibc's __clone_internal tries clone3
 * first and falls back to clone only on ENOSYS. Return anything else and pthread_create fails.
 */
#ifdef __NR_clone3
    DENY(clone3, ENOSYS),
#endif
};

#define DENYLIST_LEN (sizeof(DENYLIST) / sizeof(DENYLIST[0]))

/* Terminal line discipline ioctls that push characters into the controlling tty's input queue. */
#define AW_TIOCSTI 0x5412
#define AW_TIOCLINUX 0x541C

#if defined(__x86_64__)
#define AW_AUDIT_ARCH AUDIT_ARCH_X86_64
#define AW_HAS_X32 1
#elif defined(__aarch64__)
#define AW_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define AW_HAS_X32 0
#elif defined(__i386__)
#define AW_AUDIT_ARCH AUDIT_ARCH_I386
#define AW_HAS_X32 0
#elif defined(__arm__)
#define AW_AUDIT_ARCH AUDIT_ARCH_ARM
#define AW_HAS_X32 0
#else
#define AW_AUDIT_ARCH 0
#define AW_HAS_X32 0
#endif

#ifndef X32_SYSCALL_BIT
#define X32_SYSCALL_BIT 0x40000000
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ARG_LO(n) ((uint32_t)(offsetof(struct seccomp_data, args) + 8 * (n)))
#else
#define ARG_LO(n) ((uint32_t)(offsetof(struct seccomp_data, args) + 8 * (n) + 4))
#endif
#define OFF_NR ((uint32_t)offsetof(struct seccomp_data, nr))
#define OFF_ARCH ((uint32_t)offsetof(struct seccomp_data, arch))

/*
 * Build the filter.
 *
 * Every conditional jump below moves at most a handful of instructions. That is not style. BPF
 * jump offsets are eight bits, a filter that outgrows 255 instructions between a test and its
 * target silently stops meaning what it reads like, and the assembler here is a hand-written
 * array. Two instructions per denied syscall with a jump distance of one can never overflow no
 * matter how long the denylist grows.
 */
static size_t build_filter(struct sock_filter *out, size_t cap, enum seccomp_action action) {
  size_t n = 0;

#define EMIT(instr)                       \
  do {                                    \
    if (n >= cap) return 0;               \
    out[n++] = (struct sock_filter)instr; \
  } while (0)
#define DENY_RET(errcode)                                                                  \
  do {                                                                                     \
    if (action == SECCOMP_KILL) {                                                          \
      EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));                           \
    } else {                                                                               \
      EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ((errcode) & SECCOMP_RET_DATA))); \
    }                                                                                      \
  } while (0)

  /* A filter written for one architecture says nothing about syscalls entering under another. */
  EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
  EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AW_AUDIT_ARCH, 1, 0));
  EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

  EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
#if AW_HAS_X32
  /* x32 reuses x86_64 numbers with a high bit set, so the numbers below would not match. */
  EMIT(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
  EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
#endif

  for (size_t i = 0; i < DENYLIST_LEN; i++) {
    /* Equal: fall through to the deny return. Not equal: skip over it. */
    EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)DENYLIST[i].nr, 0, 1));
    DENY_RET(DENYLIST[i].err);
  }

#ifdef __NR_clone
  /*
   * clone(CLONE_NEWUSER) is the same privilege gain as unshare(CLONE_NEWUSER) through another
   * door. Flags live in args[0] on every architecture this builds for. Every other clone is left
   * alone: Node forks and creates threads constantly.
   */
  EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3));
  EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARG_LO(0)));
  EMIT(BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWUSER, 0, 1));
  DENY_RET(EPERM);
  EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
#endif

#ifdef __NR_ioctl
  /*
   * TIOCSTI writes bytes into the controlling terminal's input queue, so an agent sharing a tty
   * with its operator can type commands as that operator. TIOCLINUX has a console variant of the
   * same trick. Both are request codes rather than syscalls, so they are filtered on args[1].
   */
  EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 5));
  EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARG_LO(1)));
  EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AW_TIOCSTI, 0, 1));
  DENY_RET(EPERM);
  EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AW_TIOCLINUX, 0, 1));
  DENY_RET(EPERM);
  EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
#endif

  EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

#undef EMIT
#undef DENY_RET
  return n;
}

/* 1 = filter mode with a queryable action set, -1 = probably usable, 0 = unusable. */
static int seccomp_filter_available(void) {
  uint32_t action = SECCOMP_RET_KILL_PROCESS;
  long rc = syscall(__NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
  if (rc == 0) return 1;
  /* Older kernels lack the query operation but still support filter mode. */
  return (errno == EINVAL || errno == EOPNOTSUPP) ? -1 : 0;
}

/* ------------------------------------------------------------------ profile parsing */

static char *read_all(int fd, size_t *out_len) {
  size_t cap = 8192, len = 0;
  char *buf = malloc(cap);
  if (buf == NULL) fail("out of memory reading the profile.");
  for (;;) {
    if (len + 1 >= cap) {
      if (cap >= MAX_PROFILE_BYTES) fail("profile is larger than %d bytes.", MAX_PROFILE_BYTES);
      cap *= 2;
      char *grown = realloc(buf, cap);
      if (grown == NULL) fail("out of memory reading the profile.");
      buf = grown;
    }
    ssize_t got = read(fd, buf + len, cap - len - 1);
    if (got < 0) {
      if (errno == EINTR) continue;
      fail("could not read the profile: %s", strerror(errno));
    }
    if (got == 0) break;
    len += (size_t)got;
  }
  buf[len] = '\0';
  *out_len = len;
  return buf;
}

/* Split "verb rest" at the first run of blanks. Returns rest, which may be empty. */
static char *split_word(char *line, char **word) {
  while (*line == ' ' || *line == '\t') line++;
  *word = line;
  while (*line != '\0' && *line != ' ' && *line != '\t') line++;
  if (*line != '\0') {
    *line = '\0';
    line++;
    while (*line == ' ' || *line == '\t') line++;
  }
  return line;
}

static void parse_profile(char *text, struct profile *p) {
  memset(p, 0, sizeof(*p));
  p->seccomp = SECCOMP_OFF;
  int line_no = 0;

  char *save = NULL;
  for (char *line = strtok_r(text, "\n", &save); line != NULL;
       line = strtok_r(NULL, "\n", &save)) {
    line_no++;
    /* Strip a trailing carriage return so a CRLF profile is not a mystery. */
    size_t l = strlen(line);
    if (l > 0 && line[l - 1] == '\r') line[l - 1] = '\0';

    char *verb = NULL;
    char *rest = split_word(line, &verb);
    if (verb[0] == '\0' || verb[0] == '#') continue;

    if (strcmp(verb, "version") == 0) {
      p->version = atoi(rest);
      if (p->version != 1) fail("profile line %d: unsupported version '%s'.", line_no, rest);
    } else if (strcmp(verb, "fs") == 0) {
      char *mode_word = NULL;
      char *path = split_word(rest, &mode_word);
      enum fs_mode mode = FS_READ;
      if (strcmp(mode_word, "read") == 0) {
        mode = FS_READ;
      } else if (strcmp(mode_word, "exec") == 0) {
        mode = FS_EXEC;
      } else if (strcmp(mode_word, "write") == 0) {
        mode = FS_WRITE;
      } else if (strcmp(mode_word, "rwdev") == 0) {
        mode = FS_RWDEV;
      } else {
        fail("profile line %d: unknown fs mode '%s'.", line_no, mode_word);
      }
      if (path[0] != '/') {
        fail("profile line %d: fs path must be absolute, got '%s'.", line_no, path);
      }
      if (strlen(path) >= MAX_PATH_LEN) fail("profile line %d: fs path too long.", line_no);
      if (p->fs_count >= MAX_FS_RULES) fail("profile has more than %d fs rules.", MAX_FS_RULES);
      p->fs[p->fs_count].mode = mode;
      snprintf(p->fs[p->fs_count].path, MAX_PATH_LEN, "%s", path);
      p->fs_count++;
    } else if (strcmp(verb, "net") == 0) {
      char *kind = NULL;
      char *arg = split_word(rest, &kind);
      if (strcmp(kind, "restrict") == 0) {
        p->net_restrict = 1;
      } else if (strcmp(kind, "connect-tcp") == 0 || strcmp(kind, "bind-tcp") == 0) {
        char *endp = NULL;
        unsigned long port = strtoul(arg, &endp, 10);
        if (endp == arg || port > 65535) fail("profile line %d: bad port '%s'.", line_no, arg);
        if (p->net_count >= MAX_NET_RULES) {
          fail("profile has more than %d net rules.", MAX_NET_RULES);
        }
        p->net[p->net_count].bind = (kind[0] == 'b');
        p->net[p->net_count].port = port;
        p->net_count++;
      } else {
        fail("profile line %d: unknown net directive '%s'.", line_no, kind);
      }
    } else if (strcmp(verb, "seccomp") == 0) {
      if (strcmp(rest, "off") == 0) {
        p->seccomp = SECCOMP_OFF;
      } else if (strcmp(rest, "errno") == 0) {
        p->seccomp = SECCOMP_ERRNO;
      } else if (strcmp(rest, "kill") == 0) {
        p->seccomp = SECCOMP_KILL;
      } else {
        fail("profile line %d: seccomp must be off, errno or kill.", line_no);
      }
    } else if (strcmp(verb, "require-abi") == 0) {
      p->require_abi = atoi(rest);
    } else if (strcmp(verb, "allow-degraded") == 0) {
      p->allow_degraded = 1;
    } else if (strcmp(verb, "end") == 0) {
      p->terminated = 1;
    } else {
      fail("profile line %d: unknown directive '%s'.", line_no, verb);
    }
  }

  if (p->version != 1) fail("profile has no `version 1` line.");
  if (!p->terminated) {
    fail("profile has no `end` line, so it may have been truncated. A truncated profile can drop "
         "the seccomp directive, which would silently produce a weaker sandbox than was asked "
         "for.");
  }
}

/* ------------------------------------------------------------------ applying it */

struct applied {
  int abi;
  size_t fs_rules;
  size_t fs_missing;
  size_t net_rules;
  int net_enforced;
  /* Whether the kernel knew the IOCTL_DEV right. Reported on the summary line, not as a warning. */
  int ioctl_dev;
  int seccomp_instructions;
};

static void apply_landlock(const struct profile *p, struct applied *a) {
  a->abi = landlock_abi();

  if (a->abi == 0) {
    if (p->require_abi > 0) {
      fail("this kernel has no Landlock (landlock_create_ruleset is unavailable) but the profile "
           "requires ABI %d. Filesystem confinement cannot be installed here.",
           p->require_abi);
    }
    if (!p->allow_degraded) {
      fail("this kernel has no Landlock, so no filesystem confinement can be installed. Landlock "
           "needs Linux 5.13 or newer with CONFIG_SECURITY_LANDLOCK=y and `landlock` present in "
           "the boot-time LSM list. Put allow-degraded in the profile to run anyway, knowing the "
           "filesystem is not confined.");
    }
    warn_line("DEGRADED: no Landlock on this kernel. The filesystem is NOT confined. Continuing "
              "only because the profile said allow-degraded.");
    return;
  }

  if (p->require_abi > a->abi) {
    fail("profile requires Landlock ABI %d, this kernel provides %d.", p->require_abi, a->abi);
  }

  uint64_t handled_fs = fs_handled_for_abi(a->abi);
  uint64_t handled_net = 0;
  if (p->net_restrict) {
    if (a->abi >= 4) {
      handled_net = AW_NET_BIND_TCP | AW_NET_CONNECT_TCP;
      a->net_enforced = 1;
    } else {
      warn_line("DEGRADED: the profile asks for TCP port confinement, which needs Landlock ABI 4 "
                "(Linux 6.7). This kernel reports ABI %d, so outbound TCP is NOT confined by "
                "Landlock here. Whatever network control you have is the only one in effect.",
                a->abi);
    }
  }
  if (!a->net_enforced && p->net_count > 0) {
    warn_line("%zu net rule(s) in the profile were not installed, for the reason above.",
              p->net_count);
  }

  if (a->abi < 3) {
    warn_line("DEGRADED: Landlock ABI %d has no TRUNCATE right (added in ABI 3, Linux 6.2). A "
              "file under a read-only path can still be emptied with truncate(2) on this kernel.",
              a->abi);
  }
  /*
   * IOCTL_DEV is reported on the summary line rather than warned about, because it is missing on
   * every kernel below 6.10 and a warning that fires on almost every run is a warning operators
   * learn to pipe away. The genuine degradations above are rare and stay loud.
   */
  a->ioctl_dev = (handled_fs & AW_FS_IOCTL_DEV) != 0;

  struct aw_ruleset_attr attr = {
      .handled_access_fs = handled_fs,
      .handled_access_net = handled_net,
  };
  int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
  if (ruleset_fd < 0) fail("landlock_create_ruleset failed: %s", strerror(errno));

  for (size_t i = 0; i < p->fs_count; i++) {
    uint64_t rights = fs_rights_for_mode(p->fs[i].mode, handled_fs);
    if (rights == 0) continue;
    int path_fd = open(p->fs[i].path, O_PATH | O_CLOEXEC);
    if (path_fd < 0) {
      /*
       * A path in the profile that does not exist on this host. Skipping is right: base profiles
       * name paths present on most distributions and absent on some, and refusing would make the
       * sandbox unusable rather than safer. Skipping quietly would not be right, because a typo
       * in a write path looks exactly like this and produces an agent that cannot do its job.
       */
      warn_line("skipping fs rule for %s: %s", p->fs[i].path, strerror(errno));
      a->fs_missing++;
      continue;
    }

    /*
     * Rights are declared per mode without knowing what is on the other end of the path, so a
     * non-directory target has its directory-only rights removed here rather than being refused.
     * `fs exec /path/to/node` is a reasonable thing for an operator to write and it should work.
     */
    struct stat st;
    if (fstat(path_fd, &st) == 0 && !S_ISDIR(st.st_mode)) {
      rights &= AW_FS_FILE_APPLICABLE;
      if (rights == 0) {
        warn_line("skipping fs rule for %s: it is not a directory, and none of the requested "
                  "rights apply to a file.",
                  p->fs[i].path);
        close(path_fd);
        a->fs_missing++;
        continue;
      }
    }
    struct aw_path_beneath_attr beneath = {.allowed_access = rights, .parent_fd = path_fd};
    if (syscall(__NR_landlock_add_rule, ruleset_fd, AW_LANDLOCK_RULE_PATH_BENEATH, &beneath, 0)) {
      int saved = errno;
      close(path_fd);
      close(ruleset_fd);
      fail("landlock_add_rule failed for %s: %s", p->fs[i].path, strerror(saved));
    }
    close(path_fd);
    a->fs_rules++;
  }

  if (a->net_enforced) {
    for (size_t i = 0; i < p->net_count; i++) {
      struct aw_net_port_attr port = {
          .allowed_access = p->net[i].bind ? AW_NET_BIND_TCP : AW_NET_CONNECT_TCP,
          .port = p->net[i].port,
      };
      if (syscall(__NR_landlock_add_rule, ruleset_fd, AW_LANDLOCK_RULE_NET_PORT, &port, 0)) {
        int saved = errno;
        close(ruleset_fd);
        fail("landlock_add_rule failed for tcp port %llu: %s", (unsigned long long)p->net[i].port,
             strerror(saved));
      }
      a->net_rules++;
    }
  }

  if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0)) {
    int saved = errno;
    close(ruleset_fd);
    fail("landlock_restrict_self failed: %s", strerror(saved));
  }
  close(ruleset_fd);
}

static void apply_seccomp(const struct profile *p, struct applied *a) {
  if (p->seccomp == SECCOMP_OFF) return;

  if (AW_AUDIT_ARCH == 0) {
    fail("seccomp was requested but this architecture has no AUDIT_ARCH constant in this build, "
         "so a filter here could not tell one syscall ABI from another.");
  }

  if (seccomp_filter_available() == 0) {
    fail("seccomp filter mode is unavailable on this kernel: %s. Build the kernel with "
         "CONFIG_SECCOMP_FILTER=y or set `seccomp off` in the profile.",
         strerror(errno));
  }

  struct sock_filter filter[512];
  size_t len = build_filter(filter, sizeof(filter) / sizeof(filter[0]), p->seccomp);
  if (len == 0) fail("internal error: the seccomp filter did not fit in its buffer.");

  struct sock_fprog prog = {.len = (unsigned short)len, .filter = filter};
  if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog)) {
    fail("seccomp(SECCOMP_SET_MODE_FILTER) failed: %s", strerror(errno));
  }
  a->seccomp_instructions = (int)len;
}

/* ------------------------------------------------------------------------- modes */

static int mode_probe(void) {
  struct utsname u;
  int abi = landlock_abi();
  printf("landlock_abi=%d\n", abi);
  printf("landlock_max_known_abi=5\n");
  printf("landlock_fs=%s\n", abi >= 1 ? "yes" : "no");
  printf("landlock_truncate=%s\n", abi >= 3 ? "yes" : "no");
  printf("landlock_net_tcp=%s\n", abi >= 4 ? "yes" : "no");
  printf("landlock_ioctl_dev=%s\n", abi >= 5 ? "yes" : "no");

  int avail = seccomp_filter_available();
  printf("seccomp_filter=%s\n", avail != 0 ? "yes" : "no");
  printf("seccomp_kill_process=%s\n", avail == 1 ? "yes" : "unknown");
  printf("seccomp_denied_syscalls=%zu\n", DENYLIST_LEN);
  printf("arch_supported=%s\n", AW_AUDIT_ARCH != 0 ? "yes" : "no");
  if (uname(&u) == 0) printf("kernel_release=%s\n", u.release);
  return 0;
}

static int mode_list_denied(void) {
  for (size_t i = 0; i < DENYLIST_LEN; i++) {
    printf("%s=%d errno=%d\n", DENYLIST[i].name, DENYLIST[i].nr, DENYLIST[i].err);
  }
  printf("clone_newuser=filtered errno=%d\n", EPERM);
  printf("ioctl_tiocsti=filtered errno=%d\n", EPERM);
  printf("ioctl_tioclinux=filtered errno=%d\n", EPERM);
  return 0;
}

static const char *USAGE =
    "Usage:\n"
    "  agentwall-sandbox [--profile-fd N | --profile-file PATH] [--quiet] -- COMMAND [ARGS...]\n"
    "  agentwall-sandbox --probe\n"
    "  agentwall-sandbox --list-denied\n"
    "\n"
    "Applies a Landlock ruleset and a seccomp filter to itself, then execs COMMAND. The profile\n"
    "is read from file descriptor 3 by default, so it never lands on disk. See docs/sandbox.md.\n";

int main(int argc, char **argv) {
  int profile_fd = 3;
  const char *profile_file = NULL;
  int quiet = 0;
  int i = 1;

  for (; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--") == 0) {
      i++;
      break;
    }
    if (strcmp(arg, "--probe") == 0) return mode_probe();
    if (strcmp(arg, "--list-denied") == 0) return mode_list_denied();
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      fputs(USAGE, stdout);
      return 0;
    }
    if (strcmp(arg, "--quiet") == 0) {
      quiet = 1;
      continue;
    }
    if (strcmp(arg, "--profile-fd") == 0 && i + 1 < argc) {
      profile_fd = atoi(argv[++i]);
      continue;
    }
    if (strcmp(arg, "--profile-file") == 0 && i + 1 < argc) {
      profile_file = argv[++i];
      continue;
    }
    fprintf(stderr, "%s: unknown option %s\n%s", PROG, arg, USAGE);
    return EXIT_SANDBOX_FAILED;
  }

  if (i >= argc) {
    fprintf(stderr, "%s: no command after --\n%s", PROG, USAGE);
    return EXIT_SANDBOX_FAILED;
  }

  int fd = profile_fd;
  if (profile_file != NULL) {
    fd = open(profile_file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail("could not open profile %s: %s", profile_file, strerror(errno));
  }

  size_t len = 0;
  char *text = read_all(fd, &len);
  if (len == 0) {
    fail("the profile was empty, so nothing would have been restricted. The command was not "
         "started.");
  }
  if (profile_file != NULL) close(fd);

  struct profile p;
  parse_profile(text, &p);

  /*
   * no_new_privs first, and unconditionally. landlock_restrict_self and an unprivileged seccomp
   * filter both require it, and it is independently the thing that stops a confined process from
   * exec'ing a setuid binary straight back out of the confinement.
   */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    fail("prctl(PR_SET_NO_NEW_PRIVS) failed: %s", strerror(errno));
  }

  struct applied applied;
  memset(&applied, 0, sizeof(applied));
  apply_landlock(&p, &applied);
  apply_seccomp(&p, &applied);

  if (!quiet) {
    fprintf(stderr,
            "%s: landlock abi=%d fs-rules=%zu skipped=%zu net=%s net-rules=%zu ioctl-dev=%s "
            "seccomp=%s filter-insns=%d\n",
            PROG, applied.abi, applied.fs_rules, applied.fs_missing,
            applied.net_enforced ? "tcp" : "off", applied.net_rules,
            applied.ioctl_dev ? "on" : "unavailable",
            p.seccomp == SECCOMP_OFF ? "off" : (p.seccomp == SECCOMP_KILL ? "kill" : "errno"),
            applied.seccomp_instructions);
  }

  free(text);

  execvp(argv[i], &argv[i]);
  int saved = errno;
  fprintf(stderr, "%s: could not exec %s: %s\n", PROG, argv[i], strerror(saved));
  /*
   * The sandbox is already installed by this point, so a failure here is usually the sandbox
   * doing its job: the command sits outside every fs exec rule. Say so rather than leaving the
   * operator to guess.
   */
  if (saved == EACCES) {
    fprintf(stderr,
            "%s: EACCES after the sandbox was applied usually means no `fs exec` rule covers this "
            "path.\n",
            PROG);
  }
  return saved == ENOENT ? EXIT_NOT_FOUND : EXIT_CANNOT_EXEC;
}
