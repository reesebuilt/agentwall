/*
 * A syscall probe for the kernel enforcement tests.
 *
 * Every line it prints is the result of one real syscall, formatted as `name=rc errno=N`. The
 * tests run it twice, once bare and once under the launcher, and compare. That comparison is the
 * only thing in this repository that can honestly claim seccomp or Landlock networking works: a
 * test that asserts the rendered profile contains `seccomp errno` proves the string, and a test
 * that asserts a syscall failed under the filter but succeeded without it proves the kernel.
 *
 * It is C rather than Node because Node cannot issue a raw syscall, and because the point is to
 * make the forbidden call directly rather than through a library that might not make it at all.
 * Compiled by tests/sandbox-kernel.test.ts into a temporary directory, never checked in built.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void report(const char *name, long rc) {
  printf("%s=%ld errno=%d\n", name, rc, rc < 0 ? errno : 0);
}

/* Connect to a loopback port and report only whether the kernel permitted the attempt. */
static void probe_connect(const char *label, int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    printf("%s=-1 errno=%d\n", label, errno);
    return;
  }
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((unsigned short)port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  /*
   * ECONNREFUSED means the kernel let the connect through and nothing was listening, which is a
   * PASS for the permitted case. EACCES means Landlock refused it before it left the host.
   */
  printf("%s=%d errno=%d\n", label, rc, rc < 0 ? errno : 0);
  close(fd);
}

static void probe_bind(const char *label, int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    printf("%s=-1 errno=%d\n", label, errno);
    return;
  }
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((unsigned short)port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
  printf("%s=%d errno=%d\n", label, rc, rc < 0 ? errno : 0);
  close(fd);
}

static void probe_open(const char *label, const char *path, int flags) {
  int fd = open(path, flags, 0600);
  printf("%s=%d errno=%d\n", label, fd < 0 ? -1 : 0, fd < 0 ? errno : 0);
  if (fd >= 0) close(fd);
}

/*
 * Usage: sandbox-syscall-probe <read-path> <write-path> <permitted-port> <forbidden-port>
 * Always exits 0. The tests read the printed lines; a nonzero exit would only hide them.
 */
int main(int argc, char **argv) {
  const char *read_path = argc > 1 ? argv[1] : "/etc/hostname";
  const char *write_path = argc > 2 ? argv[2] : "/tmp/agentwall-probe-write";
  int permitted_port = argc > 3 ? atoi(argv[3]) : 0;
  int forbidden_port = argc > 4 ? atoi(argv[4]) : 0;

  probe_open("open_read", read_path, O_RDONLY);
  probe_open("open_write", write_path, O_WRONLY | O_CREAT | O_TRUNC);

  /* Denied by the seccomp filter. Succeeds unsandboxed on a host with unprivileged user ns. */
  report("unshare_newuser", syscall(__NR_unshare, CLONE_NEWUSER));
  /* Denied by the seccomp filter. PTRACE_TRACEME is 0 and succeeds unsandboxed. */
  report("ptrace_traceme", syscall(__NR_ptrace, 0, 0, 0, 0));
  /*
   * Denied by the seccomp filter. Unsandboxed this returns EFAULT for the NULL params, which is
   * still proof the syscall was reached; sandboxed it must be EPERM before any argument is read.
   */
  report("io_uring_setup", syscall(__NR_io_uring_setup, 1, NULL));
  /* A control. If this ever fails the filter is broken, not the thing under test. */
  report("getpid", syscall(__NR_getpid));

  if (permitted_port > 0) probe_connect("connect_permitted", permitted_port);
  if (forbidden_port > 0) probe_connect("connect_forbidden", forbidden_port);
  if (forbidden_port > 0) probe_bind("bind_forbidden", forbidden_port);

  return 0;
}
